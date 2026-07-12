"""The agent loop: gathering (deterministic) -> Detection -> Validation.

Each LLM phase runs the same generic sub-loop (`_run_phase`) but with its OWN system
prompt and its OWN subset of MCP tools, and the LLM context is RESET between phases
(Claim Check): only a lightweight flow-inventory (the work-list) travels across,
while the heavy artifacts (CodeQL DB, SARIF) stay on disk.

- Gathering (NO LLM): `_gather_evidence` creates the CodeQL DB and calls the 12
  mechanical inventory tools (find_all_flows + 11 categorized/extra ones) directly.
  These need zero judgement to run ("call each once"), so no model is involved.
- Detection (LLM): enriches that pre-gathered evidence by reading the code — real
  names/values/algorithms, a relevance judgement. Does NOT discover signals itself
  and does NOT assign CWEs; its analysis text is carried forward to Validation.
- Validation (LLM): builds/runs the targeted queries it needs (results are
  trustworthy), associates a CWE to each finding, and WRITES THE FINAL REPORT.

(Evaluation with standard CodeQL queries is deliberately OUT of this framework.)
Pure orchestration — every other concern lives in its own module.
"""
from __future__ import annotations

import json
import re
import sys
import time

from agent import config
from agent.clients import mcp
from agent.clients.factory import make_llm
from agent.phases import DETECTION, VALIDATION, fetch_phase_tools, filter_tools
from agent.progress import make_progress
from agent.prompt_router import prompt_set
from agent.report import RunStats
from agent.robustness import checkpoint as ckpt_mod
from agent.robustness.dbpath import resolve_db_path
from agent.robustness.degenerate import is_degenerate_text
from agent.robustness.readargs import fix_read_file_snippet_args
from agent.robustness.toolcalls import extract_text_tool_calls
from agent.worklist import WorkList

_DUP_NUDGE_SUMMARY = (
    "\n\nNOTE: You already called this exact tool. The result is unchanged. Do NOT "
    "call it again. Run a DIFFERENT tool you have not used yet, or write your SHORT "
    "summary now."
)
_DUP_NUDGE_REPORT = (
    "\n\nNOTE: You already called this exact tool. The result is unchanged. Do NOT "
    "call it again. Run a DIFFERENT tool you have not used yet, or write the final "
    "SECURITY REPORT now."
)
_STUCK_SUMMARY = (
    "You are repeating tool calls without new information. Stop using tools and "
    "write your SHORT summary now, based on what you have."
)
_STUCK_REPORT = (
    "You are repeating tool calls without new information. Stop using tools and "
    "write the final SECURITY REPORT now, based on the findings already gathered."
)
_NO_DB_ERROR = json.dumps(
    {"error": "No CodeQL database exists yet. Call create_codeql_database first, "
              "then pass the db_path it returns."}
)
_LOCAL_LONG_PROSE_CHARS = 1200
_CWE_RE = re.compile(r"CWE-(\d+)", re.IGNORECASE)
# Tool names that count as "actually verified something" in Validation (query the DB
# for real evidence). read_file_snippet/cwe_knowledge/list_cwes don't count: they read
# context/knowledge, they don't produce CodeQL evidence.
_VERIFICATION_TOOLS = {
    "run_taint_query", "run_api_misuse_query", "run_insecure_config_flag_query",
    "run_custom_query",
}


# Obiettivo: dire se un nome di tool conta come "verifica" (query CodeQL vera) per il
#            controllo che impedisce di scrivere il report senza aver verificato nulla.
def _is_verification_tool(name: str) -> bool:
    return name in _VERIFICATION_TOOLS or name.startswith("check_")


# Obiettivo: contare quante chiamate di verifica DISTINTE sono gia' state fatte in questa
#            fase, per confrontarle col numero di elementi da verificare (un tool a botta
#            non basta: ne serve almeno una per ciascun flow/operazione dell'evidenza).
# Input:    seen = dict {sig: content} delle chiamate gia' fatte questa fase (sopravvive
#           al --resume). Output: quante di quelle firme sono un tool di verifica.
def _verification_count(seen: dict) -> int:
    return sum(1 for sig in seen if _is_verification_tool(sig.split("|", 1)[0]))


# Obiettivo: dire se Detection ha letto con successo ALMENO un file in questa fase — se
#            ogni read_file_snippet e' fallito (o non ne ha chiamato nessuno), qualunque
#            "analisi" scritta e' quasi certamente inventata (non puo' aver visto codice
#            vero). Input: seen = dict {sig: content} delle chiamate gia' fatte questa
#            fase (sopravvive al --resume). Output: True se almeno una lettura e' riuscita.
def _has_successful_read(seen: dict) -> bool:
    for sig, content in seen.items():
        if sig.split("|", 1)[0] != "read_file_snippet":
            continue
        try:
            if "error" not in json.loads(content):
                return True
        except (json.JSONDecodeError, ValueError):
            continue
    return False


# Obiettivo: estrarre l'insieme dei CWE citati in un testo, normalizzati nella STESSA
#            forma canonica usata dal server (server/core/template.py:normalize_cwe,
#            "CWE-<numero>" senza zero-padding), per confrontarli con quelli REALMENTE
#            confermati da un tool (stats.cwes) senza falsi mismatch tipo "CWE-089" vs "CWE-89".
# Input:    text = il testo scritto dal modello (il report). Output: set di "CWE-<numero>".
# Come realizzato: regex con gruppo catturante sul numero, poi int() per togliere lo zero-padding.
def _cited_cwes(text: str) -> set[str]:
    return {f"CWE-{int(n)}" for n in _CWE_RE.findall(text or "")}


_LEFTOVER_ROW_RE = re.compile(r"^-\s*`?CWE-\d+`?\s*[—-]", re.IGNORECASE)
_LEFTOVER_SEPARATOR_RE = re.compile(r"^[-|:\s]{3,}$")
_LEFTOVER_HEADING_RE = re.compile(r"final\s+security\s+report|^#+\s*security\s+report", re.IGNORECASE)


# Obiettivo: la tabella dei finding e il verdetto sono ormai costruiti in automatico
#            (agent/report.py:RunStats.report_body) — se un modello debole prova comunque
#            a scrivere la vecchia tabella/lista/intestazione-report nel suo commento
#            libero (visto in un run reale: una tabella markdown SENZA pipe iniziale,
#            "CWE | Count | Severity |", non riconosciuta da un controllo piu' stretto),
#            tagliarla via cosi' non contraddice visivamente quella autoritativa.
# Input:    text = il commento libero del modello. Output: lo stesso testo troncato alla
#           prima riga che sembra una riga/intestazione di tabella o report.
def _strip_leftover_table(text: str) -> str:
    lines = (text or "").splitlines()
    for i, line in enumerate(lines):
        s = line.strip()
        if not s:
            continue
        is_table_row = s.count("|") >= 2 or _LEFTOVER_SEPARATOR_RE.match(s)
        if s.startswith("|") or is_table_row or _LEFTOVER_ROW_RE.match(s) \
                or _LEFTOVER_HEADING_RE.search(s):
            return "\n".join(lines[:i]).strip()
    return text


# Obiettivo: stampare un messaggio di avanzamento "live" su stderr, subito visibile.
# Input:    msg = il testo da mostrare. Output: nessuno (scrive su stderr).
# Come realizzato: print su sys.stderr con flush=True.
def _log(msg: str) -> None:
    print(msg, file=sys.stderr, flush=True)


# Obiettivo: accorciare gli argomenti di una tool-call per un log leggibile su una riga.
# Input:    args = dict degli argomenti. Output: stringa compatta (troncata).
# Come realizzato: serializza in JSON e taglia a 120 caratteri.
def _brief(args: dict) -> str:
    s = json.dumps(args, ensure_ascii=False)
    return s if len(s) <= 120 else s[:117] + "..."


# Obiettivo: callback che, durante la Detection, cattura ENTRAMBI i segnali nella
#            work-list: l'inventario dei flow e quello delle operazioni sensibili.
# Input:    worklist. Output: una funzione (name, content) -> None.
# Come realizzato: find_all_flows popola i candidati; ognuno dei tool categorizzati in
#            _OPERATION_TOOLS (una query per categoria/kind) popola le operazioni.
_OPERATION_TOOLS = (
    "find_command_execution", "find_code_execution", "find_sql_execution",
    "find_filesystem_access", "find_decoding_operations", "find_crypto_operations",
    "find_weak_randomness", "find_insecure_config_flags",
    "find_exception_handling_issues", "find_broken_sanitizer_patterns",
    "find_resource_handling_issues",
)


# Obiettivo: comunicare al server MCP quale fase e' ora attiva (set_phase), cosi' i
#            tool riservati a Detection (read_file_snippet) si rifiutino di girare una
#            volta iniziata Validation — enforcement lato server, non solo la lista
#            dichiarativa di list_phase_tools. Non deve mai interrompere l'analisi: se
#            il tool non e' disponibile (server non aggiornato) l'errore viene solo loggato.
# Input:    session = connessione MCP; phase = "detection" o "validation".
# Output:   nessuno.
async def _set_server_phase(session, phase: str) -> None:
    try:
        result = await session.call_tool("set_phase", {"phase": phase})
        _log(f"[{phase}] server phase set: {mcp.tool_result_text(result)}")
    except Exception as e:
        _log(f"[{phase}] WARNING: could not set server phase ({e}); "
             f"phase-based tool enforcement may not apply")


def _capture_detection(worklist: WorkList):
    def cb(name: str, content: str) -> None:
        if name != "find_all_flows" and name not in _OPERATION_TOOLS:
            return
        try:
            payload = json.loads(content)
        except (json.JSONDecodeError, ValueError):
            return
        if name == "find_all_flows":
            worklist.add_candidates(payload)
        else:
            worklist.add_operations(payload)
    return cb


# Obiettivo: raccogliere l'evidenza meccanica (DB + le 12 inventory: flow + 11 tool
#            categorizzati/extra) SENZA nessuna chiamata LLM. Sono chiamate a ZERO
#            giudizio (il prompt diceva gia' "chiamale tutte, una volta ciascuna"): non
#            serve un modello per eseguirle, solo per interpretarle dopo. Popola la
#            worklist esattamente come faceva _capture_detection durante il vecchio loop.
# Input:    session = connessione MCP; repo_path; worklist/stats/progress = accumulatori.
# Output:   None se la raccolta riesce; una stringa di errore se create_codeql_database
#           fallisce (il chiamante deve interrompersi SENZA aver invocato l'LLM).
async def _gather_evidence(session, repo_path: str, worklist: WorkList, stats, progress) -> str | None:
    on_result = _capture_detection(worklist)
    _log("[gathering] start | creating CodeQL database")
    progress.phase("gathering", "start")

    t0 = time.time()
    try:
        result = await session.call_tool("create_codeql_database", {"repo_path": repo_path})
        content = mcp.tool_result_text(result)
    except Exception as e:
        return f"Failed to create CodeQL database: {e}"
    stats.record_tool_result("create_codeql_database", content)
    _log(f"[gathering]    create_codeql_database ({time.time() - t0:.1f}s)")
    try:
        payload = json.loads(content)
    except (json.JSONDecodeError, ValueError):
        payload = {}
    if "error" in payload or not payload.get("db_path"):
        return f"Failed to create CodeQL database: {payload.get('error', content)}"
    db_path = payload["db_path"]
    worklist.db_path = db_path
    stats.last_db_path = db_path

    for i, name in enumerate(("find_all_flows",) + _OPERATION_TOOLS, 1):
        _log(f"[gathering] -> {name}(db_path)")
        progress.tool("gathering", i, name, "running")
        t0 = time.time()
        try:
            result = await session.call_tool(name, {"db_path": db_path, "repo_path": repo_path})
            content = mcp.tool_result_text(result)
            status = "ok"
        except Exception as e:
            content = json.dumps({"error": str(e)})
            status = "ERROR"
        stats.record_tool_result(name, content)
        progress.tool("gathering", i, name, "ok" if status == "ok" else "error",
                      dur=time.time() - t0)
        _log(f"[gathering]    {status} {name} ({time.time() - t0:.1f}s)")
        _log(f"    result: {content}")
        if status == "ok":
            on_result(name, content)

    progress.phase("gathering", "done")
    _log(f"[gathering] done: {len(worklist.candidates)} flow(s), "
         f"{len(worklist.operations)} sensitive op(s); db={worklist.db_path}")
    return None


# Obiettivo: eseguire UNA fase LLM (Detection o Validation): il sotto-loop generico
#            che chiede al modello, esegue i tool ammessi nella fase (assorbendone gli
#            errori), cattura i flow nella work-list e salva i checkpoint.
# Input:    session/llm = connessione MCP e modello; phase = nome fase; tools = schema
#           tool (gia' filtrati per fase); tool_names = nomi ammessi; seed = messaggi
#           iniziali; stats/worklist = accumulatori; ckpt = file checkpoint;
#           repo/model/report = per il checkpoint; completed = fasi gia' concluse;
#           max_steps = turni max; progress = emettitore eventi; on_result = callback;
#           finalize_report = se True la fase e' Validation (il gate di verifica e lo
#           strip della tabella-fantasma si attivano solo li'); resume_state = stato da
#           cui riprendere (o None).
# Output:   stringa col testo finale del modello: il riassunto per Detection; per
#           Validation e' SOLO l'eventuale commento libero opzionale (mai il report —
#           la tabella/verdetto li costruisce run_agent da stats.report_body(), non
#           questo testo), "" se il modello non ha aggiunto nulla.
# Come realizzato: replica il loop storico (chat -> tool_calls/testo -> fix db_path ->
#            anti-dup -> call_tool -> record/cattura -> checkpoint) parametrizzato su
#            prompt e set di tool; se il modello smette di chiamare tool, il suo testo e'
#            l'output; se la fase-report esaurisce i passi, forza una scrittura finale.
async def _run_phase(
    session, llm, *, phase, tools, tool_names, seed, stats, worklist, ckpt,
    repo_path, model, report_path, completed, max_steps, progress,
    on_result=None, finalize_report=False, resume_state=None,
) -> str:
    dup_nudge = _DUP_NUDGE_REPORT if finalize_report else _DUP_NUDGE_SUMMARY
    stuck_msg = _STUCK_REPORT if finalize_report else _STUCK_SUMMARY

    if resume_state:
        messages = resume_state["messages"]
        seen = resume_state.get("seen", {})
        start_step = resume_state.get("next_step", 0)
        _log(f"[{phase}] resuming at step {start_step}")
    else:
        messages = list(seed)
        seen = {}
        start_step = 0
    dup_streak = 0
    verification_retries = 0
    read_retries = 0
    malformed_retries = 0
    long_prose_retries = 0
    degenerate_retries = 0
    # Whether there is any evidence to verify at all — the check below only requires
    # AT LEAST ONE real verification call, not one per item (a single check_*/run_*
    # call can legitimately confirm several flows/operations at once).
    total_findings = len(worklist.candidates) + len(worklist.operations)

    # Tools whose schema declares a db_path parameter — models sometimes OMIT it
    # entirely (not just pass a placeholder), so we can't only fix it when the key is
    # already present; know which tools need it so we can inject it either way.
    db_path_tools = {
        t["function"]["name"] for t in tools
        if "db_path" in (t["function"].get("parameters") or {}).get("properties", {})
    }

    _log(f"[{phase}] start | {len(tool_names)} tools | model={model}")

    # Obiettivo: emettere i conteggi live (candidati/finding/CWE) verso la UI grafica.
    def _emit_counts() -> None:
        progress.counts(len(worklist.candidates), stats.total_findings, len(stats.cwes))

    # Obiettivo: salvare lo stato (per --resume), includendo fase e work-list.
    def _save(step: int) -> None:
        ckpt_mod.save_checkpoint(ckpt, {
            "repo_path": repo_path, "model": model, "report_path": report_path,
            "phase": phase, "completed_phases": completed,
            "next_step": step + 1, "messages": messages, "seen": seen,
            "worklist": worklist.to_dict(),
        })

    for step in range(start_step, max_steps):
        _log(f"[{phase} step {step}] asking {model} ...")
        progress.think(phase, step)
        t0 = time.time()
        msg = await llm.chat(messages, tools=tools)
        _log(f"[{phase} step {step}] model replied in {time.time() - t0:.1f}s")
        messages.append(msg)

        calls = msg.get("tool_calls") or []
        if not calls:
            calls = extract_text_tool_calls(msg.get("content", ""), tool_names)
        if calls and (msg.get("content") or "").strip():
            _log(f"[{phase} step {step}] note: reply mixed text with {len(calls)} "
                 f"tool-call(s) — the text is NOT treated as final (a reply needs ZERO "
                 f"tool calls to finalize); only the tool-call(s) are executed now.")
        if not calls:
            content = msg.get("content", "")
            if is_degenerate_text(content) and degenerate_retries < 3:
                degenerate_retries += 1
                _log(f"[{phase} step {step}] reply looks like degenerate/incoherent "
                     f"text ({len(content)} chars, near-zero word repetition) -> "
                     f"asking to rewrite plainly")
                messages.append({
                    "role": "user",
                    "content": (
                        "Your last reply was not coherent text (it read like a stream "
                        "of unrelated word fragments, not real sentences). Discard it "
                        "and reply again in plain, grammatical language following the "
                        "required format above — or call exactly one tool if that is "
                        "what is needed next."
                    ),
                })
                _save(step)
                continue
            if degenerate_retries >= 3 and is_degenerate_text(content):
                _log(f"[{phase} step {step}] still degenerate after {degenerate_retries} "
                     f"retries -> treating this reply as empty rather than looping forever")
                content = ""
            if finalize_report and total_findings > 0 and _verification_count(seen) == 0 \
                    and len(content or "") > _LOCAL_LONG_PROSE_CHARS and long_prose_retries < 3:
                long_prose_retries += 1
                _log(f"[{phase} step {step}] long prose with no tool call "
                     f"({len(content)} chars) -> forcing strict single tool call")
                messages.append({
                    "role": "user",
                    "content": (
                        "Your last reply was long prose without a tool call. "
                        "Reply now with exactly ONE valid <tool_call> block for a "
                        "verification tool. No prose, no reasoning, no markdown."
                    ),
                })
                _save(step)
                continue
            looks_like_failed_call = '"name"' in content and '"arguments"' in content
            if looks_like_failed_call and malformed_retries < 2:
                malformed_retries += 1
                _log(f"[{phase} step {step}] reply looked like a tool call but failed "
                     f"to parse -> asking to reformat")
                messages.append({
                    "role": "user",
                    "content": (
                        "Your last reply looked like it was trying to call a tool, but "
                        "the JSON could not be parsed (check for unescaped characters, "
                        "unbalanced braces, or a missing/extra brace). Re-emit the SAME "
                        "tool call as valid JSON, following the exact format described "
                        "above."
                    ),
                })
                _save(step)
                continue
            if finalize_report:
                done = _verification_count(seen)
                if done == 0 and total_findings > 0 and verification_retries < 3:
                    verification_retries += 1
                    _log(f"[{phase} step {step}] no verification tool called yet "
                         f"({total_findings} item(s) in evidence) -> asking to verify "
                         f"before reporting")
                    messages.append({
                        "role": "user",
                        "content": (
                            "You have not called any real verification tool yet "
                            "(run_taint_query / run_api_misuse_query / "
                            "run_insecure_config_flag_query / run_custom_query / check_*). "
                            "Your next reply must be EXACTLY ONE valid <tool_call> block for "
                            "a verification tool. Do not write prose, do not explain, do not "
                            "write the report yet."
                        ),
                    })
                    _save(step)
                    continue
                if done == 0 and total_findings > 0:
                    _log(f"[{phase} step {step}] still no verification tool called; keeping "
                         f"the phase open until a real tool call appears")
                    messages.append({
                        "role": "user",
                        "content": (
                            "Still no verification tool has been called. Reply with one "
                            "valid <tool_call> block only. Do not write any report text."
                        ),
                    })
                    _save(step)
                    continue
                # The findings table/verdict are now built AUTOMATICALLY (report.py:
                # RunStats.report_body) from the tool JSON already collected — content
                # here is only the model's OPTIONAL free commentary, never the report
                # itself, so an unconfirmed CWE mention can no longer corrupt the
                # authoritative table. No LLM retry needed: just annotate it in place.
                content = _strip_leftover_table(content)
                unconfirmed = _cited_cwes(content) - stats.cwes
                if unconfirmed:
                    _log(f"[{phase} step {step}] commentary mentions unconfirmed CWE(s) "
                         f"{sorted(unconfirmed)} (confirmed by tools: "
                         f"{sorted(stats.cwes) or 'none'}) -> annotating, not blocking")
                    content = (
                        f"_(note: {sorted(unconfirmed)} mentioned above was/were not "
                        "independently confirmed by a tool this phase; see the findings "
                        "table for confirmed results.)_\n\n" + content
                    )
            elif phase == DETECTION and total_findings and not _has_successful_read(seen) \
                    and read_retries < 2:
                read_retries += 1
                _log(f"[{phase} step {step}] analysis written without a single successful "
                     f"read_file_snippet this phase -> asking to actually read the code first")
                messages.append({
                    "role": "user",
                    "content": (
                        "You wrote an analysis without a single SUCCESSFUL read_file_snippet "
                        "call this phase (every attempt failed, or you called none). Do NOT "
                        "write the analysis yet: you cannot know real names/values without "
                        "having actually read the file. If a read failed, check the file_path "
                        "you used (it must resolve to a real file — try without a leading "
                        "slash) and try again before writing anything."
                    ),
                })
                _save(step)
                continue
            _log(f"[{phase} step {step}] model wrote its final text -> phase done")
            _save(step)
            return content

        all_duplicate = True
        for call in calls:
            fn = call["function"]
            name = fn["name"]
            args = fn["arguments"]
            if isinstance(args, str):
                args = json.loads(args)
            if name == "read_file_snippet":
                args = fix_read_file_snippet_args(args, repo_path)
            if name in db_path_tools:
                resolved = resolve_db_path(args.get("db_path"), stats.last_db_path)
                if resolved is None:
                    all_duplicate = False
                    _log(f"[{phase} step {step}] (no db) {name} -> ask model to create the DB first")
                    progress.tool(phase, step, name, "nodb")
                    messages.append({"role": "tool", "tool_name": name, "content": _NO_DB_ERROR})
                    continue
                args["db_path"] = resolved
            sig = name + "|" + json.dumps(args, sort_keys=True)

            if sig in seen:
                _log(f"[{phase} step {step}] (dup) {name}({_brief(args)}) -> cached")
                progress.tool(phase, step, name, "cached", args=_brief(args))
                content = seen[sig] + dup_nudge
            else:
                all_duplicate = False
                _log(f"[{phase} step {step}] -> {name}({_brief(args)})")
                _log(f"    args: {json.dumps(args, ensure_ascii=False, indent=2)}")
                progress.tool(phase, step, name, "running", args=_brief(args))
                t0 = time.time()
                try:
                    result = await session.call_tool(name, args)
                    content = mcp.tool_result_text(result)
                    status = "ok"
                except Exception as e:  # surface tool errors back to the model
                    content = json.dumps({"error": str(e)})
                    status = "ERROR"
                seen[sig] = content
                new_findings = stats.record_tool_result(name, content)
                for f in new_findings:
                    if f.get("flow_path"):
                        progress.finding(f.get("cwe"), f.get("rule_id"),
                                          f.get("file"), f.get("line"), f["flow_path"])
                if on_result and status == "ok":
                    try:
                        on_result(name, content)
                    except Exception:  # capture must never break the loop
                        pass
                progress.tool(phase, step, name, "ok" if status == "ok" else "error",
                              dur=time.time() - t0)
                _log(f"[{phase} step {step}]    {status} {name} ({time.time() - t0:.1f}s)")
                _log(f"    result: {content}")
            messages.append({"role": "tool", "tool_name": name, "content": content})

        stats.steps_done += 1
        _emit_counts()
        _save(step)

        dup_streak = dup_streak + 1 if all_duplicate else 0
        if dup_streak >= 2:
            messages.append({"role": "user", "content": stuck_msg})
        if dup_streak >= 4:
            break

    # Loop exhausted. For the report phase, force one final (optional) comment — the
    # findings table/verdict are built automatically regardless (report.py:report_body).
    if finalize_report:
        messages.append({
            "role": "user",
            "content": (
                "Write a SHORT optional comment now (no tools, no table/list — the "
                "findings table is generated automatically by the system from the tool "
                "results already collected). If you have nothing to add, reply with "
                "just: DONE"
            ),
        })
        final = await llm.chat(messages)
        return _strip_leftover_table(final.get("content", ""))
    return ""


# Obiettivo: far girare l'intera pipeline (raccolta + 2 fasi LLM) e finalizzare il report.
# Input:    repo_path = progetto; model = modello; report_path = output; max_steps =
#           turni max PER fase; resume = riprende da checkpoint; provider = backend LLM.
# Output:   stringa col report completo (intestazione YAML + corpo scritto dall'LLM).
# Come realizzato: connette il server MCP, raccoglie l'evidenza meccanica (nessun LLM),
#            poi Detection (arricchisce l'evidenza leggendo il codice) e Validation (query
#            mirate + associazione CWE + scrittura del report), con reset del contesto tra
#            le due fasi LLM; il testo finale della Validation e' il report.
async def run_agent(
    repo_path: str, model: str, report_path: str, max_steps: int = 30,
    resume: bool = False, provider: str = "ollama",
) -> str:
    llm = make_llm(provider, model)
    prompts = prompt_set(provider)
    progress = make_progress()

    async with mcp.connect(config.MCP_SERVER_URL) as (session, mcp_tools):
        all_names = {t.name for t in mcp_tools}
        ckpt = ckpt_mod.checkpoint_path(repo_path)
        stats = RunStats(model=model, repo_path=repo_path, max_steps=max_steps)

        # Resume: restore completed phases + work-list + current-phase state.
        state: dict = {}
        completed: list[str] = []
        worklist = WorkList(repo_path=repo_path)
        det_analysis = ""
        if resume and ckpt.exists():
            state = ckpt_mod.load_checkpoint(ckpt)
            completed = list(state.get("completed_phases", []))
            if state.get("worklist"):
                worklist = WorkList.from_dict(state["worklist"])
            det_analysis = state.get("det_analysis", "")
            _log(f"Resuming: completed={completed}, phase={state.get('phase')}")

        # The tool -> phase mapping is the SERVER's responsibility (not hardcoded
        # in the agent). If unavailable, degrade to exposing every tool per phase.
        phase_tools = await fetch_phase_tools(session)
        det_allowed = phase_tools.get(DETECTION) or all_names
        val_allowed = phase_tools.get(VALIDATION) or all_names

        _log(f"Connected: {len(all_names)} tools | provider={provider} | model={model} | repo={repo_path}")
        _log(f"Phase tools from server: detection={len(det_allowed)}, validation={len(val_allowed)}")
        progress.start(["gathering", DETECTION, VALIDATION], repo_path, model, provider)

        # --- Step 0: GATHERING (deterministic, NO LLM) — DB + the 12 mechanical inventories ---
        if "gathering" not in completed:
            error = await _gather_evidence(session, repo_path, worklist, stats, progress)
            if error:
                _log(f"[gathering] FAILED: {error}")
                result = stats.finalize(f"# Analysis failed\n\n{error}\n", report_path, ckpt)
                progress.done(report_path, 0, 0, 0)
                return result
            completed.append("gathering")
            ckpt_mod.save_checkpoint(ckpt, {
                "repo_path": repo_path, "model": model, "report_path": report_path,
                "phase": "gathering", "completed_phases": completed,
                "worklist": worklist.to_dict(), "det_analysis": det_analysis,
            })

        # --- Phase 1: DETECTION (LLM) — enrich the pre-gathered evidence with real
        # names/values/relevance judgement by reading the code (no CWE assigned) ---
        if DETECTION not in completed:
            progress.phase(DETECTION, "start")
            await _set_server_phase(session, DETECTION)
            det_tools = mcp.mcp_tools_to_ollama(filter_tools(mcp_tools, det_allowed))
            if provider == "ollama":
                # Local small models saturate quickly with full-inventory prompts.
                # Feed one finding at a time and require a tool action per item.
                item_steps = max(4, min(8, max_steps))
                det_lines: list[str] = []
                items: list[tuple[str, dict]] = [
                    ("flow", c) for c in worklist.candidates
                ] + [
                    ("op", o) for o in worklist.operations
                ]
                total_items = len(items)

                for idx, (kind, item) in enumerate(items, 1):
                    if kind == "flow":
                        src = item.get("source", {})
                        snk = item.get("sink", {})
                        path = item.get("path", [])
                        evidence_lines = [
                            f"FLOW source: {src.get('file')}:{src.get('line')}",
                            f"FLOW sink: {snk.get('file')}:{snk.get('line')}",
                            f"FLOW steps: {item.get('steps', 0)}",
                        ]
                        for step in path[:8]:
                            code = step.get("code") or ""
                            evidence_lines.append(
                                f"PATH {step.get('file')}:{step.get('line')}: {code}"
                            )
                        finding_hint = "Return exactly one FLOW line for this item, or NONE."
                    else:
                        evidence_lines = [
                            f"OP kind: {item.get('kind')}",
                            f"OP location: {item.get('file')}:{item.get('line')}",
                            f"OP code: {item.get('code', '')}",
                        ]
                        finding_hint = "Return exactly one OP line for this item, or NONE."

                    seed = [
                        {"role": "system", "content": prompts[DETECTION]},
                        {"role": "user", "content": (
                            f"Repository: {repo_path}\n"
                            f"Detection item {idx}/{total_items}\n\n"
                            + "\n".join(evidence_lines)
                            + "\n\n"
                              "Before writing analysis for this item, call a tool for this "
                              "item (read_file_snippet preferred). One tool call per reply.\n"
                            + finding_hint
                        )},
                    ]

                    item_text = await _run_phase(
                        session, llm, phase=DETECTION, tools=det_tools,
                        tool_names=det_allowed & all_names, seed=seed, stats=stats,
                        worklist=worklist, ckpt=ckpt, repo_path=repo_path, model=model,
                        report_path=report_path, completed=completed, max_steps=item_steps,
                        progress=progress, resume_state=None,
                    )
                    item_text = (item_text or "").strip()
                    if item_text and item_text.upper() != "NONE":
                        det_lines.append(item_text)

                det_analysis = "\n".join(det_lines).strip() or "NONE"
            else:
                seed = [
                    {"role": "system", "content": prompts[DETECTION]},
                    {"role": "user", "content": (
                        f"Repository: {repo_path}\n\n"
                        f"{worklist.detection_summary()}\n\n"
                        "Enrich the evidence above by reading the code, then write your SHORT "
                        "analysis."
                    )},
                ]
                det_analysis = await _run_phase(
                    session, llm, phase=DETECTION, tools=det_tools,
                    tool_names=det_allowed & all_names, seed=seed, stats=stats,
                    worklist=worklist, ckpt=ckpt, repo_path=repo_path, model=model,
                    report_path=report_path, completed=completed, max_steps=max_steps,
                    progress=progress,
                    resume_state=state if state.get("phase") == DETECTION else None,
                )
            completed.append(DETECTION)
            ckpt_mod.save_checkpoint(ckpt, {
                "repo_path": repo_path, "model": model, "report_path": report_path,
                "phase": DETECTION, "completed_phases": completed,
                "worklist": worklist.to_dict(), "det_analysis": det_analysis,
            })
            progress.phase(DETECTION, "done")
            progress.counts(len(worklist.candidates), stats.total_findings, len(stats.cwes))
            _log(f"[detection] done: {len(worklist.candidates)} flow(s), "
                 f"{len(worklist.operations)} sensitive op(s); db={worklist.db_path}")
            _log(f"[detection] enrichment:\n{det_analysis or '(empty)'}")

        # --- Phase 2: VALIDATION (targeted queries + associate CWE + write report) ---
        progress.phase(VALIDATION, "start")
        await _set_server_phase(session, VALIDATION)
        stats.last_db_path = worklist.db_path  # so db_path placeholders resolve
        val_tools = mcp.mcp_tools_to_ollama(filter_tools(mcp_tools, val_allowed))
        seed = [
            {"role": "system", "content": prompts[VALIDATION]},
            {"role": "user", "content": (
                f"Repository: {repo_path}\n"
                f"CodeQL database (db_path): {worklist.db_path}\n\n"
                f"{worklist.detection_summary(include_code=False)}\n\n"
                f"Detection's enrichment (real names/values/relevance judgement):\n"
                f"{det_analysis or '(none)'}\n\n"
                "Verify the dangerous flows above and associate a CWE to each confirmed "
                "finding. The findings table is built automatically once you stop calling "
                "tools — pass this exact db_path to every query."
            )},
        ]
        model_commentary = await _run_phase(
            session, llm, phase=VALIDATION, tools=val_tools,
            tool_names=val_allowed & all_names, seed=seed, stats=stats,
            worklist=worklist, ckpt=ckpt, repo_path=repo_path, model=model,
            report_path=report_path, completed=completed, max_steps=max_steps,
            progress=progress, finalize_report=True,
            resume_state=state if state.get("phase") == VALIDATION else None,
        )
        progress.phase(VALIDATION, "done")
        progress.counts(len(worklist.candidates), stats.total_findings, len(stats.cwes))

        # The findings table/verdict are built AUTOMATICALLY from the tool results
        # already collected (report.py:RunStats.report_body) — model_commentary is only
        # the model's optional free-text note, never the report itself. Finalize
        # prepends the YAML header and writes the composed body to disk.
        result = stats.finalize(stats.report_body(model_commentary), report_path, ckpt)
        progress.done(report_path, len(worklist.candidates), stats.total_findings, len(stats.cwes))
        return result
