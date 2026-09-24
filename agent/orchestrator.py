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

import itertools
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
from agent import risk_score
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
# Input:    text = il testo scritto dal modello (il report/l'analisi). Output: set di "CWE-<numero>".
# Come realizzato: rimuove PRIMA ogni occorrenza a forma di nome file (es.
#            "CWE-090_codeql_1.py") — osservato in produzione su dataset come
#            SecurityEval, dove i file SONO nominati per CWE: Detection a volte
#            ripete il path dell'evidenza invece di seguire il template di output
#            richiesto ("sink=X source=Y sanitizer=Z"), e quel path finisce per
#            "vestirsi" da classificazione CWE anche se il modello non ha giudicato
#            nulla — Detection non assegna mai CWE per design. Senza questo filtro
#            il gate di copertura della Validation insegue nomi di file, non giudizi
#            reali. Poi regex con gruppo catturante sul numero, int() per togliere
#            lo zero-padding.
def _cited_cwes(text: str) -> set[str]:
    text = _CWE_FROM_FILENAME_RE.sub("", text or "")
    return {f"CWE-{int(n)}" for n in _CWE_RE.findall(text)}


_INDEXED_LINE_RE = re.compile(r"^\s*\[(\d+)\]\s*(.*)$")


# Obiettivo: estrarre, da una risposta batch della Detection, quali item [N] il modello
#            ha effettivamente coperto — per rilevare item "saltati" in mezzo a un batch
#            (mai un problema di token, sempre un problema di completezza del modello).
# Input:    text = la risposta libera del modello (una riga attesa per item, taggata [N]).
# Output:   dict {indice item -> testo della riga SENZA il tag [N]}; righe non taggate
#           (rumore/prosa) sono ignorate, non trattate come un item valido.
def _parse_indexed_lines(text: str) -> dict[int, str]:
    out: dict[int, str] = {}
    for line in (text or "").splitlines():
        m = _INDEXED_LINE_RE.match(line)
        if m:
            out[int(m.group(1))] = m.group(2).strip()
    return out


_CWE_FROM_FILENAME_RE = re.compile(r"CWE-\d+_\w*\.\w+", re.IGNORECASE)

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
#           cui riprendere (o None); candidate_cwes = i CWE citati nell'enrichment di
#           Detection (via _cited_cwes(det_analysis)), usati SOLO in Validation per
#           pretendere una verifica per ciascuna CATEGORIA distinta, non solo "almeno una
#           in totale" (un singolo check_*/run_* puo' gia' confermare piu' flow/operazioni
#           della STESSA categoria, ma non copre categorie diverse, es. SQLi vs XSS);
#           chat_kwargs = extra kwargs passati a llm.chat() ad ogni turno (es. num_predict
#           per il loop per-item di Detection) — dict vuoto/None altrove, quindi non
#           tocca provider diversi da Ollama (che non li accettano nella loro chat()).
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
    on_result=None, finalize_report=False, resume_state=None, candidate_cwes=None,
    chat_kwargs=None, extra_state=None, require_tool_call=False,
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
    # Whether there is any evidence to verify at all. The gate below requires one real
    # verification call per DISTINCT CWE category found by Detection (candidate_cwes),
    # not one per item: a single check_*/run_* call can legitimately confirm several
    # flows/operations of the SAME category at once, but it says nothing about a
    # DIFFERENT category (e.g. a SQLi check never touches XSS candidates).
    total_findings = len(worklist.candidates) + len(worklist.operations)
    needed_verifications = max(1, len(candidate_cwes or ()))

    # Tools whose schema declares a db_path parameter — models sometimes OMIT it
    # entirely (not just pass a placeholder), so we can't only fix it when the key is
    # already present; know which tools need it so we can inject it either way.
    db_path_tools = {
        t["function"]["name"] for t in tools
        if "db_path" in (t["function"].get("parameters") or {}).get("properties", {})
    }
    # Same idea, but for repo_path: unlike db_path (which can legitimately vary if
    # several DBs exist), repo_path is FIXED for the whole run and already known
    # here — there is no legitimate reason for the model to reproduce it itself.
    # Observed in production: small local models garble long absolute paths when
    # regenerating them from "memory" instead of copying verbatim (e.g.
    # "...\Sibyl\_securityeval_repo" -> "...\Sibyl_securityeval_repo", silently
    # dropping the separator before the underscore) — every such call then fails
    # with "Not a directory"/"File not found" and burns a full LLM turn for
    # nothing. Always override with the real value instead of trusting the
    # model's copy, the same way resolve_db_path() never trusts a model-typed
    # db_path over a known-good one.
    repo_path_tools = {
        t["function"]["name"] for t in tools
        if "repo_path" in (t["function"].get("parameters") or {}).get("properties", {})
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
            **(extra_state or {}),
        })

    for step in itertools.count(start_step):
        if step >= max_steps:
            # max_steps is a budget for the NORMAL case, not a completeness override —
            # the user explicitly chose "full coverage over time" for Validation, so
            # while there is still a candidate CWE category with zero confirmed result
            # (missing from stats.cwes, which only fills from a real tool RESULT),
            # keep going past the budget instead of finalizing with silent gaps. Every
            # OTHER termination path (dup_streak, retry caps, degenerate-text handling)
            # is untouched, so this can't turn into a true infinite loop — it only
            # removes the step-COUNT ceiling specifically while genuine work remains.
            still_needs_coverage = finalize_report and total_findings > 0 and bool(
                sorted((candidate_cwes or set()) - stats.cwes)
            )
            if not still_needs_coverage:
                break
            _log(f"[{phase} step {step}] past max_steps={max_steps} with coverage "
                 f"still incomplete -> continuing (completeness over step budget)")
        _log(f"[{phase} step {step}] asking {model} ...")
        progress.think(phase, step)
        t0 = time.time()
        msg = await llm.chat(messages, tools=tools, **(chat_kwargs or {}))
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
            if finalize_report and total_findings > 0 \
                    and _verification_count(seen) < needed_verifications \
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
                missing_cwes = sorted((candidate_cwes or set()) - stats.cwes)
                retry_cap = max(3, needed_verifications)
                # Gate on ACTUAL coverage (missing_cwes: candidate categories still absent
                # from stats.cwes, which only fills from a tool's real RESULT), not on a
                # raw call COUNT — 3 calls that all happen to confirm/re-confirm the same
                # category used to satisfy `done >= needed_verifications` while genuinely
                # unchecked categories from Detection went straight to the report. Detection
                # deliberately never assigns CWEs (see phase docstring), so candidate_cwes
                # is often empty even when there IS evidence to check — keep the original
                # "at least one real attempt" floor for that case via `done == 0`.
                needs_more = missing_cwes or (not candidate_cwes and done == 0)
                if needs_more and total_findings > 0 \
                        and verification_retries < retry_cap:
                    verification_retries += 1
                    _log(f"[{phase} step {step}] only {done}/{needed_verifications} "
                         f"distinct verification categor{'y' if needed_verifications == 1 else 'ies'} "
                         f"covered ({total_findings} item(s) in evidence) -> asking to verify "
                         f"before reporting")
                    focus = (
                        f" Still-unconfirmed categories to prioritize: {', '.join(missing_cwes)}."
                        if missing_cwes else ""
                    )
                    messages.append({
                        "role": "user",
                        "content": (
                            "You have not verified enough distinct categories yet "
                            "(run_taint_query / run_api_misuse_query / "
                            "run_insecure_config_flag_query / run_custom_query / check_*) — "
                            "one verification call only confirms/rules out the ONE category it "
                            "targets, not the others Detection flagged." + focus + " Your next "
                            "reply must be EXACTLY ONE valid <tool_call> block for a "
                            "verification tool covering a category not yet checked. Do not "
                            "write prose, do not explain, do not write the report yet."
                        ),
                    })
                    _save(step)
                    continue
                if needs_more and total_findings > 0:
                    _log(f"[{phase} step {step}] still {len(missing_cwes)}/{needed_verifications} "
                         f"distinct verification categories uncovered ({missing_cwes}); "
                         f"keeping the phase open past the retry cap")
                    messages.append({
                        "role": "user",
                        "content": (
                            "Still missing verification of some categories"
                            + (f" ({', '.join(missing_cwes)})" if missing_cwes else "")
                            + ". Reply with one valid <tool_call> block only, for a category "
                            "not yet checked. Do not write any report text."
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
            elif require_tool_call and not seen and read_retries < 2:
                # Per-finding Validation calls (finalize_report=False, so none of the
                # coverage-gate logic above applies): without this, a reply with no
                # tool call at all is immediately accepted as "done", silently skipping
                # verification for this ONE finding entirely — the exact silent-drop
                # failure mode the whole batch/coverage rework this session was about,
                # just one level down (per-finding instead of per-item/per-category).
                read_retries += 1
                _log(f"[{phase} step {step}] no tool called yet this finding -> nudging "
                     f"to actually run a verification tool")
                messages.append({
                    "role": "user",
                    "content": (
                        "You have not called a verification tool for this finding yet. "
                        "Reply now with EXACTLY ONE <tool_call> block for the most "
                        "appropriate verification tool (check_* if a dedicated one "
                        "exists for this CWE, otherwise run_taint_query / "
                        "run_api_misuse_query / run_insecure_config_flag_query / "
                        "run_custom_query). Do not write prose."
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
            # Observed with gpt-oss on multi-field tools (e.g. run_taint_query):
            # sometimes it writes the WHOLE {"name":...,"arguments":{...}} envelope
            # one level too deep, i.e. the extracted "arguments" IS itself another
            # such envelope instead of the flat param dict. No real tool here has
            # both "name" and "arguments" as its own parameters, so this can only
            # be the model's own redundant self-nesting — unwrap it rather than
            # sending the outer shell (missing every real field) to the tool and
            # burning a turn on a validation error the model then struggles to
            # self-correct from (each malformed attempt has a different exact
            # shape, so it doesn't even get caught by dup-call detection).
            while (
                isinstance(args, dict) and "name" in args
                and isinstance(args.get("arguments"), dict)
            ):
                args = args["arguments"]
            if name == "read_file_snippet":
                args = fix_read_file_snippet_args(args, repo_path)
            if name in repo_path_tools:
                args["repo_path"] = repo_path
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
#           turni max PER fase; resume = riprende da checkpoint; provider = backend LLM;
#           keep_checkpoint = se True NON cancella il checkpoint dopo un run riuscito, cosi'
#           un successivo `--resume` salta gathering+detection (gia' in completed_phases)
#           e rifa' SOLO la Validation — utile per iterare sulla fase senza ripetere una
#           Detection lunga. Se False (default), comportamento invariato: cancellato a fine
#           run come sempre (agent/report.py:RunStats.finalize).
# Output:   stringa col report completo (intestazione YAML + corpo scritto dall'LLM).
# Come realizzato: connette il server MCP, raccoglie l'evidenza meccanica (nessun LLM),
#            poi Detection (arricchisce l'evidenza leggendo il codice) e Validation (query
#            mirate + associazione CWE + scrittura del report), con reset del contesto tra
#            le due fasi LLM; il testo finale della Validation e' il report.
async def run_agent(
    repo_path: str, model: str, report_path: str, max_steps: int = 30,
    resume: bool = False, provider: str = "ollama", keep_checkpoint: bool = False,
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
            # Reorder by risk score BEFORE Detection builds its "items" batching list
            # (agent/risk_score.py) - a budget-limited run then spends its steps on
            # the highest-value candidates/operations first, not whatever order
            # find_all_flows/the categorized find_* tools happened to return.
            risk_score.sort_worklist(worklist)
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
                # Local small models saturate quickly with full-inventory prompts, so we
                # never send everything in one shot — but a whole SEPARATE LLM round-trip
                # per item (the old design) is what made Detection take hours on larger
                # codebases: overhead (system prompt + tool schemas) dominates a
                # single-item prompt (~600 of ~712 tokens measured for gpt-oss:20b), so
                # paying it once per BATCH instead of once per item is the actual lever.
                # Each item still carries its own real code (already gathered
                # mechanically, no read_file_snippet round-trip needed in the common
                # case) — ~110-130 tokens/item measured — so OLLAMA_DETECTION_BATCH_SIZE
                # items/call comfortably fits even a conservative num_ctx.
                item_steps = max(4, min(8, max_steps))
                items: list[tuple[str, dict]] = [
                    ("flow", c) for c in worklist.candidates
                ] + [
                    ("op", o) for o in worklist.operations
                ]
                total_items = len(items)
                batch_size = max(1, config.OLLAMA_DETECTION_BATCH_SIZE)
                # batch_size items/call is fast, but a free-text reply can silently drop
                # an item in the middle of a batch (the model just... doesn't write a
                # line for it) — the ONE thing Detection must never do, since every
                # gathered candidate is supposed to get a judgement. Force each line to
                # be tagged with its own item number so coverage is checkable, and if a
                # batch comes back with gaps, re-ask ONLY for the missing indices (not
                # the whole batch) up to _MAX_GAP_ROUNDS times before giving up on them
                # explicitly (UNVERIFIED, never silence).
                covered: dict[int, str] = {}
                _MAX_GAP_ROUNDS = 2

                def _item_block(idx: int, kind: str, item: dict) -> str:
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
                        finding_hint = (
                            f"Reply with [{idx}] followed by exactly one FLOW line for "
                            f"this item, or [{idx}] NONE."
                        )
                    else:
                        evidence_lines = [
                            f"OP kind: {item.get('kind')}",
                            f"OP location: {item.get('file')}:{item.get('line')}",
                            f"OP code: {item.get('code', '')}",
                        ]
                        finding_hint = (
                            f"Reply with [{idx}] followed by exactly one OP line for "
                            f"this item, or [{idx}] NONE."
                        )
                    return (
                        f"Item {idx}/{total_items}\n" + "\n".join(evidence_lines)
                        + "\n" + finding_hint
                    )

                for batch_start in range(0, total_items, batch_size):
                    pending = list(range(batch_start + 1, min(batch_start + batch_size, total_items) + 1))
                    gap_round = 0
                    while pending:
                        item_blocks = [
                            _item_block(idx, *items[idx - 1]) for idx in pending
                        ]
                        seed = [
                            {"role": "system", "content": prompts[DETECTION]},
                            {"role": "user", "content": (
                                f"Repository: {repo_path}\n"
                                f"Detection batch: items {pending[0]}-{pending[-1]} of "
                                f"{total_items}\n\n"
                                + "\n\n".join(item_blocks)
                                + "\n\n"
                                  "Only call a tool (read_file_snippet preferred) for an "
                                  "item whose evidence above is not enough to judge — "
                                  "most items already carry the real code, so most "
                                  "batches need zero tool calls. One tool call per reply "
                                  "if you do need one.\n"
                                  "When ready, reply with EXACTLY ONE line per item above, "
                                  "same order, each line starting with its own [N] tag "
                                  "(e.g. \"[7] FLOW sink=... source=... — ...\" or "
                                  "\"[7] NONE\") — do not skip any [N]."
                            )},
                        ]

                        batch_text = await _run_phase(
                            session, llm, phase=DETECTION, tools=det_tools,
                            tool_names=det_allowed & all_names, seed=seed, stats=stats,
                            worklist=worklist, ckpt=ckpt, repo_path=repo_path, model=model,
                            report_path=report_path, completed=completed, max_steps=item_steps,
                            progress=progress, resume_state=None,
                            # 2048 was NOT enough headroom in practice: gpt-oss's hidden
                            # reasoning length is stochastic (temperature=0.2, not 0) and
                            # regularly exceeded 2048 alone for a 15-item batch even when
                            # a one-off isolated test succeeded under it — that test got
                            # lucky on one sample, production saw the other side of the
                            # distribution repeatedly. 4096 measured comfortable in the
                            # same isolated test (used ~1890-1930 of 4096 available).
                            chat_kwargs={"num_predict": min(
                                4096, config.OLLAMA_NUM_PREDICT_DETECTION_ITEM * len(pending)
                            )},
                        )
                        for idx, line in _parse_indexed_lines(batch_text or "").items():
                            if idx in pending:
                                covered[idx] = line

                        pending = [idx for idx in pending if idx not in covered]
                        if pending:
                            gap_round += 1
                            _log(f"[detection] batch gap: item(s) {pending} got no line "
                                 f"(round {gap_round}/{_MAX_GAP_ROUNDS})")
                            if gap_round > _MAX_GAP_ROUNDS:
                                for idx in pending:
                                    covered[idx] = (
                                        f"Item {idx}/{total_items}: UNVERIFIED (Detection "
                                        "produced no line for this item after retries)"
                                    )
                                    _log(f"[detection] item {idx}/{total_items} marked "
                                         "UNVERIFIED — never dropped silently")
                                pending = []

                det_lines = []
                for idx in range(1, total_items + 1):
                    line = covered.get(idx)
                    if not line or line.strip().upper() == "NONE":
                        continue
                    det_lines.append(line)
                    # UNVERIFIED entries stay OUT of the structured findings list (there
                    # is nothing concrete — no extracted names — for Validation to check)
                    # but stay IN det_lines/det_analysis so they remain visible in the
                    # report/checkpoint instead of vanishing.
                    if "UNVERIFIED" not in line:
                        kind, item = items[idx - 1]
                        worklist.add_detection_finding(idx, kind, line, item)
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

        if provider == "ollama":
            # Deterministic, per-finding loop: the ORCHESTRATOR — not the model —
            # knows exactly which findings need verification (worklist.findings,
            # Detection's structured per-item output) and asks about exactly one at
            # a time. Replaces the old design where the model had to self-track "how
            # many distinct CWE categories have I covered" from free text: that proxy
            # was unreliable (a CWE-named dataset like SecurityEval pollutes it via
            # filenames — see _cited_cwes) and its gate had no real ceiling, so a
            # stubborn model could nudge-loop for hours without ever finishing (see
            # agent.md run history). A finite loop over a KNOWN list can't do that:
            # total work is exactly len(worklist.findings) single-finding calls.
            resume_val = state if state.get("phase") == VALIDATION else None
            start_finding_idx = resume_val.get("validation_findings_done", 0) if resume_val else 0
            val_item_steps = max(4, min(8, max_steps))
            _log(f"[validation] {len(worklist.findings)} finding(s) to verify one at a "
                 f"time, resuming at {start_finding_idx}")
            for fi, finding in enumerate(worklist.findings):
                if fi < start_finding_idx:
                    continue
                seed = [
                    {"role": "system", "content": prompts[VALIDATION]},
                    {"role": "user", "content": (
                        f"Repository: {repo_path}\n"
                        f"CodeQL database (db_path): {worklist.db_path}\n\n"
                        f"Verify this ONE finding from Detection ({fi + 1}/"
                        f"{len(worklist.findings)}):\n{finding['line']}\n\n"
                        "Call exactly one verification tool for it (check_* preferred "
                        "when a dedicated check exists for this CWE; otherwise "
                        "run_taint_query / run_api_misuse_query / "
                        "run_insecure_config_flag_query / run_custom_query, using the "
                        "exact names above). Pass this exact db_path to the query."
                    )},
                ]
                await _run_phase(
                    session, llm, phase=VALIDATION, tools=val_tools,
                    tool_names=val_allowed & all_names, seed=seed, stats=stats,
                    worklist=worklist, ckpt=ckpt, repo_path=repo_path, model=model,
                    report_path=report_path, completed=completed, max_steps=val_item_steps,
                    progress=progress, resume_state=None, require_tool_call=True,
                )
                ckpt_mod.save_checkpoint(ckpt, {
                    "repo_path": repo_path, "model": model, "report_path": report_path,
                    "phase": VALIDATION, "completed_phases": completed,
                    "worklist": worklist.to_dict(), "det_analysis": det_analysis,
                    "validation_findings_done": fi + 1,
                })
            # The findings table/verdict are built automatically from stats (below) —
            # there is no single "final" model reply to carry a free-text comment, so
            # there is none to show (kept genuinely optional, per report_body's design).
            model_commentary = ""
        else:
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
                candidate_cwes=_cited_cwes(det_analysis),
                extra_state={"det_analysis": det_analysis},
            )
        progress.phase(VALIDATION, "done")
        progress.counts(len(worklist.candidates), stats.total_findings, len(stats.cwes))

        # The findings table/verdict are built AUTOMATICALLY from the tool results
        # already collected (report.py:RunStats.report_body) — model_commentary is only
        # the model's optional free-text note, never the report itself. Finalize
        # prepends the YAML header and writes the composed body to disk.
        if keep_checkpoint:
            # _run_phase's last _save() left "phase": VALIDATION with the FULL
            # finished transcript (messages/next_step) — a later --resume would see
            # state.get("phase") == VALIDATION and treat this completed run as an
            # interrupted one to CONTINUE (resuming at its last step, with a model
            # that already believes it is done -> zero tool calls, zero findings)
            # instead of REDOING Validation with a fresh seed, which is the whole
            # point of --keep-checkpoint. Overwrite with a clean state (no messages,
            # phase back to DETECTION) so the next --resume starts Validation at
            # step 0 with the real det_analysis/worklist seed.
            ckpt_mod.save_checkpoint(ckpt, {
                "repo_path": repo_path, "model": model, "report_path": report_path,
                "phase": DETECTION, "completed_phases": completed,
                "worklist": worklist.to_dict(), "det_analysis": det_analysis,
            })
        result = stats.finalize(stats.report_body(model_commentary), report_path,
                                 None if keep_checkpoint else ckpt)
        progress.done(report_path, len(worklist.candidates), stats.total_findings, len(stats.cwes))
        return result
