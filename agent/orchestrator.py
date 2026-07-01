"""The agent loop: a two-phase pipeline Detection -> Validation.

Each phase runs the same generic sub-loop (`_run_phase`) but with its OWN system
prompt and its OWN subset of MCP tools, and the LLM context is RESET between phases
(Claim Check): only a lightweight flow-inventory (the work-list) travels across,
while the heavy artifacts (CodeQL DB, SARIF) stay on disk.

- Detection: the model reads the code and gets ALL the flows in it (find_all_flows,
  CWE-agnostic), producing candidate flows.
- Validation: the model builds/runs the targeted queries it needs (results are
  trustworthy), associates a CWE to each finding, and WRITES THE FINAL REPORT.

(Evaluation with standard CodeQL queries is deliberately OUT of this framework.)
Pure orchestration — every other concern lives in its own module.
"""
from __future__ import annotations

import json
import sys
import time

from agent import config
from agent.clients import mcp
from agent.clients.factory import make_llm
from agent.phases import DETECTION, VALIDATION, fetch_phase_tools, filter_tools
from agent.progress import make_progress
from agent.prompts import DETECTION_PROMPT, VALIDATION_PROMPT
from agent.report import RunStats
from agent.robustness import checkpoint as ckpt_mod
from agent.robustness.dbpath import resolve_db_path
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
# Come realizzato: a seconda del tool (find_all_flows / find_sensitive_operations)
#            parsa il JSON e popola candidati oppure operazioni.
def _capture_detection(worklist: WorkList):
    def cb(name: str, content: str) -> None:
        if name not in ("find_all_flows", "find_sensitive_operations"):
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


# Obiettivo: eseguire UNA fase LLM (Detection o Validation): il sotto-loop generico
#            che chiede al modello, esegue i tool ammessi nella fase (assorbendone gli
#            errori), cattura i flow nella work-list e salva i checkpoint.
# Input:    session/llm = connessione MCP e modello; phase = nome fase; tools = schema
#           tool (gia' filtrati per fase); tool_names = nomi ammessi; seed = messaggi
#           iniziali; stats/worklist = accumulatori; ckpt = file checkpoint;
#           repo/model/report = per il checkpoint; completed = fasi gia' concluse;
#           max_steps = turni max; progress = emettitore eventi; on_result = callback;
#           finalize_report = se True l'output finale della fase e' il REPORT (Validation);
#           resume_state = stato da cui riprendere (o None).
# Output:   stringa col testo finale del modello (riassunto per Detection, REPORT per
#           Validation) o "".
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
        if not calls:
            _log(f"[{phase} step {step}] model wrote its final text -> phase done")
            _save(step)
            return msg.get("content", "")

        all_duplicate = True
        for call in calls:
            fn = call["function"]
            name = fn["name"]
            args = fn["arguments"]
            if isinstance(args, str):
                args = json.loads(args)
            if "db_path" in args:
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
                stats.record_tool_result(name, content)
                if on_result and status == "ok":
                    try:
                        on_result(name, content)
                    except Exception:  # capture must never break the loop
                        pass
                progress.tool(phase, step, name, "ok" if status == "ok" else "error",
                              dur=time.time() - t0)
                _log(f"[{phase} step {step}]    {status} {name} ({time.time() - t0:.1f}s)")
            messages.append({"role": "tool", "tool_name": name, "content": content})

        stats.steps_done += 1
        _emit_counts()
        _save(step)

        dup_streak = dup_streak + 1 if all_duplicate else 0
        if dup_streak >= 2:
            messages.append({"role": "user", "content": stuck_msg})
        if dup_streak >= 4:
            break

    # Loop exhausted. For the report phase, force one final write (no tools).
    if finalize_report:
        messages.append({
            "role": "user",
            "content": "Write the final SECURITY REPORT now from the findings gathered. Do not call tools.",
        })
        final = await llm.chat(messages)
        return final.get("content", "")
    return ""


# Obiettivo: far girare l'intera pipeline a 2 fasi e finalizzare il report.
# Input:    repo_path = progetto; model = modello; report_path = output; max_steps =
#           turni max PER fase; resume = riprende da checkpoint; provider = backend LLM.
# Output:   stringa col report completo (intestazione YAML + corpo scritto dall'LLM).
# Come realizzato: connette il server MCP, esegue Detection (codice + tutti i flow) e
#            poi Validation (query mirate + associazione CWE + scrittura del report), con
#            reset del contesto in mezzo; il testo finale della Validation e' il report.
async def run_agent(
    repo_path: str, model: str, report_path: str, max_steps: int = 30,
    resume: bool = False, provider: str = "ollama",
) -> str:
    llm = make_llm(provider, model)
    progress = make_progress()

    async with mcp.connect(config.MCP_SERVER_URL) as (session, mcp_tools):
        all_names = {t.name for t in mcp_tools}
        ckpt = ckpt_mod.checkpoint_path(repo_path)
        stats = RunStats(model=model, repo_path=repo_path, max_steps=max_steps)

        # Resume: restore completed phases + work-list + current-phase state.
        state: dict = {}
        completed: list[str] = []
        worklist = WorkList(repo_path=repo_path)
        if resume and ckpt.exists():
            state = ckpt_mod.load_checkpoint(ckpt)
            completed = list(state.get("completed_phases", []))
            if state.get("worklist"):
                worklist = WorkList.from_dict(state["worklist"])
            _log(f"Resuming: completed={completed}, phase={state.get('phase')}")

        # The tool -> phase mapping is the SERVER's responsibility (not hardcoded
        # in the agent). If unavailable, degrade to exposing every tool per phase.
        phase_tools = await fetch_phase_tools(session)
        det_allowed = phase_tools.get(DETECTION) or all_names
        val_allowed = phase_tools.get(VALIDATION) or all_names

        _log(f"Connected: {len(all_names)} tools | provider={provider} | model={model} | repo={repo_path}")
        _log(f"Phase tools from server: detection={len(det_allowed)}, validation={len(val_allowed)}")
        progress.start([DETECTION, VALIDATION], repo_path, model, provider)

        # --- Phase 1: DETECTION (code + ALL flows, CWE-agnostic) ---
        if DETECTION not in completed:
            progress.phase(DETECTION, "start")
            det_tools = mcp.mcp_tools_to_ollama(filter_tools(mcp_tools, det_allowed))
            seed = [
                {"role": "system", "content": DETECTION_PROMPT},
                {"role": "user", "content": f"Analyze the repository at: {repo_path}"},
            ]
            await _run_phase(
                session, llm, phase=DETECTION, tools=det_tools,
                tool_names=det_allowed & all_names, seed=seed, stats=stats,
                worklist=worklist, ckpt=ckpt, repo_path=repo_path, model=model,
                report_path=report_path, completed=completed, max_steps=max_steps,
                progress=progress, on_result=_capture_detection(worklist),
                resume_state=state if state.get("phase") == DETECTION else None,
            )
            worklist.db_path = stats.last_db_path or worklist.db_path
            completed.append(DETECTION)
            progress.phase(DETECTION, "done")
            progress.counts(len(worklist.candidates), stats.total_findings, len(stats.cwes))
            _log(f"[detection] done: {len(worklist.candidates)} flow(s), "
                 f"{len(worklist.operations)} sensitive op(s); db={worklist.db_path}")

        # --- Phase 2: VALIDATION (targeted queries + associate CWE + write report) ---
        progress.phase(VALIDATION, "start")
        stats.last_db_path = worklist.db_path  # so db_path placeholders resolve
        val_tools = mcp.mcp_tools_to_ollama(filter_tools(mcp_tools, val_allowed))
        seed = [
            {"role": "system", "content": VALIDATION_PROMPT},
            {"role": "user", "content": (
                f"Repository: {repo_path}\n"
                f"CodeQL database (db_path): {worklist.db_path}\n\n"
                f"{worklist.detection_summary()}\n\n"
                "Verify the dangerous flows above, associate a CWE to each confirmed "
                "finding, then write the final SECURITY REPORT. Pass this exact db_path "
                "to every query."
            )},
        ]
        report_text = await _run_phase(
            session, llm, phase=VALIDATION, tools=val_tools,
            tool_names=val_allowed & all_names, seed=seed, stats=stats,
            worklist=worklist, ckpt=ckpt, repo_path=repo_path, model=model,
            report_path=report_path, completed=completed, max_steps=max_steps,
            progress=progress, finalize_report=True,
            resume_state=state if state.get("phase") == VALIDATION else None,
        )
        progress.phase(VALIDATION, "done")
        progress.counts(len(worklist.candidates), stats.total_findings, len(stats.cwes))

        # The report is the model's final text (same format as before). Finalize
        # prepends the YAML header and writes it to disk.
        result = stats.finalize(report_text, report_path, ckpt)
        progress.done(report_path, len(worklist.candidates), stats.total_findings, len(stats.cwes))
        return result
