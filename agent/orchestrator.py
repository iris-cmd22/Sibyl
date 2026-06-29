"""The agent loop: connect to the MCP server, let the Ollama model drive the
tools, and finalize the security report. Pure orchestration — every concern
(LLM, MCP, robustness, report) lives in its own module."""
from __future__ import annotations

import json
import sys

from agent import config
from agent.clients import mcp
from agent.clients.ollama import OllamaChat
from agent.prompts import SYSTEM_PROMPT
from agent.report import RunStats
from agent.robustness import checkpoint as ckpt_mod
from agent.robustness.dbpath import resolve_db_path
from agent.robustness.toolcalls import extract_text_tool_calls

_DUP_NUDGE = (
    "\n\nNOTE: You already called this exact tool. The result is unchanged. Do NOT "
    "call it again. Run a DIFFERENT tool you have not used yet, or write the final "
    "SECURITY REPORT now."
)
_NO_DB_ERROR = json.dumps(
    {"error": "No CodeQL database exists yet. Call create_codeql_database first, "
              "then pass the db_path it returns."}
)


# Obiettivo: far girare l'intera analisi: connettersi al server, far ragionare il
#            modello, eseguire i tool che chiede (assorbendone gli errori) e finalizzare
#            il report di sicurezza.
# Input:    repo_path = progetto da analizzare; model = nome del modello LLM;
#           report_path = dove salvare il report; max_steps = numero massimo di turni;
#           resume = se True riprende da un checkpoint esistente.
# Output:   stringa col report completo (intestazione YAML + corpo); lo scrive anche su disco.
# Come realizzato: apre la connessione MCP (connect), carica o inizializza i messaggi, e per
#            ogni step chiede al modello, recupera le tool-call (anche se in testo), corregge
#            il db_path, evita le ripetizioni (cache + nudge), esegue sul server, registra le
#            statistiche e salva il checkpoint; alla fine chiama RunStats.finalize.
async def run_agent(
    repo_path: str, model: str, report_path: str, max_steps: int = 30, resume: bool = False
) -> str:
    # The MCP server is an INDEPENDENT service: the agent is just an SSE client.
    # Start it separately (e.g. `MCP_TRANSPORT=sse python -m server`) and point
    # MCP_SERVER_URL at it (localhost in local, the server host in remote).
    llm = OllamaChat(model)

    async with mcp.connect(config.MCP_SERVER_URL) as (session, mcp_tools):
        tools = mcp.mcp_tools_to_ollama(mcp_tools)
        tool_names = {t.name for t in mcp_tools}

        ckpt = ckpt_mod.checkpoint_path(repo_path)
        if resume and ckpt.exists():
            state = ckpt_mod.load_checkpoint(ckpt)
            messages = state["messages"]
            seen = state.get("seen", {})
            start_step = state.get("next_step", 0)
            print(f"Resuming from checkpoint: step {start_step}", file=sys.stderr)
        else:
            messages = [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": f"Analyze the repository at: {repo_path}"},
            ]
            seen = {}            # call signature -> result (anti-loop cache)
            start_step = 0
        dup_streak = 0           # consecutive steps with only repeated calls

        stats = RunStats(model=model, repo_path=repo_path, max_steps=max_steps,
                         steps_done=start_step)

        for step in range(start_step, max_steps):
            msg = await llm.chat(messages, tools=tools)
            messages.append(msg)

            calls = msg.get("tool_calls") or []
            # Fallback: some local models emit the tool call as TEXT instead of
            # populating tool_calls. Recover it so the loop keeps going.
            if not calls:
                calls = extract_text_tool_calls(msg.get("content", ""), tool_names)
            if not calls:
                return stats.finalize(msg.get("content", ""), report_path, ckpt)

            all_duplicate = True
            for call in calls:
                fn = call["function"]
                name = fn["name"]
                args = fn["arguments"]
                if isinstance(args, str):
                    args = json.loads(args)
                # Fix db_path placeholders: inject the real (server-reported) DB
                # path when the model didn't pass a valid directory.
                if "db_path" in args:
                    resolved = resolve_db_path(args.get("db_path"), stats.last_db_path)
                    if resolved is None:
                        all_duplicate = False
                        print(f"[step {step}] (no db) {name}({args})", file=sys.stderr)
                        messages.append({"role": "tool", "tool_name": name, "content": _NO_DB_ERROR})
                        continue
                    args["db_path"] = resolved
                sig = name + "|" + json.dumps(args, sort_keys=True)

                if sig in seen:
                    # Anti-loop: do not re-run; return the cached result plus a
                    # firm nudge so the model advances instead of repeating.
                    print(f"[step {step}] (dup) {name}({args})", file=sys.stderr)
                    content = seen[sig] + _DUP_NUDGE
                else:
                    all_duplicate = False
                    print(f"[step {step}] -> {name}({args})", file=sys.stderr)
                    try:
                        result = await session.call_tool(name, args)
                        content = mcp.tool_result_text(result)
                    except Exception as e:  # surface tool errors back to the model
                        content = json.dumps({"error": str(e)})
                    seen[sig] = content
                    stats.record_tool_result(name, content)
                messages.append({"role": "tool", "tool_name": name, "content": content})

            stats.steps_done = step + 1
            # Persist after every step so a shutdown loses at most one step.
            ckpt_mod.save_checkpoint(ckpt, {
                "repo_path": repo_path, "model": model, "report_path": report_path,
                "next_step": step + 1, "messages": messages, "seen": seen,
            })

            dup_streak = dup_streak + 1 if all_duplicate else 0
            if dup_streak >= 2:
                # The model is stuck repeating itself: force it to conclude.
                messages.append({
                    "role": "user",
                    "content": (
                        "You are repeating tool calls without new information. Stop "
                        "using tools and write the final SECURITY REPORT now, based on "
                        "the findings already gathered."
                    ),
                })
            if dup_streak >= 4:
                break

        # Forced finalize: ask once more, without tools, for the report.
        messages.append({
            "role": "user",
            "content": "Write the final SECURITY REPORT now from the findings gathered. Do not call tools.",
        })
        final = await llm.chat(messages)
        return stats.finalize(final.get("content", ""), report_path, ckpt)
