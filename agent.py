"""Security analysis agent: local Ollama model + CodeQL via MCP.

Usage:
    python agent.py <repo_path> [--model qwen2.5-coder:14b] [--report report.md]

The agent launches the CodeQL MCP server as a stdio subprocess, exposes its
tools to the Ollama model, and lets the model drive: enumerate files, build a
CodeQL database, run the security suite, inspect findings, and write a report.
"""
from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import re
import shutil
import sys
import time
from datetime import datetime
from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from ollama import AsyncClient

import config

SYSTEM_PROMPT = """You are a security analysis agent. You analyze a code repository \
for vulnerabilities using CodeQL, which is available to you through tools.

Work EVIDENCE-FIRST and be efficient. Do NOT blindly run every check or go through \
every CWE in the catalog — that wastes time. First investigate the code, then verify \
ONLY the vulnerability classes you actually have reason to suspect.

Process:
1. Call list_python_files to see ALL files in the repository.
2. Read EVERY file it returned with read_file_snippet — do NOT stop at the entry \
point or read just one file. Read each file to its end: if a file is longer than \
the snippet window, call read_file_snippet again with later line ranges until you \
have seen all of it. While reading the WHOLE codebase, look for:
   - untrusted input: HTTP request data, CLI args, environment, file/network reads;
   - dangerous operations: SQL/DB calls, OS/process execution, filesystem paths \
built from input, deserialization, HTML/response rendering, cryptography \
(hashing, ciphers, random number generation), and INSECURE CONFIGURATION FLAGS \
(verify=False on HTTPS, shell=True on subprocess, autoescape=False on templates, \
debug=True on web frameworks, weak hashes like md5/sha1, weak randomness, \
insecure cookie settings).
   Only AFTER you have seen every file, build the list of SUSPECTED vulnerability \
classes (a class is suspected if ANY file shows a relevant operation). Do not skip \
files like crypto/auth/storage helpers — vulnerabilities often live there, not only \
in the web entry point.
3. Call create_codeql_database on the repository root to build the DB. (If the repo \
is large or you are unsure what to suspect, you MAY also call analyze_database once \
for broad coverage.)
4. For EACH suspected class only (skip the ones with no indicators):
   a. Call cwe_knowledge(cwe) to get the taint intuition, the detection kind, the \
right tool, and candidate sink/source/sanitizer (or weak-API) names.
   b. VERIFY with the tool the wiki indicates, passing cwe=<the CWE> (it stamps the \
class into the evidence). Do NOT write CodeQL by hand:
      - detection "taint" -> run_taint_query(cwe, sink_names=<candidates + the real \
call names you saw in the code>, optional source_names/sanitizer_names).
      - detection "api_misuse" -> run_api_misuse_query(cwe, weak_call_names and/or \
bad_constants). Point detection (no flow_path).
      A matching ready-made check_* tool (e.g. check_sql_injection, check_weak_hash) \
is also fine when it fits the class exactly.
   c. If the verification finds nothing, MOVE ON. Do not keep refining a class that \
has no evidence in the code.
5. Optionally call read_file_snippet again to confirm the context of a finding.
6. Produce the final SECURITY REPORT in Markdown. Stop calling tools once you start \
writing it.

Be THOROUGH when reading (cover every file, step 2) but EFFICIENT when verifying: \
aim to verify each suspected class with a SINGLE targeted call. Never run a check \
for a class whose indicators are absent from the whole codebase. Do not repeat a \
tool call you already made. Always pass the exact db_path string returned by \
create_codeql_database (never a placeholder).

CRITICAL RULE ON CWE ATTRIBUTION: a vulnerability's CWE must come from the \
deterministic CodeQL evidence, never from your own assumption. A finding's `cwe` \
field (derived from the query's metadata tags) is authoritative. When you used \
run_taint_query, only claim the CWE you passed in and that the tool stamped into \
the finding. If a flow was found but no CWE is attached, report it as "taint flow \
(unclassified)" and explain, do not guess a CWE number.

For EACH finding, structure it as:
- **Deterministic evidence (CodeQL):** the rule/query id, and the data-flow path \
from `source` (file:line) through to `sink` (file:line) using the `flow_path`. \
State plainly: "Static analysis proved user-controlled data flows from X to Y."
- **Classification:** the CWE id + canonical name (from the finding), and severity.
- **Why it matters & remediation:** short explanation + the standard_remediation \
plus any code-specific fix.

Group findings by file. End with a summary table (CWE, count, severity) and an \
overall risk verdict. Be precise; every CWE claim must trace to CodeQL output."""


def mcp_tools_to_ollama(tools) -> list[dict]:
    """Convert MCP tool definitions to Ollama's function-calling schema."""
    return [
        {
            "type": "function",
            "function": {
                "name": t.name,
                "description": t.description or "",
                "parameters": t.inputSchema,
            },
        }
        for t in tools
    ]


def _tool_result_text(result) -> str:
    """Extract text payload from an MCP tool result."""
    parts = []
    for block in result.content:
        parts.append(getattr(block, "text", "") or "")
    return "\n".join(parts) or "(empty result)"


def _extract_text_tool_calls(content: str, tool_names: set[str]) -> list[dict]:
    """Fallback: recover tool calls a model emitted as TEXT instead of in the
    structured `tool_calls` field. Many local models (incl. some Ollama builds)
    print a ```json {"name":..., "arguments":...} ``` block in `content`.

    Returns a list of {"function": {"name", "arguments"}} dicts, only for JSON
    objects whose "name" is a real tool, so a normal report is never mistaken
    for a call.
    """
    if not content or '"name"' not in content:
        return []

    # Candidate JSON strings: fenced code blocks, the whole content, and every
    # top-level balanced {...} object (handles nested braces correctly).
    candidates: list[str] = []
    for m in re.finditer(r"```(?:json)?\s*(.*?)```", content, re.DOTALL):
        candidates.append(m.group(1).strip())
    candidates.append(content.strip())
    candidates.extend(_balanced_objects(content))

    calls, seen = [], set()
    for snippet in candidates:
        try:
            obj = json.loads(snippet)
        except (json.JSONDecodeError, ValueError):
            continue
        for item in obj if isinstance(obj, list) else [obj]:
            if not isinstance(item, dict):
                continue
            name = item.get("name")
            args = item.get("arguments", item.get("parameters", {}))
            key = json.dumps({"n": name, "a": args}, sort_keys=True)
            if name in tool_names and isinstance(args, dict) and key not in seen:
                seen.add(key)
                calls.append({"function": {"name": name, "arguments": args}})
    return calls


def _balanced_objects(text: str) -> list[str]:
    """Return every top-level {...} substring with balanced braces."""
    out, depth, start = [], 0, None
    for i, ch in enumerate(text):
        if ch == "{":
            if depth == 0:
                start = i
            depth += 1
        elif ch == "}" and depth:
            depth -= 1
            if depth == 0 and start is not None:
                out.append(text[start : i + 1])
                start = None
    return out


def _plain(msg) -> dict:
    """Normalize an Ollama response message to a plain JSON-serializable dict."""
    if hasattr(msg, "model_dump"):
        return msg.model_dump()
    return dict(msg)


def _checkpoint_path(repo_path: str) -> Path:
    """Per-repo checkpoint file under WORK_DIR (survives a shutdown)."""
    resolved = Path(repo_path).resolve()
    h = hashlib.sha1(str(resolved).encode()).hexdigest()[:10]
    return config.WORK_DIR / f"checkpoint_{resolved.name}_{h}.json"


def _save_checkpoint(path: Path, state: dict) -> None:
    """Write the checkpoint atomically so a crash mid-write can't corrupt it."""
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(state), encoding="utf-8")
    tmp.replace(path)


def _resolve_db_path(value, last_db_path, expected_db):
    """Return a valid DB directory path. Models often pass a placeholder
    (e.g. "<result of create_codeql_database>") instead of the real path; in
    that case fall back to the captured or deterministic DB path."""
    if isinstance(value, str) and Path(value).is_dir():
        return value
    return last_db_path or expected_db


async def run_agent(
    repo_path: str, model: str, report_path: str, max_steps: int = 30, resume: bool = False
) -> str:
    server = StdioServerParameters(
        command=sys.executable,
        args=[str(Path(__file__).parent / "codeql_mcp_server.py")],
    )
    client = AsyncClient(host=config.OLLAMA_HOST)

    async with stdio_client(server) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            mcp_tools = (await session.list_tools()).tools
            tools = mcp_tools_to_ollama(mcp_tools)
            tool_names = {t.name for t in mcp_tools}

            ckpt = _checkpoint_path(repo_path)
            if resume and ckpt.exists():
                state = json.loads(ckpt.read_text(encoding="utf-8"))
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

            # --- run statistics, embedded in the report header ---
            started = time.time()
            tool_counts: dict[str, int] = {}
            cwes: set[str] = set()
            total_findings = 0
            steps_done = start_step

            # The DB path is deterministic; keep it so we can fix calls where the
            # model passes a placeholder (e.g. "<result of create_codeql_database>").
            last_db_path: str | None = None
            _resolved = Path(repo_path).resolve()
            expected_db = str(
                config.WORK_DIR
                / f"db_{_resolved.name}_{hashlib.sha1(str(_resolved).encode()).hexdigest()[:10]}"
            )

            def finalize(report_text: str) -> str:
                header = _metadata_header(
                    model, repo_path, started, steps_done, max_steps,
                    tool_counts, cwes, total_findings,
                )
                full = header + (report_text or "(no report produced)")
                out = Path(report_path)
                out.parent.mkdir(parents=True, exist_ok=True)
                out.write_text(full, encoding="utf-8")
                ckpt.unlink(missing_ok=True)   # analysis complete
                return full

            for step in range(start_step, max_steps):
                resp = await client.chat(model=model, messages=messages, tools=tools)
                msg = _plain(resp["message"])   # plain dict -> checkpoint stays serializable
                messages.append(msg)

                calls = msg.get("tool_calls") or []
                # Fallback: some local models emit the tool call as TEXT instead of
                # populating tool_calls. Recover it so the loop keeps going.
                if not calls:
                    calls = _extract_text_tool_calls(msg.get("content", ""), tool_names)
                if not calls:
                    return finalize(msg.get("content", ""))

                all_duplicate = True
                for call in calls:
                    fn = call["function"]
                    name = fn["name"]
                    args = fn["arguments"]
                    if isinstance(args, str):
                        args = json.loads(args)
                    # Fix db_path placeholders: inject the real (deterministic) DB
                    # path when the model didn't pass a valid directory.
                    if "db_path" in args:
                        args["db_path"] = _resolve_db_path(args.get("db_path"), last_db_path, expected_db)
                    sig = name + "|" + json.dumps(args, sort_keys=True)

                    if sig in seen:
                        # Anti-loop: do not re-run; return the cached result plus a
                        # firm nudge so the model advances instead of repeating.
                        print(f"[step {step}] (dup) {name}({args})", file=sys.stderr)
                        content = (
                            seen[sig]
                            + "\n\nNOTE: You already called this exact tool. The result is "
                            "unchanged. Do NOT call it again. Run a DIFFERENT tool you "
                            "have not used yet, or write the final SECURITY REPORT now."
                        )
                    else:
                        all_duplicate = False
                        print(f"[step {step}] -> {name}({args})", file=sys.stderr)
                        try:
                            result = await session.call_tool(name, args)
                            content = _tool_result_text(result)
                        except Exception as e:  # surface tool errors back to the model
                            content = json.dumps({"error": str(e)})
                        seen[sig] = content
                        # Update run stats (tools used + findings/CWEs seen).
                        tool_counts[name] = tool_counts.get(name, 0) + 1
                        try:
                            obj = json.loads(content)
                            if isinstance(obj, dict):
                                if name == "create_codeql_database" and obj.get("db_path"):
                                    last_db_path = obj["db_path"]
                                fc = obj.get("finding_count")
                                if isinstance(fc, int):
                                    total_findings += fc
                                for f in obj.get("findings", []) or []:
                                    if isinstance(f, dict) and f.get("cwe"):
                                        cwes.add(f["cwe"])
                                if obj.get("cwe") and fc:
                                    cwes.add(obj["cwe"])
                        except (json.JSONDecodeError, ValueError):
                            pass
                    messages.append({"role": "tool", "tool_name": name, "content": content})

                steps_done = step + 1
                # Persist after every step so a shutdown loses at most one step.
                _save_checkpoint(ckpt, {
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
            final = await client.chat(model=model, messages=messages)
            return finalize(_plain(final["message"]).get("content", ""))


def _slug(s: str) -> str:
    """Filesystem-safe slug (keeps letters, digits, dot, dash, underscore)."""
    return re.sub(r"[^A-Za-z0-9._-]+", "_", s).strip("_")


def _default_report_path(repo_arg: str, model: str) -> str:
    """reports/<repo>/<model>__<timestamp>.md (one folder per repo)."""
    repo_slug = _slug(Path(repo_arg).stem)
    model_slug = _slug(model.split("/")[-1])   # drop hf.co/owner/ prefix
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    repo_dir = config.REPORTS_DIR / repo_slug
    repo_dir.mkdir(parents=True, exist_ok=True)
    return str(repo_dir / f"{model_slug}__{ts}.md")


def _metadata_header(model, repo_path, started, steps_done, max_steps,
                     tool_counts, cwes, total_findings) -> str:
    """YAML front-matter prepended to the report so each run is self-describing."""
    finished = time.time()
    tools = ", ".join(f"{k}:{v}" for k, v in sorted(tool_counts.items())) or "none"
    cwe_list = ", ".join(sorted(cwes, key=lambda c: int(re.search(r"\d+", c).group()))) or "none"
    iso = lambda t: datetime.fromtimestamp(t).isoformat(timespec="seconds")
    return (
        "---\n"
        f"model: {model}\n"
        f"repository: {repo_path}\n"
        f"started: {iso(started)}\n"
        f"finished: {iso(finished)}\n"
        f"duration_seconds: {round(finished - started, 1)}\n"
        f"steps_used: {steps_done}\n"
        f"max_steps: {max_steps}\n"
        f"tools_used: {tools}\n"
        f"cwes_found: {cwe_list}\n"
        f"total_findings: {total_findings}\n"
        "generated_by: codeql-security-agent\n"
        "---\n\n"
    )


def _resolve_source(path_str: str) -> str:
    """Accept either a directory or a .zip. A zip is extracted under WORK_DIR and
    the extracted directory is returned (the real repo root if the zip wraps a
    single top-level folder)."""
    import zipfile

    p = Path(path_str)
    if p.is_dir():
        return str(p)
    if p.is_file() and p.suffix.lower() == ".zip":
        dest = config.WORK_DIR / f"src_{p.stem}"
        if dest.exists():
            shutil.rmtree(dest)
        with zipfile.ZipFile(p) as z:
            z.extractall(dest)
        # If the zip contains a single top-level folder, use that as the root.
        entries = [e for e in dest.iterdir() if e.name != "__MACOSX"]
        root = entries[0] if len(entries) == 1 and entries[0].is_dir() else dest
        print(f"Extracted {p.name} -> {root}", file=sys.stderr)
        return str(root)
    sys.exit(f"Not a directory or .zip file: {path_str}")


def main() -> None:
    ap = argparse.ArgumentParser(description="CodeQL security agent (Ollama + MCP)")
    ap.add_argument("repo_path", help="Path to the repository (a directory or a .zip)")
    ap.add_argument("--model", default=config.AGENT_MODEL)
    ap.add_argument("--report", default=None,
                    help="Output path. Default: reports/<repo>__<model>__<timestamp>.md")
    ap.add_argument("--max-steps", type=int, default=30)
    ap.add_argument("--resume", action="store_true",
                    help="Resume from the saved checkpoint for this repo, if any.")
    args = ap.parse_args()

    repo_path = _resolve_source(args.repo_path)
    report_path = args.report or _default_report_path(args.repo_path, args.model)

    ckpt = _checkpoint_path(repo_path)
    if ckpt.exists() and not args.resume:
        print(f"NOTE: a checkpoint exists ({ckpt.name}). Re-run with --resume to "
              f"continue it, or it will be overwritten by this fresh run.", file=sys.stderr)
    print(f"Report will be saved to: {report_path}", file=sys.stderr)

    report = asyncio.run(run_agent(repo_path, args.model, report_path, args.max_steps, args.resume))
    print("\n" + "=" * 70)
    print(report)
    print("=" * 70)
    print(f"\nReport saved to: {report_path}")


if __name__ == "__main__":
    main()
