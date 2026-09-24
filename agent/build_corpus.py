"""Standalone entry point: gather CodeQL evidence for a repo, prioritize it
with the full metric set in agent/risk_score.py, and synthesize a
deterministic Phase-1 trajectory corpus (agent/trajectory_synth.py) — writes
one JSON trajectory per line (JSONL), ready to feed a future SFT stage with
zero reformatting.

NO LLM anywhere in this script, by design: only the deterministic gathering
step (agent/orchestrator.py's _gather_evidence — DB creation + the 12
mechanical find_* inventories) runs against the repo; everything after that
is pure Python over already-collected evidence + a graphify graph.

Usage:
    python -m agent.build_corpus <repo_path> [--graphify-dir graphify-out] [--out corpus.jsonl]
"""
from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

from agent import config, risk_score, trajectory_synth
from agent.clients import mcp
from agent.orchestrator import _gather_evidence
from agent.progress import make_progress
from agent.report import RunStats
from agent.source import resolve_source
from agent.worklist import WorkList


# Obiettivo: log di avanzamento su stderr, coerente con lo stile del resto di agent/.
def _log(msg: str) -> None:
    print(msg, file=sys.stderr, flush=True)


# Obiettivo: eseguire l'intera pipeline deterministica: gathering (via MCP,
#            riusando _gather_evidence di orchestrator.py — stessa funzione,
#            zero duplicazione) -> prioritizzazione (risk_score, con TUTTE le
#            metriche attive in METRICS, incluse quelle a grafo se
#            graph_index e' disponibile) -> sintesi trajectory -> scrittura
#            JSONL su disco.
# Input:    repo_path = repo da analizzare (gia' risolto); graphify_dir =
#           cartella graphify-out per questo repo, o None per saltare il
#           grounding delle evidenze; out_path = file JSONL di destinazione.
# Output:   nessuno (scrive su disco, logga il riepilogo su stderr).
async def _run(repo_path: str, graphify_dir: str | None, out_path: str) -> None:
    worklist = WorkList(repo_path=repo_path)
    stats = RunStats(model="deterministic-synth", repo_path=repo_path, max_steps=0)
    progress = make_progress()

    async with mcp.connect(config.MCP_SERVER_URL) as (session, _mcp_tools):
        error = await _gather_evidence(session, repo_path, worklist, stats, progress)
    if error:
        _log(f"FAILED: {error}")
        raise SystemExit(1)
    _log(f"[gathering] {len(worklist.candidates)} flow(s), "
         f"{len(worklist.operations)} sensitive op(s)")

    graph_index = trajectory_synth.load_graph_index(graphify_dir) if graphify_dir else None
    if graphify_dir and graph_index is None:
        _log(f"WARNING: no graph.json found under {graphify_dir!r} — evidence "
             f"citations will be ungrounded and graph-based metrics "
             f"(fan-in/out, community concentration) will score 0. Run "
             f"/graphify on this repo first to enable them.")
    elif graph_index is None:
        _log("No --graphify-dir given — evidence ungrounded, graph metrics score 0.")

    risk_score.sort_worklist(worklist, graph_index)
    corpus = trajectory_synth.synthesize_corpus(worklist, graph_index)

    valid = sum(1 for e in corpus if e["valid"])
    _log(f"{len(corpus)} trajectories synthesized, {valid} valid, "
         f"{len(corpus) - valid} rejected (see 'reason' per entry in the output)")

    out = Path(out_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", encoding="utf-8") as f:
        for entry in corpus:
            f.write(json.dumps({
                "kind": entry["kind"],
                "valid": entry["valid"],
                "reason": entry["reason"],
                "trajectory": entry["trajectory"],
            }, ensure_ascii=False) + "\n")
    _log(f"Corpus written to: {out}")


# Obiettivo: punto d'ingresso da riga di comando, stesso stile di agent/cli.py.
def main() -> None:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

    ap = argparse.ArgumentParser(
        description="Deterministic Phase-1 trajectory corpus builder (no LLM, "
                     "no teacher — see agent/trajectory_synth.py)."
    )
    ap.add_argument("repo_path", help="Path to the repository (a directory or a .zip)")
    ap.add_argument("--graphify-dir", default="graphify-out",
                     help="Path to a graphify-out/ directory for this repo "
                          "(supplies persistent node IDs for evidence grounding "
                          "and enables fan-in/out + community metrics). Default: "
                          "graphify-out. Skipped automatically if it doesn't exist.")
    ap.add_argument("--out", default="corpus.jsonl",
                     help="Output JSONL path (default: corpus.jsonl)")
    args = ap.parse_args()

    repo_path = resolve_source(args.repo_path)
    graphify_dir = args.graphify_dir if Path(args.graphify_dir).exists() else None
    asyncio.run(_run(repo_path, graphify_dir, args.out))


if __name__ == "__main__":
    main()
