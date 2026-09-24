"""Command-line entry point: parse args, resolve the input, run the agent."""
from __future__ import annotations

import argparse
import asyncio
import sys

from agent import config
from agent.orchestrator import run_agent
from agent.report import default_report_path
from agent.robustness.checkpoint import checkpoint_path
from agent.source import resolve_source


# Obiettivo: punto d'ingresso da riga di comando: leggere le opzioni, preparare l'input
#            e avviare il loop dell'agente.
# Input:    nessuno (legge gli argomenti da sys.argv via argparse).
# Output:   nessuno; stampa il report a video e lo salva su file.
# Come realizzato: definisce gli argomenti (repo, --provider, --model, --report, --max-steps,
#            --resume, --keep-checkpoint, --clear-checkpoint), sceglie il modello di default
#            in base al provider, risolve la sorgente, calcola il percorso del report, avvisa
#            se c'è un checkpoint, e lancia run_agent (--clear-checkpoint esce prima, senza
#            lanciare l'agent — vedi il branch dedicato sotto).
def main() -> None:
    # La console Windows usa spesso cp1252: forziamo UTF-8 (con replace di riserva)
    # per non crashare su caratteri come '‑' generati dal modello.
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

    ap = argparse.ArgumentParser(description="CodeQL security agent (Ollama/Gemini + MCP)")
    ap.add_argument("repo_path", help="Path to the repository (a directory or a .zip)")
    ap.add_argument("--provider", default=config.LLM_PROVIDER,
                    choices=["ollama", "gemini", "openai"],
                    help="LLM backend (default from AGENT_LLM_PROVIDER, else 'ollama'). "
                         "'openai' = any OpenAI-compatible API (Groq/Cerebras/...).")
    ap.add_argument("--model", default=None,
                    help="Model id. Default depends on provider (AGENT_MODEL / GEMINI_MODEL).")
    ap.add_argument("--report", default=None,
                    help="Output path. Default: reports/<repo>/<model>__<timestamp>.md")
    ap.add_argument("--max-steps", type=int, default=30)
    ap.add_argument("--resume", action="store_true",
                    help="Resume from the saved checkpoint for this repo, if any.")
    ap.add_argument("--keep-checkpoint", action="store_true",
                    help="Don't delete the checkpoint after a successful run. Lets a "
                         "later --resume redo just Validation (gathering+detection are "
                         "already in completed_phases) without re-running Detection.")
    ap.add_argument("--clear-checkpoint", action="store_true",
                    help="Delete the saved checkpoint for this repo (if any) and exit — "
                         "does NOT run the agent. Use this to discard a checkpoint left "
                         "by an interrupted run (e.g. cancelled mid-Detection) instead "
                         "of resuming into that partial/stale state.")
    args = ap.parse_args()

    # Per-provider default model when --model is omitted.
    _defaults = {"gemini": config.GEMINI_MODEL, "openai": config.OPENAI_MODEL}
    model = args.model or _defaults.get(args.provider, config.AGENT_MODEL)

    repo_path = resolve_source(args.repo_path)
    ckpt = checkpoint_path(repo_path)

    if args.clear_checkpoint:
        if ckpt.exists():
            ckpt.unlink()
            print(f"Checkpoint deleted: {ckpt}", file=sys.stderr)
        else:
            print(f"No checkpoint found for this repo ({ckpt.name}).", file=sys.stderr)
        return

    report_path = args.report or default_report_path(args.repo_path, model)

    if ckpt.exists() and not args.resume:
        print(f"NOTE: a checkpoint exists ({ckpt.name}). Re-run with --resume to "
              f"continue it, or it will be overwritten by this fresh run.", file=sys.stderr)
    elif args.resume and not ckpt.exists():
        print("NOTE: --resume was passed but no checkpoint exists for this repo — "
              "running a full analysis from scratch instead.", file=sys.stderr)
    print(f"Report will be saved to: {report_path}", file=sys.stderr)

    report = asyncio.run(
        run_agent(repo_path, model, report_path, args.max_steps, args.resume, args.provider,
                  args.keep_checkpoint)
    )
    print("\n" + "=" * 70)
    print(report)
    print("=" * 70)
    print(f"\nReport saved to: {report_path}")


if __name__ == "__main__":
    main()
