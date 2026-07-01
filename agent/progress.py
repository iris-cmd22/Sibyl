"""Structured progress events for a graphical front-end (e.g. the VSCode webview).

The agent already prints human-readable logs to stderr. ON TOP of those, when
enabled, it also emits MACHINE-READABLE events: one JSON object per line, each
prefixed with a unique marker so a consumer can pick them out of the same stream
and ignore the human lines. The consumer (the VSCode extension) line-buffers the
process output, parses the marked lines, and draws a live progress view.

Enable by setting SIBYL_PROGRESS_EVENTS=1 (the extension sets it automatically).
When disabled, every method is a cheap no-op, so the CLI stays clean.
"""
from __future__ import annotations

import json
import os
import sys

# Sentinel prefixing every event line. Must match the extension's parser
# (extension/src/sibylRunner.ts: SIBYL_EVENT_MARKER).
MARKER = "@@SIBYL@@"


class Progress:
    # Obiettivo: tenere lo stato "attivo/non attivo" dell'emissione eventi.
    # Input:    enabled = True se gli eventi vanno emessi.
    # Output:   nessuno.
    # Come realizzato: salva il flag; se False tutti i metodi diventano no-op.
    def __init__(self, enabled: bool) -> None:
        self.enabled = enabled

    # Obiettivo: scrivere UN evento come riga JSON marcata su stderr.
    # Input:    e = coppie chiave/valore dell'evento (incluso "t" = tipo).
    # Output:   nessuno (scrive su stderr, con flush).
    # Come realizzato: serializza in JSON, antepone il MARKER, va a capo; ignora errori
    #            (l'avanzamento non deve mai far cadere l'analisi).
    def _emit(self, **e) -> None:
        if not self.enabled:
            return
        try:
            sys.stderr.write(f"{MARKER} {json.dumps(e, ensure_ascii=False)}\n")
            sys.stderr.flush()
        except Exception:
            pass

    # Obiettivo: segnalare l'inizio dell'intera pipeline (per disegnare lo "stepper").
    def start(self, phases: list[str], repo: str, model: str, provider: str) -> None:
        self._emit(t="start", phases=phases, repo=repo, model=model, provider=provider)

    # Obiettivo: segnalare l'ingresso/uscita da una fase (state = "start"|"done").
    def phase(self, phase: str, state: str) -> None:
        self._emit(t="phase", phase=phase, state=state)

    # Obiettivo: segnalare che il modello sta "pensando" (in attesa della risposta LLM).
    def think(self, phase: str, step: int) -> None:
        self._emit(t="think", phase=phase, step=step)

    # Obiettivo: segnalare lo stato di una tool-call (running/ok/error/cached/nodb).
    # Input:    phase, step, name; state; args = riassunto argomenti; dur = durata sec.
    def tool(self, phase: str, step: int, name: str, state: str,
             args: str | None = None, dur: float | None = None) -> None:
        ev = {"t": "tool", "phase": phase, "step": step, "name": name, "state": state}
        if args is not None:
            ev["args"] = args
        if dur is not None:
            ev["dur"] = round(dur, 1)
        self._emit(**ev)

    # Obiettivo: aggiornare i conteggi live (flow candidati / finding / CWE distinti).
    def counts(self, candidates: int, findings: int, cwes: int) -> None:
        self._emit(t="counts", candidates=candidates, findings=findings, cwes=cwes)

    # Obiettivo: segnalare la fine, con il percorso del report e i totali finali.
    def done(self, report: str, candidates: int, findings: int, cwes: int) -> None:
        self._emit(t="done", report=report, candidates=candidates,
                   findings=findings, cwes=cwes)


# Obiettivo: costruire l'emettitore leggendo l'interruttore d'ambiente.
# Input:    nessuno (legge SIBYL_PROGRESS_EVENTS).
# Output:   un Progress attivo solo se la variabile è "verità" (1/true/yes/on).
# Come realizzato: normalizza il valore e abilita l'emissione di conseguenza.
def make_progress() -> Progress:
    val = os.environ.get("SIBYL_PROGRESS_EVENTS", "").strip().lower()
    return Progress(val in {"1", "true", "yes", "on", "events"})
