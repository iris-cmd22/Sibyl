"""The work-list: the lightweight artifact handed off from Detection to Validation
(Claim Check). Detection fills `candidates` (the CWE-agnostic flow inventory); the
heavy artifacts (CodeQL DB, SARIF) stay on disk and are referenced by path only.

The work-list carries the flow inventory across the context reset so Validation
knows which flows to verify. The final findings and the report are produced by the
Validation model itself, not from this structure.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field


@dataclass
class WorkList:
    repo_path: str
    db_path: str | None = None
    candidates: list[dict] = field(default_factory=list)   # flows (find_all_flows)
    operations: list[dict] = field(default_factory=list)   # sensitive ops (the categorized find_* tools)

    # Obiettivo: aggiungere alla work-list i flow CWE-agnostici prodotti da find_all_flows.
    # Input:    payload = il dict (gia' parsato) restituito da find_all_flows.
    # Output:   nessuno (popola self.candidates, deduplicando per source/sink).
    # Come realizzato: scorre payload["flows"] e crea un item per ogni flow nuovo.
    def add_candidates(self, payload: dict) -> None:
        seen = {(c["source"].get("file"), c["source"].get("line"),
                 c["sink"].get("file"), c["sink"].get("line")) for c in self.candidates}
        for flow in payload.get("flows", []) or []:
            src = flow.get("source") or {}
            snk = flow.get("sink") or {}
            key = (src.get("file"), src.get("line"), snk.get("file"), snk.get("line"))
            if key in seen:
                continue
            seen.add(key)
            self.candidates.append({
                "source": {"file": src.get("file"), "line": src.get("line")},
                "sink": {"file": snk.get("file"), "line": snk.get("line")},
                "sink_hint": flow.get("sink_hint", ""),
                "steps": flow.get("steps", 0),
                # Real code at every hop (deterministic, read from disk by the tool) —
                # never guessed. Empty if the tool ran without repo_path.
                "path": flow.get("path", []),
                "path_truncated": flow.get("path_truncated", False),
            })

    # Obiettivo: aggiungere le operazioni sensibili (non-flow) da uno dei tool categorizzati
    #            (find_crypto_operations, find_command_execution, ecc.).
    # Input:    payload = il dict (gia' parsato) restituito da uno di quei tool.
    # Output:   nessuno (popola self.operations, deduplicando per kind/file/line).
    # Come realizzato: scorre payload["operations"] e crea un item per ogni op nuova.
    def add_operations(self, payload: dict) -> None:
        seen = {(o.get("kind"), o.get("file"), o.get("line")) for o in self.operations}
        for op in payload.get("operations", []) or []:
            key = (op.get("kind"), op.get("file"), op.get("line"))
            if key in seen:
                continue
            seen.add(key)
            self.operations.append({
                "kind": op.get("kind"), "file": op.get("file"), "line": op.get("line"),
                # Real code at that line (deterministic, read from disk by the tool) —
                # never guessed. Empty if the tool ran without repo_path.
                "code": op.get("code", ""),
            })

    # Obiettivo: riassunto testuale e compatto dei flow candidati, da iniettare nel prompt.
    #            Usato per DUE scopi diversi: (1) seed di Detection, che ha il privilegio
    #            di leggere codice grezzo ed estrarre i nomi esatti; (2) seed di Validation,
    #            DOPO il reset di contesto (Claim Check) — a Validation il codice sorgente
    #            grezzo (potenzialmente non fidato, letto dal repo analizzato) NON deve mai
    #            arrivare: riceve solo posizioni/metadati e i nomi gia' estratti da Detection
    #            (via det_analysis, passato separatamente da orchestrator.py). Per questo
    #            include_code va messo a False quando si costruisce il seed di Validation.
    # Input:    limit = quanti flow elencare al massimo; path_limit = quanti passi della
    #           catena mostrare per flow (il resto e' comunque nel JSON completo su disco);
    #           include_code = se includere il codice sorgente reale di ogni passo/
    #           operazione (True solo per il seed di Detection).
    # Output:   stringa multilinea con un flow per riga (+ eventuale codice reale).
    # Come realizzato: formatta source->sink (file:line) col numero di passi e l'hint (dati
    #            strutturali di CodeQL, non testo del repo); il codice reale di ogni passo/
    #            operazione (letto deterministicamente dal disco) viene incluso solo se
    #            include_code=True.
    def detection_summary(self, limit: int = 60, ops_limit: int = 60, path_limit: int = 8,
                           include_code: bool = True) -> str:
        n = len(self.candidates)
        lines = [f"FLOW INVENTORY: {n} flow(s) (untrusted input -> a call argument)."]
        for i, c in enumerate(self.candidates[:limit], 1):
            s, k = c["source"], c["sink"]
            hint = f" | {c['sink_hint']}" if c.get("sink_hint") else ""
            lines.append(f"  [{i}] {s.get('file')}:{s.get('line')} -> "
                         f"{k.get('file')}:{k.get('line')} ({c.get('steps', 0)} steps){hint}")
            path = c.get("path") or []
            if include_code:
                for step in path[:path_limit]:
                    if step.get("code"):
                        lines.append(f"        {step.get('file')}:{step.get('line')}: {step['code']}")
                if len(path) > path_limit or c.get("path_truncated"):
                    lines.append(f"        ... more steps (full path in the tool's JSON).")
        if n > limit:
            lines.append(f"  ... and {n - limit} more (full inventory on disk).")

        m = len(self.operations)
        by_kind: dict[str, int] = {}
        for o in self.operations:
            by_kind[o.get("kind", "op")] = by_kind.get(o.get("kind", "op"), 0) + 1
        kinds = ", ".join(f"{k}:{v}" for k, v in sorted(by_kind.items())) or "none"
        lines.append("")
        lines.append(f"SENSITIVE OPERATIONS (no data-flow): {m} — by kind: {kinds}.")
        for i, o in enumerate(self.operations[:ops_limit], 1):
            code = f" | {o['code']}" if include_code and o.get("code") else ""
            lines.append(f"  [{i}] {o.get('kind')} @ {o.get('file')}:{o.get('line')}{code}")
        if m > ops_limit:
            lines.append(f"  ... and {m - ops_limit} more (full inventory on disk).")
        if not include_code:
            lines.append("")
            lines.append("(Source code text omitted here — it is untrusted repo content. "
                          "Use the exact sink/source/sanitizer names already extracted by "
                          "Detection below, not this summary, to build your queries.)")
        return "\n".join(lines)

    # --- persistence (used inside the checkpoint, for --resume) ---
    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "WorkList":
        return cls(
            repo_path=d.get("repo_path", ""),
            db_path=d.get("db_path"),
            candidates=d.get("candidates", []),
            operations=d.get("operations", []),
        )
