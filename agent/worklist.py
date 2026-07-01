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
    operations: list[dict] = field(default_factory=list)   # sensitive ops (find_sensitive_operations)

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
            })

    # Obiettivo: aggiungere le operazioni sensibili (non-flow) da find_sensitive_operations.
    # Input:    payload = il dict (gia' parsato) restituito da find_sensitive_operations.
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
            })

    # Obiettivo: riassunto testuale e compatto dei flow candidati, da iniettare nel prompt
    #            della fase di Validation (context reset: passa il manifest, non il SARIF).
    # Input:    limit = quanti flow elencare al massimo.
    # Output:   stringa multilinea con un flow per riga.
    # Come realizzato: formatta source->sink (file:line) con il numero di passi e l'hint.
    def detection_summary(self, limit: int = 60, ops_limit: int = 60) -> str:
        n = len(self.candidates)
        lines = [f"FLOW INVENTORY: {n} flow(s) (untrusted input -> a call argument)."]
        for i, c in enumerate(self.candidates[:limit], 1):
            s, k = c["source"], c["sink"]
            hint = f" | {c['sink_hint']}" if c.get("sink_hint") else ""
            lines.append(f"  [{i}] {s.get('file')}:{s.get('line')} -> "
                         f"{k.get('file')}:{k.get('line')} ({c.get('steps', 0)} steps){hint}")
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
            lines.append(f"  [{i}] {o.get('kind')} @ {o.get('file')}:{o.get('line')}")
        if m > ops_limit:
            lines.append(f"  ... and {m - ops_limit} more (full inventory on disk).")
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
