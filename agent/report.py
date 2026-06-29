"""Report output: file naming, YAML metadata header, and the RunStats accumulator
that tracks tools/CWEs/findings during a run and finalizes the report."""
from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from agent import config


# Obiettivo: ripulire una stringa qualsiasi rendendola sicura come nome di file/cartella.
# Input:    s = la stringa da trasformare (es. nome repo o modello).
# Output:   una versione "slug" con soli caratteri sicuri (lettere, cifre, . - _).
# Come realizzato: sostituisce ogni sequenza di caratteri non ammessi con "_" e taglia
#            gli "_" iniziali/finali.
def slug(s: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", s).strip("_")


# Obiettivo: calcolare il percorso di default dove salvare il report, una cartella per repo.
# Input:    repo_arg = percorso/nome del repo indicato dall'utente; model = nome del modello.
# Output:   stringa col percorso reports/<repo>/<modello>__<data-ora>.md.
# Come realizzato: crea slug di repo e modello (togliendo eventuali prefissi hf.co/...),
#            aggiunge un timestamp e crea la cartella del repo se manca.
def default_report_path(repo_arg: str, model: str) -> str:
    repo_slug = slug(Path(repo_arg).stem)
    model_slug = slug(model.split("/")[-1])   # drop hf.co/owner/ prefix
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    repo_dir = config.REPORTS_DIR / repo_slug
    repo_dir.mkdir(parents=True, exist_ok=True)
    return str(repo_dir / f"{model_slug}__{ts}.md")


# Obiettivo: raccogliere in un solo posto le statistiche di un run e saper produrre
#            l'intestazione del report e scriverlo su disco.
@dataclass
class RunStats:
    model: str
    repo_path: str
    max_steps: int
    started: float = field(default_factory=time.time)
    steps_done: int = 0
    tool_counts: dict[str, int] = field(default_factory=dict)
    cwes: set[str] = field(default_factory=set)
    total_findings: int = 0
    last_db_path: str | None = None

    # Obiettivo: aggiornare le statistiche leggendo il risultato di un tool appena eseguito.
    # Input:    name = nome del tool; content = la sua risposta (testo JSON).
    # Output:   nessuno (aggiorna i contatori interni dell'oggetto).
    # Come realizzato: incrementa il conteggio del tool; se il risultato è JSON, cattura il
    #            db_path (da create_codeql_database), somma i finding e raccoglie i CWE.
    def record_tool_result(self, name: str, content: str) -> None:
        self.tool_counts[name] = self.tool_counts.get(name, 0) + 1
        try:
            obj = json.loads(content)
        except (json.JSONDecodeError, ValueError):
            return
        if not isinstance(obj, dict):
            return
        if name == "create_codeql_database" and obj.get("db_path"):
            self.last_db_path = obj["db_path"]
        fc = obj.get("finding_count")
        if isinstance(fc, int):
            self.total_findings += fc
        for f in obj.get("findings", []) or []:
            if isinstance(f, dict) and f.get("cwe"):
                self.cwes.add(f["cwe"])
        if obj.get("cwe") and fc:
            self.cwes.add(obj["cwe"])

    # Obiettivo: produrre il front-matter YAML che rende ogni report auto-descrivente.
    # Input:    nessuno (usa i campi dell'oggetto).
    # Output:   stringa col blocco YAML (modello, repo, tempi, tool usati, CWE, finding).
    # Come realizzato: formatta i contatori raccolti e calcola la durata dal tempo d'avvio.
    def header(self) -> str:
        finished = time.time()
        tools = ", ".join(f"{k}:{v}" for k, v in sorted(self.tool_counts.items())) or "none"
        cwe_list = ", ".join(
            sorted(self.cwes, key=lambda c: int(re.search(r"\d+", c).group()))
        ) or "none"
        iso = lambda t: datetime.fromtimestamp(t).isoformat(timespec="seconds")
        return (
            "---\n"
            f"model: {self.model}\n"
            f"repository: {self.repo_path}\n"
            f"started: {iso(self.started)}\n"
            f"finished: {iso(finished)}\n"
            f"duration_seconds: {round(finished - self.started, 1)}\n"
            f"steps_used: {self.steps_done}\n"
            f"max_steps: {self.max_steps}\n"
            f"tools_used: {tools}\n"
            f"cwes_found: {cwe_list}\n"
            f"total_findings: {self.total_findings}\n"
            "generated_by: codeql-security-agent\n"
            "---\n\n"
        )

    # Obiettivo: scrivere il report finale (intestazione + corpo) su disco e ripulire.
    # Input:    report_text = il corpo scritto dal modello; report_path = file di output;
    #           checkpoint = file di checkpoint da rimuovere a fine analisi (opzionale).
    # Output:   il testo completo del report (intestazione + corpo) come stringa.
    # Come realizzato: antepone header() al corpo, crea le cartelle necessarie, scrive il
    #            file e cancella il checkpoint (analisi completata).
    def finalize(self, report_text: str, report_path: str, checkpoint: Path | None = None) -> str:
        full = self.header() + (report_text or "(no report produced)")
        out = Path(report_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(full, encoding="utf-8")
        if checkpoint is not None:
            checkpoint.unlink(missing_ok=True)   # analysis complete
        return full
