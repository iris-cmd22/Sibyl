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


_HTML_TAG_RE = re.compile(r"<[^>]+>")


# Obiettivo: impedire che il commento libero del modello (che ha letto codice del repo
#            analizzato, potenzialmente ostile/manipolato via prompt injection) inietti
#            markup pericoloso nel report finale — un link Markdown verso un URL
#            controllato dall'attaccante, o tag HTML grezzi che il renderer a valle
#            (es. l'estensione VSCode) potrebbe interpretare.
# Input:    text = il commento libero del modello.
# Output:   lo stesso testo coi link Markdown "spezzati" (mai piu' cliccabili) e i
#           tag HTML tolti.
# Come realizzato: sostituisce "](" con "] (" (rompe la sintassi `[testo](url)` senza
#            alterare la leggibilita' del testo) e rimuove ogni tag <...>.
def _sanitize_commentary(text: str) -> str:
    text = text.replace("](", "] (")
    return _HTML_TAG_RE.sub("", text)


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


# Obiettivo: dire se una stringa e' convertibile a float (per leggere "security_severity",
#            che arriva sempre come stringa, in modo sicuro).
# Input:    v = valore qualsiasi. Output: True se float(v) non solleva eccezione.
def _is_float(v) -> bool:
    try:
        float(v)
        return True
    except (TypeError, ValueError):
        return False


# Soglie CVSS-like per raggruppare un "security_severity" numerico (fisso per
# query-template, non calcolato per singolo finding) in un'etichetta leggibile.
_SEVERITY_BUCKETS = ((9.0, "Critical"), (7.0, "High"), (4.0, "Medium"), (0.1, "Low"))


# Obiettivo: tradurre un "security_severity" (stringa CVSS-like, es. "8.0") in
#            un'etichetta leggibile, per la tabella dei finding costruita in automatico.
# Input:    security_severity = valore letto dal JSON del tool (stringa, puo' essere vuota
#           o non numerica). Output: "Critical"/"High"/"Medium"/"Low"/"Unknown".
def _severity_bucket(security_severity) -> str:
    if not _is_float(security_severity):
        return "Unknown"
    score = float(security_severity)
    for threshold, label in _SEVERITY_BUCKETS:
        if score >= threshold:
            return label
    return "Unknown"


# Obiettivo: la posizione testuale di un finding per la tabella — un vero flusso
#            (source->sink, solo run_taint_query/gathering) va mostrato come tale;
#            tutti gli altri (point detection: crypto, config-flag, ecc.) sono un
#            singolo file:riga.
# Input:    f = un finding gia' normalizzato (vedi RunStats.findings). Output: stringa.
def _location_str(f: dict) -> str:
    src, sink = f.get("source"), f.get("sink")
    if f.get("flow_steps") and src and sink:
        return f"{src.get('file')}:{src.get('line')} -> {sink.get('file')}:{sink.get('line')}"
    return f"{f.get('file')}:{f.get('line')}"


# Obiettivo: ordinare i CWE in modo naturale (per numero, non alfabeticamente: "CWE-9"
#            prima di "CWE-89"), coi non classificati in fondo.
# Input:    cwe = stringa "CWE-<n>" o None/"UNCLASSIFIED". Output: chiave di ordinamento.
def _cwe_sort_key(cwe):
    m = re.search(r"\d+", cwe or "")
    return (0, int(m.group())) if m else (1, cwe or "")


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
    findings: list[dict] = field(default_factory=list)

    # Obiettivo: aggiornare le statistiche leggendo il risultato di un tool appena eseguito.
    # Input:    name = nome del tool; content = la sua risposta (testo JSON).
    # Output:   la lista dei finding appena aggiunti a self.findings in QUESTA chiamata
    #           (puo' essere vuota) — usata dal chiamante per emettere eventi live (es. la
    #           visualizzazione del path in agent/progress.py) senza dover ri-parsare il JSON.
    # Come realizzato: incrementa il conteggio del tool; se il risultato è JSON, cattura il
    #            db_path (da create_codeql_database), somma i finding e raccoglie i CWE.
    def record_tool_result(self, name: str, content: str) -> list[dict]:
        self.tool_counts[name] = self.tool_counts.get(name, 0) + 1
        try:
            obj = json.loads(content)
        except (json.JSONDecodeError, ValueError):
            return []
        if not isinstance(obj, dict):
            return []
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
        added: list[dict] = []
        for f in obj.get("findings", []) or []:
            if not isinstance(f, dict):
                continue
            entry = {
                # Fallback: ogni run_*/check_* stampa gia' il "cwe" anche a livello
                # top-level del payload (server/tools/queries.py), usato quando il
                # singolo finding non lo porta nei suoi tag SARIF (es. run_custom_query).
                "cwe": f.get("cwe") or obj.get("cwe"),
                "file": f.get("file"), "line": f.get("line"),
                "rule_id": f.get("rule_id"), "message": f.get("message"),
                "security_severity": f.get("security_severity") or "",
                "source": f.get("source"), "sink": f.get("sink"),
                "flow_steps": f.get("flow_steps", 0),
                # Catena hop-by-hop (file/line/note) gia' calcolata da CodeQL per le query
                # path-problem (server/core/sarif.py:extract_flow) — solo per la
                # visualizzazione, non usata da findings_table()/verdict().
                "flow_path": f.get("flow_path") or [],
            }
            self.findings.append(entry)
            added.append(entry)
        return added

    # Obiettivo: eliminare i finding duplicati (stessa vulnerabilita' FISICA ritrovata da
    #            chiamate diverse) prima di costruire la tabella — nessun tool/livello a
    #            monte lo fa gia' per contenuto (solo per firma-chiamata, lato orchestrator).
    #            Caso reale osservato: il modello richiama la STESSA query prima senza `cwe`
    #            (finding "UNCLASSIFIED") poi di nuovo con `cwe="CWE-89"` per "timbrarla" —
    #            stessa posizione fisica, quindi va tenuta UNA sola riga (quella classificata).
    # Input:    nessuno (usa self.findings). Output: lista deduplicata, ordine di prima vista.
    def _dedup_findings(self) -> list[dict]:
        def loc_key(f: dict) -> tuple:
            src, sink = f.get("source"), f.get("sink")
            if f.get("flow_steps") and src and sink:
                return (src.get("file"), src.get("line"), sink.get("file"), sink.get("line"))
            return (f.get("file"), f.get("line"))

        by_loc: dict[tuple, list[dict]] = {}
        for f in self.findings:
            by_loc.setdefault(loc_key(f), []).append(f)

        seen: set[tuple] = set()
        out: list[dict] = []
        for items in by_loc.values():
            # Same physical location: a later re-run that attaches a real CWE supersedes
            # an earlier unclassified hit at that same spot — keep only the classified
            # version(s) when both exist, so the same vulnerability isn't double-listed.
            classified = [f for f in items if f.get("cwe")]
            for f in classified or items:
                key = (f.get("cwe") or "UNCLASSIFIED", loc_key(f), f.get("rule_id"))
                if key in seen:
                    continue
                seen.add(key)
                out.append(f)
        return out

    # Obiettivo: costruire MECCANICAMENTE la tabella dei finding confermati (mai scritta
    #            dal modello): una riga per classe CWE (conteggio + severita' peggiore),
    #            poi una riga per finding deduplicato — cosi' nessun finding puo' piu'
    #            "sparire" per una dimenticanza di trascrizione.
    # Input:    nessuno. Output: stringa markdown (mai vuota: dice esplicitamente "nessun
    #           finding confermato" se self.findings e' vuoto dopo la dedup).
    def findings_table(self) -> str:
        deduped = self._dedup_findings()
        if not deduped:
            return "_No confirmed findings._\n"

        by_cwe: dict[str, list[dict]] = {}
        for f in deduped:
            by_cwe.setdefault(f.get("cwe") or "UNCLASSIFIED", []).append(f)

        lines = ["| CWE | Count | Severity |", "|---|---|---|"]
        for cwe in sorted(by_cwe, key=_cwe_sort_key):
            items = by_cwe[cwe]
            worst = max((float(i["security_severity"]) for i in items
                         if _is_float(i["security_severity"])), default=0.0)
            lines.append(f"| {cwe} | {len(items)} | {_severity_bucket(worst)} |")

        lines.append("")
        ordered = sorted(deduped, key=lambda f: (
            _cwe_sort_key(f.get("cwe") or "UNCLASSIFIED"), f.get("file") or "", f.get("line") or 0,
        ))
        for f in ordered:
            lines.append(f"- `{f.get('cwe') or 'UNCLASSIFIED'}` — `{_location_str(f)}` — "
                         f"`{f.get('rule_id') or 'unknown-rule'}`")
        return "\n".join(lines) + "\n"

    # Obiettivo: la riga di verdetto complessivo, calcolata (non scritta dal modello) dalla
    #            severita' peggiore tra i finding confermati.
    # Input:    nessuno. Output: stringa "Overall: <bucket> risk — N confirmed finding(s)
    #           across M file(s)." (o "NO confirmed findings" se non ce n'e' nessuno).
    def verdict(self) -> str:
        deduped = self._dedup_findings()
        if not deduped:
            return "Overall: NO confirmed findings."
        files = {f.get("file") for f in deduped if f.get("file")}
        worst = max((float(f["security_severity"]) for f in deduped
                     if _is_float(f["security_severity"])), default=0.0)
        return (f"Overall: {_severity_bucket(worst).upper()} risk — {len(deduped)} confirmed "
                f"finding(s) across {len(files)} file(s).")

    # Obiettivo: comporre il corpo del report finale — la tabella e il verdetto sono SEMPRE
    #            quelli costruiti in automatico; il testo del modello (se non banale) entra
    #            solo come commento libero, mai come sostituto dei dati autoritativi.
    # Input:    model_commentary = l'eventuale testo libero scritto dal modello nella sua
    #           risposta a zero tool-call ("" o "DONE" se non ha nulla da aggiungere).
    # Output:   stringa markdown, corpo completo del report (senza l'header YAML).
    def report_body(self, model_commentary: str = "") -> str:
        parts = ["## Findings", "", self.findings_table(), self.verdict()]
        commentary = (model_commentary or "").strip()
        if commentary and commentary.upper() != "DONE":
            parts += ["", "## Notes", "", _sanitize_commentary(commentary)]
        return "\n".join(parts) + "\n"

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
