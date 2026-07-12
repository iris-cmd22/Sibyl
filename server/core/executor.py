from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path

from server import config
from server.core.runner import run
from server.core.sarif import parse_sarif
from server.core.template import normalize_cwe


# Obiettivo: calcolare un percorso UNIVOCO e RIPETIBILE per il database CodeQL di
#            un progetto, così rianalisi successive riusano lo stesso database.
# Input:    repo_path = percorso del progetto da analizzare.
# Output:   un oggetto Path (cartella del database dentro WORK_DIR).
# Come realizzato: combina il nome della cartella con un "hash" breve del percorso
#            assoluto (SHA-1), garantendo unicità senza nomi troppo lunghi.
def db_path_for(repo_path: str) -> Path:
    digest = hashlib.sha1(str(Path(repo_path).resolve()).encode()).hexdigest()[:10]
    name = Path(repo_path).resolve().name
    return config.WORK_DIR / f"db_{name}_{digest}"


# Obiettivo: impedire che un db_path fornito dal modello punti a una directory
#            qualsiasi del filesystem — deve essere una cartella dentro WORK_DIR,
#            cioe' un database creato (o creabile) da questo stesso server.
# Input:    db_path = il percorso da verificare.
# Output:   True se db_path e' contenuto in WORK_DIR, False altrimenti.
# Come realizzato: risolve entrambi i percorsi e verifica il contenimento (stesso
#            pattern anti-traversal usato per repo_path in read_file_snippet).
def is_contained_db_path(db_path: str) -> bool:
    try:
        return Path(db_path).resolve().is_relative_to(config.WORK_DIR.resolve())
    except (OSError, ValueError):
        return False


# Obiettivo: eseguire UNA query .ql su un database CodeQL e restituire i finding
#            già puliti. È la routine condivisa da quasi tutti i tool di query.
# Input:    db_path = percorso del database; query_file = il file .ql da eseguire;
#           extra = dict opzionale di campi aggiuntivi da allegare alla risposta.
# Output:   stringa JSON con {query, finding_count, findings, + eventuali extra};
#           oppure un JSON con "error" se qualcosa va storto.
# Come realizzato: valida i percorsi, lancia "codeql database analyze" via runner.run,
#            converte il SARIF con parse_sarif, e impacchetta tutto in JSON.
def analyze_with_query(db_path: str, query_file: Path, extra: dict | None = None) -> str:
    if not is_contained_db_path(db_path):
        return json.dumps({"error": f"db_path must be inside WORK_DIR: {db_path}"})
    db = Path(db_path)
    if not db.is_dir():
        return json.dumps({"error": f"DB not found: {db_path}"})
    if not query_file.is_file():
        return json.dumps({"error": f"Query not found: {query_file}"})
    sarif = db.parent / f"{db.name}_{query_file.stem}.sarif"
    cmd = [
        config.CODEQL_BIN, "database", "analyze", str(db), str(query_file),
        f"--search-path={config.CODEQL_SEARCH_PATH}",
        "--format=sarifv2.1.0", f"--output={sarif}", "--rerun",
    ]
    try:
        rc, out, err = run(cmd)
    except subprocess.TimeoutExpired:
        return json.dumps({"error": "query timed out", "query": query_file.name})
    if rc != 0:
        return json.dumps({"error": "query failed", "query": query_file.name, "stderr": err[-2000:]})
    findings = parse_sarif(sarif)
    payload = {"query": query_file.name, "finding_count": len(findings), "findings": findings}
    if extra:
        payload.update(extra)
    return json.dumps(payload, indent=2)


# Obiettivo: eliminare la duplicazione del blocco "leggi template -> riempi i buchi
#            -> scrivi il .ql -> esegui" che prima era copiato in ogni tool di query.
# Input:    db_path = database; template_name = file .ql.tmpl in TEMPLATE_DIR;
#           replacements = dict {segnaposto: valore} specifici del template;
#           out_prefix = prefisso del file generato; cwe = classe (per timbrare i
#           metadati); extra = campi aggiuntivi da allegare alla risposta.
# Output:   stringa JSON con i finding (come analyze_with_query) o JSON "error" se il
#           template non esiste.
# Come realizzato: aggiunge automaticamente i segnaposto del CWE ({{CWE_ID_SUFFIX}} e
#           {{CWE_TAG_LINE}}) a quelli forniti, applica tutte le sostituzioni, salva la
#           query (nome univoco via hash) ed esegue analyze_with_query.
def render_and_analyze(
    db_path: str,
    template_name: str,
    replacements: dict,
    out_prefix: str,
    cwe: str = "",
    extra: dict | None = None,
) -> str:
    tmpl_path = config.TEMPLATE_DIR / template_name
    if not tmpl_path.is_file():
        return json.dumps({"error": f"template not found: {tmpl_path}"})

    _, cwe_tag, cwe_suffix = normalize_cwe(cwe)
    all_replacements = {
        "{{CWE_ID_SUFFIX}}": cwe_suffix,
        "{{CWE_TAG_LINE}}": f"\n *       {cwe_tag}" if cwe_tag else "",
        **replacements,
    }

    text = tmpl_path.read_text(encoding="utf-8")
    for placeholder, value in all_replacements.items():
        text = text.replace(placeholder, value)

    config.GENERATED_DIR.mkdir(exist_ok=True)
    tag = hashlib.sha1(text.encode()).hexdigest()[:10]
    out_ql = config.GENERATED_DIR / f"{out_prefix}_{tag}.ql"
    out_ql.write_text(text, encoding="utf-8")

    return analyze_with_query(db_path, out_ql, extra=extra)
