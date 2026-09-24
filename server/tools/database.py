"""CodeQL database lifecycle tools: create a DB, run the standard security suite."""
from __future__ import annotations

import json
import subprocess
from pathlib import Path

from server import config
from server.core.executor import db_path_for, is_contained_db_path
from server.core.runner import run
from server.core.sarif import parse_sarif
from server.transport.mcp_instance import mcp


# Obiettivo: costruire il database CodeQL di un progetto (passo obbligato prima di
#            qualsiasi analisi).
# Input:    repo_path = cartella del progetto; language = linguaggio (default "python").
# Output:   stringa JSON con {db_path, language, status}; JSON con "error" se fallisce
#           o va in timeout.
# Come realizzato: calcola il path del DB (db_path_for), compone ed esegue
#            "codeql database create ..." via runner.run, e gestisce errori/timeout.
@mcp.tool()
def create_codeql_database(repo_path: str, language: str = "python") -> str:
    """Create a CodeQL database from a repository. Returns the database path.

    For interpreted languages (python, javascript) no build command is needed.

    Args:
        repo_path: Absolute path to the repository root.
        language: CodeQL language identifier (default: python).
    """
    repo = Path(repo_path)
    if not repo.is_dir():
        return json.dumps({"error": f"Not a directory: {repo_path}"})
    db = db_path_for(repo_path)
    cmd = [
        config.CODEQL_BIN, "database", "create", str(db),
        f"--language={language}", f"--source-root={repo}", "--overwrite",
    ]
    try:
        rc, out, err = run(cmd)
    except subprocess.TimeoutExpired:
        return json.dumps({"error": "database create timed out", "db_path": str(db)})
    if rc != 0:
        return json.dumps({"error": "database create failed", "stderr": err[-2000:]})
    return json.dumps({"db_path": str(db), "language": language, "status": "created"})


# Obiettivo: eseguire l'intera suite di sicurezza standard sul database e restituire
#            tutti i finding (analisi "ad ampio raggio").
# Input:    db_path = database creato prima; suite = file .qls (default da config).
# Output:   stringa JSON con {sarif_path, finding_count, findings}; JSON "error" se fallisce.
# Come realizzato: lancia "codeql database analyze <db> <suite>" via runner.run e
#            converte il SARIF risultante con parse_sarif.
@mcp.tool()
def analyze_database(db_path: str, suite: str = "") -> str:
    """Run a CodeQL security suite against a database and return parsed findings.

    Args:
        db_path: Path returned by create_codeql_database.
        suite: Query suite (default: the configured python-security-extended.qls).
    """
    if not is_contained_db_path(db_path):
        return json.dumps({"error": f"db_path must be inside WORK_DIR: {db_path}"})
    db = Path(db_path)
    if not db.is_dir():
        return json.dumps({"error": f"DB not found: {db_path}"})
    suite = suite or config.DEFAULT_SUITE
    sarif = Path(db_path).parent / f"{Path(db_path).name}.sarif"
    cmd = [
        config.CODEQL_BIN, "database", "analyze", str(db), suite,
        f"--search-path={config.CODEQL_SEARCH_PATH}",
        "--format=sarifv2.1.0", f"--output={sarif}", "--rerun",
    ]
    try:
        rc, out, err = run(cmd)
    except subprocess.TimeoutExpired:
        return json.dumps({"error": "analyze timed out"})
    if rc != 0:
        return json.dumps({"error": "analyze failed", "stderr": err[-2000:]})
    findings = parse_sarif(sarif)
    return json.dumps(
        {"sarif_path": str(sarif), "finding_count": len(findings), "findings": findings},
        indent=2,
    )


# Obiettivo: dare alla DETECTION un inventario COMPATTO e già CWE-taggato, prodotto dalla
#            suite ufficiale CodeQL (python-security-extended, ~43 CWE coperti), così il
#            modello ha da subito evidenza deterministica senza dover indovinare nomi.
# Input:    db_path = database; max_findings = quanti finding (deduplicati) restituire.
# Output:   stringa JSON compatta {finding_count, returned, truncated, by_cwe, findings}.
# Come realizzato: richiama analyze_database (suite intera, invariata), poi deduplica per
#            (rule_id, file, line), raggruppa per CWE e tronca — stesso pattern di
#            find_all_flows/find_sensitive_operations (server/tools/queries.py). Il SARIF
#            completo resta su disco (Claim Check); qui passa solo il riassunto.
@mcp.tool()
def find_confirmed_vulnerabilities(db_path: str, max_findings: int = 200) -> str:
    """List findings from the OFFICIAL CodeQL security suite (deterministic, CWE-tagged).

    This is a Detection-phase tool: it runs the full standard python-security-extended
    suite (~43 CWE covered by GitHub-maintained, parameter-free queries) and returns a
    compact, deduplicated summary. Unlike find_all_flows/find_sensitive_operations, these
    findings ALREADY carry a real CWE from the query metadata — no verification needed in
    Validation, just cite them as-is with the exact CWE given.

    Args:
        db_path: Path returned by create_codeql_database.
        max_findings: Max number of (deduplicated) findings to return (default 200).
    """
    raw = analyze_database(db_path)
    try:
        payload = json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        return raw
    if "error" in payload:
        return raw

    seen: set = set()
    items: list[dict] = []
    by_cwe: dict[str, int] = {}
    for f in payload.get("findings", []) or []:
        key = (f.get("rule_id"), f.get("file"), f.get("line"))
        if key in seen:
            continue
        seen.add(key)
        cwe = f.get("cwe") or "unclassified"
        by_cwe[cwe] = by_cwe.get(cwe, 0) + 1
        item = {
            "cwe": f.get("cwe"),
            "rule_id": f.get("rule_id"),
            "rule_name": f.get("rule_name"),
            "message": (f.get("message") or "")[:200],
        }
        if f.get("flow_steps"):
            item["source"] = f.get("source")
            item["sink"] = f.get("sink")
            item["steps"] = f.get("flow_steps")
        else:
            item["file"] = f.get("file")
            item["line"] = f.get("line")
        items.append(item)

    total = len(items)
    return json.dumps({
        "finding_count": total,
        "returned": min(total, max_findings),
        "truncated": total > max_findings,
        "by_cwe": by_cwe,
        "findings": items[:max_findings],
        "note": "Confirmed by the official CodeQL security suite: each finding's `cwe` is "
                "real (from query metadata), not a guess. Cite it exactly; no re-verification "
                "needed in Validation, just add context (read_file_snippet) and remediation.",
    }, indent=2)
