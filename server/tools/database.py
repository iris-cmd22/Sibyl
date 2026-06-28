"""CodeQL database lifecycle tools: create a DB, run the standard security suite."""
from __future__ import annotations

import json
import subprocess
from pathlib import Path

from server import config
from server.core.executor import db_path_for
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
