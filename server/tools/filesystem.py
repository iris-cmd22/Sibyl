"""Filesystem inspection tools: enumerate sources and read snippets."""
from __future__ import annotations

import json
from pathlib import Path

from server.tools.meta import VALIDATION, get_current_phase
from server.transport.mcp_instance import mcp


# Obiettivo: elencare i file Python (.py) di un progetto, così l'AI sa cosa leggere.
# Input:    repo_path = cartella del progetto; max_files = tetto massimo di file.
# Output:   stringa JSON {"count": N, "files": [...]}; JSON con "error" se non è una cartella.
# Come realizzato: scorre ricorsivamente i .py saltando cartelle inutili
#            (.git, venv, __pycache__, ...) e si ferma al raggiungere max_files.
@mcp.tool()
def list_python_files(repo_path: str, max_files: int = 500) -> str:
    """List Python source files in a repository (skips venv/site-packages/.git).

    Args:
        repo_path: Absolute path to the repository root.
        max_files: Cap on number of files returned.
    """
    root = Path(repo_path)
    if not root.is_dir():
        return json.dumps({"error": f"Not a directory: {repo_path}"})
    skip = {".git", ".venv", "venv", "__pycache__", "site-packages", "node_modules"}
    files = []
    for p in root.rglob("*.py"):
        if any(part in skip for part in p.parts):
            continue
        files.append(str(p.relative_to(root)))
        if len(files) >= max_files:
            break
    return json.dumps({"count": len(files), "files": files}, indent=2)


# Obiettivo: leggere una porzione di un file sorgente per ispezionare il contesto
#            di un finding (senza caricare l'intero file) — SENZA che il modello debba
#            costruire da solo il path assoluto/relativo (fonte di allucinazioni: slash
#            iniziale, "./", maiuscole/minuscole, cartelle indovinate).
# Input:    repo_path = radice del repo (la stessa gia' data nel prompt); file = il
#           percorso ESATTO gia' presente nell'evidenza (es. il campo "file" di un flow/
#           operazione, o una voce di list_python_files) — mai ricostruito a mano;
#           start_line/end_line = intervallo di righe.
# Output:   stringa JSON con le righe numerate; JSON con "error" se il file non esiste.
# Come realizzato: unisce repo_path + file con Path (stesso join deterministico usato da
#            _read_line in server/tools/queries.py), poi legge/ritaglia/numera le righe.
#            Rifiuta la chiamata se la fase attiva e' Validation: questo tool e'
#            privilegio esclusivo di Detection (vedi server/tools/meta.py), cosi'
#            codice sorgente grezzo/non fidato non puo' piu' raggiungere Validation
#            nemmeno per un bug lato agente o un client MCP non ufficiale.
@mcp.tool()
def read_file_snippet(repo_path: str, file: str, start_line: int = 1, end_line: int = 40) -> str:
    """Read a slice of a source file so the model can inspect a finding's context.

    Detection-only: refuses to run once the Validation phase has started
    (see server/tools/meta.py:set_phase). Validation must never see raw source
    text — only the exact names Detection already extracted.

    Args:
        repo_path: Repository root (the same path given for this analysis).
        file: The EXACT file path already given in the evidence (e.g. a flow's
            source/sink `file`, an operation's `file`, or a list_python_files entry).
            Do not alter it, join it yourself, or guess a different one.
        start_line: First line (1-based).
        end_line: Last line (inclusive).
    """
    if get_current_phase() == VALIDATION:
        return json.dumps({"error": "read_file_snippet is Detection-only; "
                                     "not available once Validation has started"})
    repo_root = Path(repo_path).resolve()
    p = (repo_root / file.lstrip("/\\")).resolve()
    if not p.is_relative_to(repo_root):
        return json.dumps({"error": f"Path escapes repo_path: {file}"})
    if not p.is_file():
        return json.dumps({"error": f"File not found: {file} under repo_path {repo_path}"})
    lines = p.read_text(encoding="utf-8", errors="replace").splitlines()
    lo, hi = max(1, start_line), min(len(lines), end_line)
    numbered = [f"{i}: {lines[i - 1]}" for i in range(lo, hi + 1)]
    return json.dumps({"file": str(p), "lines": "\n".join(numbered)})
