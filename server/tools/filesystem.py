"""Filesystem inspection tools: enumerate sources and read snippets."""
from __future__ import annotations

import json
from pathlib import Path

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
#            di un finding (senza caricare l'intero file).
# Input:    file_path = percorso del file; start_line/end_line = intervallo di righe.
# Output:   stringa JSON con le righe numerate; JSON con "error" se il file non esiste.
# Come realizzato: legge tutte le righe, ritaglia l'intervallo richiesto (limitandolo
#            ai bordi reali del file) e le numera.
@mcp.tool()
def read_file_snippet(file_path: str, start_line: int = 1, end_line: int = 40) -> str:
    """Read a slice of a source file so the model can inspect a finding's context.

    Args:
        file_path: Absolute path to the source file.
        start_line: First line (1-based).
        end_line: Last line (inclusive).
    """
    p = Path(file_path)
    if not p.is_file():
        return json.dumps({"error": f"File not found: {file_path}"})
    lines = p.read_text(encoding="utf-8", errors="replace").splitlines()
    lo, hi = max(1, start_line), min(len(lines), end_line)
    numbered = [f"{i}: {lines[i - 1]}" for i in range(lo, hi + 1)]
    return json.dumps({"file": file_path, "lines": "\n".join(numbered)})
