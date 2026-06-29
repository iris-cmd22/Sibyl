"""Resolve the analysis input: a directory or a .zip archive."""
from __future__ import annotations

import shutil
import sys
import zipfile
from pathlib import Path

from agent import config


# Obiettivo: trasformare ciò che l'utente passa da riga di comando (una cartella
#            OPPURE un file .zip) nel percorso della cartella del progetto da analizzare.
# Input:    path_str = stringa col percorso indicato dall'utente.
# Output:   stringa col percorso di una CARTELLA pronta per l'analisi; se l'input non
#           è valido il programma esce con un messaggio d'errore.
# Come realizzato: se è già una cartella la restituisce; se è uno .zip lo estrae sotto
#            WORK_DIR e, se contiene un'unica cartella radice, usa quella come root.
def resolve_source(path_str: str) -> str:
    p = Path(path_str)
    if p.is_dir():
        return str(p)
    if p.is_file() and p.suffix.lower() == ".zip":
        dest = config.WORK_DIR / f"src_{p.stem}"
        if dest.exists():
            shutil.rmtree(dest)
        with zipfile.ZipFile(p) as z:
            z.extractall(dest)
        # If the zip contains a single top-level folder, use that as the root.
        entries = [e for e in dest.iterdir() if e.name != "__MACOSX"]
        root = entries[0] if len(entries) == 1 and entries[0].is_dir() else dest
        print(f"Extracted {p.name} -> {root}", file=sys.stderr)
        return str(root)
    sys.exit(f"Not a directory or .zip file: {path_str}")
