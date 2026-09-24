"""Tolerate the model's old habit of calling read_file_snippet with a single
joined `file_path` instead of the tool's real `repo_path` + `file` contract."""
from __future__ import annotations

from pathlib import Path


# Obiettivo: rendere read_file_snippet utilizzabile anche se il modello, per abitudine,
#            passa ancora un "file_path" unico invece di repo_path/file separati — senza
#            bisogno che il modello indovini bene lo schema del tool.
# Input:    args = argomenti gia' estratti dalla tool-call; repo_path = il path del
#           repository di QUESTA analisi (noto all'orchestratore, non al modello).
# Output:   args corretti (stesso dict, modificato sul posto).
# Come realizzato: se manca "file" ma c'e' "file_path", lo adotta come "file" dopo aver
#            tolto uno slash iniziale, un eventuale "./" e un prefisso duplicato col nome
#            della cartella del repo (es. "repo/app.py" quando repo_path e' gia' "repo").
#            repo_path stesso NON va corretto qui: l'orchestratore lo sovrascrive sempre
#            per ogni tool che lo dichiara nello schema (agent/orchestrator.py:
#            repo_path_tools), quindi qualunque valore il modello passi per repo_path
#            e' comunque ignorato — solo file/file_path e' un problema di QUESTO tool.
def fix_read_file_snippet_args(args: dict, repo_path: str) -> dict:
    if "file" not in args and "file_path" in args:
        f = str(args.pop("file_path"))
        f = f.lstrip("/\\")
        if f.startswith("./") or f.startswith(".\\"):
            f = f[2:]
        base = Path(repo_path).name
        if base and (f == base or f.startswith(base + "/") or f.startswith(base + "\\")):
            f = f[len(base):].lstrip("/\\")
        args["file"] = f
    return args
