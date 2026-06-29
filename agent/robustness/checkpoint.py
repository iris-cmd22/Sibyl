"""Per-repo checkpointing so an interrupted run can resume (--resume)."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from agent import config


# Obiettivo: calcolare un percorso di checkpoint UNIVOCO e RIPETIBILE per un repo, così
#            ogni progetto ha il suo file di ripristino sotto WORK_DIR.
# Input:    repo_path = percorso del progetto analizzato.
# Output:   un oggetto Path al file di checkpoint (.json) dentro WORK_DIR.
# Come realizzato: combina il nome della cartella con un hash breve (SHA-1) del percorso
#            assoluto, garantendo unicità senza nomi troppo lunghi.
def checkpoint_path(repo_path: str) -> Path:
    resolved = Path(repo_path).resolve()
    h = hashlib.sha1(str(resolved).encode()).hexdigest()[:10]
    return config.WORK_DIR / f"checkpoint_{resolved.name}_{h}.json"


# Obiettivo: salvare su disco lo stato del run in modo che un crash a metà scrittura
#            non possa corrompere il file di checkpoint.
# Input:    path = file di destinazione; state = dict con lo stato (messaggi, cache, step).
# Output:   nessuno (scrive il file su disco).
# Come realizzato: scrive prima su un file temporaneo .tmp, poi lo rinomina sul nome
#            finale (la rinomina è atomica sul filesystem).
def save_checkpoint(path: Path, state: dict) -> None:
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(state), encoding="utf-8")
    tmp.replace(path)


# Obiettivo: rileggere dal disco uno stato di checkpoint salvato in precedenza.
# Input:    path = file di checkpoint da leggere.
# Output:   il dict con lo stato del run (messaggi, cache, prossimo step).
# Come realizzato: legge il file di testo e lo interpreta da JSON.
def load_checkpoint(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))
