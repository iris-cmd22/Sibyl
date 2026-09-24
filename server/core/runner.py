from __future__ import annotations

import subprocess
import time

from server import config
from server.log import get_logger

_logger = get_logger()


# Obiettivo: eseguire un comando CodeQL nel sistema operativo e raccoglierne l'esito.
#            È l'UNICO punto del server che lancia davvero CodeQL.
# Input:    cmd = lista di stringhe (programma + argomenti, es. ["codeql","database",...]);
#           timeout = secondi massimi prima di interrompere (default da config).
# Output:   tupla (codice_di_uscita, output_standard, output_di_errore).
# Come realizzato: usa subprocess.run catturando stdout/stderr come testo UTF-8;
#            logga il comando e la durata a livello DEBUG.
def run(cmd: list[str], timeout: int = config.CODEQL_TIMEOUT) -> tuple[int, str, str]:
    _logger.debug("running: %s", " ".join(cmd))
    start = time.perf_counter()
    proc = subprocess.run(
        cmd, capture_output=True, text=True, timeout=timeout, encoding="utf-8", errors="replace"
    )
    _logger.debug("exit %s in %.2fs", proc.returncode, time.perf_counter() - start)
    return proc.returncode, proc.stdout, proc.stderr
