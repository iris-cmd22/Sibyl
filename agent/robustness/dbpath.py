"""Fix db_path placeholders. Models often pass a placeholder
(e.g. "<result of create_codeql_database>") instead of the real path."""
from __future__ import annotations

from pathlib import Path


# Obiettivo: ottenere un percorso di database CodeQL VALIDO quando il modello passa un
#            segnaposto (es. "<result of create_codeql_database>") invece del path vero.
# Input:    value = il db_path che il modello ha passato;
#           last_db_path = l'ultimo db_path REALE catturato da create_codeql_database.
# Output:   un percorso usabile; None se nessun database è stato ancora creato (così il
#           chiamante può dire al modello di crearne uno prima).
# Come realizzato: se value è già una cartella esistente lo usa; altrimenti ricade sul
#            db_path reale comunicato dal server (l'agente non può indovinarlo: il DB
#            sta sul filesystem del server, possibilmente su un altro host).
def resolve_db_path(value, last_db_path):
    if isinstance(value, str) and Path(value).is_dir():
        return value
    return last_db_path
