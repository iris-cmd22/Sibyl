"""CWE knowledge base loaded from bundled JSON.

Two layers:
  - CWE_REFERENCE: curated detection wiki (CWEs the templates/checks verify),
    with canonical names, taint intuition, candidate source/sink/sanitizer
    names, and remediation. Single source of truth for report grounding.
  - CWE_CATALOG: full official catalog (~969 CWEs, lookup-only fallback built
    offline from the MITRE XML).
"""
from __future__ import annotations

import json
from pathlib import Path

from server import config


# Obiettivo: caricare un file JSON in memoria in modo robusto (senza far crashare il
#            server se il file manca o è corrotto).
# Input:    path = percorso del file JSON.
# Output:   il contenuto come dict; un dict vuoto {} in caso di qualsiasi problema.
# Come realizzato: prova a leggere e fare il parse; se qualcosa va storto restituisce {}.
def load_json(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


CWE_REFERENCE = load_json(config.CWE_WIKI_PATH)
CWE_CATALOG = load_json(config.CWE_CATALOG_PATH)


# --------------------------------------------------------------------------- #
# Knowledge access SEAM. Today the knowledge lives in the JSON "wiki"; tomorrow
# a knowledge graph can replace it. Everything that needs CWE knowledge at
# runtime (queries.py, knowledge.py) goes through THESE functions, so swapping
# the backend means re-implementing only them (same signatures).
# --------------------------------------------------------------------------- #

# Obiettivo: punto d'accesso UNICO alla conoscenza operativa di un CWE (la "wiki").
# Input:    cwe_id = id normalizzato (es. "CWE-89").
# Output:   il dict della voce wiki, oppure None se non presente.
# Come realizzato: oggi una semplice lookup sul dict CWE_REFERENCE; domani basta
#            sostituire il corpo con una query al knowledge graph.
def lookup_cwe(cwe_id: str | None) -> dict | None:
    if not cwe_id:
        return None
    return CWE_REFERENCE.get(cwe_id)


# Obiettivo: fallback al catalogo MITRE completo (solo livello "ufficiale") per i CWE
#            che non hanno una scheda operativa nella wiki.
# Input:    cwe_id = id normalizzato.
# Output:   il dict del catalogo, oppure None.
# Come realizzato: lookup sul dict CWE_CATALOG (anch'esso sostituibile in futuro).
def lookup_catalog(cwe_id: str | None) -> dict | None:
    if not cwe_id:
        return None
    return CWE_CATALOG.get(cwe_id)


# Obiettivo: elencare tutte le voci della wiki (per list_cwes), dietro la stessa cucitura.
# Input:    nessuno.
# Output:   dict {cwe_id: voce}.
# Come realizzato: ritorna CWE_REFERENCE; un backend a grafo ne fornirebbe l'equivalente.
def all_cwes() -> dict:
    return CWE_REFERENCE
