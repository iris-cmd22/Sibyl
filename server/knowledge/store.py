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
