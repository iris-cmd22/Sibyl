"""Knowledge-base tools: list known CWEs and explore a single CWE page."""
from __future__ import annotations

import json

from server.core.template import normalize_cwe
from server.knowledge.store import CWE_CATALOG, all_cwes, lookup_catalog, lookup_cwe
from server.transport.mcp_instance import mcp


# Obiettivo: elencare le classi di vulnerabilità (CWE) che il server sa rilevare,
#            indicando per ciascuna quale tool usare.
# Input:    nessuno.
# Output:   stringa JSON con l'elenco dei CWE (id, nome, tipo di rilevamento, tool,
#           descrizione) e qualche conteggio.
# Come realizzato: scorre la wiki CWE_REFERENCE; una funzione interna _tool_for
#            decide il tool giusto in base al tipo di rilevamento (taint/api/config).
@mcp.tool()
def list_cwes() -> str:
    """List the vulnerability classes (CWEs) the agent knows about.

    Returns each CWE id with its name and one-line description. Call
    cwe_knowledge(cwe) to get the full page for one of them.
    """
    # Obiettivo: scegliere il nome del tool adatto a un CWE in base al suo tipo.
    # Input:    data = la voce della wiki per un CWE.
    # Output:   il nome del tool da usare (stringa).
    # Come realizzato: se la wiki indica un tool esplicito lo usa, altrimenti decide
    #            in base al campo "detection" (api_misuse / insecure_config_flag / taint).
    def _tool_for(data: dict) -> str:
        det = data.get("detection", "taint")
        # The wiki's actions.tool is authoritative when present (e.g. the
        # dedicated check_insecure_* tool for an insecure_config_flag CWE).
        if data.get("actions", {}).get("tool"):
            return data["actions"]["tool"]
        if det == "api_misuse":
            return "run_api_misuse_query"
        if det == "insecure_config_flag":
            return "run_insecure_config_flag_query"
        return "run_taint_query"

    out = [
        {
            "cwe": cid,
            "name": data.get("name", ""),
            "detection": data.get("detection", "taint"),
            "tool": _tool_for(data),
            "description": data.get("description", ""),
        }
        for cid, data in all_cwes().items()
    ]
    return json.dumps({
        "detectable_count": len(out),
        "cwes": out,
        "catalog_lookup_count": len(CWE_CATALOG),
        "note": "These are the CWEs with an automated template/check. For ANY other "
                "CWE (e.g. one reported by analyze_database), call cwe_knowledge(cwe) "
                "to get its official description from the full catalog.",
    }, indent=2)


# Obiettivo: fornire la "scheda" completa di un CWE: cos'è (livello ufficiale) e cosa
#            fare per rilevarlo (la nostra conoscenza operativa).
# Input:    cwe = id del CWE in qualsiasi forma ("CWE-89", "89", "cwe-89").
# Output:   stringa JSON con due livelli (ufficiale + nostro); se il CWE non è nella
#           wiki tenta il catalogo ufficiale; altrimenti JSON con "error".
# Come realizzato: normalizza l'id, cerca prima in CWE_REFERENCE (wiki curata), poi
#            come fallback in CWE_CATALOG (catalogo MITRE completo) e compone la scheda.
@mcp.tool()
def cwe_knowledge(cwe: str) -> str:
    """Explore the knowledge-base page for a vulnerability class (CWE).

    Use this BEFORE forming a taint hypothesis: it explains the vuln, the taint
    intuition (what source/sink/sanitizer mean for it), and gives candidate
    method/function NAMES to pass to run_taint_query (typical_sink_names,
    typical_source_names, typical_sanitizer_names).

    Args:
        cwe: CWE id, e.g. "CWE-89" (also accepts "89" or "cwe-89").
    """
    cwe_id, _, _ = normalize_cwe(cwe)
    data = lookup_cwe(cwe_id or cwe)
    if not data:
        # Fallback: any CWE from the full catalog (official layer only). These
        # have NO automated template — report them only if analyze_database flags
        # them; do not call run_taint_query/run_api_misuse_query for them.
        cat = lookup_catalog(cwe_id or cwe)
        if cat:
            return json.dumps({
                "cwe": cwe_id,
                "name": cat.get("name", ""),
                "detection": "none",
                "official": {
                    "description": cat.get("description", ""),
                    "extended_description": cat.get("extended_description"),
                    "mitigations": cat.get("mitigations", []),
                    "consequences": cat.get("consequences", []),
                    "references": [cat.get("reference", "")],
                },
                "note": "No automated detection template for this class. Use it only "
                        "to describe a finding already reported by analyze_database.",
            }, indent=2)
        return json.dumps({
            "error": f"No entry for {cwe!r}",
            "detectable": list(all_cwes().keys()),
        })
    # Two distinct layers: the official "what it is" and our "what to do".
    page = {
        "cwe": cwe_id,
        "name": data.get("name", ""),
        "detection": data.get("detection", "taint"),
        "official": {
            "description": data.get("mitre_description") or data.get("description", ""),
            "extended_description": data.get("mitre_extended_description"),
            "mitigations": data.get("mitre_mitigations", []),
            "consequences": data.get("mitre_consequences", []),
            "observed_examples": data.get("mitre_observed_examples", []),
            "references": data.get("references", []),
        },
        "our_knowledge": {
            "summary": data.get("description", ""),
            "intuition": data.get("taint_intuition") or data.get("detection_intuition", ""),
            "remediation": data.get("remediation", ""),
        },
        "actions": data.get("actions", {}),
    }
    return json.dumps(page, indent=2)
