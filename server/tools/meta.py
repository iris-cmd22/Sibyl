"""Meta-tool: the SERVER declares which tools belong to which pipeline phase.

The agent must NOT hardcode tool names. It asks the server (via list_phase_tools)
which tools to expose in Detection vs Validation, and filters accordingly. The
server is the single source of truth for tool → phase membership, because it is the
server that defines the tools.
"""
from __future__ import annotations

import json

from server.transport.mcp_instance import mcp

DETECTION = "detection"
VALIDATION = "validation"

# Named tools per phase (the dynamic check_* verification tools are added to
# 'validation' automatically at call time, see below).
_DETECTION_TOOLS = [
    "list_python_files",
    "read_file_snippet",
    "create_codeql_database",
    "find_all_flows",
    "find_sensitive_operations",
]
_VALIDATION_TOOLS = [
    "read_file_snippet",
    "run_taint_query",
    "run_api_misuse_query",
    "run_insecure_config_flag_query",
    "run_custom_query",
    "cwe_knowledge",
    "list_cwes",
]


# Obiettivo: dire all'agente QUALI tool esporre in ciascuna fase (Detection/Validation),
#            così l'agente non deve hardcodare i nomi: la verità sta sul server.
# Input:    nessuno.
# Output:   stringa JSON {"detection": [...], "validation": [...]} coi soli tool
#           effettivamente registrati.
# Come realizzato: filtra le liste per-fase sui tool realmente presenti e aggiunge in
#            automatico alla Validation tutti i check_* (scorciatoie di verifica).
@mcp.tool()
def list_phase_tools() -> str:
    """List which registered tools belong to each pipeline phase.

    Returns a JSON object {"detection": [...], "validation": [...]}. The agent uses
    it to expose a different tool subset per phase WITHOUT hardcoding tool names.
    The check_* verification tools are included in "validation" automatically.
    """
    registered = {t.name for t in mcp._tool_manager.list_tools()}
    detection = [n for n in _DETECTION_TOOLS if n in registered]
    validation = [n for n in _VALIDATION_TOOLS if n in registered]
    validation += sorted(n for n in registered if n.startswith("check_"))
    return json.dumps({DETECTION: detection, VALIDATION: validation})
