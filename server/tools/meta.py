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
#
# create_codeql_database and the 12 inventory tools (find_all_flows + the 11
# categorized/extra ones) are NOT in this list: they require zero judgement to run
# ("call each once"), so the agent's orchestrator calls them directly as a
# deterministic pre-step (agent/orchestrator.py:_gather_evidence), without an LLM
# round-trip. Detection (LLM) only reads the code to ENRICH that pre-gathered
# evidence with real names/values/relevance — it never discovers signals itself.
# Detection has the exclusive privilege of reading raw source code (read_file_snippet):
# it is the "orchestrator/extractor" that turns untrusted repo text into structured,
# short FLOW/OP lines (det_analysis). Validation must NEVER read raw source again — it
# only runs name-parameterized template queries (run_taint_query, run_api_misuse_query,
# run_insecure_config_flag_query, run_custom_query by registered template name, check_*)
# using the exact names Detection already extracted. This keeps Validation's context
# free of untrusted repo text (indirect prompt injection), matching a Dual-LLM-like
# isolation: Detection = privileged reader, Validation = constrained executor.
_DETECTION_TOOLS = [
    "list_python_files",
    "read_file_snippet",
]
_VALIDATION_TOOLS = [
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


# --- Server-side phase enforcement ---
# list_phase_tools() above is only ADVISORY: it tells the agent which tools to show
# the model, but nothing stops a tool from being called anyway (a bug in the agent,
# or any other MCP client, could still invoke a Detection-only tool while Validation
# is running). _current_phase is the actual enforcement point: the orchestrator calls
# set_phase() once at the start of each phase, and phase-restricted tools (e.g.
# read_file_snippet in server/tools/filesystem.py) check get_current_phase() and
# refuse to run outside the phase they belong to. One MCP server process serves one
# analysis session at a time (see README's deployment model), so process-wide state
# is sufficient here — this is not meant to arbitrate multiple concurrent sessions.
_current_phase: str | None = None


# Obiettivo: leggere la fase attualmente attiva, per farla controllare ai tool
#            riservati a una sola fase (es. read_file_snippet, solo Detection).
# Input:    nessuno.
# Output:   "detection"/"validation", oppure None se set_phase non e' mai stato chiamato
#           (nessuna fase impostata -> nessuna restrizione applicata, per compatibilita').
def get_current_phase() -> str | None:
    return _current_phase


# Obiettivo: far sapere al server QUALE fase e' ora attiva, cosi' i tool riservati a
#            Detection possano rifiutarsi di girare una volta iniziata Validation —
#            questa e' l'enforcement reale, non solo la lista dichiarativa sopra.
# Input:    phase = "detection" o "validation".
# Output:   stringa JSON di conferma; JSON "error" se il valore non e' valido.
# Come realizzato: aggiorna la variabile di modulo _current_phase.
@mcp.tool()
def set_phase(phase: str) -> str:
    """Tell the server which pipeline phase is now active.

    Call this once at the start of each phase (before its first tool call).
    Detection-only tools (read_file_snippet) will refuse to run once "validation"
    has been set — this is the actual server-side enforcement of the phase
    separation that list_phase_tools() only advertises.

    Args:
        phase: "detection" or "validation".
    """
    global _current_phase
    if phase not in (DETECTION, VALIDATION):
        return json.dumps({"error": f"invalid phase: {phase!r}, expected "
                                     f"{DETECTION!r} or {VALIDATION!r}"})
    _current_phase = phase
    return json.dumps({"phase": _current_phase})
