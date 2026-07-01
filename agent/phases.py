"""Per-phase tool exposure.

The pipeline runs in two phases — Detection, Validation — and each sees a DIFFERENT
subset of the MCP tools. Crucially, the tool → phase mapping is NOT hardcoded here:
it comes from the MCP **server** (the source of truth for the tools), fetched via the
`list_phase_tools` tool. The agent only owns the phase NAMES, which map to prompts.
"""
from __future__ import annotations

import json

from agent.clients.mcp import tool_result_text

DETECTION = "detection"
VALIDATION = "validation"


# Obiettivo: chiedere al SERVER quali tool esporre in ciascuna fase (niente nomi
#            hardcoded nell'agente).
# Input:    session = sessione MCP aperta.
# Output:   dict {fase: set(nomi_tool)}; dict vuoto se il server non espone la mappa.
# Come realizzato: chiama il tool list_phase_tools e converte le liste in set; in caso
#            di errore restituisce {} (l'orchestrator degrada esponendo tutti i tool).
async def fetch_phase_tools(session) -> dict[str, set[str]]:
    try:
        result = await session.call_tool("list_phase_tools", {})
        data = json.loads(tool_result_text(result))
        return {phase: set(names) for phase, names in data.items()}
    except Exception:
        return {}


# Obiettivo: tenere, fra tutti i tool del server, solo quelli ammessi (per nome).
# Input:    mcp_tools = elenco completo dei tool MCP; allowed = set di nomi ammessi.
# Output:   la lista filtrata (stesso tipo degli elementi in ingresso).
# Come realizzato: confronta t.name con l'allow-list fornita dal server.
def filter_tools(mcp_tools, allowed: set[str]):
    return [t for t in mcp_tools if t.name in allowed]
