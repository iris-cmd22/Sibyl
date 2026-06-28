"""Assemble the CodeQL MCP server and run it.

Importing the tool modules attaches the static @mcp.tool() functions to the
shared `mcp` instance; importing the registry attaches the dynamic check_*
tools. Then the transport layer runs the assembled server.

Entry points:
    python -m server                 # stdio (local; default)
    MCP_TRANSPORT=sse python -m server  # network (remote)
"""
from __future__ import annotations

from server import config
from server.log import get_logger, instrument_tool_calls
# Static tools — import for their @mcp.tool() registration side effects.
from server.tools import filesystem, database, queries, config_flags, knowledge  # noqa: F401
# Dynamic check_* tools — import for registration side effects.
from server.registry import loader  # noqa: F401
from server.transport.mcp_instance import mcp
from server.transport.run import run


# Obiettivo: stampare all'avvio un riepilogo chiaro: configurazione in uso e numero
#            di tool registrati (utile per capire subito com'è impostato il server).
# Input:    logger = l'oggetto di logging su cui scrivere.
# Output:   nessuno (scrive righe di log su stderr).
# Come realizzato: chiede al gestore dei tool la lista e logga i path di config + il conteggio.

def _log_startup(logger) -> None:
    """Emit a concise startup banner: config in use + registered tools."""
    tools = mcp._tool_manager.list_tools()
    logger.info("=" * 60)
    logger.info("CodeQL MCP server starting")
    logger.info("  codeql binary : %s", config.CODEQL_BIN)
    logger.info("  search path   : %s", config.CODEQL_SEARCH_PATH)
    logger.info("  default suite : %s", config.DEFAULT_SUITE)
    logger.info("  custom queries: %s", config.CUSTOM_QUERY_DIR)
    logger.info("  work dir      : %s", config.WORK_DIR)
    logger.info("  tools registered: %d", len(tools))
    logger.debug("  tool names: %s", sorted(t.name for t in tools))
    logger.info("=" * 60)


# Obiettivo: punto d'ingresso del server: mette insieme tutto e avvia.
# Input:    nessuno.
# Output:   nessuno (avvia il server, che resta in ascolto).
# Come realizzato: ottiene il logger, stampa il banner, attiva il logging di ogni
#            chiamata ai tool (instrument_tool_calls), poi avvia il trasporto con run().
#            (I tool si sono già registrati al momento degli import in cima al file.)
def main() -> None:
    logger = get_logger()
    _log_startup(logger)
    instrument_tool_calls(mcp)
    run()


if __name__ == "__main__":
    main()
