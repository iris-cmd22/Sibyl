"""Transport selection: how the assembled MCP server talks to the outside world.

Local deployment uses stdio (the agent launches the server as a subprocess).
Remote deployment uses a network transport (SSE / streamable-HTTP) so the agent
can reach the server over the wire.

Controlled entirely by environment variables, so the same code runs in both
scenarios without changes:

    MCP_TRANSPORT  stdio (default) | sse | streamable-http
    MCP_HOST       bind address for network transports (default 0.0.0.0)
    MCP_PORT       bind port for network transports     (default 8000)
"""
from __future__ import annotations

import os

from server.log import get_logger
from server.transport.mcp_instance import mcp

VALID_TRANSPORTS = {"stdio", "sse", "streamable-http"}


# Obiettivo: avviare il server scegliendo il CANALE di comunicazione giusto
#            (locale via stdio oppure di rete via sse/streamable-http).
# Input:    nessun parametro; legge MCP_TRANSPORT, MCP_HOST, MCP_PORT dall'ambiente.
# Output:   nessuno; la chiamata mcp.run(...) resta in ascolto (bloccante).
# Come realizzato: valida il valore di MCP_TRANSPORT; per i trasporti di rete imposta
#            host/porta; logga la scelta e infine chiama mcp.run(transport=...).
def run() -> None:
    logger = get_logger()
    transport = os.environ.get("MCP_TRANSPORT", "stdio").lower()
    if transport not in VALID_TRANSPORTS:
        raise SystemExit(
            f"Invalid MCP_TRANSPORT={transport!r}. Use one of: {sorted(VALID_TRANSPORTS)}"
        )

    if transport != "stdio":
        # Network transports: honour host/port overrides.
        mcp.settings.host = os.environ.get("MCP_HOST", "0.0.0.0")
        mcp.settings.port = int(os.environ.get("MCP_PORT", "8000"))
        logger.info("transport: %s on %s:%s", transport, mcp.settings.host, mcp.settings.port)
    else:
        logger.info("transport: stdio (waiting for MCP client on stdin/stdout)")

    mcp.run(transport=transport)
