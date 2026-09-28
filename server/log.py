"""Centralized debug logging for the MCP server.

All logs go to STDERR on purpose: with the stdio transport, STDOUT is reserved
for the MCP JSON-RPC protocol, so anything printed there would corrupt the
communication. stderr is safe and is what the agent/inspector shows as server
logs.

Verbosity is controlled by the SIBYL_LOG_LEVEL environment variable
(DEBUG | INFO | WARNING | ERROR), default INFO.
"""
from __future__ import annotations

import logging
import os
import sys
import time

_LOGGER_NAME = "sibyl.server"
_CONFIGURED = False


# Obiettivo: preparare UNA volta sola il sistema di log del server (su stderr).
# Input:    nessuno (legge la variabile d'ambiente SIBYL_LOG_LEVEL).
# Output:   l'oggetto logger pronto all'uso.
# Come realizzato: se non già configurato, crea un handler verso stderr con un
#            formato leggibile e imposta il livello; il flag _CONFIGURED evita di
#            configurarlo due volte (idempotente).
def setup_logging() -> logging.Logger:
    """Configure (once) and return the server logger. Idempotent."""
    global _CONFIGURED
    logger = logging.getLogger(_LOGGER_NAME)
    if _CONFIGURED:
        return logger

    level_name = os.environ.get("SIBYL_LOG_LEVEL", "INFO").upper()
    level = getattr(logging, level_name, logging.INFO)

    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(
        logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s", "%H:%M:%S")
    )
    logger.addHandler(handler)
    logger.setLevel(level)
    logger.propagate = False
    _CONFIGURED = True
    return logger


# Obiettivo: ottenere il logger del server da qualsiasi modulo, senza preoccuparsi
#            se è già stato configurato.
# Input:    nessuno.
# Output:   l'oggetto logger.
# Come realizzato: richiama setup_logging() (che è idempotente).
def get_logger() -> logging.Logger:
    """Return the server logger (configuring it if needed)."""
    return setup_logging()


# Obiettivo: trasformare gli argomenti di un tool in una stringa breve, adatta a
#            stare su una sola riga di log (gli argomenti possono essere enormi).
# Input:    value = qualsiasi valore (di solito il dict degli argomenti);
#           limit = lunghezza massima in caratteri (default 300).
# Output:   stringa: la rappresentazione, troncata se troppo lunga.
# Come realizzato: usa repr(); se supera 'limit' taglia e aggiunge "+N chars".
def _short(value, limit: int = 300) -> str:
    """Compact, truncated repr of tool arguments for a single log line."""
    text = repr(value)
    return text if len(text) <= limit else text[:limit] + f"... (+{len(text) - limit} chars)"


# Obiettivo: far sì che OGNI chiamata a un tool venga loggata automaticamente,
#            senza dover aggiungere log dentro ogni singolo tool.
# Input:    mcp = l'oggetto server FastMCP.
# Output:   nessuno (modifica il server "avvolgendo" la sua funzione interna).
# Come realizzato: salva la funzione originale call_tool del gestore dei tool e la
#            sostituisce con una versione (logged_call_tool) che logga prima e dopo
#            l'esecuzione, poi chiama l'originale. È il pattern "wrapper/decoratore".
def instrument_tool_calls(mcp) -> None:
    """Wrap the FastMCP tool manager's call_tool so every tool invocation is
    logged (name, arguments, duration, and errors). Central: catches all tools
    regardless of how they were registered."""
    logger = get_logger()
    tm = mcp._tool_manager
    original = tm.call_tool

    # Obiettivo: la versione "avvolta" che logga ogni invocazione.
    # Input:    name = nome del tool; arguments = dict dei parametri; il resto è
    #           passato così com'è all'originale.
    # Output:   il risultato del tool originale (o rilancia l'eccezione, loggata).
    # Come realizzato: logga "→ tool call", cronometra, chiama l'originale con await,
    #           logga "✓ tool done" col tempo; se va in errore logga "✗ tool error".
    async def logged_call_tool(name, arguments, *args, **kwargs):
        logger.info("→ tool call: %s args=%s", name, _short(arguments))
        start = time.perf_counter()
        try:
            result = await original(name, arguments, *args, **kwargs)
        except Exception as exc:
            logger.exception("✗ tool error: %s: %s", name, exc)
            raise
        logger.info("✓ tool done: %s (%.2fs)", name, time.perf_counter() - start)
        return result

    tm.call_tool = logged_call_tool
