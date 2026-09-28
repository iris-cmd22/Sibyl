"""Adapter to the independent MCP server (connected as an SSE client).

The MCP server has its own lifecycle: start it separately
(`MCP_TRANSPORT=sse python -m server`) and point MCP_SERVER_URL at it. The agent
connects over SSE, lists the tools, and exposes them to the Ollama model.
"""
from __future__ import annotations

from contextlib import asynccontextmanager

from mcp import ClientSession
from mcp.client.sse import sse_client


# Obiettivo: aprire la connessione al server MCP e fornire in un colpo solo la sessione
#            pronta all'uso e l'elenco dei tool, evitando al chiamante di annidare tre
#            blocchi "async with".
# Input:    url = indirizzo SSE del server MCP (es. http://127.0.0.1:8000/sse).
# Output:   (context manager) cede la coppia (session, mcp_tools); chiude tutto all'uscita.
# Come realizzato: apre sse_client e ClientSession, esegue initialize e list_tools, e
#            con "yield" consegna sessione e tool finché il blocco chiamante è attivo.
@asynccontextmanager
async def connect(url: str):
    async with sse_client(url) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            mcp_tools = (await session.list_tools()).tools
            yield session, mcp_tools


# Obiettivo: tradurre le definizioni dei tool MCP nel formato "function calling" che il
#            modello Ollama si aspetta.
# Input:    tools = lista di definizioni di tool ricevute dal server MCP.
# Output:   lista di dict nello schema Ollama (type/function/name/description/parameters).
# Come realizzato: per ogni tool copia nome, descrizione e schema dei parametri nella
#            struttura attesa da Ollama.
def mcp_tools_to_ollama(tools) -> list[dict]:
    return [
        {
            "type": "function",
            "function": {
                "name": t.name,
                "description": t.description or "",
                "parameters": t.inputSchema,
            },
        }
        for t in tools
    ]


# Obiettivo: estrarre il testo utile dal risultato (potenzialmente a più blocchi) di un
#            tool MCP, per poterlo restituire al modello.
# Input:    result = l'oggetto risultato restituito da session.call_tool.
# Output:   stringa con il testo unito dei blocchi; "(empty result)" se vuoto.
# Come realizzato: concatena il campo "text" di ogni blocco del contenuto, separandoli
#            con un a-capo.
def tool_result_text(result) -> str:
    parts = []
    for block in result.content:
        parts.append(getattr(block, "text", "") or "")
    return "\n".join(parts) or "(empty result)"
