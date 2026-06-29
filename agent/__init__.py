"""Security analysis agent: local Ollama model + CodeQL via MCP.

The agent is a CLIENT of an INDEPENDENT MCP server: start the server separately
(`MCP_TRANSPORT=sse python -m server`), point MCP_SERVER_URL at it, then run
`python -m agent <repo_path>`. See COMPONENTI.md for the architecture.

`run_agent` is exposed lazily so the pure helper modules (report, robustness,
source) stay importable without the `ollama`/`mcp` runtime packages installed.
"""


# Obiettivo: esporre run_agent come "agent.run_agent" senza importarlo subito, così i
#            moduli puri restano importabili anche senza i pacchetti ollama/mcp installati.
# Input:    name = nome dell'attributo richiesto sul package.
# Output:   la funzione run_agent se richiesta; altrimenti solleva AttributeError.
# Come realizzato: Python chiama questa funzione solo per attributi non trovati; se è
#            "run_agent" lo importa pigramente dall'orchestrator e lo restituisce.
def __getattr__(name):
    if name == "run_agent":
        from agent.orchestrator import run_agent

        return run_agent
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = ["run_agent"]
