import argparse
from mcp.server.fastmcp import FastMCP
# Importiamo i moduli core che andremo a creare
from .core.runner import CodeQLRunner

# Inizializziamo il server
mcp = FastMCP("codeql-security-server")

# Il runner sarà configurato all'avvio
runner = None

@mcp.tool()
def list_python_files(repo_path: str) -> str:
    """Elenca i file .py in una repository."""
    # Qui implementerai la logica che prima stava nel monolite
    return f"Logic to list python files in {repo_path}"

@mcp.tool()
def create_codeql_database(repo_path: str) -> str:
    """Crea un database CodeQL per la repo specificata."""
    # Qui userai il 'runner' importato
    return "DB created"

def start_server(transport="stdio", host="0.0.0.0", port=8000, codeql_path="codeql"):
    """Configura e avvia il server."""
    global runner
    runner = CodeQLRunner(binary_path=codeql_path)
    
    if transport == "sse":
        print(f"Server MCP in ascolto su {host}:{port}...")
        mcp.run(transport="sse", host=host, port=port)
    else:
        mcp.run(transport="stdio")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--transport", default="stdio", choices=["stdio", "sse"])
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--codeql-path", default="codeql")
    args = parser.parse_args()
    
    start_server(args.transport, args.host, args.port, args.codeql_path)