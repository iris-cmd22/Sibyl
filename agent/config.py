"""Agent-only configuration. Self-contained: defaults live INSIDE the `agent/`
package so the directory is portable. Override anything via environment variables
(a local .env in the project root is loaded if python-dotenv is installed)."""
import os
from pathlib import Path

# Root of the agent package (this file's directory). Writable defaults live here.
AGENT_DIR = Path(__file__).resolve().parent

# Load a local .env (if present). Safe no-op if python-dotenv isn't installed.
try:
    from dotenv import load_dotenv

    load_dotenv(AGENT_DIR.parent / ".env")
except ImportError:
    pass

# --- Ollama (the local LLM driving the analysis) ---
OLLAMA_HOST = os.environ.get("OLLAMA_HOST", "http://localhost:11434")
AGENT_MODEL = os.environ.get("AGENT_MODEL", "qwen2.5-coder:14b")

# --- MCP server (independent service; the agent connects as an SSE client) ---
# In local it points at localhost; for remote just change the URL (server host).
MCP_SERVER_URL = os.environ.get("MCP_SERVER_URL", "http://127.0.0.1:8000/sse")

# Where checkpoints are written (per-repo, survives a shutdown).
WORK_DIR = Path(os.environ.get("AGENT_WORK_DIR", AGENT_DIR / "_work"))
WORK_DIR.mkdir(exist_ok=True)

# Where security reports are written by default (one file per run, named after
# the repo + model + timestamp).
REPORTS_DIR = Path(os.environ.get("AGENT_REPORTS_DIR", AGENT_DIR / "reports"))
REPORTS_DIR.mkdir(exist_ok=True)
