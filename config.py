"""Central configuration. Override via environment variables (.env)."""
import os
from pathlib import Path

# Load a local .env (if present) so path/config overrides don't need to be
# exported by hand. Safe no-op if python-dotenv isn't installed or no .env file.
try:
    from dotenv import load_dotenv

    load_dotenv(Path(__file__).parent / ".env")
except ImportError:
    pass

# --- Ollama ---
OLLAMA_HOST = os.environ.get("OLLAMA_HOST", "http://localhost:11434")
AGENT_MODEL = os.environ.get("AGENT_MODEL", "qwen2.5-coder:14b")

# --- CodeQL ---
# `codeql` must be on PATH (verified: 2.25.2). Override with a full path if needed.
CODEQL_BIN = os.environ.get("CODEQL_BIN", "codeql")

# These point at a local vscode-codeql-starter checkout (NOT bundled). They are
# machine-specific, so they MUST be provided via environment / .env — no default.
def _require_env(name: str, hint: str) -> str:
    val = os.environ.get(name)
    if not val:
        raise RuntimeError(
            f"{name} is not set. Create a local .env in the project root and set it "
            f"(see README). Expected: {hint}"
        )
    return val


# Local CodeQL query checkout (vscode-codeql-starter). Used as --search-path so
# the standard query packs resolve without downloading anything.
CODEQL_SEARCH_PATH = _require_env(
    "CODEQL_SEARCH_PATH",
    "path to the 'ql' folder of a vscode-codeql-starter checkout",
)

# Standard query suite run by analyze_database() when no custom query is given.
# python-security-extended = security queries incl. lower-precision ones.
DEFAULT_SUITE = _require_env(
    "CODEQL_SUITE",
    "path to a .qls security suite inside the checkout",
)

# Directory holding the custom *Broad.ql queries encapsulated as dedicated tools.
CUSTOM_QUERY_DIR = Path(
    _require_env(
        "CUSTOM_QUERY_DIR",
        "directory containing the custom *Broad.ql queries",
    )
)

# Registry: friendly key -> (CWE, human name, query filename in CUSTOM_QUERY_DIR).
# Each entry becomes a dedicated MCP tool (see codeql_mcp_server.py).
CUSTOM_QUERIES = {
    "sql_injection": ("CWE-89", "SQL injection (remote -> DB)", "RemoteToDbBroad.ql"),
    "os_command_injection": ("CWE-78", "OS command injection", "RemoteToOsCommandBroad.ql"),
    "path_traversal": ("CWE-22", "Path traversal (remote -> file path)", "RemoteToFilePathBroad.ql"),
    "deserialization": ("CWE-502", "Unsafe deserialization", "RemoteToDeserializationBroad.ql"),
    "xss": ("CWE-79", "Cross-site scripting", "ParamToXss.ql"),
}

# --- Templated taint queries (agent fills name-based source/sink/sanitizer) ---
# Directory holding .ql.tmpl templates with {{SINK_NAMES}} / {{SOURCE_NAMES}} /
# {{SANITIZER_NAMES}} placeholders.
TEMPLATE_DIR = Path(os.environ.get("TEMPLATE_DIR", Path(__file__).parent / "query_templates"))
# A valid CodeQL pack (qlpack.yml + codeql/python-all dep) where rendered queries
# are written before running.
GENERATED_DIR = Path(os.environ.get("GENERATED_DIR", Path(__file__).parent / "generated_queries"))

# CWE knowledge base ("wiki") the agent can explore to learn each vuln class and
# get candidate source/sink/sanitizer names to feed run_taint_query.
CWE_WIKI_PATH = Path(os.environ.get("CWE_WIKI_PATH", Path(__file__).parent / "knowledge" / "cwe_wiki.json"))

# Full CWE catalog (all ~969 CWEs, official layer only) for lookup fallback.
# Built offline from the MITRE XML via build_catalog.py.
CWE_CATALOG_PATH = Path(os.environ.get("CWE_CATALOG_PATH", Path(__file__).parent / "knowledge" / "cwe_catalog.json"))

# Where CodeQL databases and SARIF outputs are written.
WORK_DIR = Path(os.environ.get("WORK_DIR", Path(__file__).parent / "_work"))
WORK_DIR.mkdir(exist_ok=True)

# Where security reports are written by default (one file per run, named after
# the repo + model + timestamp).
REPORTS_DIR = Path(os.environ.get("REPORTS_DIR", Path(__file__).parent / "reports"))
REPORTS_DIR.mkdir(exist_ok=True)

# Per-CodeQL-command timeout (seconds). DB creation on large repos is slow.
CODEQL_TIMEOUT = int(os.environ.get("CODEQL_TIMEOUT", "1800"))
