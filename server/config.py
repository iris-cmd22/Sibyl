"""Server-only configuration. Self-contained: every default path points INSIDE
the `server/` package so the whole directory can be copied to another host and
run there. Machine-specific CodeQL paths must be provided via environment.

Override anything via environment variables (a local .env in the project root is
loaded if python-dotenv is installed).
"""
import os
from pathlib import Path

# Root of the server package (this file's directory). All bundled data lives
# under here, so the package is portable.
SERVER_DIR = Path(__file__).resolve().parent

# Load a local .env (if present). Safe no-op if python-dotenv isn't installed.
try:
    from dotenv import load_dotenv

    load_dotenv(SERVER_DIR.parent / ".env")
except ImportError:
    pass


# Obiettivo: leggere una variabile d'ambiente OBBLIGATORIA e fermare il server
#            subito (con messaggio chiaro) se manca, invece di fallire più avanti.
# Input:    name = nome della variabile (es. "CODEQL_SEARCH_PATH");
#           hint = testo che spiega cosa ci si aspetta (mostrato nell'errore).
# Output:   il valore della variabile (stringa) se presente.
# Come realizzato: legge os.environ; se vuoto/assente solleva RuntimeError con hint.
def _require_env(name: str, hint: str) -> str:
    val = os.environ.get(name)
    if not val:
        raise RuntimeError(
            f"{name} is not set. Set it in the environment (or a local .env). "
            f"Expected: {hint}"
        )
    return val


# --- CodeQL toolchain (HOST prerequisites, not bundled) ---
# `codeql` must be on PATH. Override with a full path if needed.
CODEQL_BIN = os.environ.get("CODEQL_BIN", "codeql")

# Local CodeQL query checkout (vscode-codeql-starter). Used as --search-path so
# the standard query packs resolve without downloading anything.
CODEQL_SEARCH_PATH = _require_env(
    "CODEQL_SEARCH_PATH",
    "path to the 'ql' folder of a vscode-codeql-starter checkout",
)

# Standard query suite run by analyze_database() when no custom query is given.
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
# Each entry becomes a dedicated MCP tool (see server/registry/loader.py).
CUSTOM_QUERIES = {
    "sql_injection": ("CWE-89", "SQL injection (remote -> DB)", "RemoteToDbBroad.ql"),
    "os_command_injection": ("CWE-78", "OS command injection", "RemoteToOsCommandBroad.ql"),
    "path_traversal": ("CWE-22", "Path traversal (remote -> file path)", "RemoteToFilePathBroad.ql"),
    "deserialization": ("CWE-502", "Unsafe deserialization", "RemoteToDeserializationBroad.ql"),
    "xss": ("CWE-79", "Cross-site scripting", "ParamToXss.ql"),
}

# Root of the OFFICIAL CodeQL standard query library (GitHub Security Lab), inside the
# same checkout already required for CODEQL_SEARCH_PATH. Used by the non-CWE signal
# tools (find_exception_handling_issues, find_broken_sanitizer_patterns,
# find_resource_handling_issues in server/tools/queries.py) to locate their official
# .ql files (Exceptions/, Statements/, Resources/, Expressions/Regex/) — referenced
# directly, never copied.
STANDARD_QUERY_DIR = Path(CODEQL_SEARCH_PATH) / "python" / "ql" / "src"

# --- Bundled data (travels with the package; defaults point inside server/) ---
# .ql.tmpl templates with {{SINK_NAMES}} / {{SOURCE_NAMES}} / ... placeholders.
TEMPLATE_DIR = Path(os.environ.get("TEMPLATE_DIR", SERVER_DIR / "query_templates"))
# A valid CodeQL pack (qlpack.yml + codeql/python-all dep) where rendered queries
# are written before running. Must be writable at runtime.
GENERATED_DIR = Path(os.environ.get("GENERATED_DIR", SERVER_DIR / "generated_queries"))

# CWE knowledge base ("wiki") the agent can explore.
CWE_WIKI_PATH = Path(os.environ.get("CWE_WIKI_PATH", SERVER_DIR / "knowledge" / "data" / "cwe_wiki.json"))
# Full CWE catalog (all ~969 CWEs, official layer only) for lookup fallback.
CWE_CATALOG_PATH = Path(os.environ.get("CWE_CATALOG_PATH", SERVER_DIR / "knowledge" / "data" / "cwe_catalog.json"))

# Where CodeQL databases and SARIF outputs are written.
WORK_DIR = Path(os.environ.get("WORK_DIR", SERVER_DIR / "_work"))
WORK_DIR.mkdir(exist_ok=True)

# Per-CodeQL-command timeout (seconds). DB creation on large repos is slow.
CODEQL_TIMEOUT = int(os.environ.get("CODEQL_TIMEOUT", "1800"))
