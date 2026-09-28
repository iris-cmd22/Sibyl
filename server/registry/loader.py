"""Dynamic tool registration.

Builds and registers, at import time, the dedicated `check_*` tools derived from
config/knowledge data:
  - check_<key>            : encapsulated custom *Broad.ql taint queries.
  - check_<slug>           : curated crypto presets wrapping run_api_misuse_query.
  - check_insecure_<key>   : insecure-config-flag templates.

Keep this module's import side effects after the static tool modules so all tools
end up on the same shared `mcp` instance.
"""
from __future__ import annotations

from server import config
from server.core.executor import analyze_with_query, render_and_analyze
from server.core.template import normalize_cwe
from server.knowledge.store import CWE_REFERENCE
from server.tools.queries import run_api_misuse_query
from server.transport.mcp_instance import mcp


# --- Encapsulated custom taint queries (one tool per CUSTOM_QUERIES entry) ---
# Obiettivo: creare e registrare automaticamente UN tool check_<key> che esegue una
#            specifica query custom (.ql) preconfezionata.
# Input:    key = chiave breve (es. "sql_injection"); cwe = classe; name = nome leggibile;
#           filename = nome del file .ql dentro CUSTOM_QUERY_DIR.
# Output:   nessuno (registra il tool sull'oggetto mcp).
# Come realizzato: definisce una funzione interna 'tool' che chiama analyze_with_query
#            sul file, le assegna nome/descrizione dinamici e la registra con mcp.add_tool.
def make_cwe_tool(key: str, cwe: str, name: str, filename: str) -> None:
    """Build and register a dedicated MCP tool that runs one encapsulated query."""
    query_file = config.CUSTOM_QUERY_DIR / filename

    # Obiettivo: la funzione vera del tool check_<key>.
    # Input: db_path = database. Output: JSON dei finding. Come: delega ad analyze_with_query.
    def tool(db_path: str) -> str:
        return analyze_with_query(db_path, query_file, extra={"cwe": cwe, "check": name})

    tool.__name__ = f"check_{key}"
    tool.__doc__ = (
        f"Check the CodeQL database for {name} ({cwe}).\n\n"
        f"Runs the encapsulated query '{filename}' and returns findings\n"
        f"(rule, severity, file, line, message).\n\n"
        f"Args:\n    db_path: Path returned by create_codeql_database."
    )
    mcp.add_tool(tool)


for _key, (_cwe, _name, _file) in config.CUSTOM_QUERIES.items():
    make_cwe_tool(_key, _cwe, _name, _file)


# --- Curated crypto checks (one per api_misuse CWE) ---
CRYPTO_CHECK_SLUGS = {
    "CWE-328": "weak_hash",
    "CWE-327": "broken_crypto",
    "CWE-330": "weak_random",
    "CWE-916": "weak_password_hash",
}


# Obiettivo: creare e registrare un tool check_<slug> per la crittografia debole,
#            usando i "preset" (nomi deboli/costanti) presi dalla wiki.
# Input:    cwe_id = classe (es. "CWE-328"); slug = nome breve (es. "weak_hash");
#           data = la voce della wiki con weak_call_names/bad_constants.
# Output:   nessuno (registra il tool su mcp).
# Come realizzato: definisce una funzione interna che richiama run_api_misuse_query
#            con i preset, le dà nome/descrizione e la registra con mcp.add_tool.
def make_crypto_check_tool(cwe_id: str, slug: str, data: dict) -> None:
    """Register a fixed check_<slug>(db_path) tool wrapping run_api_misuse_query
    with the weak-API preset from the wiki. Mirrors the taint check_* tools so a
    small model reliably runs the crypto family too."""
    weak = data.get("weak_call_names", [])
    consts = data.get("bad_constants", [])
    name = data.get("name", cwe_id)

    # Obiettivo: la funzione vera del tool check_<slug>.
    # Input: db_path. Output: JSON dei finding. Come: richiama run_api_misuse_query coi preset.
    def tool(db_path: str) -> str:
        return run_api_misuse_query(db_path, weak_call_names=weak, bad_constants=consts, cwe=cwe_id)

    tool.__name__ = f"check_{slug}"
    tool.__doc__ = (
        f"Check the CodeQL database for {name} ({cwe_id}).\n\n"
        f"Curated crypto check: runs the weak-API preset for this class\n"
        f"(point detection). Returns findings (file, line, message).\n\n"
        f"Args:\n    db_path: Path returned by create_codeql_database."
    )
    mcp.add_tool(tool)


for _cid, _slug in CRYPTO_CHECK_SLUGS.items():
    if _cid in CWE_REFERENCE:
        make_crypto_check_tool(_cid, _slug, CWE_REFERENCE[_cid])


# --- Insecure configuration flag detection (built-in templates) ---
INSECURE_CONFIG_FLAG_TEMPLATES = {
    "verify_false": ("CWE-295", "insecure_verify_false"),
    "shell_true": ("CWE-78", "insecure_shell_true"),
    "autoescape_false": ("CWE-79", "insecure_autoescape_false"),
    "debug_true": ("CWE-489", "insecure_debug_true"),
    "weak_hash": ("CWE-327", "insecure_weak_hash"),
    "weak_randomness": ("CWE-330", "insecure_randomness"),
    "cookie_flags": ("CWE-614", "insecure_cookie_flags"),
}


# Obiettivo: creare e registrare un tool check_insecure_<key> per una configurazione
#            insicura nota (es. verify_false), basato su un template dedicato.
# Input:    key = chiave (es. "verify_false"); cwe = classe; template_name = nome del
#           file template (.ql.tmpl) senza estensione.
# Output:   nessuno (registra il tool su mcp).
# Come realizzato: definisce una funzione interna che riempie il template col CWE,
#            salva la query generata ed esegue analyze_with_query; poi la registra.
def make_insecure_config_tool(key: str, cwe: str, template_name: str) -> None:
    """Build and register a dedicated tool for insecure config flag detection."""

    # Obiettivo: la funzione vera del tool check_insecure_<key>.
    # Input: db_path. Output: JSON dei finding (o "error" se il template manca).
    # Come: delega a render_and_analyze (riempie il template col CWE, salva ed esegue).
    def tool(db_path: str) -> str:
        cwe_id = normalize_cwe(cwe)[0]
        ref = CWE_REFERENCE.get(cwe_id, {}) if cwe_id else {}
        return render_and_analyze(
            db_path, f"{template_name}.ql.tmpl", {},
            out_prefix=template_name, cwe=cwe,
            extra={
                "template": template_name,
                "cwe": cwe_id,
                "cwe_name": ref.get("name"),
                "standard_remediation": ref.get("remediation"),
            },
        )

    tool.__name__ = f"check_insecure_{key}"
    tool.__doc__ = (
        f"Check for insecure {key} ({cwe}).\n\n"
        f"Runs the encapsulated query '{template_name}' and returns findings.\n\n"
        f"Args:\n    db_path: Path returned by create_codeql_database."
    )
    mcp.add_tool(tool)


for _key, (_cwe, _tmpl) in INSECURE_CONFIG_FLAG_TEMPLATES.items():
    make_insecure_config_tool(_key, _cwe, _tmpl)
