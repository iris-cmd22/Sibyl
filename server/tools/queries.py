"""Query tools: ad-hoc custom queries and name-based taint / API-misuse templates."""
from __future__ import annotations

import json
from pathlib import Path

from server.core.executor import analyze_with_query, render_and_analyze
from server.core.template import normalize_cwe, render_consts, render_names, is_valid_name
from server.knowledge.store import CWE_REFERENCE
from server.transport.mcp_instance import mcp


# Obiettivo: eseguire un file di query .ql arbitrario fornito dall'esterno (uso libero).
# Input:    db_path = database; query_path = percorso assoluto del file .ql.
# Output:   stringa JSON con i finding (come analyze_with_query).
# Come realizzato: delega tutto a core.executor.analyze_with_query.
@mcp.tool()
def run_custom_query(db_path: str, query_path: str) -> str:
    """Run an arbitrary custom .ql query file against a database.

    Use this for ad-hoc queries. For the well-known CWE checks, prefer the
    dedicated check_* tools.

    Args:
        db_path: Path returned by create_codeql_database.
        query_path: Absolute path to a .ql file.
    """
    return analyze_with_query(db_path, Path(query_path))


# Obiettivo: verificare un'ipotesi di TAINT (un dato dell'utente arriva a un punto
#            pericoloso) generando al volo una query CodeQL dai nomi forniti.
# Input:    db_path = database; sink_names = nomi delle funzioni "pericolose" (obbligatori);
#           cwe = classe di vulnerabilità da "timbrare"; source_names/sanitizer_names = opzionali.
# Output:   stringa JSON con i finding (incluso il percorso sorgente→sink); JSON "error"
#           se i nomi non sono validi o manca il template.
# Come realizzato: valida i nomi (anti-injection), riempie il template
#            "taint_namebased.ql.tmpl" con render_names/normalize_cwe, salva la query
#            generata e la esegue con analyze_with_query, allegando i dati del CWE dalla wiki.
@mcp.tool()
def run_taint_query(
    db_path: str,
    sink_names: list[str],
    cwe: str = "",
    source_names: list[str] | None = None,
    sanitizer_names: list[str] | None = None,
) -> str:
    """Verify a taint hypothesis with CodeQL using a name-based template.

    Use this AFTER inspecting the code: supply the method/function NAMES you
    suspect are sinks (e.g. the DB/exec/file calls user input reaches), and
    optionally extra source names and sanitizer names. The names are injected
    into a pre-validated CodeQL taint template and executed. RemoteFlowSource is
    always a source. Names must be plain identifiers (letters, digits, _).

    Pass `cwe` to stamp the vulnerability class INTO the generated query's
    metadata (@tags external/cwe/cwe-NNN), so the resulting finding carries the
    CWE as deterministic provenance (not a model guess). The returned findings
    include the full source->sink data-flow path as evidence.

    Args:
        db_path: Path returned by create_codeql_database.
        sink_names: Required. Call names whose arguments are sinks, e.g.
            ["execute", "exec", "query", "read_sql"].
        cwe: Vulnerability class being verified, e.g. "CWE-89". Recommended:
            it is embedded in the query and echoed in the findings.
        source_names: Optional extra taint sources (call names), e.g.
            ["get_json", "read_input"]. RemoteFlowSource is always included.
        sanitizer_names: Optional sanitizer call names that cut the flow, e.g.
            ["quote", "escape", "sanitize"]. Empty -> no sanitizer.
    """
    bad = [n for n in (sink_names or []) if not is_valid_name(n)]
    if not sink_names:
        return json.dumps({"error": "sink_names is required and must be non-empty"})
    if bad:
        return json.dumps({"error": f"invalid names (must be identifiers): {bad}"})

    cwe_id = normalize_cwe(cwe)[0]
    ref = CWE_REFERENCE.get(cwe_id, {}) if cwe_id else {}
    return render_and_analyze(
        db_path, "taint_namebased.ql.tmpl",
        {
            "{{SINK_NAMES}}": render_names(sink_names),
            "{{SOURCE_NAMES}}": render_names(source_names),
            "{{SANITIZER_NAMES}}": render_names(sanitizer_names),
        },
        out_prefix="taint", cwe=cwe,
        extra={
            "template": "taint_namebased",
            "cwe": cwe_id,
            "cwe_name": ref.get("name"),
            "standard_remediation": ref.get("remediation"),
            "sink_names": sink_names,
            "source_names": source_names or [],
            "sanitizer_names": sanitizer_names or [],
        },
    )


# Obiettivo: rilevare l'uso di API/crittografia DEBOLE (rilevamento "puntuale", non
#            di flusso): es. chiamate a md5/sha1/DES o costanti deboli come "ecb".
# Input:    db_path = database; weak_call_names = nomi di funzioni deboli e/o
#           bad_constants = stringhe deboli (almeno una delle due liste); cwe = classe.
# Output:   stringa JSON con i finding; JSON "error" se entrambe le liste mancano o
#           i nomi non sono validi.
# Come realizzato: riempie il template "api_misuse_namebased.ql.tmpl" con
#            render_names/render_consts, salva la query ed esegue analyze_with_query.
@mcp.tool()
def run_api_misuse_query(
    db_path: str,
    weak_call_names: list[str] | None = None,
    bad_constants: list[str] | None = None,
    cwe: str = "",
) -> str:
    """Verify an insecure-API hypothesis (crypto etc.) with a name-based template.

    This is POINT DETECTION, not taint: it flags calls to weak/insecure APIs by
    name (e.g. ["md5","sha1","DES"]) and/or calls passing a weak constant
    argument (e.g. bad_constants=["md5","ecb"] catches hashlib.new("md5")).
    Use it for cryptographic CWEs (CWE-327/328/330/916, ...). Get candidate
    names from cwe_knowledge(cwe). Provide at least one of the two lists.

    Args:
        db_path: Path returned by create_codeql_database.
        weak_call_names: Insecure function/method names to flag, e.g.
            ["md5", "sha1", "random", "DES"].
        bad_constants: Weak algorithm/mode strings passed as arguments, e.g.
            ["md5", "rc4", "ecb"]. Matched case-insensitively.
        cwe: Vulnerability class, e.g. "CWE-328"; stamped into the evidence.
    """
    if not weak_call_names and not bad_constants:
        return json.dumps({"error": "provide at least one of weak_call_names / bad_constants"})
    bad = [n for n in (weak_call_names or []) if not is_valid_name(n)]
    if bad:
        return json.dumps({"error": f"invalid call names (must be identifiers): {bad}"})

    cwe_id = normalize_cwe(cwe)[0]
    ref = CWE_REFERENCE.get(cwe_id, {}) if cwe_id else {}
    return render_and_analyze(
        db_path, "api_misuse_namebased.ql.tmpl",
        {
            "{{WEAK_CALL_NAMES}}": render_names(weak_call_names),
            "{{BAD_CONSTANTS}}": render_consts(bad_constants),
        },
        out_prefix="apimisuse", cwe=cwe,
        extra={
            "template": "api_misuse_namebased",
            "cwe": cwe_id,
            "cwe_name": ref.get("name"),
            "standard_remediation": ref.get("remediation"),
            "weak_call_names": weak_call_names or [],
            "bad_constants": bad_constants or [],
        },
    )
