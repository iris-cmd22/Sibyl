"""Query tools: ad-hoc custom queries and name-based taint / API-misuse templates."""
from __future__ import annotations

import json
from pathlib import Path

from server.core.executor import analyze_with_query, render_and_analyze
from server.core.template import normalize_cwe, render_consts, render_names, is_valid_name
from server.knowledge.store import lookup_cwe
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
    ref = (lookup_cwe(cwe_id) or {}) if cwe_id else {}
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
    ref = (lookup_cwe(cwe_id) or {}) if cwe_id else {}
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


# Obiettivo: dare alla fase di DETECTION "tutti i flow disponibili" nel codice in modo
#            CWE-agnostico: ogni percorso da un input non fidato (RemoteFlowSource) fino
#            all'argomento di una qualsiasi chiamata, SENZA assumere una classe di vuln.
# Input:    db_path = database; max_flows = quanti flow (dedotti) restituire al massimo.
# Output:   stringa JSON compatta con l'inventario dei flow (source/sink file:line, passi);
#           NESSUna etichetta CWE (per non dare bias all'LLM).
# Come realizzato: esegue il template "flow_inventory.ql.tmpl" con cwe="" (i segnaposto
#            CWE si svuotano), poi deduplica per (source, sink), tronca a max_flows e
#            riassume. L'inventario completo (SARIF) resta su disco (Claim Check).
@mcp.tool()
def find_all_flows(db_path: str, max_flows: int = 200) -> str:
    """List ALL data-flows from untrusted input to any call argument (CWE-agnostic).

    This is the Detection-phase tool: it surfaces every flow the untrusted data
    takes WITHOUT committing to a vulnerability class (no CWE, no standard query),
    so the model is not biased. Source = RemoteFlowSource (where external input
    enters). Sink = the argument of ANY call (a structural "something happens
    here"). You then judge which sinks are dangerous and VERIFY them in Validation.

    Args:
        db_path: Path returned by create_codeql_database.
        max_flows: Max number of (deduplicated) flows to return (default 200).
    """
    raw = render_and_analyze(
        db_path, "flow_inventory.ql.tmpl", {}, out_prefix="flowinv", cwe="",
    )
    try:
        payload = json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        return raw
    if "error" in payload:
        return raw

    seen: set = set()
    flows: list[dict] = []
    for f in payload.get("findings", []) or []:
        src = f.get("source") or {}
        snk = f.get("sink") or {}
        key = (src.get("file"), src.get("line"), snk.get("file"), snk.get("line"))
        if key in seen:
            continue
        seen.add(key)
        flows.append({
            "source": {"file": src.get("file"), "line": src.get("line")},
            "sink": {"file": snk.get("file"), "line": snk.get("line")},
            "sink_hint": (snk.get("note") or "")[:120],
            "steps": f.get("flow_steps", 0),
        })

    total = len(flows)
    return json.dumps({
        "flow_count": total,
        "returned": min(total, max_flows),
        "truncated": total > max_flows,
        "flows": flows[:max_flows],
        "note": "CWE-agnostic flow inventory: untrusted input -> a call argument. "
                "No vulnerability class is implied. Decide which sinks are dangerous "
                "and VERIFY them in Validation (run_taint_query with cwe + refined names).",
    }, indent=2)


# La crypto e' rilevata semanticamente dal Concept Cryptography::CryptographicOperation
# nel template. Il name-based resta SOLO come rete per cio' che CodeQL non modella come
# Concept: la randomness insicura (e, in fallback, la deserializzazione). Nomi presi
# dalla wiki (CWE-330) uniti a pochi default.
_WEAK_CWES = ("CWE-330",)
_WEAK_DEFAULTS = [
    "random", "randint", "randrange", "uniform", "getrandbits", "choice",
    "loads", "load",
]
# Keyword-argument "di sicurezza" la cui presenza con un literal va segnalata.
_FLAG_PARAM_DEFAULTS = [
    "verify", "shell", "autoescape", "debug", "secure", "httponly",
    "samesite", "check_hostname", "ssl_verify",
]


# Obiettivo: dare alla DETECTION un inventario delle OPERAZIONI SENSIBILI presenti nel
#            codice A PRESCINDERE dal flusso (crypto/hash/random deboli, exec/comandi,
#            deserializzazione, config-flag), così un modello piccolo non deve accorgersene
#            da solo. CWE-agnostico: ogni voce ha un `kind` strutturale, mai un CWE.
# Input:    db_path = database; max_ops = quante operazioni (dedotte) restituire.
# Output:   stringa JSON compatta {op_count, by_kind, operations:[{kind,file,line}]}.
# Come realizzato: raccoglie i nomi deboli dalla wiki (via lookup_cwe) uniti ai default,
#            rende "sensitive_ops.ql.tmpl" con cwe="" (niente tag CWE), poi deduplica per
#            (kind,file,line), raggruppa per kind e tronca.
@mcp.tool()
def find_sensitive_operations(db_path: str, max_ops: int = 200) -> str:
    """List security-sensitive operations in the code, REGARDLESS of data flow.

    This is the Detection companion to find_all_flows: it surfaces the "non-flow"
    signals a small model easily misses. Most kinds come from CodeQL's SEMANTIC models
    (Concepts), not name matching: command-exec, code-exec, sql-exec, filesystem,
    decoding, and `crypto` (Cryptography::CryptographicOperation, which resolves
    hashlib/cryptography/Cryptodome). Only `weak-call` (insecure randomness — CodeQL
    has no Concept for it) and `config-flag` (a kwarg like verify=/shell=/debug= set to
    a literal) are name/structure based. Each item has a `kind` + file:line, never a
    CWE. Use it to decide which api-misuse / insecure-config checks to run in Validation.

    Args:
        db_path: Path returned by create_codeql_database.
        max_ops: Max number of (deduplicated) operations to return (default 200).
    """
    weak: list[str] = list(_WEAK_DEFAULTS)
    for cid in _WEAK_CWES:
        ref = lookup_cwe(cid) or {}
        weak += ref.get("weak_call_names", []) or []
        weak += ref.get("bad_constants", []) or []
    # dedup preserving order (render_names re-validates identifiers)
    weak = list(dict.fromkeys(weak))

    raw = render_and_analyze(
        db_path, "sensitive_ops.ql.tmpl",
        {
            "{{WEAK_CALL_NAMES}}": render_names(weak),
            "{{FLAG_PARAM_NAMES}}": render_names(_FLAG_PARAM_DEFAULTS),
        },
        out_prefix="sensops", cwe="",
    )
    try:
        payload = json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        return raw
    if "error" in payload:
        return raw

    seen: set = set()
    ops: list[dict] = []
    by_kind: dict[str, int] = {}
    for f in payload.get("findings", []) or []:
        kind = (f.get("message") or "op").strip()
        file, line = f.get("file"), f.get("line")
        key = (kind, file, line)
        if key in seen:
            continue
        seen.add(key)
        ops.append({"kind": kind, "file": file, "line": line})
        by_kind[kind] = by_kind.get(kind, 0) + 1

    total = len(ops)
    return json.dumps({
        "op_count": total,
        "returned": min(total, max_ops),
        "truncated": total > max_ops,
        "by_kind": by_kind,
        "operations": ops[:max_ops],
        "note": "CWE-agnostic inventory of sensitive operations (no data-flow needed). "
                "Each `kind` says WHAT kind of operation, never a CWE. In Validation, "
                "verify these with run_api_misuse_query / run_insecure_config_flag_query "
                "/ check_* and associate the CWE from the evidence.",
    }, indent=2)
