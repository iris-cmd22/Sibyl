"""Query tools: ad-hoc custom queries and name-based taint / API-misuse templates."""
from __future__ import annotations

import json
from pathlib import Path

from server import config
from server.core.executor import analyze_with_query, render_and_analyze
from server.core.template import normalize_cwe, render_consts, render_names, is_valid_name
from server.knowledge.store import lookup_cwe
from server.transport.mcp_instance import mcp

_MAX_PATH_STEPS = 15

# Concepts CodeQL semantici gia' usati in Detection (find_sql_execution ecc.),
# richiamabili come sink ANCHE in Validation invece di ri-derivare i nomi a
# mano: coprono ORM/driver/alias che un modello non conoscerebbe a memoria.
# Whitelist FISSA (mai testo libero interpolato nel .ql generato) -> per ogni
# voce, (nome del tipo QL, nome del metodo accessore che da' il DataFlow::Node
# rilevante). CryptographicOperation e' esclusa: la debolezza crypto non e' un
# problema di taint (l'input non deve essere "tainted" per essere insicuro).
_SINK_CONCEPTS = {
    "SqlExecution": ("SqlExecution", "getSql"),
    "SystemCommandExecution": ("SystemCommandExecution", "getCommand"),
    "FileSystemAccess": ("FileSystemAccess", "getAPathArgument"),
    "Decoding": ("Decoding", "getAnInput"),
}

# Nomi di funzione che leggono input LOCALE (non di rete): stdin e variabili
# d'ambiente. Aggiunti a source_names solo se include_local_sources=True
# (opt-in: di default il taint tracking resta Remote-only, meno rumoroso).
_LOCAL_SOURCE_NAMES = ["input", "getenv"]


# Obiettivo: leggere IL CODICE REALE a un file:riga, in modo deterministico (nessun LLM,
#            nessuna invenzione possibile: e' testo letto dal disco). Usato per dare a
#            Detection nomi/valori gia' certi invece di farglieli indovinare leggendo.
# Input:    repo_path = radice del progetto (vuoto = non risolvibile, es. path non passato);
#           file = percorso relativo (dal SARIF, relativo a --source-root); line = riga 1-based.
# Output:   la riga di codice (senza newline), o "" se non risolvibile/leggibile.
def _read_line(repo_path: str, file: str | None, line: int | None) -> str:
    if not repo_path or not file or not line:
        return ""
    try:
        repo_root = Path(repo_path).resolve()
        p = (repo_root / file).resolve()
        if not p.is_relative_to(repo_root):
            return ""
        lines = p.read_text(encoding="utf-8", errors="replace").splitlines()
        if 1 <= line <= len(lines):
            return lines[line - 1].strip()
    except OSError:
        pass
    return ""


# Obiettivo: eseguire per NOME un file .ql gia' registrato in CUSTOM_QUERY_DIR (mai
#            un path libero) — le query "custom" sono concettualmente dei template:
#            si estendono aggiungendo un nuovo .ql in quella cartella, non dando al
#            modello accesso a path arbitrari del filesystem.
# Input:    db_path = database; query_path = NOME del file .ql dentro CUSTOM_QUERY_DIR
#           (mai un path assoluto/relativo che esca da quella cartella).
# Output:   stringa JSON con i finding (come analyze_with_query); JSON "error" se il
#           nome non risolve dentro CUSTOM_QUERY_DIR.
# Come realizzato: unisce CUSTOM_QUERY_DIR + query_path, risolve e verifica il
#            contenimento (stesso pattern anti-traversal di read_file_snippet), poi
#            delega a core.executor.analyze_with_query.
@mcp.tool()
def run_custom_query(db_path: str, query_path: str) -> str:
    """Run a registered custom .ql query file, referenced by name, against a database.

    Use this for ad-hoc queries not yet wrapped in a dedicated check_* tool. To add
    a new one, drop a .ql file into CUSTOM_QUERY_DIR (see server/config.py) — it
    becomes runnable by name here. For the well-known CWE checks, prefer the
    dedicated check_* tools.

    Args:
        db_path: Path returned by create_codeql_database.
        query_path: Filename of a .ql file already present in CUSTOM_QUERY_DIR
            (e.g. "RemoteToDbBroad.ql"). Must not escape that directory.
    """
    base = config.CUSTOM_QUERY_DIR.resolve()
    query_file = (base / query_path).resolve()
    if not query_file.is_relative_to(base):
        return json.dumps({"error": f"query_path must reference a file inside CUSTOM_QUERY_DIR: {query_path}"})
    return analyze_with_query(db_path, query_file)


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
    sink_concept: str = "",
    include_local_sources: bool = False,
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
        sink_names: Required (can be empty ONLY if sink_concept is set). Call
            names whose arguments are sinks, e.g. ["execute", "exec", "query"].
        cwe: Vulnerability class being verified, e.g. "CWE-89". Recommended:
            it is embedded in the query and echoed in the findings.
        source_names: Optional extra taint sources (call names), e.g.
            ["get_json", "read_input"]. RemoteFlowSource is always included.
        sanitizer_names: Optional sanitizer call names that cut the flow, e.g.
            ["quote", "escape", "sanitize"]. Empty -> no sanitizer.
        sink_concept: Optional. Reuse a CodeQL semantic Concept already used in
            Detection (find_sql_execution/find_command_execution/
            find_filesystem_access/find_decoding_operations) as an ADDITIONAL
            sink, instead of re-deriving sink names by hand. One of
            "SqlExecution", "SystemCommandExecution", "FileSystemAccess",
            "Decoding". Recommended whenever Detection already surfaced the
            matching operation: the Concept covers ORM/driver aliases a model
            would not know to name.
        include_local_sources: If True, also treat stdin (input()) and
            environment variables (getenv()) as taint sources, in addition to
            RemoteFlowSource. Use for second-order/stored injection or CLI
            tools where untrusted data enters via argv/env/stdin rather than
            HTTP. Off by default (Remote-only is less noisy for the common case).
    """
    bad = [n for n in (sink_names or []) if not is_valid_name(n)]
    if not sink_names and not sink_concept:
        return json.dumps({"error": "sink_names or sink_concept is required"})
    if bad:
        return json.dumps({"error": f"invalid names (must be identifiers): {bad}"})
    if sink_concept and sink_concept not in _SINK_CONCEPTS:
        return json.dumps({"error": f"sink_concept must be one of {sorted(_SINK_CONCEPTS)}"})

    concept_clause = ""
    if sink_concept:
        ql_type, accessor = _SINK_CONCEPTS[sink_concept]
        concept_clause = f"or exists({ql_type} c | node = c.{accessor}())"

    effective_source_names = list(source_names or [])
    if include_local_sources:
        effective_source_names = list(dict.fromkeys(effective_source_names + _LOCAL_SOURCE_NAMES))

    cwe_id = normalize_cwe(cwe)[0]
    ref = (lookup_cwe(cwe_id) or {}) if cwe_id else {}
    return render_and_analyze(
        db_path, "taint_namebased.ql.tmpl",
        {
            "{{SINK_NAMES}}": render_names(sink_names),
            "{{SOURCE_NAMES}}": render_names(effective_source_names),
            "{{SANITIZER_NAMES}}": render_names(sanitizer_names),
            "{{SINK_CONCEPT_CLAUSE}}": concept_clause,
        },
        out_prefix="taint", cwe=cwe,
        extra={
            "template": "taint_namebased",
            "cwe": cwe_id,
            "cwe_name": ref.get("name"),
            "standard_remediation": ref.get("remediation"),
            "sink_names": sink_names,
            "source_names": effective_source_names,
            "sanitizer_names": sanitizer_names or [],
            "sink_concept": sink_concept,
            "include_local_sources": include_local_sources,
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
    names from cwe_knowledge(cwe). Provide at least one of the two lists, or a
    known `cwe` alone (the curated canonical names for that CWE are ALWAYS
    included, so the search is never narrower than the dedicated check_* tool).

    Args:
        db_path: Path returned by create_codeql_database.
        weak_call_names: Insecure function/method names to flag, e.g.
            ["md5", "sha1", "random", "DES"].
        bad_constants: Weak algorithm/mode strings passed as arguments, e.g.
            ["md5", "rc4", "ecb"]. Matched case-insensitively.
        cwe: Vulnerability class, e.g. "CWE-328"; stamped into the evidence.
    """
    cwe_id = normalize_cwe(cwe)[0]
    ref = (lookup_cwe(cwe_id) or {}) if cwe_id else {}
    # The model's lists are an ADDITION to, never a restriction of, the wiki's
    # curated canonical names for this CWE (the same ones the dedicated check_*
    # tool uses) — a narrower model guess must never make the search less
    # complete than calling check_* directly.
    weak_call_names = list(dict.fromkeys(
        (weak_call_names or []) + (ref.get("weak_call_names") or [])))
    bad_constants = list(dict.fromkeys(
        (bad_constants or []) + (ref.get("bad_constants") or [])))

    if not weak_call_names and not bad_constants:
        return json.dumps({"error": "provide at least one of weak_call_names / "
                                     "bad_constants, or a known cwe"})
    bad = [n for n in weak_call_names if not is_valid_name(n)]
    if bad:
        return json.dumps({"error": f"invalid call names (must be identifiers): {bad}"})

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
            "weak_call_names": weak_call_names,
            "bad_constants": bad_constants,
        },
    )


# Obiettivo: dare alla fase di DETECTION "tutti i flow disponibili" nel codice in modo
#            CWE-agnostico: ogni percorso da un input non fidato (RemoteFlowSource) fino
#            all'argomento di una qualsiasi chiamata, SENZA assumere una classe di vuln.
# Input:    db_path = database; repo_path = radice del progetto (per leggere il codice
#           reale a ogni passo, deterministico — vuoto = niente "code" nei passi);
#           max_flows = quanti flow (dedotti) restituire al massimo.
# Output:   stringa JSON compatta con l'inventario dei flow (source/sink file:line, passi,
#           e l'intera CATENA "path" con il codice reale a ogni hop); NESSUna etichetta CWE.
# Come realizzato: esegue il template "flow_inventory.ql.tmpl" con cwe="" (i segnaposto
#            CWE si svuotano), poi deduplica per (source, sink), tronca a max_flows e
#            riassume. Il "path" completo (gia' calcolato da CodeQL in flow_path, prima
#            scartato) viene arricchito col codice reale letto dal disco (_read_line) —
#            cosi' i nomi/variabili di ogni hop sono CERTI, mai indovinati da un LLM.
#            L'inventario completo (SARIF) resta su disco (Claim Check).
@mcp.tool()
def find_all_flows(db_path: str, repo_path: str = "", max_flows: int = 200) -> str:
    """List ALL data-flows from untrusted input to any call argument (CWE-agnostic).

    This is the Detection-phase tool: it surfaces every flow the untrusted data
    takes WITHOUT committing to a vulnerability class (no CWE, no standard query),
    so the model is not biased. Source = RemoteFlowSource (where external input
    enters). Sink = the argument of ANY call (a structural "something happens
    here"). Each flow includes the full intermediate `path` (file:line + the real
    source code at each hop, read deterministically from disk — never guessed) so
    the real variable/function names are already certain. You then judge which
    sinks are dangerous and VERIFY them in Validation.

    Args:
        db_path: Path returned by create_codeql_database.
        repo_path: Absolute path to the repository root, to read the real code at
            each step of the path. Omit to skip (path steps will have no `code`).
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
        raw_path = f.get("flow_path", []) or []
        path = [
            {"file": step.get("file"), "line": step.get("line"),
             "code": _read_line(repo_path, step.get("file"), step.get("line"))}
            for step in raw_path[:_MAX_PATH_STEPS]
        ]
        flows.append({
            "source": {"file": src.get("file"), "line": src.get("line")},
            "sink": {"file": snk.get("file"), "line": snk.get("line")},
            "sink_hint": (snk.get("note") or "")[:120],
            "steps": f.get("flow_steps", 0),
            "path": path,
            "path_truncated": len(raw_path) > _MAX_PATH_STEPS,
        })

    total = len(flows)
    return json.dumps({
        "flow_count": total,
        "returned": min(total, max_flows),
        "truncated": total > max_flows,
        "flows": flows[:max_flows],
        "note": "CWE-agnostic flow inventory: untrusted input -> a call argument. "
                "Each flow's `path` gives the real code at every hop (deterministic, "
                "read from disk) — use those exact names, never guess. No vulnerability "
                "class is implied. Decide which sinks are dangerous and VERIFY them in "
                "Validation (run_taint_query with cwe + the real names from `path`).",
    }, indent=2)


# Keyword-argument "di sicurezza" la cui presenza con un literal va segnalata.
_FLAG_PARAM_DEFAULTS = [
    "verify", "shell", "autoescape", "debug", "secure", "httponly",
    "samesite", "check_hostname", "ssl_verify",
]


# Obiettivo: routine condivisa dagli 8 tool di categoria sotto: esegue UN template
#            (gia' scoperto a un solo kind), deduplica per (file,line) e tronca — stesso
#            output compatto {op_count, by_kind, operations} di prima, ma un tool = UNA
#            categoria, cosi' quando l'agente lo chiama sa gia' a che famiglia appartiene.
# Input:    db_path; template_name = file .ql.tmpl; replacements = segnaposto specifici
#           (puo' essere {}); kind = etichetta fissa di questa categoria; max_ops; note;
#           repo_path = radice del progetto, per leggere il CODICE REALE di ogni
#           operazione (deterministico — vuoto = niente "code").
# Output:   stringa JSON compatta {op_count, returned, truncated, by_kind, operations}.
def _find_sensitive_kind(db_path: str, template_name: str, replacements: dict,
                          kind: str, max_ops: int, note: str, repo_path: str = "") -> str:
    raw = render_and_analyze(
        db_path, template_name, replacements, out_prefix=kind.replace("-", "_"), cwe="",
    )
    try:
        payload = json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        return raw
    if "error" in payload:
        return raw

    seen: set = set()
    ops: list[dict] = []
    for f in payload.get("findings", []) or []:
        key = (f.get("file"), f.get("line"))
        if key in seen:
            continue
        seen.add(key)
        ops.append({
            "kind": kind, "file": f.get("file"), "line": f.get("line"),
            "code": _read_line(repo_path, f.get("file"), f.get("line")),
        })

    total = len(ops)
    return json.dumps({
        "op_count": total,
        "returned": min(total, max_ops),
        "truncated": total > max_ops,
        "by_kind": {kind: total} if total else {},
        "operations": ops[:max_ops],
        "note": note,
    }, indent=2)


_NON_FLOW_NOTE = (
    "CWE-agnostic point detection (no data-flow needed): the operation exists, "
    "regardless of whether untrusted input reaches it. In Validation, verify with "
    "run_api_misuse_query / run_insecure_config_flag_query / check_* and associate "
    "the CWE from the evidence."
)


@mcp.tool()
def find_command_execution(db_path: str, repo_path: str = "", max_ops: int = 200) -> str:
    """List system command execution calls (semantic Concept), regardless of data flow.
    Each item includes the real source `code` at that line (read from disk, deterministic).

    Args:
        db_path: Path returned by create_codeql_database.
        repo_path: Absolute path to the repository root (to read the real code).
        max_ops: Max number of (deduplicated) operations to return (default 200).
    """
    return _find_sensitive_kind(db_path, "command_exec.ql.tmpl", {}, "command-exec",
                                 max_ops, _NON_FLOW_NOTE, repo_path)


@mcp.tool()
def find_code_execution(db_path: str, repo_path: str = "", max_ops: int = 200) -> str:
    """List dynamic code execution calls (exec/eval/compile), regardless of data flow.
    Each item includes the real source `code` at that line (read from disk, deterministic).

    Args:
        db_path: Path returned by create_codeql_database.
        repo_path: Absolute path to the repository root (to read the real code).
        max_ops: Max number of (deduplicated) operations to return (default 200).
    """
    return _find_sensitive_kind(db_path, "code_exec.ql.tmpl", {}, "code-exec",
                                 max_ops, _NON_FLOW_NOTE, repo_path)


@mcp.tool()
def find_sql_execution(db_path: str, repo_path: str = "", max_ops: int = 200) -> str:
    """List SQL execution calls (semantic Concept), regardless of data flow.
    Each item includes the real source `code` at that line (read from disk, deterministic).

    Args:
        db_path: Path returned by create_codeql_database.
        repo_path: Absolute path to the repository root (to read the real code).
        max_ops: Max number of (deduplicated) operations to return (default 200).
    """
    return _find_sensitive_kind(db_path, "sql_exec.ql.tmpl", {}, "sql-exec",
                                 max_ops, _NON_FLOW_NOTE, repo_path)


@mcp.tool()
def find_filesystem_access(db_path: str, repo_path: str = "", max_ops: int = 200) -> str:
    """List filesystem access calls (semantic Concept), regardless of data flow.
    Each item includes the real source `code` at that line (read from disk, deterministic).

    Args:
        db_path: Path returned by create_codeql_database.
        repo_path: Absolute path to the repository root (to read the real code).
        max_ops: Max number of (deduplicated) operations to return (default 200).
    """
    return _find_sensitive_kind(db_path, "filesystem_access.ql.tmpl", {}, "filesystem",
                                 max_ops, _NON_FLOW_NOTE, repo_path)


@mcp.tool()
def find_decoding_operations(db_path: str, repo_path: str = "", max_ops: int = 200) -> str:
    """List decoding calls (base64/pickle/marshal, semantic Concept) — often a precursor
    to unsafe deserialization. Regardless of data flow. Each item includes the real
    source `code` at that line (read from disk, deterministic).

    Args:
        db_path: Path returned by create_codeql_database.
        repo_path: Absolute path to the repository root (to read the real code).
        max_ops: Max number of (deduplicated) operations to return (default 200).
    """
    return _find_sensitive_kind(db_path, "decoding_ops.ql.tmpl", {}, "decoding",
                                 max_ops, _NON_FLOW_NOTE, repo_path)


@mcp.tool()
def find_crypto_operations(db_path: str, repo_path: str = "", max_ops: int = 200) -> str:
    """List cryptographic operations (semantic Concept, resolves hashlib/cryptography/
    Cryptodome). Reports ANY crypto op, weak or strong — Validation judges which. Each
    item includes the real source `code` at that line (read from disk, deterministic),
    so the exact algorithm (e.g. md5 vs AES-GCM) is already certain, never guessed.

    Args:
        db_path: Path returned by create_codeql_database.
        repo_path: Absolute path to the repository root (to read the real code).
        max_ops: Max number of (deduplicated) operations to return (default 200).
    """
    return _find_sensitive_kind(db_path, "crypto_ops.ql.tmpl", {}, "crypto",
                                 max_ops, _NON_FLOW_NOTE, repo_path)


@mcp.tool()
def find_weak_randomness(db_path: str, repo_path: str = "", max_ops: int = 200) -> str:
    """List calls to a curated list of randomness-related names (name-based fallback:
    CodeQL has no Concept for insecure randomness). Regardless of data flow. Each item
    includes the real source `code` at that line (read from disk, deterministic).

    Args:
        db_path: Path returned by create_codeql_database.
        repo_path: Absolute path to the repository root (to read the real code).
        max_ops: Max number of (deduplicated) operations to return (default 200).
    """
    weak = ["random", "randint", "randrange", "uniform", "getrandbits", "choice",
            "loads", "load"]
    ref = lookup_cwe("CWE-330") or {}
    weak += ref.get("weak_call_names", []) or []
    weak += ref.get("bad_constants", []) or []
    weak = list(dict.fromkeys(weak))  # dedup preserving order
    return _find_sensitive_kind(
        db_path, "weak_randomness.ql.tmpl", {"{{WEAK_CALL_NAMES}}": render_names(weak)},
        "weak-randomness", max_ops, _NON_FLOW_NOTE, repo_path,
    )


@mcp.tool()
def find_insecure_config_flags(db_path: str, repo_path: str = "", max_ops: int = 200) -> str:
    """List calls passing a security-relevant kwarg (verify=/shell=/debug=/...) as a
    literal value (structural, not name-based). Regardless of data flow. Each item
    includes the real source `code` at that line (read from disk, deterministic), so
    the actual literal value (e.g. verify=False) is already certain, never guessed.

    Args:
        db_path: Path returned by create_codeql_database.
        repo_path: Absolute path to the repository root (to read the real code).
        max_ops: Max number of (deduplicated) operations to return (default 200).
    """
    return _find_sensitive_kind(
        db_path, "insecure_config_flags.ql.tmpl",
        {"{{FLAG_PARAM_NAMES}}": render_names(_FLAG_PARAM_DEFAULTS)},
        "config-flag", max_ops, _NON_FLOW_NOTE, repo_path,
    )


# Obiettivo: eseguire PIU' query ufficiali standalone (stessa famiglia/categoria) e fondere i
#            loro finding in un unico inventario compatto, stessa forma di
#            find_sensitive_operations (op_count/by_kind/operations), cosi' i tool di
#            categoria sotto possono riusare identica compattazione (dedup + cap + group).
# Input:    db_path = database; files_and_kinds = lista di (percorso .ql, kind leggibile);
#           max_ops = quante operazioni (dedotte) restituire al massimo.
# Output:   stringa JSON compatta {op_count, returned, truncated, by_kind, operations, note}.
# Come realizzato: chiama analyze_with_query un file alla volta (ognuno e' gia' una query
#            standalone ufficiale, nessun template da riempire), tagga ogni finding col kind
#            del file da cui viene, deduplica per (kind, file, line) e tronca.
def _run_query_family(db_path: str, files_and_kinds: list[tuple[Path, str]], note: str,
                       max_ops: int = 200, repo_path: str = "") -> str:
    seen: set = set()
    ops: list[dict] = []
    by_kind: dict[str, int] = {}
    for query_file, kind in files_and_kinds:
        raw = analyze_with_query(db_path, query_file)
        try:
            payload = json.loads(raw)
        except (json.JSONDecodeError, ValueError):
            continue
        if "error" in payload:
            continue
        for f in payload.get("findings", []) or []:
            key = (kind, f.get("file"), f.get("line"))
            if key in seen:
                continue
            seen.add(key)
            ops.append({
                "kind": kind, "file": f.get("file"), "line": f.get("line"),
                "code": _read_line(repo_path, f.get("file"), f.get("line")),
            })
            by_kind[kind] = by_kind.get(kind, 0) + 1

    total = len(ops)
    return json.dumps({
        "op_count": total,
        "returned": min(total, max_ops),
        "truncated": total > max_ops,
        "by_kind": by_kind,
        "operations": ops[:max_ops],
        "note": note,
    }, indent=2)


# Obiettivo: dare alla DETECTION un segnale di sicurezza NON legato a un CWE specifico: una
#            gestione delle eccezioni troppo ampia o vuota puo' nascondere silenziosamente un
#            fallimento di autenticazione/validazione/crypto. Usa query UFFICIALI (non nostre).
# Input:    db_path = database; max_ops = quante operazioni (dedotte) restituire.
# Output:   stringa JSON compatta {op_count, by_kind, operations:[{kind,file,line}]}.
@mcp.tool()
def find_exception_handling_issues(db_path: str, repo_path: str = "", max_ops: int = 200) -> str:
    """List suspicious exception-handling patterns (official CodeQL queries).

    A silently swallowed or overly broad except clause can hide an authentication,
    validation, or crypto failure. Not a CWE by itself: cross-reference with the code
    before treating it as a real finding (e.g. an empty except in a non-security
    context is normal). Each item includes the real source `code` at that line (read
    from disk, deterministic).

    Args:
        db_path: Path returned by create_codeql_database.
        repo_path: Absolute path to the repository root (to read the real code).
        max_ops: Max number of (deduplicated) issues to return (default 200).
    """
    base = config.STANDARD_QUERY_DIR
    files = [
        (base / "Exceptions/EmptyExcept.ql", "empty-except"),
        (base / "Exceptions/CatchingBaseException.ql", "catch-base-exception"),
        (base / "Statements/UnusedExceptionObject.ql", "unused-exception-object"),
    ]
    return _run_query_family(
        db_path, files, max_ops=max_ops, repo_path=repo_path,
        note="Non-CWE security signal: suspicious exception handling. Cross-reference "
             "with the code before flagging — only report if it plausibly hides a "
             "security-relevant failure.",
    )


# Obiettivo: dare alla DETECTION un segnale su regex usate come sanitizer/validatore che
#            in realta' NON fanno quello che sembrano (bug di correttezza della regex) — un
#            falso senso di sicurezza che puo' abilitare un bypass. Query UFFICIALI.
@mcp.tool()
def find_broken_sanitizer_patterns(db_path: str, repo_path: str = "", max_ops: int = 200) -> str:
    """List regex-correctness bugs that may break an input sanitizer/validator (official).

    A regex used to validate/sanitize input that doesn't actually match what it looks
    like it should (unmatchable anchor, duplicate char in class, incomplete group) gives
    a false sense of security. Not a CWE by itself: check whether the regex is actually
    used as a security control before treating it as a real finding. Each item includes
    the real source `code` at that line (read from disk, deterministic).

    Args:
        db_path: Path returned by create_codeql_database.
        repo_path: Absolute path to the repository root (to read the real code).
        max_ops: Max number of (deduplicated) issues to return (default 200).
    """
    base = config.STANDARD_QUERY_DIR / "Expressions" / "Regex"
    files = [
        (base / "BackspaceEscape.ql", "regex-backspace-escape"),
        (base / "DuplicateCharacterInSet.ql", "regex-duplicate-in-class"),
        (base / "MissingPartSpecialGroup.ql", "regex-incomplete-special-group"),
        (base / "UnmatchableCaret.ql", "regex-unmatchable-caret"),
        (base / "UnmatchableDollar.ql", "regex-unmatchable-dollar"),
    ]
    return _run_query_family(
        db_path, files, max_ops=max_ops, repo_path=repo_path,
        note="Non-CWE security signal: a broken regex. Only relevant if that regex is "
             "used as an input sanitizer/validator — check the surrounding code.",
    )


# Obiettivo: dare alla DETECTION un segnale su gestione delle risorse scorretta (file non
#            sempre chiusi, mancato uso di 'with') — leak di risorse / possibile DoS. Query
#            UFFICIALI.
@mcp.tool()
def find_resource_handling_issues(db_path: str, repo_path: str = "", max_ops: int = 200) -> str:
    """List resource-handling issues (official CodeQL queries): possible leak / DoS.

    A file that is not always closed, or code that should use a `with` statement, can
    leak resources and contribute to a denial-of-service under load. Not a CWE by
    itself: cross-reference with the code before treating it as a real finding. Each
    item includes the real source `code` at that line (read from disk, deterministic).

    Args:
        db_path: Path returned by create_codeql_database.
        repo_path: Absolute path to the repository root (to read the real code).
        max_ops: Max number of (deduplicated) issues to return (default 200).
    """
    base = config.STANDARD_QUERY_DIR
    files = [
        (base / "Resources/FileNotAlwaysClosed.ql", "file-not-closed"),
        (base / "Statements/ShouldUseWithStatement.ql", "should-use-with"),
    ]
    return _run_query_family(
        db_path, files, max_ops=max_ops, repo_path=repo_path,
        note="Non-CWE security signal: resource handling. Relevant mainly for "
             "long-running services (possible DoS via resource exhaustion).",
    )
