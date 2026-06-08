"""MCP server exposing CodeQL as tools.

Run standalone for a quick smoke test:
    python codeql_mcp_server.py
The agent launches it automatically as a stdio subprocess (see agent.py).

Tools exposed:
    list_python_files     - enumerate .py files in a repo (lets the LLM go "file per file")
    create_codeql_database- build a CodeQL DB from a repo
    analyze_database      - run a standard security suite, return parsed findings
    run_custom_query      - run a single .ql file against a DB
    read_file_snippet     - read source lines around a finding
"""
from __future__ import annotations

import hashlib
import json
import re
import subprocess
from pathlib import Path

from mcp.server.fastmcp import FastMCP

import config

mcp = FastMCP("codeql")


def _run(cmd: list[str], timeout: int = config.CODEQL_TIMEOUT) -> tuple[int, str, str]:
    """Run a CodeQL command, return (returncode, stdout, stderr)."""
    proc = subprocess.run(
        cmd, capture_output=True, text=True, timeout=timeout, encoding="utf-8", errors="replace"
    )
    return proc.returncode, proc.stdout, proc.stderr


def _db_path_for(repo_path: str) -> Path:
    """Deterministic DB path per repo, so re-runs reuse the same slot."""
    digest = hashlib.sha1(str(Path(repo_path).resolve()).encode()).hexdigest()[:10]
    name = Path(repo_path).resolve().name
    return config.WORK_DIR / f"db_{name}_{digest}"


def _parse_sarif(sarif_path: Path) -> list[dict]:
    """Flatten a SARIF v2.1.0 file into a list of findings."""
    data = json.loads(sarif_path.read_text(encoding="utf-8"))
    findings: list[dict] = []
    for run in data.get("runs", []):
        # Build a ruleId -> severity lookup from the rule metadata.
        rules = {}
        for rule in run.get("tool", {}).get("driver", {}).get("rules", []):
            props = rule.get("properties", {})
            rules[rule.get("id")] = {
                "severity": props.get("security-severity") or props.get("problem.severity", ""),
                "name": rule.get("name", rule.get("id", "")),
                "tags": props.get("tags", []),
            }
        for res in run.get("results", []):
            rid = res.get("ruleId", "")
            loc = (res.get("locations") or [{}])[0].get("physicalLocation", {})
            tags = rules.get(rid, {}).get("tags", [])
            flow_path = _extract_flow(res)
            findings.append(
                {
                    "rule_id": rid,
                    "rule_name": rules.get(rid, {}).get("name", rid),
                    "level": res.get("level", "warning"),
                    "security_severity": rules.get(rid, {}).get("severity", ""),
                    "tags": tags,
                    "cwe": _cwe_from_tags(tags),
                    "message": res.get("message", {}).get("text", ""),
                    # The sink: where tainted data is used.
                    "file": loc.get("artifactLocation", {}).get("uri", ""),
                    "line": loc.get("region", {}).get("startLine"),
                    # Deterministic evidence: the full source -> sink data-flow path.
                    "source": flow_path[0] if flow_path else None,
                    "sink": flow_path[-1] if flow_path else None,
                    "flow_path": flow_path,
                    "flow_steps": len(flow_path),
                }
            )
    return findings


def _loc_brief(physical):
    return {
        "file": physical.get("artifactLocation", {}).get("uri", ""),
        "line": physical.get("region", {}).get("startLine"),
    }


def _extract_flow(result):
    """Pull the source->sink data-flow path from a SARIF path-problem result."""
    steps = []
    for cf in result.get("codeFlows", []):
        for tf in cf.get("threadFlows", []):
            for loc in tf.get("locations", []):
                physical = loc.get("location", {}).get("physicalLocation", {})
                entry = _loc_brief(physical)
                msg = loc.get("location", {}).get("message", {}).get("text", "")
                if msg:
                    entry["note"] = msg
                steps.append(entry)
            if steps:
                return steps  # first thread flow is enough for the report
    return steps


# CWE knowledge base ("wiki"): canonical names, taint intuition, candidate
# source/sink/sanitizer names, remediation. Single source of truth, loaded from
# JSON so it is editable like a wiki. Used both for report grounding and to give
# the agent awareness of each vulnerability class.
def _load_json(path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


# Curated detection wiki (CWEs the templates/checks can verify) + full official
# catalog (all ~969 CWEs, lookup-only fallback built from the MITRE XML).
CWE_REFERENCE = _load_json(config.CWE_WIKI_PATH)
CWE_CATALOG = _load_json(config.CWE_CATALOG_PATH)


def _cwe_from_tags(tags):
    """Derive a CWE id like 'CWE-89' from SARIF rule tags (external/cwe/cwe-089)."""
    for t in tags or []:
        m = re.search(r"cwe[-/](\d+)", str(t), re.IGNORECASE)
        if m:
            return f"CWE-{int(m.group(1))}"
    return None


@mcp.tool()
def list_python_files(repo_path: str, max_files: int = 500) -> str:
    """List Python source files in a repository (skips venv/site-packages/.git).

    Args:
        repo_path: Absolute path to the repository root.
        max_files: Cap on number of files returned.
    """
    root = Path(repo_path)
    if not root.is_dir():
        return json.dumps({"error": f"Not a directory: {repo_path}"})
    skip = {".git", ".venv", "venv", "__pycache__", "site-packages", "node_modules"}
    files = []
    for p in root.rglob("*.py"):
        if any(part in skip for part in p.parts):
            continue
        files.append(str(p.relative_to(root)))
        if len(files) >= max_files:
            break
    return json.dumps({"count": len(files), "files": files}, indent=2)


@mcp.tool()
def create_codeql_database(repo_path: str, language: str = "python") -> str:
    """Create a CodeQL database from a repository. Returns the database path.

    For interpreted languages (python, javascript) no build command is needed.

    Args:
        repo_path: Absolute path to the repository root.
        language: CodeQL language identifier (default: python).
    """
    repo = Path(repo_path)
    if not repo.is_dir():
        return json.dumps({"error": f"Not a directory: {repo_path}"})
    db = _db_path_for(repo_path)
    cmd = [
        config.CODEQL_BIN, "database", "create", str(db),
        f"--language={language}", f"--source-root={repo}", "--overwrite",
    ]
    try:
        rc, out, err = _run(cmd)
    except subprocess.TimeoutExpired:
        return json.dumps({"error": "database create timed out", "db_path": str(db)})
    if rc != 0:
        return json.dumps({"error": "database create failed", "stderr": err[-2000:]})
    return json.dumps({"db_path": str(db), "language": language, "status": "created"})


@mcp.tool()
def analyze_database(db_path: str, suite: str = "") -> str:
    """Run a CodeQL security suite against a database and return parsed findings.

    Args:
        db_path: Path returned by create_codeql_database.
        suite: Query suite (default: the configured python-security-extended.qls).
    """
    db = Path(db_path)
    if not db.is_dir():
        return json.dumps({"error": f"DB not found: {db_path}"})
    suite = suite or config.DEFAULT_SUITE
    sarif = Path(db_path).parent / f"{Path(db_path).name}.sarif"
    cmd = [
        config.CODEQL_BIN, "database", "analyze", str(db), suite,
        f"--search-path={config.CODEQL_SEARCH_PATH}",
        "--format=sarifv2.1.0", f"--output={sarif}", "--rerun",
    ]
    try:
        rc, out, err = _run(cmd)
    except subprocess.TimeoutExpired:
        return json.dumps({"error": "analyze timed out"})
    if rc != 0:
        return json.dumps({"error": "analyze failed", "stderr": err[-2000:]})
    findings = _parse_sarif(sarif)
    return json.dumps(
        {"sarif_path": str(sarif), "finding_count": len(findings), "findings": findings},
        indent=2,
    )


def _analyze_with_query(db_path: str, query_file: Path, extra: dict | None = None) -> str:
    """Run one .ql file against a DB and return parsed findings as JSON.

    Shared by run_custom_query and the per-CWE encapsulated tools.
    """
    db = Path(db_path)
    if not db.is_dir():
        return json.dumps({"error": f"DB not found: {db_path}"})
    if not query_file.is_file():
        return json.dumps({"error": f"Query not found: {query_file}"})
    sarif = db.parent / f"{db.name}_{query_file.stem}.sarif"
    cmd = [
        config.CODEQL_BIN, "database", "analyze", str(db), str(query_file),
        f"--search-path={config.CODEQL_SEARCH_PATH}",
        "--format=sarifv2.1.0", f"--output={sarif}", "--rerun",
    ]
    try:
        rc, out, err = _run(cmd)
    except subprocess.TimeoutExpired:
        return json.dumps({"error": "query timed out", "query": query_file.name})
    if rc != 0:
        return json.dumps({"error": "query failed", "query": query_file.name, "stderr": err[-2000:]})
    findings = _parse_sarif(sarif)
    payload = {"query": query_file.name, "finding_count": len(findings), "findings": findings}
    if extra:
        payload.update(extra)
    return json.dumps(payload, indent=2)


@mcp.tool()
def run_custom_query(db_path: str, query_path: str) -> str:
    """Run an arbitrary custom .ql query file against a database.

    Use this for ad-hoc queries. For the well-known CWE checks, prefer the
    dedicated check_* tools.

    Args:
        db_path: Path returned by create_codeql_database.
        query_path: Absolute path to a .ql file.
    """
    return _analyze_with_query(db_path, Path(query_path))


def _make_cwe_tool(key: str, cwe: str, name: str, filename: str):
    """Build and register a dedicated MCP tool that runs one encapsulated query."""
    query_file = config.CUSTOM_QUERY_DIR / filename

    def tool(db_path: str) -> str:
        return _analyze_with_query(db_path, query_file, extra={"cwe": cwe, "check": name})

    tool.__name__ = f"check_{key}"
    tool.__doc__ = (
        f"Check the CodeQL database for {name} ({cwe}).\n\n"
        f"Runs the encapsulated query '{filename}' and returns findings\n"
        f"(rule, severity, file, line, message).\n\n"
        f"Args:\n    db_path: Path returned by create_codeql_database."
    )
    mcp.add_tool(tool)


for _key, (_cwe, _name, _file) in config.CUSTOM_QUERIES.items():
    _make_cwe_tool(_key, _cwe, _name, _file)


_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_SENTINEL = "__never_matches__"


_CONST_RE = re.compile(r"^[A-Za-z0-9._\-]+$")


def _render_names(names) -> str:
    """Validate identifier names and render them as a QL string list body.

    Returns a comma-separated list of quoted strings. Empty/invalid -> sentinel
    that matches nothing, keeping the `in [...]` expression always valid.
    """
    clean = [n for n in (names or []) if isinstance(n, str) and _NAME_RE.match(n)]
    if not clean:
        clean = [_SENTINEL]
    return ", ".join(f'"{n}"' for n in clean)


def _render_consts(values) -> str:
    """Like _render_names but for constant literals (lowercased, broader charset)."""
    clean = [v.lower() for v in (values or []) if isinstance(v, str) and _CONST_RE.match(v)]
    if not clean:
        clean = [_SENTINEL]
    return ", ".join(f'"{v}"' for v in clean)


def _normalize_cwe(cwe):
    """'CWE-89' / 'cwe-89' / '89' -> ('CWE-89', 'external/cwe/cwe-089', '-cwe-089')."""
    if not cwe:
        return None, "", ""
    m = re.search(r"(\d+)", str(cwe))
    if not m:
        return None, "", ""
    num = int(m.group(1))
    return f"CWE-{num}", f"external/cwe/cwe-{num:03d}", f"-cwe-{num:03d}"


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
    bad = [n for n in (sink_names or []) if not (isinstance(n, str) and _NAME_RE.match(n))]
    if not sink_names:
        return json.dumps({"error": "sink_names is required and must be non-empty"})
    if bad:
        return json.dumps({"error": f"invalid names (must be identifiers): {bad}"})

    tmpl_path = config.TEMPLATE_DIR / "taint_namebased.ql.tmpl"
    if not tmpl_path.is_file():
        return json.dumps({"error": f"template not found: {tmpl_path}"})

    cwe_id, cwe_tag, cwe_suffix = _normalize_cwe(cwe)
    cwe_tag_line = f"\n *       {cwe_tag}" if cwe_tag else ""

    rendered = (
        tmpl_path.read_text(encoding="utf-8")
        .replace("{{SINK_NAMES}}", _render_names(sink_names))
        .replace("{{SOURCE_NAMES}}", _render_names(source_names))
        .replace("{{SANITIZER_NAMES}}", _render_names(sanitizer_names))
        .replace("{{CWE_ID_SUFFIX}}", cwe_suffix)
        .replace("{{CWE_TAG_LINE}}", cwe_tag_line)
    )

    config.GENERATED_DIR.mkdir(exist_ok=True)
    tag = hashlib.sha1(rendered.encode()).hexdigest()[:10]
    out_ql = config.GENERATED_DIR / f"taint_{tag}.ql"
    out_ql.write_text(rendered, encoding="utf-8")

    ref = CWE_REFERENCE.get(cwe_id, {}) if cwe_id else {}
    result = _analyze_with_query(
        db_path, out_ql,
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
    return result


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
    bad = [n for n in (weak_call_names or []) if not (isinstance(n, str) and _NAME_RE.match(n))]
    if bad:
        return json.dumps({"error": f"invalid call names (must be identifiers): {bad}"})

    tmpl_path = config.TEMPLATE_DIR / "api_misuse_namebased.ql.tmpl"
    if not tmpl_path.is_file():
        return json.dumps({"error": f"template not found: {tmpl_path}"})

    cwe_id, cwe_tag, cwe_suffix = _normalize_cwe(cwe)
    cwe_tag_line = f"\n *       {cwe_tag}" if cwe_tag else ""

    rendered = (
        tmpl_path.read_text(encoding="utf-8")
        .replace("{{WEAK_CALL_NAMES}}", _render_names(weak_call_names))
        .replace("{{BAD_CONSTANTS}}", _render_consts(bad_constants))
        .replace("{{CWE_ID_SUFFIX}}", cwe_suffix)
        .replace("{{CWE_TAG_LINE}}", cwe_tag_line)
    )

    config.GENERATED_DIR.mkdir(exist_ok=True)
    tag = hashlib.sha1(rendered.encode()).hexdigest()[:10]
    out_ql = config.GENERATED_DIR / f"apimisuse_{tag}.ql"
    out_ql.write_text(rendered, encoding="utf-8")

    ref = CWE_REFERENCE.get(cwe_id, {}) if cwe_id else {}
    return _analyze_with_query(
        db_path, out_ql,
        extra={
            "template": "api_misuse_namebased",
            "cwe": cwe_id,
            "cwe_name": ref.get("name"),
            "standard_remediation": ref.get("remediation"),
            "weak_call_names": weak_call_names or [],
            "bad_constants": bad_constants or [],
        },
    )


# Friendly tool-name slugs for the curated crypto checks (one per api_misuse CWE).
CRYPTO_CHECK_SLUGS = {
    "CWE-328": "weak_hash",
    "CWE-327": "broken_crypto",
    "CWE-330": "weak_random",
    "CWE-916": "weak_password_hash",
}


def _make_crypto_check_tool(cwe_id: str, slug: str, data: dict):
    """Register a fixed check_<slug>(db_path) tool wrapping run_api_misuse_query
    with the weak-API preset from the wiki. Mirrors the taint check_* tools so a
    small model reliably runs the crypto family too."""
    weak = data.get("weak_call_names", [])
    consts = data.get("bad_constants", [])
    name = data.get("name", cwe_id)

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
        _make_crypto_check_tool(_cid, _slug, CWE_REFERENCE[_cid])


# Insecure configuration flag detection (point-detection, not taint).
# Built-in templates for common cases (verify=False, shell=True, etc.).
INSECURE_CONFIG_FLAG_TEMPLATES = {
    "verify_false": ("CWE-295", "insecure_verify_false"),
    "shell_true": ("CWE-78", "insecure_shell_true"),
    "autoescape_false": ("CWE-79", "insecure_autoescape_false"),
    "debug_true": ("CWE-489", "insecure_debug_true"),
    "weak_hash": ("CWE-327", "insecure_weak_hash"),
    "weak_randomness": ("CWE-330", "insecure_randomness"),
    "cookie_flags": ("CWE-614", "insecure_cookie_flags"),
}


def _make_insecure_config_tool(key: str, cwe: str, template_name: str):
    """Build and register a dedicated tool for insecure config flag detection."""
    template_file = config.TEMPLATE_DIR / f"{template_name}.ql.tmpl"

    def tool(db_path: str) -> str:
        if not template_file.is_file():
            return json.dumps({"error": f"template not found: {template_file}"})

        cwe_id, cwe_tag, cwe_suffix = _normalize_cwe(cwe)
        cwe_tag_line = f"\n *       {cwe_tag}" if cwe_tag else ""

        rendered = (
            template_file.read_text(encoding="utf-8")
            .replace("{{CWE_ID_SUFFIX}}", cwe_suffix)
            .replace("{{CWE_TAG_LINE}}", cwe_tag_line)
        )

        config.GENERATED_DIR.mkdir(exist_ok=True)
        tag = hashlib.sha1(rendered.encode()).hexdigest()[:10]
        out_ql = config.GENERATED_DIR / f"{template_name}_{tag}.ql"
        out_ql.write_text(rendered, encoding="utf-8")

        ref = CWE_REFERENCE.get(cwe_id, {}) if cwe_id else {}
        return _analyze_with_query(
            db_path, out_ql,
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
    _make_insecure_config_tool(_key, _cwe, _tmpl)


@mcp.tool()
def run_insecure_config_flag_query(
    db_path: str,
    module: str,
    functions: list[str],
    param_name: str,
    insecure_value: str,
    cwe: str = "",
) -> str:
    """Detect insecure configuration flags using a generic parametrized template.

    This tool allows you to search for calls to specific functions with insecure
    keyword arguments (e.g., verify=False, shell=True, autoescape=False).
    Use this for custom patterns not covered by the built-in check_insecure_* tools.

    Args:
        db_path: Path returned by create_codeql_database.
        module: Python module name (e.g., "requests", "subprocess", "jinja2").
        functions: List of function names to check (e.g., ["get", "post", "run"]).
        param_name: The keyword parameter name (e.g., "verify", "shell", "autoescape").
        insecure_value: The insecure value as a string (e.g., "false", "true", "none").
        cwe: Vulnerability class, e.g. "CWE-295"; stamped into the evidence.
    """
    # Validate inputs
    if not all(isinstance(n, str) and _NAME_RE.match(n) for n in functions):
        return json.dumps({"error": "invalid function names (must be identifiers)"})
    if not (isinstance(param_name, str) and _NAME_RE.match(param_name)):
        return json.dumps({"error": "param_name must be an identifier"})
    if not (isinstance(module, str) and _NAME_RE.match(module)):
        return json.dumps({"error": "module must be an identifier"})

    tmpl_path = config.TEMPLATE_DIR / "insecure_config_flag_generic.ql.tmpl"
    if not tmpl_path.is_file():
        return json.dumps({"error": f"template not found: {tmpl_path}"})

    cwe_id, cwe_tag, cwe_suffix = _normalize_cwe(cwe)
    cwe_tag_line = f"\n *       {cwe_tag}" if cwe_tag else ""

    # Build the MODULE_MEMBER_CHAIN and PARAM_CONDITION for the template
    func_list = ", ".join(f'"{f}"' for f in functions)
    module_chain = (
        f'call = API::moduleImport("{module}").getMember([{func_list}]).getACall()'
    )

    # Check if value is boolean or string
    if insecure_value.lower() in ["true", "false"]:
        param_condition = (
            f'call.getKeywordParameter("{param_name}")'
            f'.getAValueReachingSink().asExpr().(ImmutableLiteral)'
            f'.booleanValue() = {insecure_value.lower()}'
        )
    else:
        # String comparison
        param_condition = (
            f'exists(StringLiteral s | s = call.getKeywordParameter("{param_name}")'
            f'.getAValueReachingSink().asExpr() and '
            f's.getText().toLowerCase() in ["\'{insecure_value.lower()}\'", '
            f'"\\\"{insecure_value.lower()}\\\""])'
        )

    message = (
        f"Insecure configuration: {module}.{functions[0]}(..., {param_name}={insecure_value}). "
        f"This is vulnerable to {cwe_id or 'security issues'}."
    )

    rendered = (
        tmpl_path.read_text(encoding="utf-8")
        .replace("{{MODULE_MEMBER_CHAIN}}", module_chain)
        .replace("{{PARAM_CONDITION}}", param_condition)
        .replace("{{MESSAGE}}", message)
        .replace("{{CWE_ID_SUFFIX}}", cwe_suffix)
        .replace("{{CWE_TAG_LINE}}", cwe_tag_line)
    )

    config.GENERATED_DIR.mkdir(exist_ok=True)
    tag = hashlib.sha1(rendered.encode()).hexdigest()[:10]
    out_ql = config.GENERATED_DIR / f"insecure_config_flag_custom_{tag}.ql"
    out_ql.write_text(rendered, encoding="utf-8")

    ref = CWE_REFERENCE.get(cwe_id, {}) if cwe_id else {}
    return _analyze_with_query(
        db_path, out_ql,
        extra={
            "template": "insecure_config_flag_generic",
            "cwe": cwe_id,
            "cwe_name": ref.get("name"),
            "standard_remediation": ref.get("remediation"),
            "module": module,
            "functions": functions,
            "param_name": param_name,
            "insecure_value": insecure_value,
        },
    )


@mcp.tool()
def list_cwes() -> str:
    """List the vulnerability classes (CWEs) the agent knows about.

    Returns each CWE id with its name and one-line description. Call
    cwe_knowledge(cwe) to get the full page for one of them.
    """
    def _tool_for(data: dict) -> str:
        det = data.get("detection", "taint")
        # The wiki's actions.tool is authoritative when present (e.g. the
        # dedicated check_insecure_* tool for an insecure_config_flag CWE).
        if data.get("actions", {}).get("tool"):
            return data["actions"]["tool"]
        if det == "api_misuse":
            return "run_api_misuse_query"
        if det == "insecure_config_flag":
            return "run_insecure_config_flag_query"
        return "run_taint_query"

    out = [
        {
            "cwe": cid,
            "name": data.get("name", ""),
            "detection": data.get("detection", "taint"),
            "tool": _tool_for(data),
            "description": data.get("description", ""),
        }
        for cid, data in CWE_REFERENCE.items()
    ]
    return json.dumps({
        "detectable_count": len(out),
        "cwes": out,
        "catalog_lookup_count": len(CWE_CATALOG),
        "note": "These are the CWEs with an automated template/check. For ANY other "
                "CWE (e.g. one reported by analyze_database), call cwe_knowledge(cwe) "
                "to get its official description from the full catalog.",
    }, indent=2)


@mcp.tool()
def cwe_knowledge(cwe: str) -> str:
    """Explore the knowledge-base page for a vulnerability class (CWE).

    Use this BEFORE forming a taint hypothesis: it explains the vuln, the taint
    intuition (what source/sink/sanitizer mean for it), and gives candidate
    method/function NAMES to pass to run_taint_query (typical_sink_names,
    typical_source_names, typical_sanitizer_names).

    Args:
        cwe: CWE id, e.g. "CWE-89" (also accepts "89" or "cwe-89").
    """
    cwe_id, _, _ = _normalize_cwe(cwe)
    data = CWE_REFERENCE.get(cwe_id or cwe)
    if not data:
        # Fallback: any CWE from the full catalog (official layer only). These
        # have NO automated template — report them only if analyze_database flags
        # them; do not call run_taint_query/run_api_misuse_query for them.
        cat = CWE_CATALOG.get(cwe_id or cwe)
        if cat:
            return json.dumps({
                "cwe": cwe_id,
                "name": cat.get("name", ""),
                "detection": "none",
                "official": {
                    "description": cat.get("description", ""),
                    "extended_description": cat.get("extended_description"),
                    "mitigations": cat.get("mitigations", []),
                    "consequences": cat.get("consequences", []),
                    "references": [cat.get("reference", "")],
                },
                "note": "No automated detection template for this class. Use it only "
                        "to describe a finding already reported by analyze_database.",
            }, indent=2)
        return json.dumps({
            "error": f"No entry for {cwe!r}",
            "detectable": list(CWE_REFERENCE.keys()),
        })
    # Two distinct layers: the official "what it is" and our "what to do".
    page = {
        "cwe": cwe_id,
        "name": data.get("name", ""),
        "detection": data.get("detection", "taint"),
        "official": {
            "description": data.get("mitre_description") or data.get("description", ""),
            "extended_description": data.get("mitre_extended_description"),
            "mitigations": data.get("mitre_mitigations", []),
            "consequences": data.get("mitre_consequences", []),
            "observed_examples": data.get("mitre_observed_examples", []),
            "references": data.get("references", []),
        },
        "our_knowledge": {
            "summary": data.get("description", ""),
            "intuition": data.get("taint_intuition") or data.get("detection_intuition", ""),
            "remediation": data.get("remediation", ""),
        },
        "actions": data.get("actions", {}),
    }
    return json.dumps(page, indent=2)


@mcp.tool()
def read_file_snippet(file_path: str, start_line: int = 1, end_line: int = 40) -> str:
    """Read a slice of a source file so the model can inspect a finding's context.

    Args:
        file_path: Absolute path to the source file.
        start_line: First line (1-based).
        end_line: Last line (inclusive).
    """
    p = Path(file_path)
    if not p.is_file():
        return json.dumps({"error": f"File not found: {file_path}"})
    lines = p.read_text(encoding="utf-8", errors="replace").splitlines()
    lo, hi = max(1, start_line), min(len(lines), end_line)
    numbered = [f"{i}: {lines[i - 1]}" for i in range(lo, hi + 1)]
    return json.dumps({"file": file_path, "lines": "\n".join(numbered)})


if __name__ == "__main__":
    mcp.run()
