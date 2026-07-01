"""Test suite for the CodeQL MCP server (component package).

Self-contained: depends only on the `server` package + stdlib. No agent, no
Ollama. Run it independently of the rest of the project:

    pytest server/tests/test_server.py                  # fast tests
    pytest server/tests/test_server.py -m "not codeql"  # explicit, skip CodeQL
    pytest server/tests/test_server.py                  # everything (needs CodeQL)

Markers (registered in the project pytest.ini):
  - (unmarked) : fast unit tests, no external dependencies.
  - codeql     : invoke the CodeQL CLI (slow; build/analyze databases).
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from server import config
from server.core import sarif, template
from server.knowledge import store
from server.registry import loader
from server.tools import config_flags, database, knowledge, meta, queries
from server.transport.mcp_instance import mcp

# Import the package entry point for its assembly side effects: this loads every
# tool module (incl. filesystem) and the registry, registering all tools on the
# shared `mcp` instance exactly as `python -m server` does.
import server.main  # noqa: F401,E402


# --------------------------------------------------------------------------- #
# Fixtures
# --------------------------------------------------------------------------- #
@pytest.fixture
def clean_repo(tmp_path: Path) -> Path:
    """A repo with no vulnerabilities (negative test)."""
    (tmp_path / "safe.py").write_text(
        "def add(a, b):\n    return a + b\n", encoding="utf-8"
    )
    return tmp_path


# --------------------------------------------------------------------------- #
# UNIT: name/const rendering and injection safety (core.template)
# --------------------------------------------------------------------------- #
def test_render_names_quotes_identifiers():
    assert template.render_names(["execute", "queryDB"]) == '"execute", "queryDB"'


def test_render_names_empty_uses_sentinel():
    assert template.render_names([]) == f'"{template._SENTINEL}"'


def test_render_names_rejects_injection():
    # A malicious "name" that would break QL is dropped -> sentinel only.
    assert template.render_names(['"]; evil //', "ok_name"]) == '"ok_name"'


def test_render_consts_lowercases():
    assert template.render_consts(["MD5", "SHA1"]) == '"md5", "sha1"'


# --------------------------------------------------------------------------- #
# UNIT: CWE normalization + extraction (core.template / core.sarif)
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("value", ["CWE-89", "cwe-89", "89"])
def test_normalize_cwe_variants(value):
    assert template.normalize_cwe(value) == ("CWE-89", "external/cwe/cwe-089", "-cwe-089")


def test_normalize_cwe_empty():
    assert template.normalize_cwe("") == (None, "", "")


def test_cwe_from_tags():
    assert sarif.cwe_from_tags(["security", "external/cwe/cwe-089"]) == "CWE-89"
    assert sarif.cwe_from_tags(["security"]) is None


# --------------------------------------------------------------------------- #
# UNIT: SARIF parsing + flow extraction (core.sarif)
# --------------------------------------------------------------------------- #
def _phys(uri, line):
    return {"physicalLocation": {"artifactLocation": {"uri": uri}, "region": {"startLine": line}}}


def test_parse_sarif_extracts_cwe_and_flow(tmp_path: Path):
    rule = {"id": "py/x", "name": "X", "properties": {"tags": ["external/cwe/cwe-89"]}}
    thread_flow = {"locations": [
        {"location": _phys("app.py", 7)},
        {"location": _phys("app.py", 18)},
    ]}
    result = {
        "ruleId": "py/x",
        "level": "error",
        "message": {"text": "flow"},
        "locations": [_phys("app.py", 18)],
        "codeFlows": [{"threadFlows": [thread_flow]}],
    }
    sarif_doc = {"runs": [{"tool": {"driver": {"rules": [rule]}}, "results": [result]}]}
    p = tmp_path / "x.sarif"
    p.write_text(json.dumps(sarif_doc), encoding="utf-8")

    findings = sarif.parse_sarif(p)
    assert len(findings) == 1
    f = findings[0]
    assert f["cwe"] == "CWE-89"
    assert f["sink"] == {"file": "app.py", "line": 18}
    assert f["source"]["line"] == 7
    assert f["flow_steps"] == 2


# --------------------------------------------------------------------------- #
# UNIT: bundled CWE knowledge base integrity (knowledge.store + bundled data)
# --------------------------------------------------------------------------- #
def test_cwe_wiki_loaded():
    assert store.CWE_REFERENCE, "wiki must load and not be empty"
    assert store.CWE_CATALOG, "catalog must load and not be empty"


def test_cwe_wiki_schema():
    for cid, e in store.CWE_REFERENCE.items():
        assert cid.startswith("CWE-")
        assert e.get("detection") in {"taint", "api_misuse", "insecure_config_flag"}
        assert e.get("name")
        if e["detection"] == "taint":
            assert e.get("typical_sink_names"), f"{cid} needs sink names"
        elif e["detection"] == "api_misuse":
            assert e.get("weak_call_names") or e.get("bad_constants"), f"{cid} needs weak names"
        else:  # insecure_config_flag
            assert e.get("actions", {}).get("tool"), f"{cid} needs an actions.tool"


# --------------------------------------------------------------------------- #
# UNIT: knowledge tools (tools.knowledge)
# --------------------------------------------------------------------------- #
def test_cwe_knowledge_two_layers():
    payload = json.loads(knowledge.cwe_knowledge("CWE-89"))
    assert payload["cwe"] == "CWE-89"
    assert "official" in payload and "actions" in payload


def test_list_cwes_routes_tool():
    cwes = {c["cwe"]: c for c in json.loads(knowledge.list_cwes())["cwes"]}
    assert cwes["CWE-328"]["tool"] == "run_api_misuse_query"
    assert cwes["CWE-89"]["tool"] == "run_taint_query"


def test_list_cwes_routes_insecure_config_flag():
    cwes = {c["cwe"]: c for c in json.loads(knowledge.list_cwes())["cwes"]}
    assert cwes["CWE-295"]["detection"] == "insecure_config_flag"
    assert cwes["CWE-295"]["tool"] == "check_insecure_verify_false"
    assert cwes["CWE-489"]["tool"] == "check_insecure_debug_true"
    assert cwes["CWE-614"]["tool"] == "check_insecure_cookie_flags"


# --------------------------------------------------------------------------- #
# UNIT: tool registration on the shared MCP instance (registry + tools)
# --------------------------------------------------------------------------- #
def _registered_tool_names() -> set[str]:
    tm = mcp._tool_manager
    return set(getattr(tm, "_tools", {}).keys()) or {t.name for t in tm.list_tools()}


def test_static_tools_registered():
    names = _registered_tool_names()
    for n in [
        "list_python_files", "read_file_snippet", "create_codeql_database",
        "analyze_database", "run_custom_query", "run_taint_query",
        "run_api_misuse_query", "run_insecure_config_flag_query",
        "list_cwes", "cwe_knowledge",
    ]:
        assert n in names, f"missing static tool {n}"


def test_insecure_config_tools_registered():
    names = _registered_tool_names()
    for key in loader.INSECURE_CONFIG_FLAG_TEMPLATES:
        assert f"check_insecure_{key}" in names, f"missing tool check_insecure_{key}"


def test_custom_query_tools_registered():
    names = _registered_tool_names()
    for key in config.CUSTOM_QUERIES:
        assert f"check_{key}" in names, f"missing tool check_{key}"


def test_crypto_check_tools_registered():
    names = _registered_tool_names()
    for slug in loader.CRYPTO_CHECK_SLUGS.values():
        assert f"check_{slug}" in names, f"missing tool check_{slug}"


# --------------------------------------------------------------------------- #
# UNIT: input validation (tools.config_flags)
# --------------------------------------------------------------------------- #
def test_generic_insecure_config_rejects_bad_input():
    db = "_work/db_does_not_matter"
    for kwargs in [
        dict(module="req-uests", functions=["get"], param_name="verify", insecure_value="false"),
        dict(module="requests", functions=["ge t"], param_name="verify", insecure_value="false"),
        dict(module="requests", functions=["get"], param_name="ver ify", insecure_value="false"),
    ]:
        r = json.loads(config_flags.run_insecure_config_flag_query(db, cwe="CWE-295", **kwargs))
        assert "error" in r


# --------------------------------------------------------------------------- #
# CODEQL: template compilation (slow)
# --------------------------------------------------------------------------- #
@pytest.mark.codeql
def test_taint_template_compiles():
    import subprocess
    tmpl = (config.TEMPLATE_DIR / "taint_namebased.ql.tmpl").read_text(encoding="utf-8")
    rendered = (tmpl.replace("{{SINK_NAMES}}", template.render_names(["execute"]))
                    .replace("{{SOURCE_NAMES}}", template.render_names([]))
                    .replace("{{SANITIZER_NAMES}}", template.render_names([]))
                    .replace("{{CWE_ID_SUFFIX}}", "").replace("{{CWE_TAG_LINE}}", ""))
    config.GENERATED_DIR.mkdir(exist_ok=True)
    out = config.GENERATED_DIR / "test_taint_compile.ql"
    out.write_text(rendered, encoding="utf-8")
    rc = subprocess.run(
        [config.CODEQL_BIN, "query", "compile", str(out),
         f"--search-path={config.CODEQL_SEARCH_PATH}"],
        capture_output=True, text=True, timeout=config.CODEQL_TIMEOUT,
    )
    out.unlink(missing_ok=True)
    assert rc.returncode == 0, rc.stderr[-1000:]


@pytest.mark.codeql
def test_api_misuse_template_compiles():
    import subprocess
    tmpl = (config.TEMPLATE_DIR / "api_misuse_namebased.ql.tmpl").read_text(encoding="utf-8")
    rendered = (tmpl.replace("{{WEAK_CALL_NAMES}}", template.render_names(["md5"]))
                    .replace("{{BAD_CONSTANTS}}", template.render_consts(["md5"]))
                    .replace("{{CWE_ID_SUFFIX}}", "").replace("{{CWE_TAG_LINE}}", ""))
    config.GENERATED_DIR.mkdir(exist_ok=True)
    out = config.GENERATED_DIR / "test_apimisuse_compile.ql"
    out.write_text(rendered, encoding="utf-8")
    rc = subprocess.run(
        [config.CODEQL_BIN, "query", "compile", str(out),
         f"--search-path={config.CODEQL_SEARCH_PATH}"],
        capture_output=True, text=True, timeout=config.CODEQL_TIMEOUT,
    )
    out.unlink(missing_ok=True)
    assert rc.returncode == 0, rc.stderr[-1000:]


_INSECURE_TEMPLATES = [
    ("insecure_verify_false", "CWE-295"),
    ("insecure_shell_true", "CWE-78"),
    ("insecure_autoescape_false", "CWE-79"),
    ("insecure_debug_true", "CWE-489"),
    ("insecure_weak_hash", "CWE-327"),
    ("insecure_randomness", "CWE-330"),
    ("insecure_cookie_flags", "CWE-614"),
]


@pytest.mark.codeql
@pytest.mark.parametrize("template_name,cwe", _INSECURE_TEMPLATES)
def test_insecure_config_template_compiles(template_name: str, cwe: str):
    import subprocess
    tmpl = (config.TEMPLATE_DIR / f"{template_name}.ql.tmpl").read_text(encoding="utf-8")
    _, cwe_tag, cwe_suffix = template.normalize_cwe(cwe)
    tag_line = f"\n *       {cwe_tag}" if cwe_tag else ""
    rendered = (tmpl.replace("{{CWE_ID_SUFFIX}}", cwe_suffix)
                    .replace("{{CWE_TAG_LINE}}", tag_line))
    config.GENERATED_DIR.mkdir(exist_ok=True)
    out = config.GENERATED_DIR / f"test_{template_name}_compile.ql"
    out.write_text(rendered, encoding="utf-8")
    rc = subprocess.run(
        [config.CODEQL_BIN, "query", "compile", str(out),
         f"--search-path={config.CODEQL_SEARCH_PATH}"],
        capture_output=True, text=True, timeout=config.CODEQL_TIMEOUT,
    )
    out.unlink(missing_ok=True)
    assert rc.returncode == 0, rc.stderr[-1000:]


# --------------------------------------------------------------------------- #
# CODEQL: integration on fixture repos (slow)
# --------------------------------------------------------------------------- #
@pytest.fixture(scope="module")
def vuln_db(tmp_path_factory):
    """Build a CodeQL DB once for the integration tests."""
    d = tmp_path_factory.mktemp("vuln")
    (d / "app.py").write_text(
        "from flask import request\n"
        "class DB:\n"
        "    def queryDB(self, sql):\n        print(sql)\n"
        "db = DB()\n"
        "def get_user():\n"
        "    uid = request.args.get('id')\n"
        "    return db.queryDB('SELECT * FROM u WHERE id=' + uid)\n",
        encoding="utf-8",
    )
    (d / "crypto_util.py").write_text(
        "import hashlib\n"
        "def fp(x):\n    return hashlib.md5(x).hexdigest()\n"
        "def legacy(x):\n    return hashlib.new('sha1')\n",
        encoding="utf-8",
    )
    res = json.loads(database.create_codeql_database(str(d)))
    assert res.get("db_path"), res
    return res["db_path"]


@pytest.mark.codeql
def test_taint_finds_sqli(vuln_db):
    r = json.loads(queries.run_taint_query(vuln_db, sink_names=["queryDB"], cwe="CWE-89"))
    assert r["cwe"] == "CWE-89"
    assert r["finding_count"] >= 1
    assert any("app.py" in (f.get("sink") or {}).get("file", "") for f in r["findings"])


@pytest.mark.codeql
def test_api_misuse_finds_weak_hash(vuln_db):
    r = json.loads(queries.run_api_misuse_query(
        vuln_db, weak_call_names=["md5"], bad_constants=["md5", "sha1"], cwe="CWE-328"))
    assert r["cwe"] == "CWE-328"
    assert r["finding_count"] >= 2


@pytest.mark.codeql
def test_clean_repo_no_taint(clean_repo):
    db = json.loads(database.create_codeql_database(str(clean_repo)))["db_path"]
    r = json.loads(queries.run_taint_query(db, sink_names=["execute", "queryDB"], cwe="CWE-89"))
    assert r["finding_count"] == 0


@pytest.fixture(scope="module")
def insecure_config_db(tmp_path_factory):
    """Build a DB once with one instance of every insecure config flag."""
    d = tmp_path_factory.mktemp("insecure_cfg")
    (d / "app.py").write_text(
        "import hashlib, random, subprocess\n"
        "import requests\n"
        "from flask import Flask, make_response\n"
        "from jinja2 import Environment\n"
        "app = Flask(__name__, debug=True)\n"
        "def fetch(u):\n    return requests.get(u, verify=False)\n"
        "def run_cmd(c):\n    return subprocess.run(c, shell=True)\n"
        "def render(t):\n    return Environment(autoescape=False).from_string(t)\n"
        "def hp(p):\n    return hashlib.md5(p.encode()).hexdigest()\n"
        "def tok():\n    return random.randint(1000, 9999)\n"
        "def sess(v):\n"
        "    r = make_response('ok')\n"
        "    r.set_cookie('s', v, secure=False, httponly=False, samesite='None')\n"
        "    return r\n",
        encoding="utf-8",
    )
    res = json.loads(database.create_codeql_database(str(d)))
    assert res.get("db_path"), res
    return res["db_path"]


@pytest.mark.codeql
def test_generic_insecure_config_finds_verify_false(insecure_config_db):
    r = json.loads(config_flags.run_insecure_config_flag_query(
        insecure_config_db, module="requests", functions=["get", "post"],
        param_name="verify", insecure_value="false", cwe="CWE-295"))
    assert r["cwe"] == "CWE-295"
    assert r["finding_count"] >= 1
    assert any("app.py" in (f.get("file") or "") for f in r["findings"])


@pytest.mark.codeql
def test_generic_insecure_config_clean_repo(clean_repo):
    db = json.loads(database.create_codeql_database(str(clean_repo)))["db_path"]
    r = json.loads(config_flags.run_insecure_config_flag_query(
        db, module="requests", functions=["get"],
        param_name="verify", insecure_value="false", cwe="CWE-295"))
    assert r["finding_count"] == 0


# --------------------------------------------------------------------------- #
# UNIT: Detection flow inventory + knowledge seam
# --------------------------------------------------------------------------- #
def test_flow_inventory_tool_registered():
    names = _registered_tool_names()
    assert "find_all_flows" in names               # Detection: flow inventory
    assert "find_sensitive_operations" in names    # Detection: non-flow inventory


def test_list_phase_tools_is_source_of_truth():
    # The SERVER owns the tool -> phase mapping (the agent does not hardcode it).
    data = json.loads(meta.list_phase_tools())
    assert set(data) == {"detection", "validation"}
    # Detection = read + build DB + the two CWE-agnostic inventories.
    assert {"find_all_flows", "find_sensitive_operations",
            "create_codeql_database"} <= set(data["detection"])
    # Validation = targeted queries + knowledge, and the check_* shortcuts are
    # auto-included (previously they were wrongly excluded).
    assert "run_taint_query" in data["validation"]
    assert any(n.startswith("check_") for n in data["validation"])
    # Detection cannot run targeted queries; Validation cannot enumerate signals.
    assert "run_taint_query" not in data["detection"]
    assert "find_all_flows" not in data["validation"]
    # The meta-tool itself is exposed to no phase (only the orchestrator calls it).
    assert "list_phase_tools" not in data["detection"] + data["validation"]


def test_knowledge_seam_lookup():
    # The single access point used by queries.py/knowledge.py (graph-swappable).
    assert store.all_cwes() is store.CWE_REFERENCE
    assert store.lookup_cwe("CWE-89") == store.CWE_REFERENCE.get("CWE-89")
    assert store.lookup_cwe(None) is None
    assert store.lookup_cwe("CWE-does-not-exist") is None


def test_find_all_flows_without_db_errors():
    # render_and_analyze reports the missing DB; find_all_flows surfaces it.
    r = json.loads(queries.find_all_flows("/no/such/db"))
    assert "error" in r


@pytest.mark.codeql
def test_flow_inventory_template_compiles():
    import subprocess
    tmpl = (config.TEMPLATE_DIR / "flow_inventory.ql.tmpl").read_text(encoding="utf-8")
    # CWE-agnostic: the CWE placeholders render to empty (no class stamped).
    rendered = tmpl.replace("{{CWE_ID_SUFFIX}}", "").replace("{{CWE_TAG_LINE}}", "")
    assert "external/cwe" not in rendered  # no CWE tag -> no bias
    config.GENERATED_DIR.mkdir(exist_ok=True)
    out = config.GENERATED_DIR / "test_flow_inventory_compile.ql"
    out.write_text(rendered, encoding="utf-8")
    rc = subprocess.run(
        [config.CODEQL_BIN, "query", "compile", str(out),
         f"--search-path={config.CODEQL_SEARCH_PATH}"],
        capture_output=True, text=True, timeout=config.CODEQL_TIMEOUT,
    )
    out.unlink(missing_ok=True)
    assert rc.returncode == 0, rc.stderr[-1000:]


@pytest.mark.codeql
def test_sensitive_ops_template_compiles():
    import subprocess
    tmpl = (config.TEMPLATE_DIR / "sensitive_ops.ql.tmpl").read_text(encoding="utf-8")
    rendered = (tmpl.replace("{{CWE_ID_SUFFIX}}", "").replace("{{CWE_TAG_LINE}}", "")
                    .replace("{{WEAK_CALL_NAMES}}", template.render_names(["md5", "random"]))
                    .replace("{{FLAG_PARAM_NAMES}}", template.render_names(["verify", "shell"])))
    assert "external/cwe" not in rendered  # CWE-agnostic inventory
    config.GENERATED_DIR.mkdir(exist_ok=True)
    out = config.GENERATED_DIR / "test_sensitive_ops_compile.ql"
    out.write_text(rendered, encoding="utf-8")
    rc = subprocess.run(
        [config.CODEQL_BIN, "query", "compile", str(out),
         f"--search-path={config.CODEQL_SEARCH_PATH}"],
        capture_output=True, text=True, timeout=config.CODEQL_TIMEOUT,
    )
    out.unlink(missing_ok=True)
    assert rc.returncode == 0, rc.stderr[-1000:]


@pytest.mark.codeql
def test_find_sensitive_operations_finds_crypto_without_flow(vuln_db):
    # crypto_util.py uses hashlib.md5 / hashlib.new('sha1') with NO data-flow:
    # find_all_flows would miss them; find_sensitive_operations must surface them.
    r = json.loads(queries.find_sensitive_operations(vuln_db))
    assert r["op_count"] >= 1
    crypto_ops = [o for o in r["operations"] if "crypto_util.py" in (o.get("file") or "")]
    assert crypto_ops, "expected a sensitive op in crypto_util.py"
    # Detected via the SEMANTIC crypto Concept (kind 'crypto'), not name matching.
    assert any(o["kind"] == "crypto" for o in crypto_ops)
    # CWE-agnostic: kinds are structural, never a CWE id.
    assert all("CWE" not in (o.get("kind") or "") for o in r["operations"])
