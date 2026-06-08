"""Test suite for the CodeQL Security Agent.

Levels (see pytest.ini markers):
  - unit + robustness : fast, no external dependencies (default).
  - codeql            : invoke the CodeQL CLI (slow). Marker: @pytest.mark.codeql
  - llm               : full agent driving Ollama (very slow). Marker: @pytest.mark.llm

Run fast only:   pytest -m "not codeql and not llm"
Run with CodeQL: pytest -m "not llm"
Run everything:  pytest
"""
from __future__ import annotations

import json
import shutil
import zipfile
from pathlib import Path

import pytest

import agent
import codeql_mcp_server as server
import config
import build_actions


# --------------------------------------------------------------------------- #
# Fixtures
# --------------------------------------------------------------------------- #
@pytest.fixture
def vuln_repo(tmp_path: Path) -> Path:
    """A tiny repo with a SQL injection (custom wrapper) and weak hashes."""
    (tmp_path / "app.py").write_text(
        "from flask import request\n"
        "class DB:\n"
        "    def queryDB(self, sql):\n"
        "        print(sql)\n"
        "db = DB()\n"
        "def get_user():\n"
        "    uid = request.args.get('id')\n"
        "    sql = 'SELECT * FROM users WHERE id = ' + uid\n"
        "    return db.queryDB(sql)\n",
        encoding="utf-8",
    )
    (tmp_path / "crypto_util.py").write_text(
        "import hashlib\n"
        "def fp(data):\n"
        "    return hashlib.md5(data).hexdigest()\n"
        "def legacy(data):\n"
        "    return hashlib.new('sha1')\n",
        encoding="utf-8",
    )
    return tmp_path


@pytest.fixture
def clean_repo(tmp_path: Path) -> Path:
    """A repo with no vulnerabilities (negative test)."""
    (tmp_path / "safe.py").write_text(
        "def add(a, b):\n    return a + b\n", encoding="utf-8"
    )
    return tmp_path


# --------------------------------------------------------------------------- #
# UNIT: tool-call recovery (text fallback)
# --------------------------------------------------------------------------- #
def test_text_tool_call_fenced_json():
    content = '```json\n{"name": "list_python_files", "arguments": {"repo_path": "x"}}\n```'
    calls = agent._extract_text_tool_calls(content, {"list_python_files"})
    assert calls == [{"function": {"name": "list_python_files", "arguments": {"repo_path": "x"}}}]


def test_text_tool_call_report_is_not_a_call():
    content = "# Report\n```json\n{\"finding\": 1}\n```"
    assert agent._extract_text_tool_calls(content, {"list_python_files"}) == []


def test_text_tool_call_unknown_name_ignored():
    content = '{"name": "rm_rf", "arguments": {}}'
    assert agent._extract_text_tool_calls(content, {"list_python_files"}) == []


def test_balanced_objects_nested():
    objs = agent._balanced_objects('a {"x": {"y": 1}} b {"z": 2}')
    assert objs == ['{"x": {"y": 1}}', '{"z": 2}']


# --------------------------------------------------------------------------- #
# UNIT: name/const rendering and injection safety
# --------------------------------------------------------------------------- #
def test_render_names_quotes_identifiers():
    assert server._render_names(["execute", "queryDB"]) == '"execute", "queryDB"'


def test_render_names_empty_uses_sentinel():
    assert server._render_names([]) == f'"{server._SENTINEL}"'


def test_render_names_rejects_injection():
    # A malicious "name" that would break QL is dropped -> sentinel only.
    assert server._render_names(['"]; evil //', "ok_name"]) == '"ok_name"'


def test_render_consts_lowercases():
    assert server._render_consts(["MD5", "SHA1"]) == '"md5", "sha1"'


# --------------------------------------------------------------------------- #
# UNIT: CWE normalization + extraction
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("value", ["CWE-89", "cwe-89", "89"])
def test_normalize_cwe_variants(value):
    assert server._normalize_cwe(value) == ("CWE-89", "external/cwe/cwe-089", "-cwe-089")


def test_normalize_cwe_empty():
    assert server._normalize_cwe("") == (None, "", "")


def test_cwe_from_tags():
    assert server._cwe_from_tags(["security", "external/cwe/cwe-089"]) == "CWE-89"
    assert server._cwe_from_tags(["security"]) is None


# --------------------------------------------------------------------------- #
# UNIT: SARIF parsing + flow extraction
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
    sarif = {"runs": [{"tool": {"driver": {"rules": [rule]}}, "results": [result]}]}
    p = tmp_path / "x.sarif"
    p.write_text(json.dumps(sarif), encoding="utf-8")

    findings = server._parse_sarif(p)
    assert len(findings) == 1
    f = findings[0]
    assert f["cwe"] == "CWE-89"
    assert f["sink"] == {"file": "app.py", "line": 18}
    assert f["source"]["line"] == 7
    assert f["flow_steps"] == 2


# --------------------------------------------------------------------------- #
# UNIT: report naming, metadata header, slug
# --------------------------------------------------------------------------- #
def test_default_report_path_is_per_repo():
    p = Path(agent._default_report_path("MyRepo", "hf.co/o/Model:Q4_K_M"))
    assert p.parent.name == "MyRepo"
    assert p.name.startswith("Model_Q4_K_M__")
    assert p.suffix == ".md"


def test_metadata_header_contains_fields():
    import time
    h = agent._metadata_header("m", "repo", time.time() - 5, 3, 30,
                               {"check_xss": 1}, {"CWE-89"}, 2)
    assert "model: m" in h and "steps_used: 3" in h
    assert "cwes_found: CWE-89" in h and "total_findings: 2" in h


def test_slug():
    assert agent._slug("a/b:c d") == "a_b_c_d"


# --------------------------------------------------------------------------- #
# ROBUSTNESS: db_path resolution, checkpoint, zip
# --------------------------------------------------------------------------- #
def test_resolve_db_path_keeps_valid_dir(tmp_path: Path):
    assert agent._resolve_db_path(str(tmp_path), None, "exp") == str(tmp_path)


def test_resolve_db_path_replaces_placeholder():
    assert agent._resolve_db_path("<result of create_codeql_database>", None, "exp") == "exp"
    assert agent._resolve_db_path("<placeholder>", "last", "exp") == "last"


def test_checkpoint_roundtrip(tmp_path: Path):
    p = tmp_path / "ckpt.json"
    state = {"next_step": 3, "messages": [{"role": "system", "content": "s"}], "seen": {"a": "b"}}
    agent._save_checkpoint(p, state)
    assert json.loads(p.read_text(encoding="utf-8"))["next_step"] == 3


def test_plain_normalizes_dict():
    assert agent._plain({"role": "assistant", "content": "x"}) == {"role": "assistant", "content": "x"}


def test_resolve_source_zip(tmp_path: Path):
    src = tmp_path / "proj"
    src.mkdir()
    (src / "a.py").write_text("x = 1\n", encoding="utf-8")
    zpath = tmp_path / "proj.zip"
    with zipfile.ZipFile(zpath, "w") as z:
        z.write(src / "a.py", "a.py")
    out = Path(agent._resolve_source(str(zpath)))
    assert out.is_dir() and (out / "a.py").exists()


# --------------------------------------------------------------------------- #
# UNIT: CWE knowledge base integrity
# --------------------------------------------------------------------------- #
def test_cwe_wiki_schema():
    wiki = json.loads(config.CWE_WIKI_PATH.read_text(encoding="utf-8"))
    assert wiki, "wiki must not be empty"
    for cid, e in wiki.items():
        assert cid.startswith("CWE-")
        assert e.get("detection") in {"taint", "api_misuse", "insecure_config_flag"}
        assert e.get("name")
        if e["detection"] == "taint":
            assert e.get("typical_sink_names"), f"{cid} needs sink names"
        elif e["detection"] == "api_misuse":
            assert e.get("weak_call_names") or e.get("bad_constants"), f"{cid} needs weak names"
        else:  # insecure_config_flag
            assert e.get("actions", {}).get("tool"), f"{cid} needs an actions.tool"


def test_build_actions_matches_detection():
    wiki = json.loads(config.CWE_WIKI_PATH.read_text(encoding="utf-8"))
    for cid, e in wiki.items():
        actions = build_actions.build_actions(cid, e)
        det = e["detection"]
        if det == "api_misuse":
            assert actions["tool"] == "run_api_misuse_query"
        elif det == "insecure_config_flag":
            # Either a dedicated check_insecure_* tool or the generic runner.
            assert actions["tool"].startswith("check_insecure_") or \
                actions["tool"] == "run_insecure_config_flag_query"
        else:
            assert actions["tool"] == "run_taint_query"


def test_cwe_knowledge_two_layers():
    payload = json.loads(server.cwe_knowledge("CWE-89"))
    assert payload["cwe"] == "CWE-89"
    assert "official" in payload and "actions" in payload


def test_list_cwes_routes_tool():
    cwes = {c["cwe"]: c for c in json.loads(server.list_cwes())["cwes"]}
    assert cwes["CWE-328"]["tool"] == "run_api_misuse_query"
    assert cwes["CWE-89"]["tool"] == "run_taint_query"


def test_list_cwes_routes_insecure_config_flag():
    cwes = {c["cwe"]: c for c in json.loads(server.list_cwes())["cwes"]}
    # The dedicated check_insecure_* tool is surfaced for these classes.
    assert cwes["CWE-295"]["detection"] == "insecure_config_flag"
    assert cwes["CWE-295"]["tool"] == "check_insecure_verify_false"
    assert cwes["CWE-489"]["tool"] == "check_insecure_debug_true"
    assert cwes["CWE-614"]["tool"] == "check_insecure_cookie_flags"


def test_insecure_config_tools_registered():
    """All 7 dedicated check_insecure_* tools must be registered on the server."""
    tm = server.mcp._tool_manager
    names = set(getattr(tm, "_tools", {}).keys()) or {t.name for t in tm.list_tools()}
    for key in server.INSECURE_CONFIG_FLAG_TEMPLATES:
        assert f"check_insecure_{key}" in names, f"missing tool check_insecure_{key}"


def test_generic_insecure_config_rejects_bad_input():
    db = "_work/db_does_not_matter"
    # Invalid module / function / param names must be rejected before running.
    for kwargs in [
        dict(module="req-uests", functions=["get"], param_name="verify", insecure_value="false"),
        dict(module="requests", functions=["ge t"], param_name="verify", insecure_value="false"),
        dict(module="requests", functions=["get"], param_name="ver ify", insecure_value="false"),
    ]:
        r = json.loads(server.run_insecure_config_flag_query(db, cwe="CWE-295", **kwargs))
        assert "error" in r


# --------------------------------------------------------------------------- #
# CODEQL: template compilation
# --------------------------------------------------------------------------- #
@pytest.mark.codeql
def test_taint_template_compiles(tmp_path: Path):
    import subprocess
    tmpl = (config.TEMPLATE_DIR / "taint_namebased.ql.tmpl").read_text(encoding="utf-8")
    rendered = (tmpl.replace("{{SINK_NAMES}}", server._render_names(["execute"]))
                    .replace("{{SOURCE_NAMES}}", server._render_names([]))
                    .replace("{{SANITIZER_NAMES}}", server._render_names([]))
                    .replace("{{CWE_ID_SUFFIX}}", "").replace("{{CWE_TAG_LINE}}", ""))
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
    rendered = (tmpl.replace("{{WEAK_CALL_NAMES}}", server._render_names(["md5"]))
                    .replace("{{BAD_CONSTANTS}}", server._render_consts(["md5"]))
                    .replace("{{CWE_ID_SUFFIX}}", "").replace("{{CWE_TAG_LINE}}", ""))
    out = config.GENERATED_DIR / "test_apimisuse_compile.ql"
    out.write_text(rendered, encoding="utf-8")
    rc = subprocess.run(
        [config.CODEQL_BIN, "query", "compile", str(out),
         f"--search-path={config.CODEQL_SEARCH_PATH}"],
        capture_output=True, text=True, timeout=config.CODEQL_TIMEOUT,
    )
    out.unlink(missing_ok=True)
    assert rc.returncode == 0, rc.stderr[-1000:]


# --------------------------------------------------------------------------- #
# CODEQL: integration on a fixture repo
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
    res = json.loads(server.create_codeql_database(str(d)))
    assert res.get("db_path"), res
    return res["db_path"]


@pytest.mark.codeql
def test_taint_finds_sqli(vuln_db):
    r = json.loads(server.run_taint_query(vuln_db, sink_names=["queryDB"], cwe="CWE-89"))
    assert r["cwe"] == "CWE-89"
    assert r["finding_count"] >= 1
    assert any("app.py" in (f.get("sink") or {}).get("file", "") for f in r["findings"])


@pytest.mark.codeql
def test_api_misuse_finds_weak_hash(vuln_db):
    r = json.loads(server.run_api_misuse_query(
        vuln_db, weak_call_names=["md5"], bad_constants=["md5", "sha1"], cwe="CWE-328"))
    assert r["cwe"] == "CWE-328"
    assert r["finding_count"] >= 2


@pytest.mark.codeql
def test_clean_repo_no_taint(clean_repo):
    db = json.loads(server.create_codeql_database(str(clean_repo)))["db_path"]
    r = json.loads(server.run_taint_query(db, sink_names=["execute", "queryDB"], cwe="CWE-89"))
    assert r["finding_count"] == 0


# --------------------------------------------------------------------------- #
# CODEQL: insecure configuration flag templates
# --------------------------------------------------------------------------- #
_INSECURE_TEMPLATES = [
    ("insecure_verify_false", "CWE-295"),
    ("insecure_shell_true", "CWE-78"),
    ("insecure_autoescape_false", "CWE-79"),
    ("insecure_debug_true", "CWE-489"),
    ("insecure_weak_hash", "CWE-327"),
    ("insecure_randomness", "CWE-330"),
    ("insecure_cookie_flags", "CWE-614"),
]


def _render_insecure(template_name: str, cwe: str) -> str:
    tmpl = (config.TEMPLATE_DIR / f"{template_name}.ql.tmpl").read_text(encoding="utf-8")
    _, cwe_tag, cwe_suffix = server._normalize_cwe(cwe)
    tag_line = f"\n *       {cwe_tag}" if cwe_tag else ""
    return (tmpl.replace("{{CWE_ID_SUFFIX}}", cwe_suffix)
                .replace("{{CWE_TAG_LINE}}", tag_line))


@pytest.mark.codeql
@pytest.mark.parametrize("template_name,cwe", _INSECURE_TEMPLATES)
def test_insecure_config_template_compiles(template_name: str, cwe: str):
    import subprocess
    rendered = _render_insecure(template_name, cwe)
    out = config.GENERATED_DIR / f"test_{template_name}_compile.ql"
    out.write_text(rendered, encoding="utf-8")
    rc = subprocess.run(
        [config.CODEQL_BIN, "query", "compile", str(out),
         f"--search-path={config.CODEQL_SEARCH_PATH}"],
        capture_output=True, text=True, timeout=config.CODEQL_TIMEOUT,
    )
    out.unlink(missing_ok=True)
    assert rc.returncode == 0, rc.stderr[-1000:]


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
    res = json.loads(server.create_codeql_database(str(d)))
    assert res.get("db_path"), res
    return res["db_path"]


@pytest.mark.codeql
def test_generic_insecure_config_finds_verify_false(insecure_config_db):
    r = json.loads(server.run_insecure_config_flag_query(
        insecure_config_db, module="requests", functions=["get", "post"],
        param_name="verify", insecure_value="false", cwe="CWE-295"))
    assert r["cwe"] == "CWE-295"
    assert r["finding_count"] >= 1
    assert any("app.py" in (f.get("file") or "") for f in r["findings"])


@pytest.mark.codeql
def test_generic_insecure_config_clean_repo(clean_repo):
    db = json.loads(server.create_codeql_database(str(clean_repo)))["db_path"]
    r = json.loads(server.run_insecure_config_flag_query(
        db, module="requests", functions=["get"],
        param_name="verify", insecure_value="false", cwe="CWE-295"))
    assert r["finding_count"] == 0


# --------------------------------------------------------------------------- #
# LLM: end-to-end (very slow; opt-in)
# --------------------------------------------------------------------------- #
@pytest.mark.llm
def test_end_to_end_report(vuln_repo, tmp_path: Path):
    import asyncio
    report_path = tmp_path / "report.md"
    asyncio.run(agent.run_agent(str(vuln_repo), config.AGENT_MODEL, str(report_path), max_steps=25))
    text = report_path.read_text(encoding="utf-8")
    assert "CWE-89" in text
    assert "CWE-328" in text
