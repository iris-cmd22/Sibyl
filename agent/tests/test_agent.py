"""Test suite for the CodeQL Security Agent (pure modules only).

These tests need neither Ollama nor the MCP server: they cover the robustness
helpers, report naming/header, message normalization, and source resolution.
Server-side logic (sarif/template/queries) is covered by server/tests/test_server.py.

Run:  python -m pytest agent/tests/test_agent.py -q
"""
from __future__ import annotations

import json
import time
import zipfile
from pathlib import Path

import pytest

from agent.clients.openai_compat import _to_openai
from agent.clients.ollama import plain
from agent.phases import DETECTION, VALIDATION, filter_tools
from agent.report import RunStats, default_report_path, slug
from agent.robustness.checkpoint import save_checkpoint
from agent.robustness.dbpath import resolve_db_path
from agent.robustness.toolcalls import _balanced_objects, extract_text_tool_calls
from agent.source import resolve_source
from agent.worklist import WorkList


class _Tool:
    """Minimal stand-in for an MCP tool definition (only `.name` is used)."""
    def __init__(self, name: str):
        self.name = name


# --------------------------------------------------------------------------- #
# tool-call recovery (text fallback)
# --------------------------------------------------------------------------- #
def test_text_tool_call_fenced_json():
    content = '```json\n{"name": "list_python_files", "arguments": {"repo_path": "x"}}\n```'
    calls = extract_text_tool_calls(content, {"list_python_files"})
    assert calls == [{"function": {"name": "list_python_files", "arguments": {"repo_path": "x"}}}]


def test_text_tool_call_report_is_not_a_call():
    content = "# Report\n```json\n{\"finding\": 1}\n```"
    assert extract_text_tool_calls(content, {"list_python_files"}) == []


def test_text_tool_call_unknown_name_ignored():
    content = '{"name": "rm_rf", "arguments": {}}'
    assert extract_text_tool_calls(content, {"list_python_files"}) == []


def test_balanced_objects_nested():
    objs = _balanced_objects('a {"x": {"y": 1}} b {"z": 2}')
    assert objs == ['{"x": {"y": 1}}', '{"z": 2}']


# --------------------------------------------------------------------------- #
# report naming, metadata header, slug
# --------------------------------------------------------------------------- #
def test_default_report_path_is_per_repo():
    p = Path(default_report_path("MyRepo", "hf.co/o/Model:Q4_K_M"))
    assert p.parent.name == "MyRepo"
    assert p.name.startswith("Model_Q4_K_M__")
    assert p.suffix == ".md"


def test_metadata_header_contains_fields():
    stats = RunStats(model="m", repo_path="repo", max_steps=30, started=time.time() - 5,
                     steps_done=3, tool_counts={"check_xss": 1}, cwes={"CWE-89"},
                     total_findings=2)
    h = stats.header()
    assert "model: m" in h and "steps_used: 3" in h
    assert "cwes_found: CWE-89" in h and "total_findings: 2" in h


def test_slug():
    assert slug("a/b:c d") == "a_b_c_d"


def test_run_stats_records_findings_and_db_path():
    stats = RunStats(model="m", repo_path="r", max_steps=30)
    stats.record_tool_result("create_codeql_database", json.dumps({"db_path": "/db"}))
    stats.record_tool_result("run_taint_query",
                             json.dumps({"finding_count": 2, "findings": [{"cwe": "CWE-89"}]}))
    assert stats.last_db_path == "/db"
    assert stats.total_findings == 2
    assert stats.cwes == {"CWE-89"}
    assert stats.tool_counts == {"create_codeql_database": 1, "run_taint_query": 1}


# --------------------------------------------------------------------------- #
# robustness: db_path resolution, checkpoint, zip; message normalization
# --------------------------------------------------------------------------- #
def test_resolve_db_path_keeps_valid_dir(tmp_path: Path):
    assert resolve_db_path(str(tmp_path), None) == str(tmp_path)


def test_resolve_db_path_replaces_placeholder():
    assert resolve_db_path("<result of create_codeql_database>", "last") == "last"
    assert resolve_db_path("<placeholder>", None) is None


def test_checkpoint_roundtrip(tmp_path: Path):
    p = tmp_path / "ckpt.json"
    state = {"next_step": 3, "messages": [{"role": "system", "content": "s"}], "seen": {"a": "b"}}
    save_checkpoint(p, state)
    assert json.loads(p.read_text(encoding="utf-8"))["next_step"] == 3


def test_plain_normalizes_dict():
    assert plain({"role": "assistant", "content": "x"}) == {"role": "assistant", "content": "x"}


def test_gemini_message_translation_pairs_tool_call_ids():
    # An assistant turn with a tool call, followed by its tool result, must be
    # translated so the tool message carries the matching tool_call_id.
    messages = [
        {"role": "system", "content": "sys"},
        {"role": "user", "content": "go"},
        {"role": "assistant", "content": "",
         "tool_calls": [{"id": "abc", "function": {"name": "list_python_files",
                                                   "arguments": {"repo_path": "x"}}}]},
        {"role": "tool", "tool_name": "list_python_files", "content": "result"},
    ]
    out = _to_openai(messages)
    assert out[2]["tool_calls"][0]["id"] == "abc"
    assert out[2]["tool_calls"][0]["function"]["arguments"] == '{"repo_path": "x"}'  # serialized
    assert out[3] == {"role": "tool", "tool_call_id": "abc", "content": "result"}


def test_resolve_source_zip(tmp_path: Path):
    src = tmp_path / "proj"
    src.mkdir()
    (src / "a.py").write_text("x = 1\n", encoding="utf-8")
    zpath = tmp_path / "proj.zip"
    with zipfile.ZipFile(zpath, "w") as z:
        z.write(src / "a.py", "a.py")
    out = Path(resolve_source(str(zpath)))
    assert out.is_dir() and (out / "a.py").exists()


# --------------------------------------------------------------------------- #
# phases: filtering keeps only the names allowed (the allow-list comes from the
# SERVER via list_phase_tools; here we unit-test the pure filter).
# --------------------------------------------------------------------------- #
def test_filter_tools_keeps_only_allowed():
    tools = [_Tool(n) for n in ["find_all_flows", "run_taint_query", "cwe_knowledge"]]
    kept = {t.name for t in filter_tools(tools, {"find_all_flows", "cwe_knowledge"})}
    assert kept == {"find_all_flows", "cwe_knowledge"}
    # empty allow-list -> nothing passes (orchestrator handles the degrade case)
    assert filter_tools(tools, set()) == []
    assert DETECTION == "detection" and VALIDATION == "validation"


# --------------------------------------------------------------------------- #
# worklist: the Detection -> Validation flow-inventory handoff (Claim Check)
# --------------------------------------------------------------------------- #
def test_worklist_candidates_dedup():
    wl = WorkList(repo_path="/r", db_path="/db")
    wl.add_candidates({"flows": [
        {"source": {"file": "a.py", "line": 3}, "sink": {"file": "a.py", "line": 18},
         "sink_hint": "sql", "steps": 8},
        {"source": {"file": "a.py", "line": 3}, "sink": {"file": "a.py", "line": 18},
         "sink_hint": "dup", "steps": 8},
    ]})
    assert len(wl.candidates) == 1
    assert "a.py:3" in wl.detection_summary()


def test_worklist_operations_dedup_and_summary():
    wl = WorkList(repo_path="/r", db_path="/db")
    wl.add_operations({"operations": [
        {"kind": "weak-call", "file": "c.py", "line": 3},
        {"kind": "weak-call", "file": "c.py", "line": 3},   # dup
        {"kind": "config-flag", "file": "a.py", "line": 8},
    ]})
    assert len(wl.operations) == 2
    s = wl.detection_summary()
    assert "SENSITIVE OPERATIONS" in s and "weak-call @ c.py:3" in s


def test_worklist_roundtrip():
    wl = WorkList(repo_path="/r", db_path="/db")
    wl.add_candidates({"flows": [{"source": {"file": "a.py", "line": 1},
                                  "sink": {"file": "a.py", "line": 9},
                                  "sink_hint": "", "steps": 2}]})
    wl.add_operations({"operations": [{"kind": "weak-call", "file": "c.py", "line": 3}]})
    back = WorkList.from_dict(wl.to_dict())
    assert back.db_path == "/db" and len(back.candidates) == 1 and len(back.operations) == 1
