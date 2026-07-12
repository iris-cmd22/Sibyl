"""Maintain OUR knowledge base of agent ACTIONS in cwe_wiki.json.

The wiki holds two layers per CWE:
  1. Official "what it is"  -> mitre_description / mitre_mitigations (from MITRE).
  2. Our "what to do"       -> the `actions` block (this script).

The `actions` block is the agent's operational playbook for that CWE: which tool
to call, how to verify, how to read the result, and known false-positive notes.

This script fills `actions` for any CWE that lacks it (idempotent), so manual
refinements are preserved. Use --force to regenerate all of them.

Usage:
    python build_actions.py            # fill missing actions
    python build_actions.py --force    # regenerate every actions block
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

# Bundled knowledge data lives inside the server package.
CWE_WIKI_PATH = Path(__file__).resolve().parent / "server" / "knowledge" / "data" / "cwe_wiki.json"

# CWE -> dedicated check_insecure_* tool (mirrors INSECURE_CONFIG_FLAG_TEMPLATES
# in server/registry/loader.py). Keep in sync when adding insecure_config_flag CWEs.
INSECURE_CONFIG_TOOLS = {
    "CWE-295": "check_insecure_verify_false",
    "CWE-78": "check_insecure_shell_true",
    "CWE-79": "check_insecure_autoescape_false",
    "CWE-489": "check_insecure_debug_true",
    "CWE-327": "check_insecure_weak_hash",
    "CWE-330": "check_insecure_weak_randomness",
    "CWE-614": "check_insecure_cookie_flags",
}

# CWE -> zero-parameter check_* tools for taint/api_misuse CWEs (mirrors CUSTOM_QUERIES in
# server/config.py and CRYPTO_CHECK_SLUGS in server/registry/loader.py). Keep in sync: these
# are recommended BEFORE the generic run_taint_query/run_api_misuse_query because they need
# no model-supplied names (see build_actions main() below). These are OUR OWN queries (broad
# name-based taint / curated crypto presets) — not a wrapper around CodeQL's official
# Security/ query pack: the agent still has to judge the class, these just remove the
# name-guessing step for known-common cases.
CUSTOM_QUERY_CHECKS = {
    "CWE-89": ["check_sql_injection"],
    "CWE-78": ["check_os_command_injection"],
    "CWE-22": ["check_path_traversal"],
    "CWE-502": ["check_deserialization"],
    "CWE-79": ["check_xss"],
}
CRYPTO_CHECK_TOOLS = {
    "CWE-328": ["check_weak_hash"],
    "CWE-327": ["check_broken_crypto"],
    "CWE-330": ["check_weak_random"],
    "CWE-916": ["check_weak_password_hash"],
}


# Obiettivo: elencare i nostri check_* a zero parametri disponibili per un CWE (custom broad
#            + crypto), da raccomandare prima delle query generiche.
# Input:    cid = CWE id (es. "CWE-89"). Output: lista di nomi di tool (puo' essere vuota).
def _zero_param_checks(cid: str) -> list[str]:
    return CUSTOM_QUERY_CHECKS.get(cid, []) + CRYPTO_CHECK_TOOLS.get(cid, [])


# Per-CWE caveats worth surfacing to the agent (extend as the KB grows).
FP_NOTES = {
    "CWE-330": "The random module is frequently used for non-security purposes; confirm the value is security-sensitive (token, key, password, nonce) before reporting.",
    "CWE-338": "Same as CWE-330: only flag when the PRNG output is used for security.",
    "CWE-916": "Hash calls are also used for checksums/caching; confirm the input is a password before reporting.",
    "CWE-117": "Logging calls are extremely common; only a flow from untrusted input to the log message is a real issue.",
    "CWE-918": "Outbound HTTP is normal; the issue is only when the destination URL is user-controlled.",
    "CWE-601": "redirect() is normal; the issue is only when the target is user-controlled and not allow-listed.",
}


def _taint_actions(cid: str, e: dict) -> dict:
    sinks = e.get("typical_sink_names", [])
    checks = _zero_param_checks(cid)
    if checks:
        how_to_verify = (
            f"Try these zero-parameter checks FIRST (no names to guess): "
            + ", ".join(f"{c}(db_path)" for c in checks)
            + f". If none of them finds it and you suspect a custom wrapper function not "
            f"covered by them, fall back to run_taint_query(cwe='{cid}', "
            f"sink_names=<candidates below + any real wrapper names you saw in the code>)."
        )
    else:
        how_to_verify = (
            f"Call run_taint_query(cwe='{cid}', sink_names=<candidates below + any "
            f"real wrapper names you saw in the code>). Optionally pass source_names "
            f"and sanitizer_names. RemoteFlowSource is always a source."
        )
    return {
        "tool": checks[0] if checks else "run_taint_query",
        "how_to_verify": how_to_verify,
        "candidate_sink_names": sinks,
        "candidate_source_names": e.get("typical_source_names", []),
        "candidate_sanitizer_names": e.get("typical_sanitizer_names", []),
        "interpretation": (
            f"A path finding proves user-controlled data flows to a {e.get('name', cid)} "
            f"sink. The CWE is read from the query @tags (deterministic), and the "
            f"flow_path (source->sink, file:line) is the evidence to cite."
        ),
    }


def _api_misuse_actions(cid: str, e: dict) -> dict:
    checks = _zero_param_checks(cid)
    if checks:
        how_to_verify = (
            f"Try these zero-parameter checks FIRST (no names to guess): "
            + ", ".join(f"{c}(db_path)" for c in checks)
            + f". If none of them finds it and you suspect a custom/uncommon API not "
            f"covered by them, fall back to run_api_misuse_query(cwe='{cid}', "
            f"weak_call_names=<candidates below>, bad_constants=<weak algorithm/mode "
            f"strings>)."
        )
    else:
        how_to_verify = (
            f"Call run_api_misuse_query(cwe='{cid}', weak_call_names=<candidates below>, "
            f"bad_constants=<weak algorithm/mode strings>). Provide at least one list."
        )
    return {
        "tool": checks[0] if checks else "run_api_misuse_query",
        "how_to_verify": how_to_verify,
        "candidate_weak_call_names": e.get("weak_call_names", []),
        "candidate_bad_constants": e.get("bad_constants", []),
        "interpretation": (
            "Point detection (no data flow): a finding flags a call to a weak/insecure "
            "API or one passing a weak constant. Confirm the surrounding context with "
            "read_file_snippet before reporting."
        ),
    }


def _insecure_config_flag_actions(cid: str, e: dict) -> dict:
    tool = INSECURE_CONFIG_TOOLS.get(cid, "run_insecure_config_flag_query")
    # Preserve hand-written candidate patterns if present in the wiki entry.
    patterns = e.get("actions", {}).get("candidate_patterns", [])
    return {
        "tool": tool,
        "how_to_verify": (
            f"Call {tool}(db_path) to detect this insecure configuration flag. "
            f"For custom module/parameter patterns, use run_insecure_config_flag_query("
            f"db_path, module, functions, param_name, insecure_value, cwe='{cid}')."
        ),
        "candidate_patterns": patterns,
        "interpretation": (
            "Point detection (no data flow): a finding flags a call configured with an "
            "insecure flag. Confirm the surrounding context with read_file_snippet "
            "before reporting; severity may depend on the deployment environment."
        ),
    }


def build_actions(cid: str, e: dict) -> dict:
    kind = e.get("detection", "taint")
    if kind == "api_misuse":
        actions = _api_misuse_actions(cid, e)
    elif kind == "insecure_config_flag":
        actions = _insecure_config_flag_actions(cid, e)
    else:
        actions = _taint_actions(cid, e)
    if cid in FP_NOTES:
        actions["false_positive_notes"] = FP_NOTES[cid]
    return actions


def main(argv: list[str]) -> int:
    force = "--force" in argv
    wiki = json.loads(CWE_WIKI_PATH.read_text(encoding="utf-8"))
    changed = 0
    for cid, e in wiki.items():
        if force or "actions" not in e:
            e["actions"] = build_actions(cid, e)
            changed += 1
            print(f"  {'~' if force else '+'} {cid}: actions {'regenerated' if force else 'added'}")
    CWE_WIKI_PATH.write_text(
        json.dumps(wiki, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    print(f"Updated actions for {changed}/{len(wiki)} CWEs in {CWE_WIKI_PATH}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
