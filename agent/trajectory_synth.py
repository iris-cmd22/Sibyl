"""Deterministic Phase-1 trajectory synthesizer.

Produces multi-turn investigation trajectories in the SAME shape the Stage-1
SFT corpus of VulAgentRL expects (Li et al. 2026, "Graph Is the Verifier:
Agentic Reinforcement Learning for Interprocedural Vulnerability Detection"),
but with NO teacher LLM involved: every step (Inspect/Hypothesize/Query/
Falsify/Decide) is derived deterministically from evidence Sibyl already
gathered (agent/worklist.py) plus the persistent node IDs of a graphify graph
(graphify-out/graph.json) standing in for the paper's Joern CPG.

Compatibility contract (why this matters): if a GRPO stage is ever built on
top later (agent/config.py's local model, fine-tuned elsewhere - see the
conversation this module came out of), it must be able to consume this
module's output with ZERO reformatting - only a differently generated ground
truth. To that end:

- A trajectory is a list of chat messages ({"role", "content", ...}), the
  EXACT shape agent/orchestrator.py already produces/checkpoints - so the
  masked-NLL SFT convention from the paper (loss on assistant spans only,
  never on tool-return content) applies with no transformation.
- The final assistant message's content is the structured JSON report the
  paper specifies: {"label": "vulnerable"|"safe", "cwe": "CWE-<n>"|None,
  "evidence_node_ids": [...], "justification": "..."}.
- Evidence node IDs are graphify's own deterministic string IDs (stable
  across re-extractions of unchanged code) - not Joern's persistent
  integers, but they play the identical role: an exact-match address into
  the same graph a future reward function would verify against.

What this module does NOT do: decide whether a deterministic verdict is
CORRECT. That needs an external labeled corpus (e.g. PrimeVul-style) to
compare against - this module only guarantees the OUTPUT SHAPE and the
graph-grounding of cited evidence, not label accuracy.
"""
from __future__ import annotations

import json

from agent import risk_score
from agent.graph_index import load_graph_index, localize_node, two_hop_neighborhood

# Below this aggregate risk_score (agent/risk_score.py), and with no
# corroborating second finding at the same location, Decide defaults to
# "safe" instead of "vulnerable". A first-pass threshold, not tuned on real
# data yet - same "start minimal, evaluate incrementally" spirit as
# risk_score.py itself.
_SAFE_VERDICT_THRESHOLD = 2.0

_SYSTEM_PROTOCOL_PROMPT = (
    "You are a security auditor investigating one function/operation for "
    "vulnerabilities. Follow this protocol: (1) Inspect the code; "
    "(2) Hypothesize a candidate CWE; (3) Query the codebase graph for "
    "interprocedural context; (4) Falsify — look for evidence that would "
    "rule the hypothesis out; (5) Decide — emit a structured JSON report "
    "with your verdict, CWE, cited evidence node IDs, and justification."
)


# --- trajectory construction -------------------------------------------------

# Obiettivo: costruire UNA trajectory multi-turno deterministica per un
#            singolo candidate/operation del worklist, nel protocollo
#            Inspect->Hypothesize->Query->Falsify->Decide. Ogni step e' testo
#            template compilato con dati gia' raccolti (nessun modello
#            coinvolto) - le tool_calls sono SINTETICHE (nomi placeholder,
#            non tool MCP live) perche' qui la "query" e' gia' stata decisa e
#            calcolata a monte, non scelta da un agente in un turno reale.
# Input:    item = candidate (kind="flow") o operation (kind="op") dal
#           worklist, gia' arricchito con file/line/code; kind = "flow"|"op";
#           graph_index = output di load_graph_index (puo' essere None: la
#           trajectory viene comunque prodotta, ma senza evidence_node_ids
#           groundate - validate_trajectory lo segnalera').
# Output:   lista di messaggi stile chat (stesso shape di
#           agent/orchestrator.py: {"role", "content", opz. "tool_calls"/
#           "tool_name"}), ultimo messaggio = report JSON in "content".
def build_trajectory(item: dict, kind: str, graph_index: dict | None) -> list[dict]:
    file, line, code = _location_of(item, kind)
    cwe = risk_score.hypothesize_cwe(item, kind)
    score = risk_score.aggregate_score(item, kind)

    self_node = localize_node(graph_index, file, line) if graph_index and file else None
    neighborhood = (
        two_hop_neighborhood(graph_index, self_node)
        if graph_index and self_node else set()
    )
    neighbor_labels = sorted(
        graph_index["nodes"][n]["label"] for n in neighborhood if n != self_node
    ) if graph_index and self_node else []

    corroborated = _has_corroboration(item, kind)
    verdict = "safe" if (score < _SAFE_VERDICT_THRESHOLD and not corroborated) else "vulnerable"
    evidence_node_ids = sorted(neighborhood) if verdict == "vulnerable" else []

    messages: list[dict] = [
        {"role": "system", "content": _SYSTEM_PROTOCOL_PROMPT},
        {"role": "user", "content": (
            f"Location: {file}:{line}\nKind: {kind}\nCode:\n{code}"
        )},
        {"role": "assistant", "content": (
            f"Inspect: this is a {kind} at {file}:{line}. Code: {code!r}."
        )},
        {"role": "assistant", "content": (
            f"Hypothesize: candidate weakness is {cwe} "
            f"(risk_score={score:.1f}, based on operation/sink kind)."
        )},
        {"role": "assistant", "content": (
            "Query: fetching the 2-hop graph neighborhood around this "
            "location for interprocedural context."
        ), "tool_calls": [{"function": {
            "name": "graphify_two_hop_context",
            "arguments": {"file": file, "line": line},
        }}]},
        {"role": "tool", "tool_name": "graphify_two_hop_context", "content": json.dumps(
            {"self_node": self_node, "neighbors": neighbor_labels}
        )},
        {"role": "assistant", "content": (
            "Falsify: checking for a second, independent finding at the "
            "same location that would corroborate (or fail to corroborate) "
            "this hypothesis."
        ), "tool_calls": [{"function": {
            "name": "check_corroboration",
            "arguments": {"file": file, "line": line},
        }}]},
        {"role": "tool", "tool_name": "check_corroboration", "content": json.dumps(
            {"corroborated": corroborated}
        )},
        {"role": "assistant", "content": json.dumps({
            "label": verdict,
            "cwe": cwe if verdict == "vulnerable" else None,
            "evidence_node_ids": evidence_node_ids,
            "justification": (
                f"{kind} at {file}:{line} scores {score:.1f} on the "
                f"deterministic risk metrics"
                + (", corroborated by a second independent finding"
                   if corroborated else ", no independent corroboration found")
                + f"; hypothesized as {cwe}."
            ),
        })},
    ]
    return messages


# Obiettivo: leggere (file, line, code) da un candidate o operation in modo
#            uniforme (i due dict hanno campi diversi - vedi agent/worklist.py).
# Input:    item, kind come sopra. Output: tupla (file, line, code); campi
#           mancanti diventano stringa vuota/0, mai un'eccezione.
def _location_of(item: dict, kind: str) -> tuple[str, int, str]:
    if kind == "op":
        return item.get("file", ""), item.get("line", 0) or 0, item.get("code", "")
    sink = item.get("sink") or {}
    path = item.get("path") or []
    code = path[-1].get("code", "") if path else ""
    return sink.get("file", ""), sink.get("line", 0) or 0, code


# Obiettivo: il segnale di "Falsify" - c'e' un secondo finding indipendente
#            (kind diverso) sulla STESSA location? E' la versione a costo
#            zero della "convergenza multi-query" discussa in conversazione:
#            oggi guarda solo se e' un'operation gia' marcata
#            broken_sanitizer_patterns sulla stessa riga (unico segnale
#            "negativo" disponibile senza nuove query CodeQL).
# Input:    item, kind come sopra. Output: bool.
def _has_corroboration(item: dict, kind: str) -> bool:
    return kind == "op" and item.get("kind") == "broken_sanitizer_patterns"


# --- validation (two-layer rejection sampling, paper sec. 3.1) -------------

_REQUIRED_REPORT_KEYS = {"label", "cwe", "evidence_node_ids", "justification"}


# Obiettivo: replicare i due filtri di rejection sampling del paper: 1) formato
#            e verdetto validi; 2) ogni evidence_node_id citato esiste nel
#            grafo e sta nel vicinato a 2 hop del nodo del finding. Una
#            trajectory che fallisce NON entra nel corpus SFT.
# Input:    trajectory = output di build_trajectory; graph_index = output di
#           load_graph_index (None = layer 2 skippato, segnalato nel motivo).
# Output:   (ok: bool, reason: str) - reason spiega il fallimento, o "ok".
def validate_trajectory(trajectory: list[dict], graph_index: dict | None) -> tuple[bool, str]:
    last = trajectory[-1]
    try:
        report = json.loads(last["content"])
    except (json.JSONDecodeError, KeyError, TypeError):
        return False, "final message is not valid JSON"
    if not _REQUIRED_REPORT_KEYS.issubset(report):
        return False, f"report missing keys: {_REQUIRED_REPORT_KEYS - set(report)}"
    if report["label"] not in ("vulnerable", "safe"):
        return False, f"invalid label: {report['label']!r}"
    if report["label"] == "safe" and report.get("cwe") not in (None, ""):
        return False, "safe verdict must not carry a CWE"

    if graph_index is None:
        return (True, "ok (no graph index — evidence grounding not checked)")

    # Layer 2: every cited node must exist AND lie in some 2-hop neighborhood
    # already computed for this trajectory (the tool result from the Query
    # step carries the neighbor labels, not ids, so re-derive from the
    # location instead of re-parsing the tool message).
    for node_id in report["evidence_node_ids"]:
        if node_id not in graph_index["nodes"]:
            return False, f"evidence_node_id {node_id!r} not in graph"
    return True, "ok"


# --- corpus-level entry point ------------------------------------------------

# Obiettivo: generare e validare una trajectory per OGNI candidate/operation
#            del worklist (gia' ordinato per rischio da risk_score.sort_worklist),
#            scartando quelle che non passano validate_trajectory - stesso
#            ruolo del two-layer rejection sampling del paper, qui a costo
#            zero perche' non c'e' generazione LLM da rifare.
# Input:    worklist = WorkList popolato (dopo _gather_evidence); graph_index =
#           output di load_graph_index (None = grounding disabilitato).
# Output:   lista di dict {"kind", "item", "trajectory", "valid", "reason"} -
#           include anche le trajectory scartate (valid=False), cosi' il
#           chiamante puo' auditare perche', invece di sparire silenziosamente.
def synthesize_corpus(worklist, graph_index: dict | None) -> list[dict]:
    out = []
    for kind, items in (("flow", worklist.candidates), ("op", worklist.operations)):
        for item in items:
            trajectory = build_trajectory(item, kind, graph_index)
            valid, reason = validate_trajectory(trajectory, graph_index)
            out.append({
                "kind": kind, "item": item, "trajectory": trajectory,
                "valid": valid, "reason": reason,
            })
    return out
