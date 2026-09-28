"""Shared graphify graph loading + lookups.

Used by BOTH agent/risk_score.py (contextual metrics: fan-in/out, community
concentration) and agent/trajectory_synth.py (evidence grounding, two-hop
neighborhood) — kept in its own module so neither of the two needs to import
the other (risk_score.hypothesize_cwe is used by trajectory_synth; if
trajectory_synth also owned graph loading, risk_score would need it back,
a cycle).
"""
from __future__ import annotations

import json
import re
from collections import deque
from pathlib import Path

_LINE_RE = re.compile(r"(\d+)")


# Obiettivo: leggere il numero di riga da un source_location tipo "L15".
# Input:    source_location = stringa (o None/altro) dal nodo graphify.
# Output:   int, o None se non parsabile.
def _parse_line(source_location) -> int | None:
    if not isinstance(source_location, str):
        return None
    m = _LINE_RE.search(source_location)
    return int(m.group(1)) if m else None


# Obiettivo: caricare graphify-out/graph.json in un indice utilizzabile senza
#            dipendere da networkx (agent/ resta self-contained, per lo stesso
#            motivo dichiarato in agent/config.py). Costruisce: nodes (id ->
#            dict), by_file (source_file -> lista (line, id) ordinata),
#            adjacency (id -> set di vicini, NON orientata, per il vicinato a
#            2 hop), e in_adj/out_adj (id -> set, orientati, SOLO per edge
#            relation=="calls" — l'unica relazione con direzione
#            caller->callee garantita, per costruzione, dallo
#            extraction-spec di graphify — usati per fan-in/fan-out).
# Input:    graphify_out_dir = path alla cartella graphify-out (contiene
#           graph.json).
# Output:   dict con le chiavi sopra, oppure None se il file non esiste
#           (nessuna eccezione: il chiamante decide come degradare, es.
#           saltando il grounding delle evidenze o azzerando le metriche a
#           grafo).
def load_graph_index(graphify_out_dir: str) -> dict | None:
    path = Path(graphify_out_dir) / "graph.json"
    if not path.exists():
        return None
    data = json.loads(path.read_text(encoding="utf-8"))

    nodes = {n["id"]: n for n in data.get("nodes", [])}
    by_file: dict[str, list[tuple[int, str]]] = {}
    for n in data.get("nodes", []):
        line = _parse_line(n.get("source_location"))
        if line is None:
            continue
        by_file.setdefault(n.get("source_file", ""), []).append((line, n["id"]))
    for entries in by_file.values():
        entries.sort()

    adjacency: dict[str, set[str]] = {}
    in_adj: dict[str, set[str]] = {}
    out_adj: dict[str, set[str]] = {}
    for e in data.get("links", data.get("edges", [])):
        src, tgt = e.get("source"), e.get("target")
        if src is None or tgt is None:
            continue
        adjacency.setdefault(src, set()).add(tgt)
        adjacency.setdefault(tgt, set()).add(src)
        if e.get("relation") == "calls":
            out_adj.setdefault(src, set()).add(tgt)
            in_adj.setdefault(tgt, set()).add(src)

    return {
        "nodes": nodes, "by_file": by_file, "adjacency": adjacency,
        "in_adj": in_adj, "out_adj": out_adj,
    }


# Obiettivo: individuare il nodo graphify che rappresenta l'entita' che
#            racchiude una data riga di codice (join CodeQL/SAST-riga -> nodo
#            grafo), usando SOLO file + riga, cosi' generalizza a qualunque
#            tool che riporti una location (non solo CodeQL — vedi
#            conversazione: il join dipende solo da file/line, SARIF-style).
# Input:    graph_index = output di load_graph_index; file = source_file
#           relativo (deve combaciare con quello registrato da graphify);
#           line = riga target.
# Output:   node id piu' vicino "per difetto" (riga <= target, la piu' alta),
#           o il nodo con riga piu' vicina in assoluto se nessuno la precede;
#           None se il file non ha nodi indicizzati.
def localize_node(graph_index: dict, file: str, line: int) -> str | None:
    entries = graph_index["by_file"].get(file)
    if not entries:
        return None
    best = None
    for entry_line, node_id in entries:
        if entry_line <= line:
            best = node_id
        else:
            break
    return best if best is not None else entries[0][1]


# Obiettivo: calcolare il vicinato a 2 hop di un nodo (non orientato) per il
#            filtro di validita' delle evidenze (stesso ruolo del "two-hop
#            neighborhood" nel paper VulAgentRL, sez. 3.1, layer 2 del
#            rejection sampling) - un nodo citato come evidenza fuori da qui
#            e' quasi certamente irrilevante/allucinato rispetto al finding
#            in esame.
# Input:    graph_index; node_id = nodo di partenza.
# Output:   set di node id raggiungibili in <= 2 hop (include node_id stesso).
def two_hop_neighborhood(graph_index: dict, node_id: str) -> set[str]:
    adjacency = graph_index["adjacency"]
    visited = {node_id}
    frontier = deque([(node_id, 0)])
    while frontier:
        current, depth = frontier.popleft()
        if depth >= 2:
            continue
        for neighbor in adjacency.get(current, ()):
            if neighbor not in visited:
                visited.add(neighbor)
                frontier.append((neighbor, depth + 1))
    return visited
