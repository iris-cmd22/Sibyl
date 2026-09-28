"""Per-finding risk score: prioritizes the ORDER Detection/Validation consume
worklist candidates/operations/findings, so a budget-limited run covers the
highest-value items first instead of whatever order find_all_flows/the
categorized find_* tools happened to return them in.

Metrics come in two shapes, both scored on an open scale (higher = more
worth exploring first), never raising, returning 0.0 when not applicable:

- STATELESS  (item, kind, context) -> float: only look at the single item
  (score_flow_length, score_operation_kind, score_path_truncated).
- CONTEXTUAL (item, kind, context) -> float: need aggregate info computed
  ONCE per worklist (sink fan-out across all flows, files with a broken
  sanitizer, fan-in/out and community from a graphify graph) — build_context()
  computes that once; aggregate_score()/sort_worklist() always pass it, so a
  contextual metric never has to recompute shared state per item.

New metrics get added to METRICS one at a time and can be evaluated/toggled
independently (comment out a line) without touching the others. Metrics that
need infrastructure Sibyl doesn't have yet (a real AST parser, an external
Halstead tool, a trained naturalness model) are defined but kept OUT of
METRICS, in PENDING_METRICS, with a docstring explaining the blocker — so
they stay visible instead of silently missing (same "never silently drop"
principle as the UNVERIFIED tags in agent/orchestrator.py).
"""
from __future__ import annotations

from typing import Callable

from agent import graph_index as gi

MetricFn = Callable[[dict, str, dict], float]


# --- stateless metrics -------------------------------------------------------

# Obiettivo: dare priorita' ai flow in base alla lunghezza della catena
#            source->sink: piu' hop = piu' difficile da giudicare a occhio, quindi
#            piu' valore nel farlo verificare per primo da Detection/Validation.
# Input:    item = un candidate dal worklist (ha gia' "steps", da find_all_flows);
#           kind = "flow"|"op"; context = non usata. Output: 0.0 se kind !=
#           "flow", altrimenti item["steps"].
def score_flow_length(item: dict, kind: str, context: dict) -> float:
    if kind != "flow":
        return 0.0
    return float(item.get("steps", 0))


# Obiettivo: pesare le operazioni sensibili per kind, dato che alcune categorie
#            sono intrinsecamente piu' pericolose di altre (command execution vale
#            piu' di un semplice filesystem access). Pesi iniziali giudicati a mano
#            sui find_* categorizzati esistenti (agent/orchestrator.py:_OPERATION_TOOLS)
#            — DA TARARE con dati reali (es. Big-Vul/DiverseVul) appena disponibili.
# Input:    item = un'operation dal worklist (ha gia' "kind", dal find_* che l'ha
#           trovata); kind = "flow"|"op"; context = non usata. Output: peso per
#           il kind, 1.0 di default per kind non elencati (non azzerato: resta
#           comunque un'operazione sensibile, solo senza un peso specifico).
_OP_KIND_WEIGHT = {
    "command_execution": 5.0,
    "code_execution": 5.0,
    "sql_execution": 4.0,
    "broken_sanitizer_patterns": 4.0,
    "crypto_operations": 3.0,
    "weak_randomness": 3.0,
    "decoding_operations": 2.0,
    "filesystem_access": 2.0,
    "insecure_config_flags": 2.0,
    "resource_handling_issues": 2.0,
    "exception_handling_issues": 1.0,
}


def score_operation_kind(item: dict, kind: str, context: dict) -> float:
    if kind != "op":
        return 0.0
    return _OP_KIND_WEIGHT.get(item.get("kind", ""), 1.0)


# Obiettivo: dare un bonus ai flow il cui path e' stato troncato
#            (path_truncated=True, da find_all_flows) - il flow reale e' PIU'
#            lungo di quanto mostrato, quindi probabilmente piu' difficile da
#            giudicare a occhio di quanto gia' suggerisca "steps" da solo.
# Input:    item, kind, context (non usata). Output: 2.0 se troncato, 0.0 altrimenti.
def score_path_truncated(item: dict, kind: str, context: dict) -> float:
    if kind != "flow":
        return 0.0
    return 2.0 if item.get("path_truncated") else 0.0


# --- contextual metrics (need build_context() run once per worklist) -------

# Obiettivo: un source che raggiunge MOLTI sink distinti e' una superficie
#            d'attacco piu' ampia di uno che ne raggiunge uno solo ("sink
#            diversity", una delle metriche "gratis" gia' derivabili da
#            worklist.candidates - qui precalcolata una volta in build_context
#            invece che ricontata per ogni item).
# Input:    item (un candidate), kind, context (deve avere
#           "sink_fanout_by_source" da build_context). Output: numero di
#           sink DISTINTI aggiuntivi oltre il primo per lo stesso source, 0.0
#           per gli item "op" o se il context non e' stato costruito.
def score_sink_fanout(item: dict, kind: str, context: dict) -> float:
    if kind != "flow":
        return 0.0
    src = item.get("source") or {}
    key = (src.get("file"), src.get("line"))
    return float(max(0, context.get("sink_fanout_by_source", {}).get(key, 1) - 1))


# Obiettivo: dare priorita' a flow/operation nello STESSO file di un finding
#            gia' marcato find_broken_sanitizer_patterns - segnale grezzo (a
#            livello di file, non di riga esatta) che quel file ha gia' un
#            tentativo di sanitizzazione fallito altrove. Complementare, non
#            sostitutivo, del check di corroborazione riga-per-riga usato da
#            agent/trajectory_synth.py per lo step Falsify (quello e' per
#            riga esatta e serve al verdetto; questo e' per file e serve solo
#            a ordinare la coda di esplorazione).
# Input:    item, kind, context (deve avere "broken_sanitizer_files" da
#           build_context). Output: 3.0 se il file combacia, 0.0 altrimenti.
def score_broken_sanitizer_proximity(item: dict, kind: str, context: dict) -> float:
    file = item.get("file") if kind == "op" else (item.get("sink") or {}).get("file")
    return 3.0 if file in context.get("broken_sanitizer_files", set()) else 0.0


# Obiettivo: quante entita' DISTINTE chiamano la funzione/entita' che
#            racchiude questo finding, via gli edge "calls" di graphify (fan-in) -
#            alto fan-in = raggio di impatto piu' ampio se il finding e' davvero
#            vulnerabile (proprieta' strutturale, zero nuove query CodeQL: il
#            call-graph e' gia' estratto da graphify).
# Input:    item, kind, context (deve avere "graph_index" e "localized" da
#           build_context). Output: 0.0 se non c'e' un graph_index o l'item
#           non e' localizzabile, altrimenti il numero di chiamanti distinti.
def score_fan_in(item: dict, kind: str, context: dict) -> float:
    graph = context.get("graph_index")
    node = context.get("localized", {}).get(id(item))
    if graph is None or node is None:
        return 0.0
    return float(len(graph["in_adj"].get(node, ())))


# Obiettivo: quante entita' DISTINTE chiama la funzione che racchiude questo
#            finding (fan-out) - proxy economico di complessita'/orchestrazione:
#            una funzione che ne chiama molte altre e' tipicamente piu' complessa
#            da verificare a mano. Stessa fonte gratis di score_fan_in.
# Input/Output: come score_fan_in, ma su graph["out_adj"].
def score_fan_out(item: dict, kind: str, context: dict) -> float:
    graph = context.get("graph_index")
    node = context.get("localized", {}).get(id(item))
    if graph is None or node is None:
        return 0.0
    return float(len(graph["out_adj"].get(node, ())))


# Obiettivo: quanti ALTRI finding di questo stesso worklist ricadono nella
#            STESSA community graphify (gia' clusterizzata via Louvain) - un
#            cluster denso di finding e' un segnale di area di codice
#            strutturalmente a rischio (concetto di "software network" pesato
#            discusso in conversazione, arxiv 1902.04844).
# Input:    item, kind, context (deve avere "graph_index", "localized" e
#           "community_counts" da build_context). Output: 0.0 se non
#           localizzabile o senza community, altrimenti il conteggio (esclusa
#           se stessa) di altri finding nella stessa community.
def score_community_concentration(item: dict, kind: str, context: dict) -> float:
    graph = context.get("graph_index")
    node = context.get("localized", {}).get(id(item))
    if graph is None or node is None:
        return 0.0
    community = graph["nodes"].get(node, {}).get("community")
    if community is None:
        return 0.0
    return float(max(0, context.get("community_counts", {}).get(community, 1) - 1))


# --- documented gaps: metrics needing infrastructure Sibyl doesn't have yet -

# Obiettivo: placeholder per McCabe/cognitive complexity, numero di nodi AST
#            (la singola metrica piu' predittiva secondo l'ICSE'26 su cui ci
#            siamo basati), nesting depth, numero di branch. PENDING: serve un
#            parser AST reale (tree-sitter) o una nuova query CodeQL dedicata —
#            nessuna delle due esiste oggi in Sibyl.
def score_cyclomatic_complexity(item: dict, kind: str, context: dict) -> float:
    return 0.0


# Obiettivo: placeholder per CBO/LCOM (coupling/cohesion a livello di classe).
#            PENDING: specifico per OOP, priorita' bassa per un target
#            prevalentemente C/C++; richiederebbe comunque una query CodeQL
#            dedicata sugli accessi ai membri.
def score_coupling_cohesion(item: dict, kind: str, context: dict) -> float:
    return 0.0


# Obiettivo: placeholder per Halstead (volume/difficulty/effort da conteggio
#            operatori/operandi). PENDING: serve un tool esterno (radon/lizard),
#            non installato — CodeQL non e' pensato per contare in questo modo.
def score_halstead(item: dict, kind: str, context: dict) -> float:
    return 0.0


# Obiettivo: placeholder per naturalness/entropy (n-gram, Ray et al. 2016).
#            PENDING: serve un modello n-gram pre-addestrato sul corpus, non
#            costruito. Nessun collegamento con Benford (testato in
#            conversazione, scartato per i literal numerici).
def score_naturalness(item: dict, kind: str, context: dict) -> float:
    return 0.0


# Obiettivo: placeholder per LOC/numero-parametri della funzione racchiudente.
#            PENDING: richiede identificare in modo affidabile i confini di
#            una funzione multi-linguaggio (Python/C/C++/JS) — un'euristica a
#            regex rischierebbe di dare un numero SBAGLIATO invece di nessun
#            segnale, peggio che ometterla. Serve un parser reale prima.
def score_function_size(item: dict, kind: str, context: dict) -> float:
    return 0.0


PENDING_METRICS: list[MetricFn] = [
    score_cyclomatic_complexity,
    score_coupling_cohesion,
    score_halstead,
    score_naturalness,
    score_function_size,
]


# Registro delle metriche ATTIVE: per aggiungerne una nuova, scrivere la
# funzione sopra (stessa firma (item, kind, context) -> float, mai
# un'eccezione) e appenderla qui. Per valutarne una da sola, commentare
# temporaneamente le altre righe. Una metrica in PENDING_METRICS si sposta
# qui solo quando l'infrastruttura che le serve esiste davvero.
METRICS: list[MetricFn] = [
    score_flow_length,
    score_operation_kind,
    score_path_truncated,
    score_sink_fanout,
    score_broken_sanitizer_proximity,
    score_fan_in,
    score_fan_out,
    score_community_concentration,
]


# Obiettivo: leggere (file, line) da un candidate o operation in modo
#            uniforme (i due dict hanno campi diversi — vedi agent/worklist.py).
# Input:    item, kind = "flow"|"op". Output: tupla (file, line); None se il
#           campo non c'e', mai un'eccezione.
def _item_location(item: dict, kind: str) -> tuple[str | None, int | None]:
    if kind == "op":
        return item.get("file"), item.get("line")
    sink = item.get("sink") or {}
    return sink.get("file"), sink.get("line")


# Obiettivo: precalcolare UNA VOLTA per worklist tutto cio' che le metriche
#            contestuali leggono, invece di ricalcolarlo item per item:
#            fan-out dei sink per source, file con sanitizzatori rotti, e (se
#            c'e' un graph_index) la localizzazione di ogni item sul grafo +
#            il conteggio per community.
# Input:    worklist = l'oggetto WorkList popolato da _gather_evidence;
#           graph_index = output di graph_index.load_graph_index, o None
#           (le metriche a grafo tornano 0.0, il resto funziona comunque).
# Output:   dict passato a ogni chiamata di aggregate_score.
def build_context(worklist, graph_index: dict | None = None) -> dict:
    context: dict = {"graph_index": graph_index}

    sink_fanout: dict[tuple, int] = {}
    for c in worklist.candidates:
        src = c.get("source") or {}
        key = (src.get("file"), src.get("line"))
        sink_fanout[key] = sink_fanout.get(key, 0) + 1
    context["sink_fanout_by_source"] = sink_fanout

    context["broken_sanitizer_files"] = {
        o.get("file") for o in worklist.operations
        if o.get("kind") == "broken_sanitizer_patterns"
    }

    localized: dict[int, str | None] = {}
    community_counts: dict = {}
    if graph_index is not None:
        for kind, items in (("flow", worklist.candidates), ("op", worklist.operations)):
            for item in items:
                file, line = _item_location(item, kind)
                node = gi.localize_node(graph_index, file, line) if file and line else None
                localized[id(item)] = node
                if node is not None:
                    community = graph_index["nodes"].get(node, {}).get("community")
                    if community is not None:
                        community_counts[community] = community_counts.get(community, 0) + 1
    context["localized"] = localized
    context["community_counts"] = community_counts
    return context


# --- CWE hypothesis (used by agent/trajectory_synth.py's "Hypothesize" step) -

# Obiettivo: mappa deterministica kind -> CWE candidato, usata da
#            agent/trajectory_synth.py per lo step "Hypothesize" (nessun modello
#            coinvolto: e' solo un lookup). Un solo CWE per kind e' una
#            semplificazione (una vera operation puo' ricadere sotto piu' CWE a
#            seconda del contesto) — DA RAFFINARE con evidenza reale (es. il
#            sink_hint di un flow) prima di fidarsene ciecamente.
OP_KIND_TO_CWE = {
    "command_execution": "CWE-78",
    "code_execution": "CWE-94",
    "sql_execution": "CWE-89",
    "broken_sanitizer_patterns": "CWE-20",
    "crypto_operations": "CWE-327",
    "weak_randomness": "CWE-330",
    "decoding_operations": "CWE-502",
    "filesystem_access": "CWE-22",
    "insecure_config_flags": "CWE-16",
    "resource_handling_issues": "CWE-404",
    "exception_handling_issues": "CWE-755",
}

# Obiettivo: stessa idea ma per i flow (find_all_flows), dove l'unico segnale
#            deterministico disponibile senza analisi aggiuntiva e' il
#            sink_hint gia' estratto dal tool. Matching per sottostringa (case
#            insensitive), fallback su CWE-20 (Improper Input Validation) come
#            categoria generica di taint flow quando nessuna keyword combacia.
_SINK_HINT_TO_CWE = [
    ("sql", "CWE-89"),
    ("command", "CWE-78"),
    ("exec", "CWE-78"),
    ("path", "CWE-22"),
    ("file", "CWE-22"),
    ("xml", "CWE-611"),
    ("xpath", "CWE-643"),
    ("ldap", "CWE-90"),
    ("template", "CWE-1336"),
    ("deserial", "CWE-502"),
    ("regex", "CWE-1333"),
    ("format", "CWE-134"),
    ("redirect", "CWE-601"),
    ("log", "CWE-117"),
]
_FLOW_FALLBACK_CWE = "CWE-20"


# Obiettivo: dato un item (flow o op), restituire il CWE candidato per lo step
#            "Hypothesize" di agent/trajectory_synth.py — puro lookup, mai
#            un'eccezione.
# Input:    item = candidate o operation dal worklist; kind = "flow"|"op".
# Output:   stringa "CWE-<n>", mai None (i fallback coprono ogni caso).
def hypothesize_cwe(item: dict, kind: str) -> str:
    if kind == "op":
        return OP_KIND_TO_CWE.get(item.get("kind", ""), _FLOW_FALLBACK_CWE)
    hint = (item.get("sink_hint") or "").lower()
    for needle, cwe in _SINK_HINT_TO_CWE:
        if needle in hint:
            return cwe
    return _FLOW_FALLBACK_CWE


# --- scoring entry points -----------------------------------------------------

# Obiettivo: comporre il punteggio finale di un item sommando ogni metrica attiva.
# Input:    item, kind come sopra; context = output di build_context (default
#           {}: le metriche contestuali tornano 0.0, quelle stateless
#           funzionano comunque); metrics = elenco di metriche da usare
#           (default: l'intero registro METRICS corrente).
# Output:   float, punteggio aggregato (piu' alto = priorita' piu' alta).
def aggregate_score(item: dict, kind: str, context: dict | None = None,
                     metrics: list[MetricFn] = METRICS) -> float:
    context = context if context is not None else {}
    return sum(m(item, kind, context) for m in metrics)


# Obiettivo: riordinare IN PLACE candidates/operations/findings del worklist per
#            punteggio di rischio decrescente. Va chiamata subito dopo il gathering
#            (prima che orchestrator.py costruisca la lista "items" per il batching
#            di Detection): cosi' un run a budget limitato (max_steps) esaurisce gli
#            step sui candidati piu' a rischio, non su quelli arrivati per primi da
#            find_all_flows. worklist.findings e' tipicamente ancora vuota a questo
#            punto (si popola durante Detection, che legge gia' l'ordine appena
#            fissato qui) — il sort su di essa e' innocuo (no-op su lista vuota) e
#            serve solo se questa funzione viene richiamata piu' tardi.
# Input:    worklist = l'oggetto WorkList popolato da _gather_evidence;
#           graph_index = output di graph_index.load_graph_index, opzionale
#           (None = le metriche a grafo si azzerano, tutto il resto invariato —
#           agent/orchestrator.py chiama questa funzione senza passarlo).
# Output:   nessuno (modifica worklist.candidates/.operations/.findings in place).
def sort_worklist(worklist, graph_index: dict | None = None) -> None:
    context = build_context(worklist, graph_index)
    worklist.candidates.sort(key=lambda c: aggregate_score(c, "flow", context), reverse=True)
    worklist.operations.sort(key=lambda o: aggregate_score(o, "op", context), reverse=True)
    worklist.findings.sort(
        key=lambda f: aggregate_score(f["item"], f["kind"], context), reverse=True
    )
