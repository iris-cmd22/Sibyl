from __future__ import annotations

import json
import re
from pathlib import Path


# Obiettivo: ricavare il codice CWE (es. "CWE-89") dalle "etichette" (tags) che
#            CodeQL allega a una regola.
# Input:    tags = lista di stringhe (es. ["external/cwe/cwe-089", "security"]).
# Output:   stringa "CWE-<numero>" se trovato, altrimenti None.
# Come realizzato: cerca con una espressione regolare il pattern "cwe-<numero>" e
#            ne normalizza il numero (089 -> 89).
def cwe_from_tags(tags) -> str | None:
    for t in tags or []:
        m = re.search(r"cwe[-/](\d+)", str(t), re.IGNORECASE)
        if m:
            return f"CWE-{int(m.group(1))}"
    return None


# Obiettivo: estrarre da una posizione SARIF (verbosa) solo file e numero di riga.
# Input:    physical = il blocco "physicalLocation" di un risultato SARIF.
# Output:   dict semplice {"file": <percorso>, "line": <riga>}.
# Come realizzato: naviga le chiavi annidate del SARIF con .get() (sicuro se mancano).
def loc_brief(physical: dict) -> dict:
    return {
        "file": physical.get("artifactLocation", {}).get("uri", ""),
        "line": physical.get("region", {}).get("startLine"),
    }


# Obiettivo: ricostruire il "percorso del dato" (data-flow) da sorgente a punto
#            pericoloso, che è la PROVA di una vulnerabilità di tipo taint.
# Input:    result = un singolo risultato SARIF (può contenere "codeFlows").
# Output:   lista ordinata di passi [{file, line, note?}, ...]; vuota se non c'è flusso.
# Come realizzato: scorre codeFlows -> threadFlows -> locations, e per ogni passo
#            crea un {file,line} (+ eventuale nota); usa il primo threadFlow trovato.

# TODO: se non c'è flusso non deve tornare nulla, invece mi trovo dei flussi vuoti che confondono l'agente
def extract_flow(result: dict) -> list[dict]:
    steps = []
    for cf in result.get("codeFlows", []):
        for tf in cf.get("threadFlows", []):
            for loc in tf.get("locations", []):
                physical = loc.get("location", {}).get("physicalLocation", {})
                entry = loc_brief(physical)
                msg = loc.get("location", {}).get("message", {}).get("text", "")
                if msg:
                    entry["note"] = msg
                # CodeQL often visits the same file:line more than once in a row
                # (different taint states at the same node); collapsing consecutive
                # duplicates halves the noise sent to the LLM every turn without
                # losing any hop (downstream consumers only use file/line/code).
                if steps and steps[-1].get("file") == entry.get("file") \
                        and steps[-1].get("line") == entry.get("line"):
                    continue
                steps.append(entry)
            if steps:
                return steps
    return steps


# Obiettivo: trasformare un file SARIF (l'output grezzo e verboso di CodeQL) in una
#            lista semplice di "finding" (vulnerabilità) pronti da usare.
# Input:    sarif_path = percorso del file .sarif prodotto da CodeQL.
# Output:   lista di dict, uno per finding: regola, gravità, CWE, file, riga,
#           messaggio, sorgente, sink e l'intero percorso del dato.
# Come realizzato: legge il JSON, costruisce una tabella regola->info, poi per ogni
#            risultato compone il finding usando loc_brief, cwe_from_tags ed extract_flow.
def parse_sarif(sarif_path: Path) -> list[dict]:
    data = json.loads(sarif_path.read_text(encoding="utf-8"))
    findings: list[dict] = []
    for run in data.get("runs", []):
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
            flow_path = extract_flow(res)
            findings.append({
                "rule_id": rid,
                "rule_name": rules.get(rid, {}).get("name", rid),
                "level": res.get("level", "warning"),
                "security_severity": rules.get(rid, {}).get("severity", ""),
                "tags": tags,
                "cwe": cwe_from_tags(tags),
                "message": res.get("message", {}).get("text", ""),
                "file": loc.get("artifactLocation", {}).get("uri", ""),
                "line": loc.get("region", {}).get("startLine"),
                "source": flow_path[0] if flow_path else None,
                "sink": flow_path[-1] if flow_path else None,
                "flow_path": flow_path,
                "flow_steps": len(flow_path),
            })
    return findings
