"""Recover tool calls that a model emitted as TEXT instead of in the structured
`tool_calls` field. Many local models (incl. some Ollama builds) print a
```json {"name":..., "arguments":...} ``` block in `content`."""
from __future__ import annotations

import json
import re


# Obiettivo: recuperare una chiamata a tool che il modello ha STAMPATO come testo
#            (in un blocco json) invece di metterla nel canale strutturato tool_calls,
#            così il loop non si blocca e quel testo non viene scambiato per il report.
# Input:    content = il testo della risposta del modello;
#           tool_names = insieme dei nomi di tool REALI (per filtrare i falsi positivi).
# Output:   lista di dict {"function": {"name", "arguments"}}; vuota se non c'è nulla.
# Come realizzato: raccoglie i candidati JSON (blocchi recintati, l'intero testo, ogni
#            {...} bilanciato), li interpreta, e tiene solo gli oggetti il cui "name" è
#            un tool reale, evitando duplicati.
def extract_text_tool_calls(content: str, tool_names: set[str]) -> list[dict]:
    if not content or '"name"' not in content:
        return []

    # Candidate JSON strings: fenced code blocks, the whole content, and every
    # top-level balanced {...} object (handles nested braces correctly).
    candidates: list[str] = []
    for m in re.finditer(r"```(?:json)?\s*(.*?)```", content, re.DOTALL):
        candidates.append(m.group(1).strip())
    candidates.append(content.strip())
    candidates.extend(_balanced_objects(content))

    calls, seen = [], set()
    for snippet in candidates:
        try:
            obj = json.loads(snippet)
        except (json.JSONDecodeError, ValueError):
            continue
        for item in obj if isinstance(obj, list) else [obj]:
            if not isinstance(item, dict):
                continue
            name = item.get("name")
            args = item.get("arguments", item.get("parameters", {}))
            key = json.dumps({"n": name, "a": args}, sort_keys=True)
            if name in tool_names and isinstance(args, dict) and key not in seen:
                seen.add(key)
                calls.append({"function": {"name": name, "arguments": args}})
    return calls


# Obiettivo: trovare nel testo ogni oggetto JSON di primo livello {...} con le
#            parentesi graffe bilanciate (gestendo correttamente l'annidamento).
# Input:    text = la stringa in cui cercare.
# Output:   lista di sotto-stringhe, ciascuna un {...} completo e bilanciato.
# Come realizzato: scorre i caratteri tenendo un contatore di profondità; quando torna
#            a zero ha trovato un oggetto completo e lo aggiunge alla lista.
def _balanced_objects(text: str) -> list[str]:
    out, depth, start = [], 0, None
    for i, ch in enumerate(text):
        if ch == "{":
            if depth == 0:
                start = i
            depth += 1
        elif ch == "}" and depth:
            depth -= 1
            if depth == 0 and start is not None:
                out.append(text[start : i + 1])
                start = None
    return out
