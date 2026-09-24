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
# Obiettivo: tollerare la virgola finale prima di "}" o "]" che alcuni modelli
#            aggiungono per abitudine (valida in Python/JS, non in JSON standard) e
#            che altrimenti fa fallire json.loads su una tool-call altrimenti corretta.
# Input:    s = candidato JSON grezzo. Output: la stessa stringa senza virgole finali.
def _strip_trailing_commas(s: str) -> str:
    return re.sub(r",(\s*[}\]])", r"\1", s)


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
            obj = json.loads(_strip_trailing_commas(snippet))
        except (json.JSONDecodeError, ValueError):
            continue
        # Some models batch multiple calls under a wrapper key instead of a bare
        # list, e.g. {"function_calls": [...]} or {"tool_calls": [...]}.
        if isinstance(obj, dict):
            for wrapper_key in ("function_calls", "tool_calls", "calls"):
                wrapped = obj.get(wrapper_key)
                if isinstance(wrapped, list):
                    obj = wrapped
                    break
        for item in obj if isinstance(obj, list) else [obj]:
            if not isinstance(item, dict):
                continue
            name = item.get("name")
            args = item.get("arguments", item.get("parameters", {}))
            key = json.dumps({"n": name, "a": args}, sort_keys=True)
            if name in tool_names and isinstance(args, dict) and key not in seen:
                seen.add(key)
                calls.append({"function": {"name": name, "arguments": args}})

    # Fallback: the model sometimes narrates several call attempts as prose with
    # truncated/mismatched braces (e.g. missing the outer closing "}", or fenced
    # blocks that never close before the next one starts). That breaks whole-object
    # parsing above, but the "arguments" value itself is still a well-formed {...}
    # right after its key — recover name/arguments pairs directly, ignoring whether
    # the surrounding wrapper is well-formed.
    if not calls:
        calls = _scan_name_argument_pairs(content, tool_names, seen)
    return calls


# Obiettivo: recuperare coppie name/arguments anche quando l'oggetto che le racchiude
#            e' malformato (graffa di chiusura mancante, fence troncate, piu' blocchi
#            incollati) — l'oggetto "arguments" preso da solo e' quasi sempre valido.
# Input:    content = testo del modello; tool_names = tool reali ammessi; seen = chiavi
#           gia' raccolte (per non duplicare con le altre strategie). Output: le call
#           trovate in questo modo.
# Come realizzato: per ogni occorrenza di "name": "<tool>", cerca la "arguments": {...}
#           piu' vicina subito dopo ed estrae SOLO quel blocco graffe-bilanciato.
def _scan_name_argument_pairs(content: str, tool_names: set[str], seen: set) -> list[dict]:
    calls = []
    for name_match in re.finditer(r'"name"\s*:\s*"([A-Za-z_][A-Za-z0-9_]*)"', content):
        name = name_match.group(1)
        if name not in tool_names:
            continue
        args_key = re.compile(r'"arguments"\s*:\s*').search(content, name_match.end())
        if not args_key or args_key.start() - name_match.end() > 200:
            continue
        brace_start = content.find("{", args_key.end())
        if brace_start == -1 or brace_start - args_key.end() > 20:
            continue
        obj_str = _balanced_from(content, brace_start)
        if obj_str is None:
            continue
        try:
            args = json.loads(_strip_trailing_commas(obj_str))
        except (json.JSONDecodeError, ValueError):
            continue
        if not isinstance(args, dict):
            continue
        key = json.dumps({"n": name, "a": args}, sort_keys=True)
        if key in seen:
            continue
        seen.add(key)
        calls.append({"function": {"name": name, "arguments": args}})
    return calls


# Obiettivo: estrarre UN oggetto {...} bilanciato che inizia esattamente a `start`.
# Input:    text; start = indice della "{" di apertura. Output: la sottostringa
#           bilanciata, o None se non si richiude entro la fine del testo.
def _balanced_from(text: str, start: int) -> str | None:
    depth = 0
    for i in range(start, len(text)):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                return text[start:i + 1]
    return None


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
