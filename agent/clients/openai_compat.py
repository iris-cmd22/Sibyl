"""Adapter for any OpenAI-compatible chat API (Gemini, Groq, Cerebras, OpenRouter,
OpenAI, ...). Same protocol, different base_url + api_key + model.

Uses the official `openai` async SDK. The tool schema the agent already builds is
OpenAI function-calling format, so tools need no conversion. Only the message
history is translated, because under the OpenAI protocol each tool result must
carry the tool_call_id it answers. Adds a proactive throttle and 429 retry."""
from __future__ import annotations

import asyncio
import json
import re
import sys


# Obiettivo: tradurre i messaggi nel formato "canonico" dell'agente verso il formato
#            chat di OpenAI (richiesto da questi endpoint).
# Input:    messages = lista di messaggi dell'agente (system/user/assistant/tool).
# Output:   lista di messaggi in formato OpenAI (con tool_call_id sui risultati tool).
# Come realizzato: copia system/user/assistant; per ogni messaggio "tool" gli abbina, in
#            ordine, l'id della tool-call dell'assistant precedente (OpenAI lo richiede).
def _to_openai(messages: list[dict]) -> list[dict]:
    out: list[dict] = []
    pending_ids: list[str] = []
    for m in messages:
        role = m.get("role")
        if role == "assistant":
            tcs = m.get("tool_calls") or []
            pending_ids = []
            am: dict = {"role": "assistant", "content": m.get("content") or ""}
            oai_tcs = []
            for i, tc in enumerate(tcs):
                fn = tc.get("function", {})
                cid = tc.get("id") or f"call_{i}"
                pending_ids.append(cid)
                args = fn.get("arguments", {})
                if not isinstance(args, str):
                    args = json.dumps(args)
                oai_tcs.append({"id": cid, "type": "function",
                                "function": {"name": fn.get("name"), "arguments": args}})
            if oai_tcs:
                am["tool_calls"] = oai_tcs
            out.append(am)
        elif role == "tool":
            cid = pending_ids.pop(0) if pending_ids else "call_0"
            out.append({"role": "tool", "tool_call_id": cid, "content": m.get("content", "")})
        else:  # system, user
            out.append({"role": role, "content": m.get("content", "")})
    return out


# Obiettivo: capire quanti secondi aspettare dopo un errore 429 (rate limit).
# Input:    exc = l'eccezione RateLimitError (il suo testo contiene il ritardo suggerito).
# Output:   secondi da attendere (float).
# Come realizzato: cerca nel messaggio "retry in <n>s" o "retryDelay: <n>s"; default se assente.
def _retry_delay(exc, default: float = 30.0) -> float:
    text = str(exc)
    m = re.search(r"retry in ([\d.]+)s", text) or re.search(r"retryDelay['\"]?:?\s*['\"]?(\d+)", text)
    if m:
        return float(m.group(1)) + 1.0   # piccolo margine
    return default


# Obiettivo: capire se un 429 è dovuto alla quota GIORNALIERA (non recuperabile aspettando).
# Input:    exc = l'eccezione RateLimitError.
# Output:   True se è una quota per-giorno; False altrimenti.
# Come realizzato: cerca nel messaggio i marcatori della quota giornaliera.
def _is_daily_quota(exc) -> bool:
    t = str(exc)
    return "PerDay" in t or "RequestsPerDay" in t or "per day" in t.lower()


# Obiettivo: incapsulare un client per QUALSIASI API OpenAI-compatibile, esponendo la
#            stessa interfaccia di OllamaChat (chat asincrona) all'orchestrator.
class OpenAICompatChat:
    # Obiettivo: preparare il client verso l'endpoint scelto.
    # Input:    model = id del modello; api_key = chiave; base_url = endpoint OpenAI-compat;
    #           min_interval = secondi minimi tra richieste (throttle); label = nome provider.
    # Output:   nessuno (inizializza l'oggetto).
    # Come realizzato: import pigro di AsyncOpenAI (dipendenza opzionale), verifica la key,
    #            crea il client e prepara lo stato per il throttle.
    def __init__(self, model: str, api_key: str | None, base_url: str,
                 min_interval: float = 0.0, label: str = "llm"):
        from openai import AsyncOpenAI  # lazy: optional dependency

        if not api_key:
            raise RuntimeError(
                f"[{label}] API key non impostata. Aggiungila al .env per usare questo provider."
            )
        self.model = model
        self.label = label
        self._client = AsyncOpenAI(api_key=api_key, base_url=base_url)
        self._min_interval = min_interval
        self._last_call = 0.0

    # Obiettivo: distanziare le richieste per non superare il limite richieste/minuto.
    # Input:    nessuno (usa l'istante dell'ultima chiamata e l'intervallo minimo).
    # Output:   nessuno (eventualmente attende).
    # Come realizzato: dorme per il tempo mancante all'intervallo minimo, poi aggiorna il timestamp.
    async def _throttle(self) -> None:
        if self._min_interval <= 0:
            return
        import time

        wait = self._min_interval - (time.monotonic() - self._last_call)
        if wait > 0:
            print(f"[{self.label}] throttle: attendo {wait:.1f}s (rate limit)",
                  file=sys.stderr, flush=True)
            await asyncio.sleep(wait)
        self._last_call = time.monotonic()

    # Obiettivo: inviare un turno di conversazione e restituirlo nel formato dell'orchestrator.
    # Input:    messages = la conversazione finora; tools = i tool disponibili (opzionale).
    # Output:   dict del messaggio assistant, con eventuali tool_calls normalizzate.
    # Come realizzato: applica throttle, traduce i messaggi, chiama chat.completions con retry
    #            sul 429 (fail-fast se la quota è giornaliera) e ricompone content + tool_calls.
    async def chat(self, messages: list[dict], tools: list[dict] | None = None) -> dict:
        from openai import RateLimitError

        await self._throttle()
        oai_messages = _to_openai(messages)
        last_exc = None
        for attempt in range(6):
            try:
                resp = await self._client.chat.completions.create(
                    model=self.model,
                    messages=oai_messages,
                    tools=tools or None,
                )
                break
            except RateLimitError as e:
                last_exc = e
                if _is_daily_quota(e):
                    print(f"[{self.label}] quota GIORNALIERA del free tier esaurita per "
                          f"'{self.model}'. Cambia modello/provider o attiva il billing.",
                          file=sys.stderr, flush=True)
                    raise
                delay = _retry_delay(e)
                print(f"[{self.label}] rate limited (429), waiting {delay:.0f}s "
                      f"(attempt {attempt + 1}/6)", file=sys.stderr, flush=True)
                await asyncio.sleep(delay)
        else:
            raise last_exc   # all attempts exhausted

        choice = resp.choices[0].message
        msg: dict = {"role": "assistant", "content": choice.content or ""}
        if getattr(choice, "tool_calls", None):
            msg["tool_calls"] = [
                {"id": tc.id, "type": "function",
                 "function": {"name": tc.function.name, "arguments": tc.function.arguments}}
                for tc in choice.tool_calls
            ]
        return msg
