"""Adapter to Google Gemini via its OpenAI-compatible endpoint.

Lets the agent run on a hosted model (fast) instead of local Ollama. Uses the
official `openai` async SDK pointed at Gemini's OpenAI-compatible base URL; the
tool schema the agent already builds is OpenAI function-calling format, so tools
need no conversion. Only the message history is translated, because under the
OpenAI protocol each tool result must carry the tool_call_id it answers."""
from __future__ import annotations

import asyncio
import json
import re
import sys
import time

from agent import config


# Obiettivo: capire quanti secondi aspettare dopo un errore 429 (rate limit).
# Input:    exc = l'eccezione RateLimitError (il suo testo contiene il ritardo suggerito).
# Output:   secondi da attendere (float).
# Come realizzato: cerca nel messaggio "retry in <n>s" o "retryDelay: <n>s"; se non trova
#            nulla usa il default.
def _retry_delay(exc, default: float = 30.0) -> float:
    text = str(exc)
    m = re.search(r"retry in ([\d.]+)s", text) or re.search(r"retryDelay['\"]?:?\s*['\"]?(\d+)", text)
    if m:
        return float(m.group(1)) + 1.0   # piccolo margine
    return default


# Obiettivo: capire se un errore 429 è dovuto alla quota GIORNALIERA (non recuperabile
#            aspettando) invece che al limite al minuto.
# Input:    exc = l'eccezione RateLimitError.
# Output:   True se è una quota per-giorno; False altrimenti.
# Come realizzato: cerca nel messaggio i marcatori della quota giornaliera di Google.
def _is_daily_quota(exc) -> bool:
    t = str(exc)
    return "PerDay" in t or "RequestsPerDay" in t or "per day" in t.lower()


# Obiettivo: tradurre i messaggi nel formato "canonico" dell'agente verso il formato
#            chat di OpenAI (richiesto dall'endpoint compatibile di Gemini).
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


# Obiettivo: incapsulare il client Gemini esponendo la stessa interfaccia di OllamaChat,
#            così l'orchestrator non sa quale provider sta usando.
class GeminiChat:
    # Obiettivo: preparare il client verso l'endpoint OpenAI-compatibile di Gemini.
    # Input:    model = id del modello Gemini (es. gemini-2.5-flash / gemini-2.5-pro).
    # Output:   nessuno (inizializza l'oggetto).
    # Come realizzato: importa AsyncOpenAI in modo pigro (dipendenza opzionale), verifica
    #            la presenza della GEMINI_API_KEY e crea il client puntato al base URL di Gemini.
    def __init__(self, model: str):
        from openai import AsyncOpenAI  # lazy: optional dependency

        if not config.GEMINI_API_KEY:
            raise RuntimeError(
                "GEMINI_API_KEY is not set. Add it to your .env to use the gemini provider."
            )
        self.model = model
        self._client = AsyncOpenAI(api_key=config.GEMINI_API_KEY,
                                   base_url=config.GEMINI_BASE_URL)
        # Min seconds between requests (proactive throttle to stay under the RPM
        # limit). 0 = disabled. For the free tier set GEMINI_MIN_INTERVAL.
        self._min_interval = config.GEMINI_MIN_INTERVAL
        self._last_call = 0.0

    # Obiettivo: distanziare le richieste a Gemini per non superare il limite di
    #            richieste/minuto (evita a monte gli errori 429).
    # Input:    nessuno (usa l'istante dell'ultima chiamata e l'intervallo minimo).
    # Output:   nessuno (eventualmente attende).
    # Come realizzato: se dall'ultima chiamata è passato meno dell'intervallo minimo,
    #            dorme per il tempo rimanente; poi aggiorna il timestamp.
    async def _throttle(self) -> None:
        if self._min_interval <= 0:
            return
        wait = self._min_interval - (time.monotonic() - self._last_call)
        if wait > 0:
            print(f"[gemini] throttle: attendo {wait:.1f}s (rate limit)",
                  file=sys.stderr, flush=True)
            await asyncio.sleep(wait)
        self._last_call = time.monotonic()

    # Obiettivo: inviare un turno di conversazione a Gemini e restituirlo nel formato che
    #            l'orchestrator si aspetta (uguale a quello di Ollama).
    # Input:    messages = la conversazione finora; tools = i tool disponibili (opzionale).
    # Output:   dict del messaggio assistant, con eventuali tool_calls normalizzate.
    # Come realizzato: traduce i messaggi con _to_openai, chiama l'API chat.completions e
    #            ricompone content + tool_calls (name/arguments) nel formato canonico.
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
            except RateLimitError as e:   # free tier quota: wait and retry
                last_exc = e
                if _is_daily_quota(e):
                    # A daily cap won't clear by waiting: fail fast with guidance.
                    print("[gemini] quota GIORNALIERA del free tier esaurita per "
                          f"'{self.model}'. Cambia GEMINI_MODEL (es. gemini-2.0-flash) "
                          "o attiva il billing.", file=sys.stderr, flush=True)
                    raise
                delay = _retry_delay(e)
                print(f"[gemini] rate limited (429), waiting {delay:.0f}s "
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
