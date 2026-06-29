"""Adapter to Google Gemini via its OpenAI-compatible endpoint.

Lets the agent run on a hosted model (fast) instead of local Ollama. Uses the
official `openai` async SDK pointed at Gemini's OpenAI-compatible base URL; the
tool schema the agent already builds is OpenAI function-calling format, so tools
need no conversion. Only the message history is translated, because under the
OpenAI protocol each tool result must carry the tool_call_id it answers."""
from __future__ import annotations

import json

from agent import config


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

    # Obiettivo: inviare un turno di conversazione a Gemini e restituirlo nel formato che
    #            l'orchestrator si aspetta (uguale a quello di Ollama).
    # Input:    messages = la conversazione finora; tools = i tool disponibili (opzionale).
    # Output:   dict del messaggio assistant, con eventuali tool_calls normalizzate.
    # Come realizzato: traduce i messaggi con _to_openai, chiama l'API chat.completions e
    #            ricompone content + tool_calls (name/arguments) nel formato canonico.
    async def chat(self, messages: list[dict], tools: list[dict] | None = None) -> dict:
        resp = await self._client.chat.completions.create(
            model=self.model,
            messages=_to_openai(messages),
            tools=tools or None,
        )
        choice = resp.choices[0].message
        msg: dict = {"role": "assistant", "content": choice.content or ""}
        if getattr(choice, "tool_calls", None):
            msg["tool_calls"] = [
                {"id": tc.id, "type": "function",
                 "function": {"name": tc.function.name, "arguments": tc.function.arguments}}
                for tc in choice.tool_calls
            ]
        return msg
