"""Adapter to the local Ollama LLM. Hides AsyncClient and message normalization
so the orchestrator deals only with plain JSON-serializable dicts."""
from __future__ import annotations

import sys

from agent import config


# Obiettivo: trasformare il messaggio di risposta di Ollama in un dict Python semplice
#            e serializzabile, così può finire nei messaggi e nei checkpoint senza problemi.
# Input:    msg = il messaggio restituito da Ollama (oggetto o dict).
# Output:   un dict "puro" (chiavi/valori JSON-serializzabili).
# Come realizzato: se l'oggetto offre model_dump() lo usa; altrimenti lo converte con dict().
def plain(msg) -> dict:
    if hasattr(msg, "model_dump"):
        return msg.model_dump()
    return dict(msg)


# Obiettivo: opzioni di generazione anti-loop-di-ripetizione, da passare a OGNI chiamata
#            Ollama. Senza queste, un modello piccolo/quantizzato/abliterated puo'
#            incastrarsi a ripetere lo stesso blocco di testo all'infinito in una singola
#            risposta (nessun freno, nessun tetto di lunghezza).
# Input:    nessuno (legge agent.config). Output: dict da passare come options=.
def _gen_options(*, tools_mode: bool = False) -> dict:
    num_predict = config.OLLAMA_NUM_PREDICT_TOOLS if tools_mode else config.OLLAMA_NUM_PREDICT
    return {
        "repeat_penalty": config.OLLAMA_REPEAT_PENALTY,
        "repeat_last_n": config.OLLAMA_REPEAT_LAST_N,
        "num_predict": num_predict,
        "temperature": config.OLLAMA_TEMPERATURE,
        "top_p": config.OLLAMA_TOP_P,
        "top_k": config.OLLAMA_TOP_K,
    }


# Obiettivo: incapsulare il client Ollama così l'orchestrator non vede i dettagli della
#            libreria e riceve sempre messaggi già normalizzati.
class OllamaChat:
    # Obiettivo: preparare il client verso il modello LLM scelto.
    # Input:    model = nome del modello (es. qwen2.5-coder:14b);
    #           host = indirizzo di Ollama (default da config.OLLAMA_HOST).
    # Output:   nessuno (inizializza l'oggetto).
    # Come realizzato: importa AsyncClient in modo "pigro" (così plain() resta usabile
    #            anche senza il pacchetto ollama installato) e crea il client.
    def __init__(self, model: str, host: str | None = None):
        from ollama import AsyncClient  # lazy: keep `plain` importable without ollama

        self.model = model
        self._client = AsyncClient(host=host or config.OLLAMA_HOST)

    # Obiettivo: inviare un turno di conversazione al modello e ottenere la sua risposta.
    # Input:    messages = la conversazione finora; tools = i tool disponibili (opzionale).
    # Output:   il messaggio di risposta del modello, già normalizzato a dict.
    # Come realizzato: se OLLAMA_SHOW_THINKING e' attivo, chiama in streaming e stampa il
    #            reasoning mano a mano (vedi _chat_streaming); altrimenti comportamento
    #            invariato (chiamata unica, nessun output intermedio).
    async def chat(self, messages: list[dict], tools: list[dict] | None = None) -> dict:
        tools_mode = bool(tools)
        show_thinking = config.OLLAMA_SHOW_THINKING and (
            not tools_mode or config.OLLAMA_SHOW_THINKING_WITH_TOOLS
        )
        if show_thinking:
            return await self._chat_streaming(messages, tools)
        resp = await self._client.chat(
            model=self.model, messages=messages, tools=tools,
            options=_gen_options(tools_mode=tools_mode),
        )
        return plain(resp["message"])

    # Obiettivo: come chat(), ma mostrando dal vivo su stderr il reasoning ("thinking") del
    #            modello mentre arriva, cosi' si vede che sta ragionando e non che e' bloccato.
    # Input/Output: uguali a chat().
    # Come realizzato: chiama l'API in streaming con think=True; se il modello non supporta
    #            il thinking la chiamata fallisce e si rifa' lo streaming senza (fallback).
    #            Il campo "thinking" non viene incluso nel messaggio restituito: e' solo per
    #            la stampa a video, non deve rientrare nella conversazione.
    async def _chat_streaming(self, messages: list[dict], tools: list[dict] | None = None) -> dict:
        try:
            stream = await self._client.chat(
                model=self.model, messages=messages, tools=tools, stream=True, think=True,
                options=_gen_options(tools_mode=bool(tools)),
            )
            final = await self._consume_stream(stream)
        except Exception:
            stream = await self._client.chat(
                model=self.model, messages=messages, tools=tools, stream=True,
                options=_gen_options(tools_mode=bool(tools)),
            )
            final = await self._consume_stream(stream)
        final.pop("thinking", None)
        return final

    # Obiettivo: leggere lo stream di chunk e ricostruire il messaggio finale, stampando
    #            intanto il reasoning ("thinking", se il modello lo supporta) E il testo
    #            ("content") mano a mano: cosi' si vede SEMPRE qualcosa scorrere, anche con
    #            modelli senza thinking esplicito (es. Qwen abliterated).
    # Input:    stream = async iterator di ChatResponse. Output: dict del messaggio finale.
    async def _consume_stream(self, stream) -> dict:
        content_parts: list[str] = []
        printed_header = False
        final_msg = None
        async for chunk in stream:
            msg = chunk.message
            piece = msg.thinking or msg.content
            if piece:
                if not printed_header:
                    print("\n  [live] ", end="", file=sys.stderr, flush=True)
                    printed_header = True
                print(piece, end="", file=sys.stderr, flush=True)
            if msg.content:
                content_parts.append(msg.content)
            final_msg = msg
        if printed_header:
            print(file=sys.stderr, flush=True)
        result = plain(final_msg) if final_msg is not None else {"role": "assistant"}
        result["content"] = "".join(content_parts)
        return result
