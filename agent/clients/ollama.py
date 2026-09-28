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


# Obiettivo: loggare quanti token ha effettivamente usato l'ultima chiamata, per capire
#            empiricamente quanto margine resta rispetto a OLLAMA_NUM_CTX (invece di
#            stimarlo a occhio) su una repo/modello dati.
# Input:    resp = risposta (o ultimo chunk streaming) di Ollama, con prompt_eval_count/
#           eval_count se il server li restituisce (non garantito da tutte le versioni).
# Output:   nessuno (stampa una riga su stderr, se i conteggi sono presenti).
# Obiettivo: quando il modello genera una tool-call NATIVA con JSON rotto (es. una
#            virgoletta di troppo), Ollama la rifiuta lato server PRIMA di restituire un
#            messaggio (HTTP 500, ollama.ResponseError) — senza questa conversione,
#            l'eccezione risale fino a run_agent, spacca il task group asyncio/SSE e
#            uccide l'intero processo (visto in produzione: un singolo argomento
#            malformato buttava via un'ora di lavoro). Il caso "JSON rotto" ha gia' un
#            percorso di recupero in _run_phase (malformed_retries, per le tool-call
#            TESTUALI che non parsano) — travestiamo l'errore da messaggio assistant che
#            fa scattare EXACTLY quel percorso, invece di inventarne uno nuovo.
# Input:    err = l'eccezione sollevata da Ollama. Output: un messaggio "assistant" fittizio
#           che _run_phase riconosce come tool-call malformata e nudge-a per farla riprovare.
def _malformed_tool_call_message(err: Exception) -> dict:
    return {
        "role": "assistant",
        "content": (
            '{"name": "?", "arguments": "?"} '
            f"-- Ollama rejected this tool call as malformed JSON: {err}"
        ),
    }


def _log_usage(resp) -> None:
    d = plain(resp)
    prompt_tokens, reply_tokens = d.get("prompt_eval_count"), d.get("eval_count")
    if prompt_tokens is None and reply_tokens is None:
        return
    print(f"[ollama] token: prompt={prompt_tokens} risposta={reply_tokens} "
          f"(num_ctx={config.OLLAMA_NUM_CTX})", file=sys.stderr, flush=True)


# Obiettivo: opzioni di generazione anti-loop-di-ripetizione, da passare a OGNI chiamata
#            Ollama. Senza queste, un modello piccolo/quantizzato/abliterated puo'
#            incastrarsi a ripetere lo stesso blocco di testo all'infinito in una singola
#            risposta (nessun freno, nessun tetto di lunghezza).
# Input:    tools_mode = True se la chiamata espone tool (usa il budget piu' corto
#           OLLAMA_NUM_PREDICT_TOOLS come default); num_predict_override = se dato,
#           vince SEMPRE, anche con tools_mode=True — usato dal loop a batch di
#           Detection, che espone SEMPRE i suoi 2 tool (quindi tools_mode e' sempre
#           True) ma per un batch da N item ha bisogno di molto piu' del tetto
#           generico di 512 token pensato per un turno "o chiami un tool o niente".
#           BUG STORICO (fisso qui): la versione precedente ignorava l'override
#           ogni volta che tools_mode era True — cioe' SEMPRE durante la Detection,
#           dato che i tool restano esposti anche sul turno in cui il modello
#           decide di scrivere testo invece di chiamarne uno. Il risultato osservato
#           in produzione: ogni turno troncato esattamente a 512 token (il tetto
#           generico), il ragionamento di gpt-oss da solo bastava a saturarlo prima
#           di arrivare a scrivere le righe [N] richieste — il batch sembrava un
#           problema di formato/contesto, era un problema di budget mai applicato.
# Output:   dict da passare come options=.
def _gen_options(*, tools_mode: bool = False, num_predict_override: int | None = None) -> dict:
    if num_predict_override is not None:
        num_predict = num_predict_override
    elif tools_mode:
        num_predict = config.OLLAMA_NUM_PREDICT_TOOLS
    else:
        num_predict = config.OLLAMA_NUM_PREDICT
    return {
        "repeat_penalty": config.OLLAMA_REPEAT_PENALTY,
        "repeat_last_n": config.OLLAMA_REPEAT_LAST_N,
        "num_predict": num_predict,
        "temperature": config.OLLAMA_TEMPERATURE,
        "top_p": config.OLLAMA_TOP_P,
        "top_k": config.OLLAMA_TOP_K,
        "num_ctx": config.OLLAMA_NUM_CTX,
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
    # Input:    messages = la conversazione finora; tools = i tool disponibili (opzionale);
    #           num_predict = se dato, sostituisce OLLAMA_NUM_PREDICT SOLO per questa
    #           chiamata e SOLO se non ci sono tool (vedi _gen_options) — usato dal loop
    #           per-item di Detection per il tetto piu' stretto di
    #           OLLAMA_NUM_PREDICT_DETECTION_ITEM, senza toccare le altre fasi/turni.
    # Output:   il messaggio di risposta del modello, già normalizzato a dict.
    # Come realizzato: se OLLAMA_SHOW_THINKING e' attivo, chiama in streaming e stampa il
    #            reasoning mano a mano (vedi _chat_streaming); altrimenti comportamento
    #            invariato (chiamata unica, nessun output intermedio).
    async def chat(self, messages: list[dict], tools: list[dict] | None = None,
                    num_predict: int | None = None) -> dict:
        tools_mode = bool(tools)
        show_thinking = config.OLLAMA_SHOW_THINKING and (
            not tools_mode or config.OLLAMA_SHOW_THINKING_WITH_TOOLS
        )
        if show_thinking:
            return await self._chat_streaming(messages, tools, num_predict)
        from ollama import ResponseError

        try:
            resp = await self._client.chat(
                model=self.model, messages=messages, tools=tools,
                options=_gen_options(tools_mode=tools_mode, num_predict_override=num_predict),
            )
        except ResponseError as e:
            return _malformed_tool_call_message(e)
        _log_usage(resp)
        return plain(resp["message"])

    # Obiettivo: come chat(), ma mostrando dal vivo su stderr il reasoning ("thinking") del
    #            modello mentre arriva, cosi' si vede che sta ragionando e non che e' bloccato.
    # Input/Output: uguali a chat().
    # Come realizzato: chiama l'API in streaming con think=True; se il modello non supporta
    #            il thinking la chiamata fallisce e si rifa' lo streaming senza (fallback).
    #            Il campo "thinking" non viene incluso nel messaggio restituito: e' solo per
    #            la stampa a video, non deve rientrare nella conversazione.
    async def _chat_streaming(self, messages: list[dict], tools: list[dict] | None = None,
                               num_predict: int | None = None) -> dict:
        from ollama import ResponseError

        opts = _gen_options(tools_mode=bool(tools), num_predict_override=num_predict)
        try:
            try:
                stream = await self._client.chat(
                    model=self.model, messages=messages, tools=tools, stream=True, think=True,
                    options=opts,
                )
                final = await self._consume_stream(stream)
            except Exception:
                # Broad on purpose: this fallback exists for "the model/server doesn't
                # support think=True", not just ResponseError — keep it broad, the
                # malformed-tool-call case (ResponseError) is handled by the outer
                # try below regardless of which attempt raised it.
                stream = await self._client.chat(
                    model=self.model, messages=messages, tools=tools, stream=True,
                    options=opts,
                )
                final = await self._consume_stream(stream)
        except ResponseError as e:
            return _malformed_tool_call_message(e)
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
        final_chunk = None
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
            final_chunk = chunk
        if printed_header:
            print(file=sys.stderr, flush=True)
        if final_chunk is not None:
            _log_usage(final_chunk)
        result = plain(final_msg) if final_msg is not None else {"role": "assistant"}
        result["content"] = "".join(content_parts)
        return result
