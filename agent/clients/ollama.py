"""Adapter to the local Ollama LLM. Hides AsyncClient and message normalization
so the orchestrator deals only with plain JSON-serializable dicts."""
from __future__ import annotations

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
    # Come realizzato: chiama l'API chat di Ollama e passa la risposta attraverso plain().
    async def chat(self, messages: list[dict], tools: list[dict] | None = None) -> dict:
        resp = await self._client.chat(model=self.model, messages=messages, tools=tools)
        return plain(resp["message"])
