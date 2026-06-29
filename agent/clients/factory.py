"""Select the LLM backend (provider) for the agent."""
from __future__ import annotations


# Obiettivo: costruire il client LLM giusto in base al provider scelto, così l'orchestrator
#            resta indipendente dal modello/servizio sottostante.
# Input:    provider = "ollama" | "gemini"; model = id del modello da usare.
# Output:   un oggetto con metodo async chat(messages, tools) (OllamaChat o GeminiChat).
# Come realizzato: import pigro del solo adattatore richiesto (così le dipendenze opzionali
#            non servono se non usi quel provider); errore chiaro se il provider è ignoto.
def make_llm(provider: str, model: str):
    provider = (provider or "ollama").lower()
    if provider == "ollama":
        from agent.clients.ollama import OllamaChat

        return OllamaChat(model)
    if provider == "gemini":
        from agent.clients.gemini import GeminiChat

        return GeminiChat(model)
    raise ValueError(f"Unknown LLM provider: {provider!r} (use 'ollama' or 'gemini')")
