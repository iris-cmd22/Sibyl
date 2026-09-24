"""Select the LLM backend (provider) for the agent."""
from __future__ import annotations

from agent import config


# Obiettivo: costruire il client LLM giusto in base al provider scelto, così l'orchestrator
#            resta indipendente dal modello/servizio sottostante.
# Input:    provider = "ollama" | "gemini" | "openai"; model = id del modello da usare.
# Output:   un oggetto con metodo async chat(messages, tools).
# Come realizzato: import pigro del solo adattatore richiesto. "gemini" e "openai" usano lo
#            stesso adattatore OpenAI-compatibile con base_url/chiave diversi (così Groq,
#            Cerebras, OpenRouter, OpenAI... si configurano via env senza nuovo codice).
def make_llm(provider: str, model: str):
    provider = (provider or "ollama").lower()
    if provider == "ollama":
        from agent.clients.ollama import OllamaChat

        return OllamaChat(model)
    if provider == "gemini":
        from agent.clients.openai_compat import OpenAICompatChat

        return OpenAICompatChat(model, config.GEMINI_API_KEY, config.GEMINI_BASE_URL,
                                config.GEMINI_MIN_INTERVAL, "gemini")
    if provider == "openai":
        from agent.clients.openai_compat import OpenAICompatChat

        return OpenAICompatChat(model, config.OPENAI_API_KEY, config.OPENAI_BASE_URL,
                                config.OPENAI_MIN_INTERVAL, "openai")
    raise ValueError(f"Unknown LLM provider: {provider!r} (use 'ollama', 'gemini' or 'openai')")
