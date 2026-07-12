"""Select the prompt set based on the LLM backend.

API-style providers keep the existing prompts in agent.prompts.
Local Ollama models use the more procedural prompt set in agent.prompts_local.
"""

from __future__ import annotations

from agent import config
from agent.prompts import DETECTION_PROMPT as API_DETECTION_PROMPT
from agent.prompts import VALIDATION_PROMPT as API_VALIDATION_PROMPT
from agent.prompts_local import LOCAL_PROMPT_SET


def prompt_set(provider: str | None = None) -> dict[str, str]:
    chosen = (provider or config.LLM_PROVIDER or "ollama").lower()
    if chosen == "ollama":
        return LOCAL_PROMPT_SET
    return {
        "detection": API_DETECTION_PROMPT,
        "validation": API_VALIDATION_PROMPT,
    }
