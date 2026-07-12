"""Agent-only configuration. Self-contained: defaults live INSIDE the `agent/`
package so the directory is portable. Override anything via environment variables
(a local .env in the project root is loaded if python-dotenv is installed)."""
import os
from pathlib import Path

# Root of the agent package (this file's directory). Writable defaults live here.
AGENT_DIR = Path(__file__).resolve().parent

# Load a local .env (if present). Safe no-op if python-dotenv isn't installed.
try:
    from dotenv import load_dotenv

    load_dotenv(AGENT_DIR.parent / ".env")
except ImportError:
    pass

# --- LLM provider (which backend drives the analysis) ---
# "ollama" = local model; "gemini" = hosted Google model (via OpenAI-compat API).
LLM_PROVIDER = os.environ.get("AGENT_LLM_PROVIDER", "ollama")

# --- Ollama (the local LLM driving the analysis) ---
OLLAMA_HOST = os.environ.get("OLLAMA_HOST", "http://localhost:11434")
AGENT_MODEL = os.environ.get("AGENT_MODEL", "qwen2.5-coder:14b")
# Se true, stampa su stderr il reasoning ("thinking") del modello mentre arriva (utile per
# capire se uno step lungo sta ragionando o e' bloccato). Off di default: nessun cambio di
# comportamento, e non tutti i modelli supportano il thinking.
OLLAMA_SHOW_THINKING = os.environ.get("OLLAMA_SHOW_THINKING", "false").lower() in ("1", "true", "yes")

# Freni anti-loop-di-ripetizione (i modelli piccoli/quantizzati/abliterated possono
# incastrarsi a ripetere lo stesso blocco all'infinito in una singola risposta).
# repeat_penalty: quanto penalizzare i token gia' usati di recente (default Ollama: 1.1).
#   ATTENZIONE: un valore troppo alto (era 1.3) unito a repeat_last_n ampio penalizza
#   anche le parole di funzione comuni ("the", "is", "of"...): il modello finisce per
#   evitare OGNI token recente e degenera in frammenti di parole senza senso invece di
#   limitarsi a smettere di ripetere la stessa frase (osservato con qwen3.5:9b locale).
# repeat_last_n: quante posizioni indietro considerare per la penalita' (default: 64).
# num_predict: tetto massimo di token generati in UN turno (-1 = nessun limite, il default).
OLLAMA_REPEAT_PENALTY = float(os.environ.get("OLLAMA_REPEAT_PENALTY", "1.1"))
OLLAMA_REPEAT_LAST_N = int(os.environ.get("OLLAMA_REPEAT_LAST_N", "128"))
OLLAMA_NUM_PREDICT = int(os.environ.get("OLLAMA_NUM_PREDICT", "1536"))
# Questa pipeline deve estrarre/verificare fedelmente, non scrivere in modo creativo:
# una temperature/top_p piu' bassi tengono il modello vicino ai token piu' probabili,
# il che (insieme a un repeat_penalty piu' moderato sopra) e' cio' che davvero previene
# la deriva verso token rari e incoerenti nei modelli locali piccoli.
OLLAMA_TEMPERATURE = float(os.environ.get("OLLAMA_TEMPERATURE", "0.2"))
OLLAMA_TOP_P = float(os.environ.get("OLLAMA_TOP_P", "0.85"))
OLLAMA_TOP_K = int(os.environ.get("OLLAMA_TOP_K", "40"))
# In tool-calling mode we want short, structured outputs (one call per turn), not
# long prose. Keep a lower default budget for turns where tools are exposed.
OLLAMA_NUM_PREDICT_TOOLS = int(os.environ.get("OLLAMA_NUM_PREDICT_TOOLS", "512"))
# In tool-calling mode, showing reasoning tends to produce verbose text drift on
# small local models. Keep it off by default unless explicitly enabled.
OLLAMA_SHOW_THINKING_WITH_TOOLS = os.environ.get(
    "OLLAMA_SHOW_THINKING_WITH_TOOLS", "false"
).lower() in ("1", "true", "yes")

# --- Gemini (hosted, via its OpenAI-compatible endpoint) ---
# Set GEMINI_API_KEY (or GOOGLE_API_KEY) to use --provider gemini.
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY")
GEMINI_BASE_URL = os.environ.get(
    "GEMINI_BASE_URL", "https://generativelanguage.googleapis.com/v1beta/openai/"
)
GEMINI_MODEL = os.environ.get("GEMINI_MODEL", "gemini-2.5-flash")
# Secondi minimi tra due richieste a Gemini (throttle anti rate-limit). 0 = off.
# Free tier 5 req/min -> ~13s; 15 req/min -> ~5s.
GEMINI_MIN_INTERVAL = float(os.environ.get("GEMINI_MIN_INTERVAL", "0"))

# --- Generic OpenAI-compatible provider (Groq, Cerebras, OpenRouter, OpenAI, ...) ---
# Choose with --provider openai; point OPENAI_BASE_URL at the chosen service.
# Esempi: Groq https://api.groq.com/openai/v1 ; Cerebras https://api.cerebras.ai/v1
OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY")
OPENAI_BASE_URL = os.environ.get("OPENAI_BASE_URL", "https://api.openai.com/v1")
OPENAI_MODEL = os.environ.get("OPENAI_MODEL", "gpt-4o-mini")
OPENAI_MIN_INTERVAL = float(os.environ.get("OPENAI_MIN_INTERVAL", "0"))

# --- MCP server (independent service; the agent connects as an SSE client) ---
# In local it points at localhost; for remote just change the URL (server host).
MCP_SERVER_URL = os.environ.get("MCP_SERVER_URL", "http://127.0.0.1:8000/sse")

# Where checkpoints are written (per-repo, survives a shutdown).
WORK_DIR = Path(os.environ.get("AGENT_WORK_DIR", AGENT_DIR / "_work"))
WORK_DIR.mkdir(exist_ok=True)

# Where security reports are written by default (one file per run, named after
# the repo + model + timestamp).
REPORTS_DIR = Path(os.environ.get("AGENT_REPORTS_DIR", AGENT_DIR / "reports"))
REPORTS_DIR.mkdir(exist_ok=True)
