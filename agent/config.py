"""Agent-only configuration. Self-contained: defaults live INSIDE the `agent/`
package so the directory is portable. Override anything via environment variables
(a local .env in the project root is loaded if python-dotenv is installed)."""
import os
import re
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
# Context window (token) da chiedere esplicitamente a Ollama per OGNI richiesta. Senza
# questo, Ollama usa il default del modello (spesso 2048/4096), che con 41 tool MCP
# esposti + system prompt + storia dei messaggi puo' sforare gia' al primo turno con
# tool (Detection step 0): il runner crasha e il client vede una risposta troncata
# (ollama._types.ResponseError: EOF, status 500). Sotto gli 8192 questo bug puo'
# ripresentarsi, quindi le fasce sotto non scendono mai piu' giu' di cosi'.
#
# La KV-cache che Ollama alloca per num_ctx scala pero' con l'architettura del modello,
# non solo col numero di parametri: modelli sulla fascia ~7-13B (es. qwen3.5:9b) si sono
# visti andare in OOM/heap crash a 8192 su repo con snippet lunghi (es. SecurityEval),
# pur essendo piu' piccoli del modello di default 14b che a 8192 e' invece il valore
# storicamente usato. Percio' il suggerimento sotto NON e' monotono nella dimensione:
# e' tarato sui casi osservati, non su una formula fisica precisa. E' solo un default
# di partenza (mostrato come placeholder anche nel form dell'estensione, vedi
# extension/src/envConfig.ts) - resta sempre sovrascrivibile esplicitamente via env
# OLLAMA_NUM_CTX o dal campo dedicato nel form.
_NUM_CTX_SIZE_BUCKETS = [  # (soglia max miliardi di parametri, num_ctx suggerito)
    (3, 16384),
    (7, 12288),
    (13, 6144),
    (24, 8192),
]
_NUM_CTX_FALLBACK = 8192  # taglia non parsabile dal tag del modello.
_NUM_CTX_ABOVE_24B = 4096  # oltre i 24B il peso dei pesi domina, poco margine per la KV-cache.


def _suggested_num_ctx(model: str) -> int:
    m = re.search(r":(\d+(?:\.\d+)?)b\b", model, re.IGNORECASE)
    if not m:
        return _NUM_CTX_FALLBACK
    size_b = float(m.group(1))
    for threshold, ctx in _NUM_CTX_SIZE_BUCKETS:
        if size_b <= threshold:
            return ctx
    return _NUM_CTX_ABOVE_24B


OLLAMA_NUM_CTX = int(os.environ.get("OLLAMA_NUM_CTX") or _suggested_num_ctx(AGENT_MODEL))
# In tool-calling mode we want short, structured outputs (one call per turn), not
# long prose — but 512 (the old default) measured too tight for a REASONING model
# like gpt-oss: it always emits a hidden "thinking" pass before the actual tool call
# (Ollama auto-splits it into message.thinking, separate from message.content/
# tool_calls), and that reasoning alone regularly ran 700-2000+ tokens even for a
# single, moderately complex decision (e.g. picking among Validation's 22 tools) —
# at 512 the model was cut off mid-thought, produced NO tool call, and the turn was
# wasted. 2048 is comfortable headroom for reasoning + one compact tool call without
# being the much larger budget batched/multi-item turns need (see
# OLLAMA_NUM_PREDICT_DETECTION_ITEM and the Detection batch loop's own override).
OLLAMA_NUM_PREDICT_TOOLS = int(os.environ.get("OLLAMA_NUM_PREDICT_TOOLS", "2048"))
# Detection's per-item loop (orchestrator.py: the "one candidate per prompt" path used
# only for provider=ollama) asks for EXACTLY one FLOW/OP line (or NONE) as the item's
# final non-tool reply — a few dozen tokens, never a paragraph. Kept SEPARATE from
# OLLAMA_NUM_PREDICT (used for every other non-tool reply, e.g. Validation's free-text
# report commentary, which legitimately needs more room): capping the shared constant
# would also cap those. This one only bounds the worst case when a small/quantized model
# rambles instead of stopping (see the degenerate-text retry logic) — it doesn't change
# what's asked of the model, so it shouldn't cost accuracy, only wasted generation time.
OLLAMA_NUM_PREDICT_DETECTION_ITEM = int(
    os.environ.get("OLLAMA_NUM_PREDICT_DETECTION_ITEM", "300")
)
# How many work-list items (flows/ops) Detection packs into a SINGLE LLM call,
# instead of one call per item. Raw PROMPT tokens are cheap at 15/call (fixed
# overhead ~600 + ~110-130/item measured for gpt-oss:20b), but that was never
# the real constraint — gpt-oss always reasons in a hidden "thinking" channel
# before answering, and that reasoning's length is stochastic (temperature=0.2)
# and scales with how much it has to judge at once. At 15 items/call, production
# runs regularly needed 2000-2900+ tokens of hidden reasoning ALONE and still
# sometimes failed to leave room to write all 15 tagged [N] lines, even with a
# 4096-token reply budget and num_ctx=8192 — dropped to 8/call to cut that
# reasoning load per call. Tune down further if a model keeps missing items
# near the end of a batch (see the "batch gap"/UNVERIFIED log lines).
OLLAMA_DETECTION_BATCH_SIZE = int(os.environ.get("OLLAMA_DETECTION_BATCH_SIZE", "8"))
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
