"""Detect free-text model replies that are syntactically fine but semantically
degenerate — a known failure mode of small/quantized local models pushed by an
aggressive repeat_penalty: instead of looping the same phrase (which repeat_penalty
is designed to stop), the model avoids reusing ANY recent token — including common
function words ("the", "a", "is", "of"...) — and drifts into a stream of short,
almost-never-repeated word fragments with no sentence structure at all."""
from __future__ import annotations

import re

_WORD_RE = re.compile(r"[A-Za-z]+")
_SENTENCE_END_RE = re.compile(r"[.!?]")
_STOPWORDS = {
    "the", "a", "an", "is", "of", "to", "and", "in", "that", "it", "for", "on",
    "with", "as", "this", "be", "are", "was", "were", "by", "at", "from", "or",
    "not", "but", "if", "so", "which", "has", "have", "had", "you", "your", "its",
}

_MIN_WORDS = 60
_UNIQUE_RATIO_THRESHOLD = 0.90
_STOPWORD_RATIO_THRESHOLD = 0.08


# Obiettivo: riconoscere un testo "degenerato" (quasi nessuna parola ripetuta, quasi
#            nessuna parola comune di funzione, nessuna struttura di frase) — il pattern
#            osservato con modelli locali piccoli (es. qwen 9B) sotto repeat_penalty
#            aggressivo, che finisce per penalizzare anche "the"/"is"/"of" e produce un
#            flusso di frammenti di parole senza senso invece del solito loop ripetitivo
#            che repeat_penalty dovrebbe prevenire.
# Input:    text = il testo scritto dal modello in questo turno.
# Output:   True se il testo sembra degenerato; False se e' troppo corto per giudicare o
#           non soddisfa ENTRAMBE le condizioni (evita falsi positivi su prosa tecnica
#           legittima, che ripete comunque parole comuni anche quando e' densa di termini
#           tecnici unici).
# Come realizzato: due soglie insieme, non singolarmente: rapporto parole-uniche/totale
#            molto alto (la legge di Zipf garantisce ripetizioni in qualunque testo
#            naturale abbastanza lungo) E rapporto di stopword quasi nullo (repeat_penalty
#            colpisce anche le parole di funzione, che normalmente sono il 30-50% del
#            testo). La punteggiatura di fine frase e' registrata ma non e' richiesta da
#            sola: alcune fasi scrivono output a righe (FLOW/OP) senza periodi.
def is_degenerate_text(text: str) -> bool:
    words = _WORD_RE.findall(text or "")
    if len(words) < _MIN_WORDS:
        return False
    lower = [w.lower() for w in words]
    unique_ratio = len(set(lower)) / len(lower)
    stopword_ratio = sum(1 for w in lower if w in _STOPWORDS) / len(lower)
    return unique_ratio > _UNIQUE_RATIO_THRESHOLD and stopword_ratio < _STOPWORD_RATIO_THRESHOLD
