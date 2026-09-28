from __future__ import annotations

import re

_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_CONST_RE = re.compile(r"^[A-Za-z0-9._\-]+$")
_SENTINEL = "__never_matches__"


# Obiettivo: trasformare una lista di nomi (di funzioni "sink/source") nel testo da
#            inserire dentro una query CodeQL, in modo SICURO.
# Input:    names = lista di stringhe (nomi di funzioni/metodi).
# Output:   stringa tipo '"execute", "query"' pronta da incollare nel template.
# Come realizzato: tiene solo i nomi che sono identificatori validi (anti-injection);
#            se la lista è vuota usa un valore-sentinella che non corrisponde a nulla.
def render_names(names) -> str:
    clean = [n for n in (names or []) if isinstance(n, str) and _NAME_RE.match(n)]
    if not clean:
        clean = [_SENTINEL]
    return ", ".join(f'"{n}"' for n in clean)


# Obiettivo: come render_names, ma per costanti/stringhe (es. "md5", "ecb") da
#            confrontare nelle query.
# Input:    values = lista di stringhe (algoritmi/modalità deboli).
# Output:   stringa tipo '"md5", "sha1"' (tutto minuscolo) per il template.
# Come realizzato: filtra con un set di caratteri più ampio di render_names e
#            converte in minuscolo; sentinella se la lista è vuota.
def render_consts(values) -> str:
    clean = [v.lower() for v in (values or []) if isinstance(v, str) and _CONST_RE.match(v)]
    if not clean:
        clean = [_SENTINEL]
    return ", ".join(f'"{v}"' for v in clean)


# Obiettivo: accettare un CWE scritto in vari modi e produrre le forme che servono.
# Input:    cwe = stringa libera ("CWE-89", "cwe-89", "89") o vuota.
# Output:   tupla (id, tag, suffisso): es. ("CWE-89", "external/cwe/cwe-089", "-cwe-089");
#           (None, "", "") se l'input non contiene un numero.
# Come realizzato: estrae il numero con regex e formatta le tre stringhe (il tag e il
#            suffisso vengono "stampati" nei metadati della query generata).
def normalize_cwe(cwe) -> tuple[str | None, str, str]:
    if not cwe:
        return None, "", ""
    m = re.search(r"(\d+)", str(cwe))
    if not m:
        return None, "", ""
    num = int(m.group(1))
    return f"CWE-{num}", f"external/cwe/cwe-{num:03d}", f"-cwe-{num:03d}"


# Obiettivo: dire se una stringa è un identificatore Python valido (lettere, cifre,
#            underscore, che non inizia con una cifra) — usato per validare gli input.
# Input:    s = la stringa da controllare.
# Output:   True se è un identificatore valido, False altrimenti.
# Come realizzato: verifica che sia una stringa e che corrisponda alla regex _NAME_RE.
def is_valid_name(s: str) -> bool:
    return isinstance(s, str) and bool(_NAME_RE.match(s))


# Obiettivo: sfuggire una stringa ARBITRARIA (non un identificatore, es. un valore di
#            configurazione come "false"/un URL) perche' possa essere interpolata
#            dentro un literal QL (delimitato da apici doppi) senza romperne la
#            sintassi (anti QL-injection, analogo a render_names per gli identificatori).
# Input:    value = la stringa da sfuggire.
# Output:   il contenuto gia' sfuggito, SENZA gli apici doppi esterni.
# Come realizzato: escape manuale di backslash e doppio apice, in quest'ordine (il
#            backslash va sfuggito per primo, altrimenti raddoppierebbe quelli appena
#            inseriti per gli apici).
def escape_ql_string(value: str) -> str:
    return str(value).replace("\\", "\\\\").replace('"', '\\"')


# Obiettivo: come escape_ql_string, ma restituisce il literal QL completo, pronto da
#            incollare cosi' com'e' dove serve un'intera stringa tra apici.
# Input:    value = la stringa da incapsulare.
# Output:   stringa QL letterale gia' tra doppi apici, con backslash e apice sfuggiti.
def render_ql_string(value: str) -> str:
    return f'"{escape_ql_string(value)}"'
