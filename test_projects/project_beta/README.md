# project_beta — ground truth (NON letto dall'agente)

Servizio con vulnerabilità **non basate sul flusso** (crypto/hash deboli, randomness
insicura, config-flag pericolosi, credenziali hardcoded). Serve a testare la fase
Detection `find_sensitive_operations` + Validation (`run_api_misuse_query` /
`run_insecure_config_flag_query` / `check_*`). Nessun commento nel codice: questo
README è l'unica fonte di verità, e l'agente NON lo legge (analizza solo i `.py`).

## CWE attese

| CWE | Nome | File | Funzione | Innesco |
|-----|------|------|----------|---------|
| CWE-916 | Weak Password Hashing | hashing.py | `hash_password` | `hashlib.md5(password)` per una password |
| CWE-328 | Weak Hash | hashing.py | `fingerprint`, `checksum` | `hashlib.sha1(...)`, `hashlib.new("md4", ...)` |
| CWE-327 | Broken/Weak Crypto | crypto.py | `encrypt`, `decrypt` | `DES` + modalità `ECB` |
| CWE-798 | Hardcoded Credentials | crypto.py, app.py | `KEY`, `SECRET_KEY` | chiave DES e SECRET_KEY hardcoded |
| CWE-330 | Insecure Randomness | tokens.py | `generate_token`, `session_id`, `reset_code` | `random.choice/randint/random` per token/sessione |
| CWE-295 | Improper Certificate Validation | client.py | `fetch`, `post_data` | `requests.get/post(..., verify=False)` |
| CWE-489 | Debug Mode Enabled | app.py | `__main__` | `app.run(debug=True)` |

## Note per il test
- Queste sono quasi tutte **point detection senza flusso**: `find_all_flows` NON le
  mostra. Ci si aspetta che `find_sensitive_operations` le elenchi coi `kind`:
  `weak-call` (md5/sha1/md4/DES/random...), `config-flag` (verify, debug),
  `command-exec`/`decoding` dove applicabile.
- È il caso che verifica il punto cieco "non-flow": se il meccanismo funziona, in
  Validation il modello deve lanciare `run_api_misuse_query` / `check_weak_hash` /
  `check_broken_crypto` / `check_weak_random` / `check_insecure_verify_false` /
  `check_insecure_debug_true`.
- `KEY`/`SECRET_KEY` hardcoded (CWE-798) e `debug=True` (CWE-489) sono extra: utili per
  vedere se emergono, anche se non tutte hanno un tool dedicato.
