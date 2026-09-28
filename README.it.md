# CodeQL Security Agent

Agente che usa un **modello Ollama locale** per analizzare la sicurezza di una
repository, eseguendo query **CodeQL** esposte come **tool MCP**.

## Architettura

```
Ollama LLM  ──tool_calls──►  agent.py (host)  ──MCP/stdio──►  codeql_mcp_server.py  ──►  CodeQL CLI
(qwen2.5-coder:14b)          loop tool-calling                tool MCP                    + query locali
```

- **`codeql_mcp_server.py`** — server MCP (FastMCP) che incapsula la CLI CodeQL.
- **`agent.py`** — host: avvia il server come subprocess stdio, espone i tool al
  modello Ollama, gira il loop chat→tool→risultato finché il modello scrive il report.
- **`config.py`** — modello, percorsi CodeQL, suite di default, timeout.
- **`query_templates/`** — template `.ql.tmpl` parametrizzati (taint, api-misuse, insecure-config-flag).
- **`knowledge/`** — `cwe_wiki.json` (CWE verificabili con azioni) + `cwe_catalog.json` (969 CWE, lookup).

## Tool MCP esposti

**Esplorazione / DB**
- `list_python_files` — enumera i `.py` della repo
- `read_file_snippet` — legge righe sorgente attorno a un finding
- `create_codeql_database` — costruisce il DB CodeQL
- `analyze_database` — esegue la suite standard `python-security-extended`
- `run_custom_query` — esegue un `.ql` arbitrario

**Knowledge base**
- `list_cwes` — elenca i CWE rilevabili (con detection kind e tool giusto)
- `cwe_knowledge(cwe)` — scheda completa di un CWE (descrizione MITRE + azioni operative)

**Verifica vulnerabilità** — tre famiglie name-based / template-based:

| Detection | Tool | CWE tipici |
|-----------|------|------------|
| **taint** (dataflow source→sink) | `run_taint_query` | 89, 78, 22, 79, 502, 90, 94, 611, 643, 601, 918, 117 |
| **api_misuse** (point detection) | `run_api_misuse_query` | 327, 328, 330, 916 |
| **insecure_config_flag** (point detection) | `check_insecure_*` + `run_insecure_config_flag_query` | 295, 78, 79, 489, 327, 330, 614 |

### Insecure configuration flags

Rileva flag di configurazione insicuri (point detection, no dataflow). Sette check
dedicati + un tool generico parametrizzato:

| Tool dedicato | CWE | Pattern |
|---------------|-----|---------|
| `check_insecure_verify_false` | CWE-295 | `requests.get(..., verify=False)` |
| `check_insecure_shell_true` | CWE-78 | `subprocess.run(..., shell=True)` |
| `check_insecure_autoescape_false` | CWE-79 | `jinja2/flask(..., autoescape=False)` |
| `check_insecure_debug_true` | CWE-489 | `Flask(..., debug=True)` |
| `check_insecure_weak_hash` | CWE-327 | `hashlib.md5()/sha1()` |
| `check_insecure_weak_randomness` | CWE-330 | `random.random()/randint()` per crypto |
| `check_insecure_cookie_flags` | CWE-614 | `set_cookie(secure=False/httponly=False/samesite='None')` |

Per pattern non coperti: `run_insecure_config_flag_query(db_path, module, functions,
param_name, insecure_value, cwe)`.

## Prerequisiti

- **CodeQL CLI** (≥ 2.25) su PATH (oppure imposta `CODEQL_BIN`)
- Un checkout di **[vscode-codeql-starter](https://github.com/github/vscode-codeql-starter)**
  (le query si usano via `--search-path`, **niente download di pack**)
- **Ollama** in esecuzione con il modello desiderato (default `qwen2.5-coder:14b`)

## Setup

```powershell
# 1. dipendenze (uv consigliato)
uv venv
uv pip install -r requirements.txt
#   oppure: pip install -r requirements.txt

# 2. configura i percorsi locali in un file .env (NON committato)
```

Crea un file **`.env`** nella root del progetto con i percorsi della **tua**
copia di `vscode-codeql-starter`. Le tre variabili CodeQL sono **obbligatorie**
(senza, `config.py` si ferma con un messaggio esplicito):

```env
# percorsi del checkout vscode-codeql-starter (adatta alla tua macchina)
CODEQL_SEARCH_PATH=C:\path\to\vscode-codeql-starter\ql
CODEQL_SUITE=C:\path\to\vscode-codeql-starter\ql\python\ql\src\codeql-suites\python-security-extended.qls
CUSTOM_QUERY_DIR=C:\path\to\vscode-codeql-starter\codeql-custom-queries-python

# opzionali (questi hanno un default)
AGENT_MODEL=qwen2.5-coder:14b
OLLAMA_HOST=http://localhost:11434
CODEQL_BIN=codeql
```

`.env` è in `.gitignore`: ogni macchina ha il suo.

## Uso

```powershell
uv run python agent.py "C:\path\alla\repo"
#   oppure: python agent.py "C:\path\alla\repo"
# opzioni: --model qwen2.5-coder:7b   --max-steps 30   --resume   --report path.md
```

Il report Markdown viene salvato **automaticamente** in
`reports/<repo>/<model>__<timestamp>.md`, con front-matter YAML (model, repository,
durata, tools_used, cwes_found, total_findings). `--report` forza un path specifico
ma non è necessario. Database CodeQL e SARIF intermedi finiscono in `_work/`.

Esempio sugli insecure config flag (repo di prova con tutti i pattern):

```powershell
python agent.py _insecure_config_testrepo
```

## Estendere: aggiungere un template

1. Scrivi `query_templates/<nome>.ql.tmpl` con placeholder `{{CWE_ID_SUFFIX}}` /
   `{{CWE_TAG_LINE}}` (più gli eventuali segnaposto specifici).
2. Registra il tool in `codeql_mcp_server.py`
   (per gli insecure config flag basta una voce in `INSECURE_CONFIG_FLAG_TEMPLATES`,
   il tool `check_insecure_<key>` viene generato in automatico).
3. Valida con `codeql query compile`.
4. Aggiungi la voce a `knowledge/cwe_wiki.json` (con `detection` e `actions`).
5. `python build_actions.py` per rigenerare/completare le azioni.
6. Aggiungi i test in `tests_agent.py` (compile + integrazione).

## Test

```powershell
pytest -m "not codeql and not llm"   # veloci (unit + KB), nessuna dipendenza esterna
pytest -m "not llm"                  # + compile/integrazione CodeQL (lenti)
pytest                               # + end-to-end LLM (molto lento)
```

## Configurazione (via `.env` o variabili d'ambiente)

| Variabile | Obbligatoria | Default |
|-----------|:---:|---------|
| `CODEQL_SEARCH_PATH` | ✅ | — (percorso al checkout) |
| `CODEQL_SUITE` | ✅ | — |
| `CUSTOM_QUERY_DIR` | ✅ | — |
| `AGENT_MODEL` | | `qwen2.5-coder:14b` |
| `OLLAMA_HOST` | | `http://localhost:11434` |
| `CODEQL_BIN` | | `codeql` |
| `CODEQL_TIMEOUT` | | `1800` |

Le tre obbligatorie non hanno default: se mancano, `config.py` solleva un errore
con il nome della variabile da impostare.
