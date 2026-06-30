# Sibyl — CodeQL Security Agent

Sibyl analizza la sicurezza di una repository facendo guidare l'analisi a un
**modello Ollama locale**, che esegue query **CodeQL** esposte come **tool MCP**.

È composto da **due programmi indipendenti** che girano in parallelo:

- **Server MCP** (`python -m server`) — incapsula la CLI CodeQL ed espone 26 tool.
- **Agente** (`python -m agent`) — client che connette l'LLM al server e orchestra
  l'analisi fino al report.

## Architettura

Tre processi che dialogano su `localhost` (nessuna porta esposta all'esterno):

```
                    ┌─────────────────────────────────────────────┐
                    │  Stessa macchina (Ubuntu o Windows)          │
   python -m agent ─┤                                              │
   (client)         │   Agente ──HTTP:11434──►  Ollama (qwen)      │
                    │      │                                       │
                    │      └────SSE:8000────►  Server MCP ──► CodeQL CLI
                    │                          (python -m server)  │
                    └─────────────────────────────────────────────┘
```

- L'agente parla con l'**LLM** via HTTP (function calling) e con il **server** via
  SSE (tool MCP). Il modello decide *cosa* fare, l'agente fa *eseguire* al server.
- Dettagli interni: `documentazione/agent.md` (agente) e
  `documentazione/Server_MCP_Architettura.md` (server).

> ⚠️ Il server legge i file della repo dal **proprio filesystem**: la repository da
> analizzare deve trovarsi **sulla macchina dove gira il server** (vedi §Uso).

## Componenti

| Cartella | Cosa contiene |
|---|---|
| `server/` | Server MCP autocontenuto: `core/`, `tools/`, `registry/`, `knowledge/`, `transport/`, `config.py` |
| `agent/` | Agente modulare: `orchestrator.py`, `clients/`, `robustness/`, `report.py`, `config.py` |
| `query_templates/`, `generated_queries/` | template `.ql.tmpl` e query generate (dentro `server/`) |

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

## Prerequisiti (entrambi gli OS)

- **Python 3.10+** (consigliato 3.12/3.13; con Python molto recente alcune wheel
  potrebbero mancare — in tal caso usa un venv 3.12/3.13).
- **CodeQL CLI** (≥ 2.25) — su PATH oppure imposta `CODEQL_BIN` col percorso completo.
- Un checkout di **[vscode-codeql-starter](https://github.com/github/vscode-codeql-starter)**
  (le query si usano via `--search-path`, **niente download di pack**):
  ```
  git clone --depth 1 --recursive --shallow-submodules \
    https://github.com/github/vscode-codeql-starter.git
  ```
- **Ollama** in esecuzione con il modello desiderato (`ollama pull qwen2.5-coder:3b`,
  o la taglia che preferisci).

## Setup

Un solo file **`.env`** nella root serve sia al server sia all'agente (entrambi lo
caricano). Le tre variabili CodeQL sono **obbligatorie**. Parti da `.env.example`
(`cp .env.example .env`, su Windows `copy .env.example .env`) e adatta i percorsi.

### Ubuntu / Linux

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -U pip
pip install -r requirements.txt        # mcp + ollama + python-dotenv
pip install pytest                      # solo se vuoi lanciare i test

cat > .env <<'EOF'
CODEQL_BIN=/home/utente/codeql-tools/codeql/codeql
CODEQL_SEARCH_PATH=/home/utente/codeql-tools/vscode-codeql-starter/ql
CODEQL_SUITE=/home/utente/codeql-tools/vscode-codeql-starter/ql/python/ql/src/codeql-suites/python-security-extended.qls
CUSTOM_QUERY_DIR=/home/utente/codeql-tools/vscode-codeql-starter/codeql-custom-queries-python
AGENT_MODEL=qwen2.5-coder:3b
EOF
```

### Windows (PowerShell)

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -U pip
pip install -r requirements.txt        # mcp + ollama + python-dotenv
pip install pytest                      # solo se vuoi lanciare i test
```

Crea il file `.env` nella root (adatta i percorsi alla tua macchina):

```env
CODEQL_BIN=C:\codeql-tools\codeql\codeql.exe
CODEQL_SEARCH_PATH=C:\codeql-tools\vscode-codeql-starter\ql
CODEQL_SUITE=C:\codeql-tools\vscode-codeql-starter\ql\python\ql\src\codeql-suites\python-security-extended.qls
CUSTOM_QUERY_DIR=C:\codeql-tools\vscode-codeql-starter\codeql-custom-queries-python
AGENT_MODEL=qwen2.5-coder:3b
```

`.env` è in `.gitignore`: ogni macchina ha il suo.

## Uso

Servono **due terminali** (il server resta in ascolto, l'agente lo usa). La
repository da analizzare deve stare **sulla stessa macchina del server**.

### Ubuntu / Linux

```bash
# Terminale A — avvia il server MCP (resta in esecuzione)
source .venv/bin/activate
MCP_TRANSPORT=sse python -m server          # atteso: "tools registered: 26" su :8000

# Terminale B — lancia l'agente
source .venv/bin/activate
python -m agent /percorso/alla/repo
#   esempio incluso:  python -m agent _smoketest_repo
#   opzioni: --model qwen2.5-coder:3b  --max-steps 30  --resume  --report out.md
```

### Windows (PowerShell)

```powershell
# Terminale A — avvia il server MCP (resta in esecuzione)
.\.venv\Scripts\Activate.ps1
$env:MCP_TRANSPORT = "sse"; python -m server

# Terminale B — lancia l'agente
.\.venv\Scripts\Activate.ps1
python -m agent C:\percorso\alla\repo
#   opzioni: --model qwen2.5-coder:3b  --max-steps 30  --resume  --report out.md
```

L'agente accetta anche un file **`.zip`** (lo estrae da solo). Durante l'esecuzione
stampa l'avanzamento live su stderr (`[step N] -> tool(...)`, tempi, esito).

Il report Markdown è salvato in `agent/reports/<repo>/<model>__<timestamp>.md`, con
front-matter YAML (model, repository, durata, tools_used, cwes_found,
total_findings). `--report` forza un percorso specifico. Database CodeQL e SARIF
intermedi finiscono in `server/_work/`; i checkpoint dell'agente in `agent/_work/`.

## Estensione VS Code

In `extension/` c'è un'estensione VS Code che fa da **telecomando** dell'agente: non
analizza in proprio, lancia la **CLI** di Sibyl (`python -m agent <repo>`) come
sottoprocesso e mostra il report in un pannello a destra. È utile per avviare
un'analisi senza usare il terminale.

### Installazione (uso normale)

Serve **Node.js 18+**. Si crea un pacchetto `.vsix` e lo si installa una volta:

```bash
cd extension
npm install
npm run package                              # genera sibyl.vsix
code --install-extension sibyl.vsix --force
```

Poi **ricarica VS Code** (*Developer: Reload Window*): l'estensione è attiva in ogni
finestra. Al primo comando, se non trova l'installazione di Sibyl, la chiede e salva il
percorso in **`sibyl.rootPath`**.

> Da installata, l'estensione non sta più dentro la cartella di Sibyl: imposta
> **`sibyl.rootPath`** sulla root del progetto (con venv, `sibyl.pythonPath` punta da solo
> a `<rootPath>/.venv/bin/python`). I prerequisiti (CodeQL, `.env`, Ollama o API key) sono
> quelli descritti sopra: l'estensione li riutilizza, non li sostituisce.

### Installazione (modalità sviluppo)

Per lavorare al codice dell'estensione: `npm install`, apri la cartella `extension/` in
VS Code e premi **F5** (apre l'*Extension Development Host* coi sorgenti). In questo caso
`sibyl.rootPath` viene dedotto in automatico.

### Uso

Apri una repo Python da analizzare, poi dalla **Command Palette** (`Ctrl+Shift+P`):

0. **`Sibyl: Configurazione (.env)`** — apre un form per impostare i percorsi CodeQL e il
   provider/chiavi LLM, scritti direttamente nel `.env` (alternativa user-friendly all'editing a mano).
1. **`Sibyl: Avvia Server MCP`** — avvia il server (equivale a `MCP_TRANSPORT=sse python -m server`).
   Se lanci l'analisi senza server attivo, l'estensione propone di avviarlo.
2. **`Sibyl: Analizza Repository`** — esegue l'agente sulla repo aperta (o, se non c'è
   workspace, chiede una cartella) e a fine analisi apre il **report a destra**.
   L'avanzamento live è nel canale di output **"Sibyl"**.
3. **`Sibyl: Ferma Server MCP`** — ferma il server avviato dall'estensione.

### Impostazioni (`sibyl.*`)

| Setting | Default | Significato |
|---|---|---|
| `sibyl.rootPath` | _(auto)_ | cartella con `agent/`/`server/` (default: padre dell'estensione, poi workspace) |
| `sibyl.pythonPath` | _(auto)_ | interprete Python (default: `<rootPath>/.venv/bin/python`, poi `python3`) |
| `sibyl.provider` | `auto` | backend LLM (`--provider`). `auto` = usa il `.env` (`AGENT_LLM_PROVIDER`) |
| `sibyl.model` | _(da `.env`)_ | modello LLM (`--model`). Se vuoto usa il modello del `.env` |
| `sibyl.mcpServerUrl` | `http://127.0.0.1:8000/sse` | URL del server MCP (`MCP_SERVER_URL`) |
| `sibyl.manageServer` | `true` | se `true` l'estensione può avviare/fermare il server; se `false` si collega soltanto |
| `sibyl.maxSteps` | `30` | passi massimi dell'agente (`--max-steps`) |

> **Collegarsi a un server già avviato:** imposta `sibyl.mcpServerUrl` sul tuo server.
> Se è raggiungibile, `Sibyl: Analizza Repository` lo usa senza avviarne uno nuovo. Per
> evitare del tutto l'avvio automatico (es. server su un'altra porta/host che gestisci tu),
> metti `sibyl.manageServer` a `false`: l'estensione si limita a connettersi.

## Test

```bash
pytest -m "not codeql and not llm"   # veloci (unit agente + server), nessuna dipendenza esterna
pytest -m "not llm"                  # + compile/integrazione CodeQL (lenti)
pytest                               # + end-to-end LLM (molto lento)
```

I test puri dell'agente girano anche senza Ollama:
`pytest agent/tests/test_agent.py`.

## Configurazione (via `.env` o variabili d'ambiente)

**Server MCP** (lette da `server/config.py`):

| Variabile | Obbligatoria | Default | Significato |
|---|:---:|---|---|
| `CODEQL_SEARCH_PATH` | ✅ | — | cartella `ql` del checkout vscode-codeql-starter |
| `CODEQL_SUITE` | ✅ | — | file `.qls` della suite di sicurezza |
| `CUSTOM_QUERY_DIR` | ✅ | — | cartella con le query custom `*Broad.ql` |
| `CODEQL_BIN` | | `codeql` | binario CodeQL (percorso completo se non su PATH) |
| `MCP_TRANSPORT` | | `stdio` | trasporto: `stdio` / `sse` / `streamable-http` |
| `MCP_HOST` / `MCP_PORT` | | `0.0.0.0` / `8000` | indirizzo e porta (solo trasporti di rete) |
| `CODEQL_TIMEOUT` | | `1800` | timeout (s) per comando CodeQL |
| `SIBYL_LOG_LEVEL` | | `INFO` | verbosità log del server |

**Agente** (lette da `agent/config.py`):

| Variabile | Default | Significato |
|---|---|---|
| `AGENT_LLM_PROVIDER` | `ollama` | backend: `ollama` (locale), `gemini` o `openai` (OpenAI-compat) |
| `AGENT_MODEL` | `qwen2.5-coder:14b` | modello Ollama da usare |
| `OLLAMA_HOST` | `http://localhost:11434` | indirizzo di Ollama |
| `GEMINI_API_KEY` | — | API key di Google AI Studio (solo per `gemini`) |
| `GEMINI_MODEL` | `gemini-2.5-flash` | modello Gemini (es. `gemini-2.0-flash`) |
| `OPENAI_API_KEY` / `OPENAI_BASE_URL` | — / OpenAI | chiave + endpoint per provider `openai` (Groq/Cerebras/...) |
| `OPENAI_MODEL` | `gpt-4o-mini` | modello per il provider `openai` |
| `MCP_SERVER_URL` | `http://127.0.0.1:8000/sse` | URL SSE del server MCP |
| `AGENT_WORK_DIR` | `agent/_work` | dove salvare i checkpoint |
| `AGENT_REPORTS_DIR` | `agent/reports` | dove salvare i report |

### Scegliere il provider LLM

L'agente può usare un modello **locale** (Ollama) o uno **hosted** (Gemini, utile
quando la GPU locale non è pronta). Il provider si sceglie con `--provider` o con
`AGENT_LLM_PROVIDER`:

```bash
# Ollama (default)
python -m agent _smoketest_repo

# Gemini (serve una API key di Google AI Studio, non l'abbonamento dell'app)
export GEMINI_API_KEY=...          # o mettila nel .env
python -m agent _smoketest_repo --provider gemini --model gemini-2.0-flash

# Qualsiasi API OpenAI-compatibile (es. Groq: free tier generoso e veloce)
export OPENAI_BASE_URL=https://api.groq.com/openai/v1
export OPENAI_API_KEY=gsk_...
python -m agent _smoketest_repo --provider openai --model llama-3.3-70b-versatile
```

> Per Gemini/OpenAI-compat serve `pip install openai` (incluso in `requirements.txt`).
> Free tier consigliati per l'uso ad agente (molte richieste): **Groq**
> (https://console.groq.com) o **Cerebras**; Gemini free è più limitato.

Le tre obbligatorie non hanno default: se mancano, il server si ferma con un errore
che indica la variabile da impostare.

## Estendere: aggiungere un template

1. Scrivi `server/query_templates/<nome>.ql.tmpl` con placeholder `{{CWE_ID_SUFFIX}}` /
   `{{CWE_TAG_LINE}}` (più gli eventuali segnaposto specifici).
2. Registra il tool nel server (per gli insecure config flag basta una voce in
   `INSECURE_CONFIG_FLAG_TEMPLATES`, il tool `check_insecure_<key>` viene generato
   in automatico da `server/registry/loader.py`).
3. Valida con `codeql query compile`.
4. Aggiungi la voce a `server/knowledge/cwe_wiki.json` (con `detection` e `actions`).
5. `python build_actions.py` per rigenerare/completare le azioni.
6. Aggiungi i test in `server/tests/test_server.py` (compile + integrazione).
