# Sibyl — CodeQL Security Agent

Sibyl analyzes the security of a repository by having the analysis driven by a
**local Ollama model**, which runs **CodeQL** queries exposed as **MCP tools**.

It consists of **two independent programs** that run in parallel:

- **MCP Server** (`python -m server`) — wraps the CodeQL CLI and exposes 41 tools
  (see §Exposed MCP tools). On Windows/PowerShell remember to set
  `$env:MCP_TRANSPORT = "sse"` before starting it for network/SSE use (§Usage).
- **Agent** (`python -m agent`) — client that connects the LLM to the server and
  orchestrates the analysis up to the report.

## Architecture

Three processes talking over `localhost` (no port exposed externally):

```
                    ┌─────────────────────────────────────────────┐
                    │  Same machine (Ubuntu or Windows)            │
   python -m agent ─┤                                              │
   (client)         │   Agent ──HTTP:11434──►  Ollama (qwen)       │
                    │      │                                       │
                    │      └────SSE:8000────►  MCP Server ──► CodeQL CLI
                    │                          (python -m server)  │
                    └─────────────────────────────────────────────┘
```

- The agent talks to the **LLM** via HTTP (function calling) and to the **server**
  via SSE (MCP tools). The model decides *what* to do, the agent has the server
  *execute* it.
- Internal details: `documentazione/agent.md` (agent) and
  `documentazione/Server_MCP_Architettura.md` (server).

> ⚠️ The server reads the repo's files from its **own filesystem**: the repository
> to analyze must be located **on the machine where the server runs** (see §Usage).

## Components

| Folder | What it contains |
|---|---|
| `server/` | Self-contained MCP server: `core/`, `tools/`, `registry/`, `knowledge/`, `transport/`, `config.py` |
| `agent/` | Modular agent: `orchestrator.py`, `prompts.py`/`prompts_local.py`/`prompt_router.py`, `worklist.py`, `progress.py`, `clients/`, `robustness/` (incl. `degenerate.py`, `readargs.py`), `report.py`, `config.py` |
| `query_templates/`, `generated_queries/` | `.ql.tmpl` templates and generated queries (inside `server/`) |

## Analysis pipeline

The agent runs the analysis in three stages (`agent/orchestrator.py`):

1. **Gathering** (deterministic, no LLM calls) — `_gather_evidence` builds the
   CodeQL database (`create_codeql_database`) and calls `find_all_flows` in sequence
   plus the 11 categorized tools (see §Exposed MCP tools), populating a work-list of
   candidate flows/operations. No judgment required, so no model is involved.
2. **Detection** (LLM) — reads the actual code (`read_file_snippet`,
   `list_python_files`) and **enriches** the evidence already gathered (real
   names/values/algorithms, relevance judgment). It does not discover signals on
   its own and does not assign a CWE.
3. **Validation** (LLM) — runs the targeted queries (zero-parameter checks first,
   `run_taint_query`/`run_api_misuse_query`/`run_insecure_config_flag_query` as a
   fallback), assigns a real CWE to each finding, and writes the final report.

Built-in anti-hallucination controls: Validation cannot close the report until it
has verified with a real tool a number of items consistent with the evidence
gathered, and every CWE cited in the report must be confirmed by a tool actually
called at that stage.

## Exposed MCP tools

**Exploration / DB**
- `list_python_files` — enumerates the repo's `.py` files
- `read_file_snippet(repo_path, file, start_line, end_line)` — reads source lines
  around a finding (the path must be passed as `repo_path` + relative `file`, no
  longer an absolute path)
- `create_codeql_database` — builds the CodeQL DB (called deterministically by
  Gathering, no longer an LLM tool in Detection)
- `analyze_database` — runs the standard `python-security-extended` suite
- `find_confirmed_vulnerabilities(db_path, max_findings=200)` — runs the entire
  official suite and returns deduplicated results already tagged with a certified
  CWE. Registered but **not wired** into any stage of the automatic pipeline today
  (neither Gathering nor Detection/Validation): available for manual use or as a
  basis for a future "Evaluation" step outside the pipeline.
- `run_custom_query(db_path, query_path)` — runs a `.ql` already registered inside
  `CUSTOM_QUERY_DIR` BY NAME (never a free path: this is the only way custom
  queries are extended, by adding a new file to that folder)

**Knowledge base**
- `list_cwes` — lists detectable CWEs (with detection kind and the right tool)
- `cwe_knowledge(cwe)` — full profile of a CWE (MITRE description + operational
  actions)

**CWE-agnostic inventory** (Gathering stage, deterministic) — replace the single
monolithic tool `find_sensitive_operations` (removed): one tool per category, each
`(db_path, repo_path="", max_ops=200)`, none of which assigns a CWE.

| Tool | Kind | Template |
|---|---|---|
| `find_command_execution` | command-exec | `command_exec.ql.tmpl` |
| `find_code_execution` | code-exec | `code_exec.ql.tmpl` |
| `find_sql_execution` | sql-exec | `sql_exec.ql.tmpl` |
| `find_filesystem_access` | filesystem | `filesystem_access.ql.tmpl` |
| `find_decoding_operations` | decoding | `decoding_ops.ql.tmpl` |
| `find_crypto_operations` | crypto | `crypto_ops.ql.tmpl` |
| `find_weak_randomness` | weak-randomness | `weak_randomness.ql.tmpl` |
| `find_insecure_config_flags` | config-flag | `insecure_config_flags.ql.tmpl` |

Plus 3 "non-CWE" tools based on standard official CodeQL queries (structural
signals to be interpreted, not already-classified vulnerabilities):

| Tool | Signal | Official queries used |
|---|---|---|
| `find_exception_handling_issues` | overly broad/empty except | `Exceptions/EmptyExcept.ql`, `Exceptions/CatchingBaseException.ql`, `Statements/UnusedExceptionObject.ql` |
| `find_broken_sanitizer_patterns` | broken regex sanitizer | queries in `Expressions/Regex/` |
| `find_resource_handling_issues` | unclosed resources / missing `with` | `Resources/FileNotAlwaysClosed.ql`, `Statements/ShouldUseWithStatement.ql` |

**Vulnerability verification** — the CWE wiki (`cwe_knowledge`) always recommends
the dedicated zero-parameter check first; the generic tools
`run_taint_query`/`run_api_misuse_query` remain available as a fallback for custom
wrappers/APIs not covered by the dedicated checks:

| Detection | Primary tool | Fallback | Typical CWEs |
|-----------|------|------|------------|
| **taint** (dataflow source→sink) | `check_sql_injection`, `check_os_command_injection`, `check_path_traversal`, `check_deserialization`, `check_xss` | `run_taint_query` | 89, 78, 22, 79, 502, 90, 94, 611, 643, 601, 918, 117 |
| **api_misuse** (point detection) | `check_weak_hash`, `check_broken_crypto`, `check_weak_random`, `check_weak_password_hash` | `run_api_misuse_query` | 327, 328, 330, 916 |
| **insecure_config_flag** (point detection) | `check_insecure_*` | `run_insecure_config_flag_query` | 295, 78, 79, 489, 327, 330, 614 |

### Insecure configuration flags

Detects insecure configuration flags (point detection, no dataflow). Seven
dedicated checks plus one generic parametrized tool:

| Dedicated tool | CWE | Pattern |
|---------------|-----|---------|
| `check_insecure_verify_false` | CWE-295 | `requests.get(..., verify=False)` |
| `check_insecure_shell_true` | CWE-78 | `subprocess.run(..., shell=True)` |
| `check_insecure_autoescape_false` | CWE-79 | `jinja2/flask(..., autoescape=False)` |
| `check_insecure_debug_true` | CWE-489 | `Flask(..., debug=True)` |
| `check_insecure_weak_hash` | CWE-327 | `hashlib.md5()/sha1()` |
| `check_insecure_weak_randomness` | CWE-330 | `random.random()/randint()` for crypto |
| `check_insecure_cookie_flags` | CWE-614 | `set_cookie(secure=False/httponly=False/samesite='None')` |

For patterns not covered: `run_insecure_config_flag_query(db_path, module,
functions, param_name, insecure_value, cwe)`.

## Prerequisites (both OSes)

- **Python 3.10+** (3.12/3.13 recommended; with very recent Python some wheels
  might be missing — in that case use a 3.12/3.13 venv).
- **CodeQL CLI** (≥ 2.25) — on PATH or set `CODEQL_BIN` with the full path.
- A checkout of **[vscode-codeql-starter](https://github.com/github/vscode-codeql-starter)**
  (queries are used via `--search-path`, **no pack downloads**):
  ```
  git clone --depth 1 --recursive --shallow-submodules \
    https://github.com/github/vscode-codeql-starter.git
  ```
- **Ollama** running with the desired model (`ollama pull qwen2.5-coder:3b`,
  or whatever size you prefer).

## Setup

A single **`.env`** file in the root is used by both the server and the agent
(both load it). The three CodeQL variables are **mandatory**. Start from
`.env.example` (`cp .env.example .env`, on Windows `copy .env.example .env`) and
adjust the paths.

### Ubuntu / Linux

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -U pip
pip install -r requirements.txt        # mcp + ollama + python-dotenv
pip install pytest                      # only if you want to run the tests

cat > .env <<'EOF'
CODEQL_BIN=/home/user/codeql-tools/codeql/codeql
CODEQL_SEARCH_PATH=/home/user/codeql-tools/vscode-codeql-starter/ql
CODEQL_SUITE=/home/user/codeql-tools/vscode-codeql-starter/ql/python/ql/src/codeql-suites/python-security-extended.qls
CUSTOM_QUERY_DIR=/home/user/codeql-tools/vscode-codeql-starter/codeql-custom-queries-python
AGENT_MODEL=qwen2.5-coder:3b
EOF
```

### Windows (PowerShell)

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -U pip
pip install -r requirements.txt        # mcp + ollama + python-dotenv
pip install pytest                      # only if you want to run the tests
```

Create the `.env` file in the root (adjust the paths to your machine):

```env
CODEQL_BIN=C:\codeql-tools\codeql\codeql.exe
CODEQL_SEARCH_PATH=C:\codeql-tools\vscode-codeql-starter\ql
CODEQL_SUITE=C:\codeql-tools\vscode-codeql-starter\ql\python\ql\src\codeql-suites\python-security-extended.qls
CUSTOM_QUERY_DIR=C:\codeql-tools\vscode-codeql-starter\codeql-custom-queries-python
AGENT_MODEL=qwen2.5-coder:3b
```

`.env` is in `.gitignore`: each machine has its own.

## Usage

You need **two terminals** (the server keeps listening, the agent uses it). The
repository to analyze must be located **on the same machine as the server**.

### Ubuntu / Linux

```bash
# Terminal A — start the MCP server (keeps running)
source .venv/bin/activate
MCP_TRANSPORT=sse python -m server          # expected: "tools registered: 41" on :8000

# Terminal B — launch the agent
source .venv/bin/activate
python -m agent /path/to/repo
#   included example:  python -m agent _smoketest_repo
#   options: --model qwen2.5-coder:3b  --max-steps 30  --resume  --report out.md
```

### Windows (PowerShell)

```powershell
# Terminal A — start the MCP server (keeps running)
.\.venv\Scripts\Activate.ps1
$env:MCP_TRANSPORT = "sse"; python -m server

# Terminal B — launch the agent
.\.venv\Scripts\Activate.ps1
python -m agent C:\path\to\repo
#   options: --model qwen2.5-coder:3b  --max-steps 30  --resume  --report out.md
```

The agent also accepts a **`.zip`** file (it extracts it automatically). During
execution it prints live progress to stderr (`[step N] -> tool(...)`, timings,
outcome).

The Markdown report is saved to `agent/reports/<repo>/<model>__<timestamp>.md`,
with YAML front-matter (model, repository, duration, tools_used, cwes_found,
total_findings). `--report` forces a specific path. Intermediate CodeQL databases
and SARIF files end up in `server/_work/`; the agent's checkpoints in
`agent/_work/`.

## VS Code Extension

`extension/` contains a VS Code extension that acts as a **remote control** for
the agent: it does not analyze on its own, it launches the Sibyl **CLI**
(`python -m agent <repo>`) as a subprocess and shows the report in a panel on the
right. It's useful for starting an analysis without using the terminal.

### Installation (normal use)

Requires **Node.js 18+**. Build a `.vsix` package and install it once:

```bash
cd extension
npm install
npm run package                              # generates sibyl.vsix
code --install-extension sibyl.vsix --force
```

Then **reload VS Code** (*Developer: Reload Window*): the extension is active in
every window. On the first command, if it can't find a Sibyl installation, it
will ask for one and save the path in **`sibyl.rootPath`**.

> Once installed, the extension no longer lives inside the Sibyl folder: set
> **`sibyl.rootPath`** to the project root (with a venv, `sibyl.pythonPath` points
> automatically to `<rootPath>/.venv/bin/python`). The prerequisites (CodeQL,
> `.env`, Ollama or API key) are the ones described above: the extension reuses
> them, it doesn't replace them.

### Installation (development mode)

To work on the extension's code: `npm install`, open the `extension/` folder in
VS Code and press **F5** (opens the *Extension Development Host* with the
sources). In this case `sibyl.rootPath` is inferred automatically.

### Usage

Open a Python repo to analyze, then from the **Command Palette**
(`Ctrl+Shift+P`):

0. **`Sibyl: Configuration (.env)`** — opens a form to set the CodeQL paths and
   the LLM provider/keys, written directly to the `.env` file (a user-friendly
   alternative to manual editing).
1. **`Sibyl: Start MCP Server`** — starts the server (equivalent to
   `MCP_TRANSPORT=sse python -m server`). If you run the analysis without an
   active server, the extension offers to start it.
2. **`Sibyl: Analyze Repository`** — runs the agent on the open repo (or, if
   there's no workspace, asks for a folder) and opens the **report on the right**
   when the analysis finishes. Live progress is in the **"Sibyl"** output
   channel.
3. **`Sibyl: Stop MCP Server`** — stops the server started by the extension.

### Settings (`sibyl.*`)

| Setting | Default | Meaning |
|---|---|---|
| `sibyl.rootPath` | _(auto)_ | folder with `agent/`/`server/` (default: extension's parent, then workspace) |
| `sibyl.pythonPath` | _(auto)_ | Python interpreter (default: `<rootPath>/.venv/bin/python`, then `python3`) |
| `sibyl.provider` | `auto` | LLM backend (`--provider`). `auto` = uses `.env` (`AGENT_LLM_PROVIDER`) |
| `sibyl.model` | _(from `.env`)_ | LLM model (`--model`). If empty, uses the `.env` model |
| `sibyl.mcpServerUrl` | `http://127.0.0.1:8000/sse` | MCP server URL (`MCP_SERVER_URL`) |
| `sibyl.manageServer` | `true` | if `true` the extension can start/stop the server; if `false` it only connects |
| `sibyl.maxSteps` | `30` | maximum agent steps (`--max-steps`) |

> **Connecting to an already-running server:** set `sibyl.mcpServerUrl` to your
> server. If it's reachable, `Sibyl: Analyze Repository` uses it without starting
> a new one. To avoid automatic startup entirely (e.g. a server on another
> port/host that you manage yourself), set `sibyl.manageServer` to `false`: the
> extension will only connect.

## Tests

```bash
pytest -m "not codeql and not llm"   # fast (agent + server unit tests), no external dependencies
pytest -m "not llm"                  # + CodeQL compile/integration (slow)
pytest                               # + end-to-end LLM (very slow)
```

The agent's pure unit tests also run without Ollama:
`pytest agent/tests/test_agent.py`.

## Configuration (via `.env` or environment variables)

**MCP Server** (read from `server/config.py`):

| Variable | Required | Default | Meaning |
|---|:---:|---|---|
| `CODEQL_SEARCH_PATH` | ✅ | — | `ql` folder of the vscode-codeql-starter checkout |
| `CODEQL_SUITE` | ✅ | — | `.qls` file of the security suite |
| `CUSTOM_QUERY_DIR` | ✅ | — | folder with the custom `*Broad.ql` queries |
| `CODEQL_BIN` | | `codeql` | CodeQL binary (full path if not on PATH) |
| `MCP_TRANSPORT` | | `stdio` | transport: `stdio` / `sse` / `streamable-http` |
| `MCP_HOST` / `MCP_PORT` | | `127.0.0.1` / `8000` | address and port (network transports only; the server has no authentication, set `0.0.0.0` only deliberately) |
| `CODEQL_TIMEOUT` | | `1800` | timeout (s) for CodeQL commands |
| `SIBYL_LOG_LEVEL` | | `INFO` | server log verbosity |

**Agent** (read from `agent/config.py`):

| Variable | Default | Meaning |
|---|---|---|
| `AGENT_LLM_PROVIDER` | `ollama` | backend: `ollama` (local), `gemini` or `openai` (OpenAI-compatible) |
| `AGENT_MODEL` | `qwen2.5-coder:14b` | Ollama model to use |
| `OLLAMA_HOST` | `http://localhost:11434` | Ollama address |
| `OLLAMA_SHOW_THINKING` | `false` | if `true`, prints the model's "thinking" to stderr as it arrives |
| `OLLAMA_SHOW_THINKING_WITH_TOOLS` | `false` | same as above, but also in turns where tools are exposed |
| `OLLAMA_REPEAT_PENALTY` | `1.1` | repetition penalty (anti-loop for small/quantized models; too high a value causes "degenerate" text, see `agent/robustness/degenerate.py`) |
| `OLLAMA_REPEAT_LAST_N` | `128` | how many positions back to consider for the penalty |
| `OLLAMA_NUM_PREDICT` | `1536` | max token cap generated in a turn (`-1` = no limit) |
| `OLLAMA_NUM_PREDICT_TOOLS` | `512` | shorter cap used in turns where tools are exposed |
| `OLLAMA_TEMPERATURE` | `0.2` | sampling temperature |
| `OLLAMA_TOP_P` | `0.85` | nucleus sampling |
| `OLLAMA_TOP_K` | `40` | top-k sampling |
| `GEMINI_API_KEY` | — | Google AI Studio API key (only for `gemini`) |
| `GEMINI_MODEL` | `gemini-2.5-flash` | Gemini model (e.g. `gemini-2.0-flash`) |
| `GEMINI_BASE_URL` | Google's OpenAI-compatible endpoint | alternative endpoint (compatible proxy/gateway) |
| `GEMINI_MIN_INTERVAL` | `0` | minimum interval (s) between requests, for client-side throttling |
| `OPENAI_API_KEY` / `OPENAI_BASE_URL` | — / OpenAI | key + endpoint for the `openai` provider (Groq/Cerebras/...) |
| `OPENAI_MODEL` | `gpt-4o-mini` | model for the `openai` provider |
| `OPENAI_MIN_INTERVAL` | `0` | minimum interval (s) between requests, for client-side throttling |
| `MCP_SERVER_URL` | `http://127.0.0.1:8000/sse` | MCP server SSE URL |
| `AGENT_WORK_DIR` | `agent/_work` | where checkpoints are saved |
| `AGENT_REPORTS_DIR` | `agent/reports` | where reports are saved |

### Choosing the LLM provider

The agent can use a **local** model (Ollama) or a **hosted** one (Gemini, useful
when the local GPU isn't ready). The provider is chosen with `--provider` or
`AGENT_LLM_PROVIDER`:

```bash
# Ollama (default)
python -m agent _smoketest_repo

# Gemini (needs a Google AI Studio API key, not the app subscription)
export GEMINI_API_KEY=...          # or put it in .env
python -m agent _smoketest_repo --provider gemini --model gemini-2.0-flash

# Any OpenAI-compatible API (e.g. Groq: generous, fast free tier)
export OPENAI_BASE_URL=https://api.groq.com/openai/v1
export OPENAI_API_KEY=gsk_...
python -m agent _smoketest_repo --provider openai --model llama-3.3-70b-versatile
```

> For Gemini/OpenAI-compatible you need `pip install openai` (included in
> `requirements.txt`). Recommended free tiers for agentic use (many requests):
> **Groq** (https://console.groq.com) or **Cerebras**; Gemini's free tier is more
> limited.

The three mandatory variables have no default: if missing, the server stops with
an error indicating which variable to set.

## Extending: adding a template

1. Write `server/query_templates/<name>.ql.tmpl` with placeholders
   `{{CWE_ID_SUFFIX}}` / `{{CWE_TAG_LINE}}` (plus any specific placeholders
   needed).
2. Register the tool in the server (for insecure config flags, an entry in
   `INSECURE_CONFIG_FLAG_TEMPLATES` is enough, the `check_insecure_<key>` tool is
   generated automatically by `server/registry/loader.py`).
3. Validate with `codeql query compile`.
4. Add the entry to `server/knowledge/cwe_wiki.json` (with `detection` and
   `actions`).
5. Run `python build_actions.py` to regenerate/complete the actions.
6. Add tests in `server/tests/test_server.py` (compile + integration).

## Step-by-Step Guide

A complete walkthrough from zero to your first security report, on Windows/PowerShell.

**1. Install the prerequisites**
- Python 3.12/3.13.
- CodeQL CLI ≥ 2.25 — unzip it somewhere and either add it to `PATH` or note the
  full path to `codeql.exe`.
- Clone the query pack (no pack download needed, queries are used via
  `--search-path`):
  ```powershell
  git clone --depth 1 --recursive --shallow-submodules `
    https://github.com/github/vscode-codeql-starter.git
  ```
- Install [Ollama](https://ollama.com) and pull a model:
  ```powershell
  ollama pull qwen2.5-coder:3b
  ```

**2. Get Sibyl and create the virtual environment**
```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -U pip
pip install -r requirements.txt
```

**3. Configure `.env`**
Copy `.env.example` to `.env` (`copy .env.example .env`) and fill in the three
mandatory CodeQL paths plus the model, matching your machine:
```env
CODEQL_BIN=C:\codeql-tools\codeql\codeql.exe
CODEQL_SEARCH_PATH=C:\codeql-tools\vscode-codeql-starter\ql
CODEQL_SUITE=C:\codeql-tools\vscode-codeql-starter\ql\python\ql\src\codeql-suites\python-security-extended.qls
CUSTOM_QUERY_DIR=C:\codeql-tools\vscode-codeql-starter\codeql-custom-queries-python
AGENT_MODEL=qwen2.5-coder:3b
```

**4. Start the MCP server (Terminal A)**
```powershell
.\.venv\Scripts\Activate.ps1
$env:MCP_TRANSPORT = "sse"; python -m server
```
Wait for `tools registered: 41` on port `:8000`. Leave this terminal running.

**5. Run the agent on a target repository (Terminal B)**
```powershell
.\.venv\Scripts\Activate.ps1
python -m agent C:\path\to\target-repo
```
- Accepts a folder or a `.zip` file.
- Useful options: `--model qwen2.5-coder:3b`, `--max-steps 30`, `--resume`,
  `--report out.md`.
- Progress prints live to the console (`[step N] -> tool(...)`).

**6. Read the report**
Once the run finishes, the Markdown report is saved to
`agent/reports/<repo>/<model>__<timestamp>.md` (or to the path passed with
`--report`). It includes YAML front-matter with model, duration, tools used,
and CWEs found.

**7. (Optional) Use the VS Code extension instead of Terminal B**
- Install it once: `cd extension; npm install; npm run package; code --install-extension sibyl.vsix --force`, then reload VS Code.
- Open the target repo in VS Code, then from the Command Palette:
  `Sibyl: Configurazione (.env)` → `Sibyl: Avvia Server MCP` → `Sibyl: Analizza Repository`.
- The report opens automatically in a panel on the right.

**8. Re-running / troubleshooting**
- Server not starting: check the three mandatory `.env` variables are set and
  `CODEQL_BIN` is correct.
- Agent can't connect: confirm the server terminal still shows it running and
  `MCP_SERVER_URL` matches (`http://127.0.0.1:8000/sse` by default).
- Interrupted run: re-launch with `--resume` to continue from the last
  checkpoint in `agent/_work/`.
