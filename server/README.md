# CodeQL MCP Server

Self-contained MCP server that exposes CodeQL as tools. The whole `server/`
directory is portable: copy it to another host, install the requirements, set the
CodeQL environment variables, and run it.

## Architecture (components)

```
server/
├── config.py          # server-only configuration (independent)
├── main.py            # assembles tools + registry, then runs the transport
├── core/              # pure logic, no MCP: runner, sarif, executor, template
├── knowledge/         # CWE knowledge base (store.py + bundled data/)
├── query_templates/   # .ql.tmpl templates (bundled)
├── generated_queries/ # writable CodeQL pack for rendered queries
├── transport/         # MCP instance + transport selection (stdio | sse)
├── tools/             # @mcp.tool() definitions (filesystem/database/queries/...)
└── registry/          # dynamic registration of the check_* tools
```

Dependency direction (never upward):
`transport ← registry ← tools ← core, knowledge ← config`

## Requirements

```bash
pip install -r server/requirements.txt
```

Plus the CodeQL toolchain on the **host** (not bundled):

| Env var | Required | Meaning |
|---|---|---|
| `CODEQL_BIN` | no (default `codeql`) | CodeQL CLI binary |
| `CODEQL_SEARCH_PATH` | ✅ | `ql` folder of a vscode-codeql-starter checkout |
| `CODEQL_SUITE` | ✅ | path to a `.qls` security suite |
| `CUSTOM_QUERY_DIR` | ✅ | directory with the custom `*Broad.ql` queries |

Optional overrides: `TEMPLATE_DIR`, `GENERATED_DIR`, `CWE_WIKI_PATH`,
`CWE_CATALOG_PATH`, `WORK_DIR`, `CODEQL_TIMEOUT`. Defaults all point inside
`server/`, so nothing outside the package is needed for the bundled data.

## Running

Local (stdio) — the default; an agent launches this as a subprocess:

```bash
python -m server
```

Remote (network) — bind an SSE/HTTP listener the agent connects to over the wire:

```bash
MCP_TRANSPORT=sse MCP_HOST=0.0.0.0 MCP_PORT=8000 python -m server
```

Transport variables:

| Env var | Default | Meaning |
|---|---|---|
| `MCP_TRANSPORT` | `stdio` | `stdio` \| `sse` \| `streamable-http` |
| `MCP_HOST` | `0.0.0.0` | bind address (network transports only) |
| `MCP_PORT` | `8000` | bind port (network transports only) |

## Debug logging

All logs go to **stderr** (stdout is reserved for the MCP protocol on stdio).
A startup banner (config + registered tool count) and one line per tool
invocation (`→ tool call` / `✓ tool done` / `✗ tool error`) are emitted.
Control verbosity with `SIBYL_LOG_LEVEL` (`DEBUG` | `INFO` | `WARNING` | `ERROR`,
default `INFO`). `DEBUG` also logs each CodeQL command and its exit/duration.

```bash
SIBYL_LOG_LEVEL=DEBUG python -m server
```
