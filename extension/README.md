# Sibyl — Estensione VS Code

Telecomando per l'agent di analisi sicurezza **Sibyl**. L'estensione non implementa
analisi proprie: lancia la **CLI** di Sibyl (`python -m agent <repo>`) come sottoprocesso,
ne mostra l'avanzamento e visualizza il **report** in un pannello a destra.

## Installazione (uso normale)

Per usarla come una vera estensione (senza F5), si crea un pacchetto `.vsix` e lo si installa:

```bash
cd extension
npm install
npm run package          # genera sibyl.vsix (esegue compile + vsce)
code --install-extension sibyl.vsix --force
```

Poi **ricarica VS Code** (Developer: Reload Window). L'estensione è ora attiva in
qualsiasi finestra. Al primo utilizzo, se non trova l'installazione di Sibyl, te la
chiede e salva il percorso in `sibyl.rootPath` (vedi sotto).

> **Importante:** da installata, l'estensione non sta più dentro la cartella di Sibyl,
> quindi non può dedurre da sola dove sono `agent/`/`server/`. Imposta **`sibyl.rootPath`**
> sulla cartella di Sibyl (lo fa anche il prompt automatico al primo comando). Se usi un
> venv, `sibyl.pythonPath` punta in automatico a `<rootPath>/.venv/bin/python`.

## Come funziona

1. Il server MCP di Sibyl deve essere attivo (`python -m server` in modalità SSE).
   L'estensione può avviarlo con il comando **"Sibyl: Avvia Server MCP"**.
2. Con il comando **"Sibyl: Analizza Repository"** scegli la repo (di default il
   workspace aperto), l'estensione esegue l'agent e, al termine, apre il report
   markdown convertito in HTML nella colonna di destra.

## Comandi

- `Sibyl: Configurazione (.env)` — form per impostare percorsi CodeQL e provider/chiavi LLM, scritti nel `.env`.
- `Sibyl: Analizza Repository` — esegue l'agent sull'intera repo e mostra il report.
- `Sibyl: Avvia Server MCP` — avvia il server MCP (SSE).
- `Sibyl: Ferma Server MCP` — ferma il server avviato dall'estensione.

## Impostazioni (`sibyl.*`)

| Setting | Default | Descrizione |
|---|---|---|
| `sibyl.rootPath` | _(auto)_ | Cartella con `agent/` e `server/`. In sviluppo (F5) si deduce da sola; da installata va impostata (o la chiede al primo comando). |
| `sibyl.pythonPath` | _(auto)_ | Interprete Python. Default: `<rootPath>/.venv/bin/python`, poi `python3`. |
| `sibyl.provider` | `auto` | Backend LLM (`--provider`). `auto` = usa il `.env` (`AGENT_LLM_PROVIDER`). |
| `sibyl.model` | _(da `.env`)_ | Modello LLM (`--model`). Se vuoto usa il modello del `.env`. |
| `sibyl.mcpServerUrl` | `http://127.0.0.1:8000/sse` | URL del server MCP. Punta qui un server già avviato per collegarti ad esso. |
| `sibyl.manageServer` | `true` | Se `true` l'estensione può avviare/fermare il server; se `false` si collega soltanto. |
| `sibyl.maxSteps` | `30` | Passi massimi dell'agent. |

## Collegarsi a un server MCP già avviato

Se hai già un server MCP in esecuzione, imposta `sibyl.mcpServerUrl` sul suo indirizzo:
`Sibyl: Analizza Repository` lo rileva e lo usa senza avviarne un altro. Per impedire
del tutto l'avvio automatico, metti `sibyl.manageServer` a `false` — l'estensione si
limiterà a connettersi a quell'URL (e segnala un errore se non risponde).

## Sviluppo

Per lavorare al codice dell'estensione (non per l'uso quotidiano):

```bash
npm install
npm run compile      # oppure npm run watch
```

Apri la cartella `extension/` in VS Code e premi **F5** per avviare l'Extension
Development Host (una seconda finestra con l'estensione caricata dai sorgenti).
