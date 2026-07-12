// sibylRunner.ts — avvia l'agent/server di Sibyl via CLI come sottoprocessi.
import * as vscode from 'vscode';
import * as cp from 'child_process';
import * as net from 'net';
import * as path from 'path';
import * as fs from 'fs';
import { RunOptions, RunResult, SibylConfig } from './types';

let serverProcess: cp.ChildProcess | undefined;

/** Prefisso delle righe di avanzamento STRUTTURATE emesse dall'agent (progress.py). */
const SIBYL_EVENT_MARKER = '@@SIBYL@@';

/**
 * Costruisce un gestore di 'data' che accumula i chunk e li spezza in RIGHE
 * complete (l'output di un processo non arriva allineato ai newline). Ogni riga
 * viene passata a onLine.
 */
function lineSplitter(onLine: (line: string) => void): { push: (d: Buffer) => void; end: () => void } {
  let buf = '';
  return {
    push(d: Buffer) {
      buf += d.toString();
      let idx: number;
      while ((idx = buf.indexOf('\n')) >= 0) {
        onLine(buf.slice(0, idx).replace(/\r$/, ''));
        buf = buf.slice(idx + 1);
      }
    },
    end() {
      if (buf.length) { onLine(buf.replace(/\r$/, '')); buf = ''; }
    },
  };
}

/**
 * Risolve la configurazione dell'estensione in valori concreti.
 * @param extensionPath cartella dell'estensione (per dedurre rootPath di default).
 */
export function resolveConfig(extensionPath: string): SibylConfig {
  const cfg = vscode.workspace.getConfiguration('sibyl');

  // rootPath: setting esplicito → cartella padre dell'estensione → workspace.
  let rootPath = (cfg.get<string>('rootPath') || '').trim();
  if (!rootPath) {
    const parent = path.dirname(extensionPath);
    if (fs.existsSync(path.join(parent, 'agent'))) {
      rootPath = parent;
    } else {
      rootPath = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath || parent;
    }
  }

  // pythonPath: setting esplicito → .venv del rootPath (Windows/Unix) → fallback.
  let pythonPath = (cfg.get<string>('pythonPath') || '').trim();
  if (!pythonPath) {
    const candidatePaths = [
      path.join(rootPath, '.venv', 'Scripts', 'python.exe'),
      path.join(rootPath, '.venv', 'Scripts', 'python'),
      path.join(rootPath, '.venv', 'bin', 'python'),
    ];
    const venvPython = candidatePaths.find((candidate) => fs.existsSync(candidate));
    pythonPath = venvPython || 'python';
  }

  return {
    rootPath,
    pythonPath,
    provider: (cfg.get<string>('provider') || 'auto').trim(),
    model: (cfg.get<string>('model') || '').trim(),
    mcpServerUrl: (cfg.get<string>('mcpServerUrl') || 'http://127.0.0.1:8000/sse').trim(),
    manageServer: cfg.get<boolean>('manageServer') ?? true,
    maxSteps: cfg.get<number>('maxSteps') ?? 30,
  };
}

/** Estrae host/porta dall'URL del server MCP (default 127.0.0.1:8000). */
function hostPort(mcpServerUrl: string): { host: string; port: number } {
  try {
    const u = new URL(mcpServerUrl);
    return { host: u.hostname || '127.0.0.1', port: Number(u.port) || 8000 };
  } catch {
    return { host: '127.0.0.1', port: 8000 };
  }
}

/** Verifica se il server MCP risponde (connessione TCP, timeout 1s). */
export function isServerUp(mcpServerUrl: string): Promise<boolean> {
  const { host, port } = hostPort(mcpServerUrl);
  return new Promise((resolve) => {
    const socket = new net.Socket();
    const done = (ok: boolean) => {
      socket.destroy();
      resolve(ok);
    };
    socket.setTimeout(1000);
    socket.once('connect', () => done(true));
    socket.once('timeout', () => done(false));
    socket.once('error', () => done(false));
    socket.connect(port, host);
  });
}

/** Ambiente comune ai sottoprocessi: eredita process.env + override Sibyl. */
function childEnv(config: SibylConfig, extra: NodeJS.ProcessEnv = {}): NodeJS.ProcessEnv {
  return {
    ...process.env,
    PYTHONUNBUFFERED: '1', // output in tempo reale
    MCP_SERVER_URL: config.mcpServerUrl,
    ...extra,
  };
}

/** Avvia il server MCP (`python -m server`) in modalità SSE. Idempotente. */
export function startServer(config: SibylConfig, channel: vscode.OutputChannel): cp.ChildProcess {
  if (serverProcess && serverProcess.exitCode === null) {
    channel.appendLine('[server] già in esecuzione.');
    return serverProcess;
  }

  const { host, port } = hostPort(config.mcpServerUrl);
  channel.appendLine(`[server] avvio: ${config.pythonPath} -m server (SSE su ${host}:${port})`);

  serverProcess = cp.spawn(config.pythonPath, ['-m', 'server'], {
    cwd: config.rootPath,
    env: childEnv(config, { MCP_TRANSPORT: 'sse', MCP_HOST: host, MCP_PORT: String(port) }),
  });

  serverProcess.stdout?.on('data', (d) => channel.append(`[server] ${d}`));
  serverProcess.stderr?.on('data', (d) => channel.append(`[server] ${d}`));
  serverProcess.on('exit', (code) => {
    channel.appendLine(`[server] terminato (exit ${code}).`);
    serverProcess = undefined;
  });
  serverProcess.on('error', (err) => {
    channel.appendLine(`[server] errore: ${err.message}`);
    serverProcess = undefined;
  });

  return serverProcess;
}

/** Ferma il server MCP se avviato da noi. */
export function stopServer(channel: vscode.OutputChannel): void {
  if (serverProcess) {
    channel.appendLine('[server] arresto in corso...');
    serverProcess.kill();
    serverProcess = undefined;
  } else {
    channel.appendLine('[server] nessun processo da fermare.');
  }
}

/**
 * Esegue l'agent su una repo (`python -m agent <repo> ...`) e attende il termine.
 * Streamma stdout/stderr nel canale; risolve quando il processo termina.
 */
export function runAgent(
  config: SibylConfig,
  options: RunOptions,
  channel: vscode.OutputChannel,
  token?: vscode.CancellationToken,
  onEvent?: (evt: any) => void,
): Promise<RunResult> {
  const args = ['-m', 'agent', options.repoPath,
    '--report', options.reportPath, '--max-steps', String(config.maxSteps)];
  // 'auto' (o vuoto) = non forzare: lascia decidere al .env (AGENT_LLM_PROVIDER).
  if (config.provider && config.provider !== 'auto') {
    args.push('--provider', config.provider);
  }
  if (config.model) {
    args.push('--model', config.model);
  }

  channel.appendLine(`[agent] avvio: ${config.pythonPath} ${args.join(' ')}`);
  channel.appendLine(`[agent] cwd: ${config.rootPath}`);

  return new Promise((resolve, reject) => {
    const proc = cp.spawn(config.pythonPath, args, {
      cwd: config.rootPath,
      // SIBYL_PROGRESS_EVENTS=1 => l'agent emette gli eventi strutturati che la
      // webview grafica disegna (le righe umane restano nel canale di output).
      env: childEnv(config, { SIBYL_PROGRESS_EVENTS: '1' }),
    });

    token?.onCancellationRequested(() => {
      channel.appendLine('[agent] annullato dall\'utente.');
      proc.kill();
    });

    // Righe con il MARKER = eventi (vanno alla webview); tutte le altre = log nel canale.
    const onLine = (line: string) => {
      if (onEvent && line.startsWith(SIBYL_EVENT_MARKER)) {
        try {
          onEvent(JSON.parse(line.slice(SIBYL_EVENT_MARKER.length).trim()));
        } catch {
          /* riga di evento malformata: la si ignora */
        }
        return;
      }
      channel.appendLine(line);
    };
    const out = lineSplitter(onLine);
    const err = lineSplitter(onLine);

    proc.stdout?.on('data', (d) => out.push(d));
    proc.stderr?.on('data', (d) => err.push(d));

    proc.on('error', (err) => {
      channel.appendLine(`[agent] errore di avvio: ${err.message}`);
      reject(err);
    });

    proc.on('exit', (code) => {
      out.end();
      err.end();
      channel.appendLine(`[agent] terminato (exit ${code}).`);
      resolve({ exitCode: code ?? -1, reportPath: options.reportPath });
    });
  });
}
