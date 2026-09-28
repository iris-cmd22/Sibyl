// extension.ts — telecomando VSCode per l'agent CLI di Sibyl.
import * as vscode from 'vscode';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { clearCheckpoint, isServerUp, resolveConfig, runAgent, startServer, stopServer } from './sibylRunner';
import { renderMarkdown } from './markdown';
import { envFilePath, readEnvValues, renderConfigHtml, writeEnvValues } from './envConfig';
import { createProgressPanel } from './progressView';
import { Finding } from './types';

let channel: vscode.OutputChannel;
let statusBarItem: vscode.StatusBarItem;
let diagnostics: vscode.DiagnosticCollection;

/** Mappa il bucket di severità (agent/report.py:_severity_bucket) sulla severità VSCode. */
const SEVERITY_MAP: Record<string, vscode.DiagnosticSeverity> = {
  Critical: vscode.DiagnosticSeverity.Error,
  High: vscode.DiagnosticSeverity.Error,
  Medium: vscode.DiagnosticSeverity.Warning,
  Low: vscode.DiagnosticSeverity.Information,
  Unknown: vscode.DiagnosticSeverity.Information,
};

export function activate(context: vscode.ExtensionContext) {
  channel = vscode.window.createOutputChannel('Sibyl');
  diagnostics = vscode.languages.createDiagnosticCollection('sibyl');

  statusBarItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 100);
  statusBarItem.text = '$(shield) Sibyl';
  statusBarItem.tooltip = 'Analizza la repository con Sibyl';
  statusBarItem.command = 'sibyl.analyzeRepository';
  statusBarItem.show();

  context.subscriptions.push(
    channel,
    diagnostics,
    statusBarItem,
    vscode.commands.registerCommand('sibyl.analyzeRepository', () => analyzeRepository(context)),
    vscode.commands.registerCommand('sibyl.resumeValidation', () => analyzeRepository(context, { resume: true })),
    vscode.commands.registerCommand('sibyl.startServer', () => startServerCommand(context)),
    vscode.commands.registerCommand('sibyl.stopServer', () => {
      channel.show(true);
      const stopped = stopServer(channel);
      if (stopped) {
        vscode.window.showInformationMessage('Sibyl: server MCP fermato.');
      } else {
        vscode.window.showWarningMessage('Sibyl: nessun server MCP in esecuzione (avviato da questa estensione).');
      }
    }),
    vscode.commands.registerCommand('sibyl.configure', () => openConfig(context)),
    vscode.commands.registerCommand('sibyl.clearCheckpoint', () => clearCheckpointCommand(context)),
  );
}

export function deactivate() {
  if (channel) {
    stopServer(channel);
  }
}

/**
 * Risolve la config e verifica che rootPath sia una vera installazione di Sibyl
 * (contiene agent/). Se non lo è, chiede all'utente la cartella e la salva nei settings.
 * Necessario quando l'estensione è installata (la sua cartella non è dentro Sibyl).
 */
async function getValidConfig(context: vscode.ExtensionContext) {
  let config = resolveConfig(context.extensionPath);
  if (fs.existsSync(path.join(config.rootPath, 'agent'))) {
    return config;
  }

  const choice = await vscode.window.showErrorMessage(
    `Sibyl: non trovo l'installazione (cartella con agent/ e server/). Indica dove si trova Sibyl.`,
    'Seleziona cartella Sibyl', 'Annulla',
  );
  if (choice !== 'Seleziona cartella Sibyl') {
    return undefined;
  }

  const picked = await vscode.window.showOpenDialog({
    canSelectFolders: true,
    canSelectFiles: false,
    canSelectMany: false,
    openLabel: 'Usa come cartella Sibyl',
  });
  const root = picked?.[0]?.fsPath;
  if (!root) {
    return undefined;
  }
  if (!fs.existsSync(path.join(root, 'agent'))) {
    vscode.window.showErrorMessage('Sibyl: la cartella selezionata non contiene agent/. Riprova.');
    return undefined;
  }

  await vscode.workspace.getConfiguration('sibyl')
    .update('rootPath', root, vscode.ConfigurationTarget.Global);
  config = resolveConfig(context.extensionPath); // ri-risolve con il nuovo rootPath
  return config;
}

/** Apre il form (webview) per modificare il .env di Sibyl. */
async function openConfig(context: vscode.ExtensionContext) {
  const config = await getValidConfig(context);
  if (!config) {
    return;
  }
  const rootPath = config.rootPath;

  const panel = vscode.window.createWebviewPanel(
    'sibylConfig',
    'Sibyl: Configurazione',
    vscode.ViewColumn.Active,
    { enableScripts: true, retainContextWhenHidden: true },
  );

  panel.webview.html = renderConfigHtml(readEnvValues(rootPath), envFilePath(rootPath));

  panel.webview.onDidReceiveMessage(async (msg) => {
    if (msg.command === 'save') {
      try {
        writeEnvValues(rootPath, msg.values || {});
        panel.webview.postMessage({ command: 'status', text: '✓ Salvato in .env' });
        vscode.window.showInformationMessage(`Sibyl: .env aggiornato (${envFilePath(rootPath)}).`);
      } catch (err: any) {
        vscode.window.showErrorMessage(`Sibyl: impossibile scrivere il .env — ${err.message}`);
      }
    } else if (msg.command === 'pick') {
      const picked = await vscode.window.showOpenDialog({
        canSelectFiles: !msg.folder,
        canSelectFolders: !!msg.folder,
        canSelectMany: false,
        openLabel: 'Seleziona',
      });
      if (picked?.[0]) {
        panel.webview.postMessage({ command: 'setValue', key: msg.key, value: picked[0].fsPath });
      }
    }
  }, undefined, context.subscriptions);
}

/**
 * Sceglie la repo, assicura il server, lancia l'agent, mostra il report.
 * @param opts.resume se true, passa --resume: riprende dal checkpoint della repo
 *   (se gathering+detection erano già completati, rifà solo Validation — vedi
 *   'sibyl.resumeValidation'). Richiede un run precedente completato con
 *   --keep-checkpoint (di default per ogni run lanciato da questa estensione);
 *   se manca, l'agent degrada da solo a un'analisi completa da zero.
 */
async function analyzeRepository(context: vscode.ExtensionContext, opts: { resume?: boolean } = {}) {
  const config = await getValidConfig(context);
  if (!config) {
    return;
  }

  const repoPath = await pickRepo();
  if (!repoPath) {
    return;
  }

  // Assicura che il server MCP sia raggiungibile (collegandosi a uno esistente, se c'è).
  if (!(await isServerUp(config.mcpServerUrl))) {
    if (!config.manageServer) {
      vscode.window.showErrorMessage(
        `Sibyl: nessun server MCP raggiungibile su ${config.mcpServerUrl}. ` +
        'Avvialo tu, oppure abilita "sibyl.manageServer" per farlo gestire all\'estensione.');
      return;
    }
    const choice = await vscode.window.showWarningMessage(
      `Il server MCP di Sibyl non risponde su ${config.mcpServerUrl}.`,
      'Avvia server', 'Annulla',
    );
    if (choice !== 'Avvia server') {
      return;
    }
    channel.show(true);
    startServer(config, channel);
    if (!(await waitServerUp(config.mcpServerUrl))) {
      vscode.window.showErrorMessage('Il server MCP non si è avviato in tempo. Controlla l\'output "Sibyl".');
      return;
    }
  }

  const reportPath = path.join(os.tmpdir(), `sibyl-report-${Date.now()}.md`);
  diagnostics.clear(); // via i diagnostics della repo/run precedente
  channel.show(true);

  // Vista grafica di avanzamento (al posto dei log): riceve gli eventi dell'agent.
  const progressPanel = createProgressPanel(context, path.basename(repoPath), repoPath);

  const title = opts.resume
    ? `Sibyl: rilancio Validation su ${path.basename(repoPath)}...`
    : `Sibyl: analisi di ${path.basename(repoPath)}...`;
  await vscode.window.withProgress(
    {
      location: vscode.ProgressLocation.Notification,
      title,
      cancellable: true,
    },
    async (_progress, token) => {
      try {
        const result = await runAgent(
          config, { repoPath, reportPath, resume: opts.resume }, channel, token,
          (evt) => progressPanel.update(evt),
        );
        if (token.isCancellationRequested) {
          return;
        }
        if (result.exitCode !== 0) {
          vscode.window.showErrorMessage(`Sibyl: l'agent è terminato con errore (exit ${result.exitCode}). Vedi output "Sibyl".`);
          return;
        }
        const markdown = readReport(reportPath);
        showReport(context, path.basename(repoPath), markdown);
        applyDiagnosticsFromReport(reportPath, repoPath);
      } catch (err: any) {
        vscode.window.showErrorMessage(`Sibyl: impossibile avviare l'agent — ${err.message}`);
      }
    },
  );
}

/** Avvia il server MCP (se non già su) e mostra un popup con l'esito reale (non solo il log). */
async function startServerCommand(context: vscode.ExtensionContext) {
  const config = await getValidConfig(context);
  if (!config) {
    return;
  }
  channel.show(true);

  if (await isServerUp(config.mcpServerUrl)) {
    vscode.window.showInformationMessage(`Sibyl: server MCP già attivo su ${config.mcpServerUrl}.`);
    return;
  }

  startServer(config, channel);
  const up = await waitServerUp(config.mcpServerUrl);
  if (up) {
    vscode.window.showInformationMessage(`Sibyl: server MCP avviato su ${config.mcpServerUrl}.`);
  } else {
    vscode.window.showErrorMessage('Sibyl: il server MCP non si è avviato in tempo. Vedi output "Sibyl".');
  }
}

/**
 * Cancella il checkpoint salvato per una repo (agent/robustness/checkpoint.py), utile
 * per scartare lo stato lasciato da un run interrotto invece di riprenderlo con
 * 'sibyl.resumeValidation'. Chiede conferma perché non è annullabile.
 */
async function clearCheckpointCommand(context: vscode.ExtensionContext) {
  const config = await getValidConfig(context);
  if (!config) {
    return;
  }

  const repoPath = await pickRepo();
  if (!repoPath) {
    return;
  }

  const choice = await vscode.window.showWarningMessage(
    `Cancellare il checkpoint salvato per "${path.basename(repoPath)}"? Un successivo run ripartirà da zero.`,
    'Cancella checkpoint', 'Annulla',
  );
  if (choice !== 'Cancella checkpoint') {
    return;
  }

  channel.show(true);
  try {
    const result = await clearCheckpoint(config, repoPath, channel);
    if (result.exitCode !== 0) {
      vscode.window.showErrorMessage(`Sibyl: cancellazione checkpoint fallita (exit ${result.exitCode}). Vedi output "Sibyl".`);
      return;
    }
    vscode.window.showInformationMessage(`Sibyl: checkpoint cancellato per "${path.basename(repoPath)}".`);
  } catch (err: any) {
    vscode.window.showErrorMessage(`Sibyl: impossibile cancellare il checkpoint — ${err.message}`);
  }
}

/** Apre il file-picker nativo per scegliere una cartella qualsiasi (anche una
 *  sottocartella del workspace corrente, es. un repo target annidato in Sibyl). */
async function browseForRepo(): Promise<string | undefined> {
  const chosen = await vscode.window.showOpenDialog({
    canSelectFolders: true,
    canSelectFiles: false,
    canSelectMany: false,
    openLabel: 'Analizza questa repository',
  });
  return chosen?.[0]?.fsPath;
}

interface RepoPickItem extends vscode.QuickPickItem {
  fsPath?: string; // undefined = voce "Sfoglia..."
}

/** Determina la repo da analizzare. NON assume mai in silenzio che l'unico
 *  workspace aperto sia il target giusto (es. Sibyl aperto come workspace con
 *  il repo da analizzare annidato in una sua sottocartella) — chiede sempre
 *  conferma, con "Sfoglia..." sempre disponibile per scegliere qualsiasi altra
 *  cartella, inclusa una sottocartella del workspace. */
async function pickRepo(): Promise<string | undefined> {
  const folders = vscode.workspace.workspaceFolders ?? [];
  if (folders.length === 0) {
    return browseForRepo();
  }

  const items: RepoPickItem[] = folders.map((f) => ({
    label: `$(root-folder) ${f.name}`,
    description: f.uri.fsPath,
    fsPath: f.uri.fsPath,
  }));
  items.push({
    label: '$(folder-opened) Sfoglia...',
    description: 'Scegli un\'altra cartella, anche una sottocartella del workspace',
  });

  const picked = await vscode.window.showQuickPick(items, {
    placeHolder: 'Quale repository vuoi analizzare?',
  });
  if (!picked) {
    return undefined;
  }
  return picked.fsPath ?? browseForRepo();
}

/** Aspetta che il server risponda (max ~15s). */
async function waitServerUp(url: string): Promise<boolean> {
  for (let i = 0; i < 15; i++) {
    if (await isServerUp(url)) {
      return true;
    }
    await new Promise((r) => setTimeout(r, 1000));
  }
  return false;
}

function readReport(reportPath: string): string {
  try {
    return fs.readFileSync(reportPath, 'utf8');
  } catch {
    return '_Report non trovato sul disco. Controlla l\'output "Sibyl"._';
  }
}

/** Apre la webview del report nella colonna di destra (come Pynt). */
function showReport(context: vscode.ExtensionContext, title: string, markdown: string) {
  // No script needed: the report is static, pre-rendered HTML (renderMarkdown below).
  // Scripts stay disabled so that HTML/markup surviving into the report (e.g. from the
  // model's free-text commentary, which ultimately derives from the analyzed repo's
  // source code) can never execute as JS in this webview.
  const panel = vscode.window.createWebviewPanel(
    'sibylReport',
    `Sibyl: ${title}`,
    vscode.ViewColumn.Two,
    { enableScripts: false, retainContextWhenHidden: true },
  );

  const templatePath = path.join(context.extensionPath, 'views', 'report.html');
  const template = fs.readFileSync(templatePath, 'utf8');
  const body = renderMarkdown(markdown);

  panel.webview.html = template
    .replace('__TITLE__', escapeHtml(title))
    .replace('__CONTENT__', body);
}

function escapeHtml(s: string): string {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

/**
 * Legge il file JSON gemello del report (scritto da agent/report.py:RunStats.finalize)
 * e popola il Problems panel. Non fatale: se manca o è malformato, il report resta
 * comunque visibile senza diagnostics.
 */
function applyDiagnosticsFromReport(reportPath: string, repoPath: string): void {
  const jsonPath = reportPath.replace(/\.md$/, '.json');
  try {
    const parsed = JSON.parse(fs.readFileSync(jsonPath, 'utf8'));
    applyDiagnostics(repoPath, parsed.findings || []);
  } catch {
    /* nessun JSON dei finding per questo run */
  }
}

/** Risolve `file` (relativo a repoPath, come nel SARIF di CodeQL) in un URI assoluto,
 *  verificando che resti dentro repoPath (stesso controllo di progressView.ts). */
function resolveRepoFile(repoPath: string, file: string): vscode.Uri | undefined {
  const repoRoot = path.resolve(repoPath);
  const abs = path.isAbsolute(file) ? path.resolve(file) : path.resolve(repoRoot, file);
  if (abs !== repoRoot && !abs.startsWith(repoRoot + path.sep)) {
    return undefined;
  }
  return vscode.Uri.file(abs);
}

function toDiagnosticRange(line: number): vscode.Range {
  const l = Math.max(0, line - 1);
  return new vscode.Range(l, 0, l, Number.MAX_SAFE_INTEGER); // VSCode clampa a fine riga reale
}

/** Costruisce un vscode.Diagnostic per file e li registra nella DiagnosticCollection. */
function applyDiagnostics(repoPath: string, findings: Finding[]): void {
  const byFile = new Map<string, { uri: vscode.Uri; diags: vscode.Diagnostic[] }>();

  for (const f of findings) {
    if (!f.file || !f.line) {
      continue;
    }
    const uri = resolveRepoFile(repoPath, f.file);
    if (!uri) {
      continue;
    }

    const diag = new vscode.Diagnostic(
      toDiagnosticRange(f.line),
      `${f.cwe ?? 'UNCLASSIFIED'} (${f.rule_id ?? 'unknown-rule'}): ${f.message ?? ''}`,
      SEVERITY_MAP[f.severity_bucket] ?? vscode.DiagnosticSeverity.Information,
    );
    diag.source = 'Sibyl';
    if (f.rule_id) {
      diag.code = f.rule_id;
    }

    if (f.flow_steps > 0 && f.source && (f.source.file !== f.file || f.source.line !== f.line)) {
      const srcUri = resolveRepoFile(repoPath, f.source.file);
      if (srcUri) {
        diag.relatedInformation = [
          new vscode.DiagnosticRelatedInformation(
            new vscode.Location(srcUri, toDiagnosticRange(f.source.line)),
            'Origine del dato non fidato',
          ),
        ];
      }
    }

    const key = uri.toString();
    let entry = byFile.get(key);
    if (!entry) {
      entry = { uri, diags: [] };
      byFile.set(key, entry);
    }
    entry.diags.push(diag);
  }

  for (const { uri, diags } of byFile.values()) {
    diagnostics.set(uri, diags);
  }
}
