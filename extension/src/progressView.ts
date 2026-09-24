// progressView.ts — webview grafica che mostra l'avanzamento dell'agent in tempo reale.
import * as vscode from 'vscode';
import * as fs from 'fs';
import * as path from 'path';

/** Handle sul pannello di avanzamento: gli si inviano gli eventi dell'agent. */
export interface ProgressPanel {
  /** Inoltra un evento (parsed) alla webview; bufferizza finché la webview è pronta. */
  update(evt: any): void;
  /** Riporta in primo piano il pannello. */
  reveal(): void;
  /** Chiude il pannello. */
  dispose(): void;
}

/**
 * Crea il pannello grafico di avanzamento (colonna a destra) caricando
 * views/progress.html. Gli eventi inviati prima che lo script della webview sia
 * pronto vengono messi in coda e riprodotti al primo messaggio "__ready".
 *
 * @param repoPath radice del repo analizzato: serve a risolvere in path assoluto i
 *   file (relativi a --source-root) che compaiono negli eventi "finding", quando
 *   l'utente clicca un hop del path per aprirlo nell'editor.
 */
export function createProgressPanel(
  context: vscode.ExtensionContext, title: string, repoPath: string,
): ProgressPanel {
  const panel = vscode.window.createWebviewPanel(
    'sibylProgress',
    `Sibyl: ${title}`,
    { viewColumn: vscode.ViewColumn.Two, preserveFocus: true },
    { enableScripts: true, retainContextWhenHidden: true },
  );

  const templatePath = path.join(context.extensionPath, 'views', 'progress.html');
  panel.webview.html = fs.readFileSync(templatePath, 'utf8');

  let alive = true;
  let ready = false;
  const queue: any[] = [];

  const flush = () => {
    while (queue.length) {
      panel.webview.postMessage(queue.shift());
    }
  };

  panel.webview.onDidReceiveMessage(async (msg) => {
    if (msg && msg.t === '__ready') {
      ready = true;
      flush();
      return;
    }
    // Click su un hop del path di un finding: apre il file alla riga indicata.
    // `file` arriva relativo a --source-root (il repo analizzato) dal SARIF di
    // CodeQL, quindi non e' testo libero del modello — ma per coerenza con gli
    // stessi controlli aggiunti lato server (contenimento, non solo join) si
    // verifica comunque che il path risolto resti dentro repoPath.
    if (msg && msg.t === '__open' && typeof msg.file === 'string') {
      try {
        const repoRoot = path.resolve(repoPath);
        const abs = path.isAbsolute(msg.file)
          ? path.resolve(msg.file)
          : path.resolve(repoRoot, msg.file);
        if (abs !== repoRoot && !abs.startsWith(repoRoot + path.sep)) {
          vscode.window.showWarningMessage(`Sibyl: percorso fuori dalla repo analizzata: ${msg.file}`);
          return;
        }
        const doc = await vscode.workspace.openTextDocument(abs);
        const editor = await vscode.window.showTextDocument(doc, vscode.ViewColumn.One);
        const line = Math.max(0, (Number(msg.line) || 1) - 1);
        const range = editor.document.lineAt(Math.min(line, editor.document.lineCount - 1)).range;
        editor.selection = new vscode.Selection(range.start, range.start);
        editor.revealRange(range, vscode.TextEditorRevealType.InCenter);
      } catch {
        vscode.window.showWarningMessage(`Sibyl: impossibile aprire ${msg.file}:${msg.line}`);
      }
    }
  }, undefined, context.subscriptions);

  panel.onDidDispose(() => { alive = false; }, undefined, context.subscriptions);

  return {
    update(evt: any) {
      if (!alive) {
        return;
      }
      if (ready) {
        panel.webview.postMessage(evt);
      } else {
        queue.push(evt);   // la webview non ha ancora agganciato il listener
      }
    },
    reveal() {
      if (alive) {
        panel.reveal(vscode.ViewColumn.Two, true);
      }
    },
    dispose() {
      if (alive) {
        panel.dispose();
      }
    },
  };
}
