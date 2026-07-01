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
 */
export function createProgressPanel(context: vscode.ExtensionContext, title: string): ProgressPanel {
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

  panel.webview.onDidReceiveMessage((msg) => {
    if (msg && msg.t === '__ready') {
      ready = true;
      flush();
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
