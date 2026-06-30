// envConfig.ts — lettura/scrittura del .env di Sibyl e form (webview) di configurazione.
import * as fs from 'fs';
import * as path from 'path';

export type FieldKind = 'text' | 'secret' | 'pathFile' | 'pathFolder';

export interface EnvField {
  key: string;
  label: string;
  group: string;
  kind: FieldKind;
  hint?: string;
}

/** Campi CodeQL (server), obbligatori per l'analisi. */
const CODEQL_FIELDS: EnvField[] = [
  { key: 'CODEQL_BIN', label: 'Binario CodeQL', group: 'CodeQL (server)', kind: 'pathFile', hint: 'Eseguibile codeql (vuoto = cerca su PATH).' },
  { key: 'CODEQL_SEARCH_PATH', label: 'Search path (cartella ql/)', group: 'CodeQL (server)', kind: 'pathFolder', hint: 'Cartella ql del checkout vscode-codeql-starter.' },
  { key: 'CODEQL_SUITE', label: 'Suite di sicurezza (.qls)', group: 'CodeQL (server)', kind: 'pathFile', hint: 'File .qls (es. python-security-extended.qls).' },
  { key: 'CUSTOM_QUERY_DIR', label: 'Cartella query custom', group: 'CodeQL (server)', kind: 'pathFolder', hint: 'Cartella con le query custom *Broad.ql.' },
];

/** Campi LLM in modalità Locale (Ollama). */
const LLM_LOCAL_FIELDS: EnvField[] = [
  { key: 'AGENT_MODEL', label: 'Modello Ollama', group: 'LLM', kind: 'text', hint: 'Es. qwen2.5-coder:14b.' },
  { key: 'OLLAMA_HOST', label: 'Ollama host', group: 'LLM', kind: 'text', hint: 'Default http://localhost:11434.' },
];

/** Campi LLM in modalità Remoto (API OpenAI-compatibile: OpenAI/Groq/Cerebras/...). */
const LLM_REMOTE_FIELDS: EnvField[] = [
  { key: 'OPENAI_BASE_URL', label: 'Base URL', group: 'LLM', kind: 'text', hint: 'Es. https://api.cerebras.ai/v1 (Groq/Cerebras/OpenAI).' },
  { key: 'OPENAI_MODEL', label: 'Modello', group: 'LLM', kind: 'text', hint: 'Modello del provider remoto.' },
  { key: 'OPENAI_API_KEY', label: 'API key', group: 'LLM', kind: 'secret' },
];

export function envFilePath(rootPath: string): string {
  return path.join(rootPath, '.env');
}

function stripQuotes(v: string): string {
  const t = v.trim();
  if ((t.startsWith('"') && t.endsWith('"')) || (t.startsWith("'") && t.endsWith("'"))) {
    return t.slice(1, -1);
  }
  return t;
}

/** Legge i valori correnti del .env (ignora commenti). */
export function readEnvValues(rootPath: string): Record<string, string> {
  const file = envFilePath(rootPath);
  const out: Record<string, string> = {};
  if (!fs.existsSync(file)) {
    return out;
  }
  for (const line of fs.readFileSync(file, 'utf8').split(/\r?\n/)) {
    if (line.trimStart().startsWith('#')) {
      continue;
    }
    const m = line.match(/^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$/);
    if (m) {
      out[m[1]] = stripQuotes(m[2]);
    }
  }
  return out;
}

/**
 * Aggiorna il .env con i valori passati, preservando commenti e righe non gestite.
 * Le chiavi esistenti vengono sostituite sul posto; le nuove (non vuote) accodate.
 */
export function writeEnvValues(rootPath: string, updates: Record<string, string>): void {
  const file = envFilePath(rootPath);
  const lines = fs.existsSync(file) ? fs.readFileSync(file, 'utf8').split(/\r?\n/) : [];
  const pending = new Set(Object.keys(updates));

  const result = lines.map((line) => {
    if (line.trimStart().startsWith('#')) {
      return line;
    }
    const m = line.match(/^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=/);
    if (m && pending.has(m[1])) {
      const k = m[1];
      pending.delete(k);
      return `${k}=${updates[k]}`;
    }
    return line;
  });

  for (const k of pending) {
    if (updates[k] !== '') {
      result.push(`${k}=${updates[k]}`);
    }
  }

  fs.writeFileSync(file, result.join('\n'), 'utf8');
}

function escapeAttr(s: string): string {
  return s.replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

function escapeHtml(s: string): string {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

function renderField(f: EnvField, value: string): string {
  const v = escapeAttr(value);
  const hint = f.hint ? `<div class="hint">${escapeHtml(f.hint)}</div>` : '';

  if (f.kind === 'pathFile' || f.kind === 'pathFolder') {
    const folder = f.kind === 'pathFolder' ? 'true' : 'false';
    return `<div class="field">
      <label>${escapeHtml(f.label)}</label>
      <div class="row">
        <input type="text" data-key="${f.key}" value="${v}" />
        <button type="button" onclick="pick('${f.key}', ${folder})">Sfoglia…</button>
      </div>
      ${hint}
    </div>`;
  }

  const type = f.kind === 'secret' ? 'password' : 'text';
  return `<div class="field">
    <label>${escapeHtml(f.label)}</label>
    <input type="${type}" data-key="${f.key}" value="${v}" />
    ${hint}
  </div>`;
}

/** Genera l'HTML del form di configurazione, precompilato con i valori del .env. */
export function renderConfigHtml(values: Record<string, string>, envPath: string): string {
  const codeql = CODEQL_FIELDS.map((f) => renderField(f, values[f.key] ?? '')).join('');
  const localFields = LLM_LOCAL_FIELDS.map((f) => renderField(f, values[f.key] ?? '')).join('');
  const remoteFields = LLM_REMOTE_FIELDS.map((f) => renderField(f, values[f.key] ?? '')).join('');

  // Provider del .env → modalità del form: ollama = Locale, openai/gemini = Remoto.
  const provider = values['AGENT_LLM_PROVIDER'] || '';
  const mode = provider === 'openai' || provider === 'gemini' ? 'remote' : 'local';
  const checked = (m: string) => (mode === m ? ' checked' : '');

  return `<!DOCTYPE html>
<html lang="it">
<head>
<meta charset="UTF-8">
<style>
  body { font-family: var(--vscode-font-family); color: var(--vscode-editor-foreground);
         background: var(--vscode-editor-background); padding: 20px; line-height: 1.5; }
  .container { max-width: 720px; margin: 0 auto; }
  h1 { font-size: 1.4em; }
  h2 { font-size: 1.1em; border-bottom: 1px solid var(--vscode-panel-border);
       padding-bottom: 4px; margin-top: 28px; }
  .field { margin: 14px 0; }
  label { display: block; font-weight: bold; margin-bottom: 4px; }
  input, select { width: 100%; box-sizing: border-box; padding: 6px 8px;
    background: var(--vscode-input-background); color: var(--vscode-input-foreground);
    border: 1px solid var(--vscode-input-border, var(--vscode-panel-border)); border-radius: 4px; }
  input[type=radio] { width: auto; }
  label.radio { display: inline-flex; align-items: center; gap: 6px; font-weight: normal; margin-right: 20px; }
  .row { display: flex; gap: 8px; }
  .row input { flex: 1; }
  button { background: var(--vscode-button-background); color: var(--vscode-button-foreground);
    border: none; padding: 6px 14px; border-radius: 4px; cursor: pointer; }
  button:hover { background: var(--vscode-button-hoverBackground); }
  .hint { font-size: 0.85em; opacity: 0.7; margin-top: 3px; }
  .actions { margin-top: 26px; display: flex; align-items: center; gap: 12px; }
  #status { opacity: 0.8; }
  .path { font-size: 0.85em; opacity: 0.6; word-break: break-all; }
</style>
</head>
<body>
  <div class="container">
    <h1>🛡️ Configurazione Sibyl</h1>
    <div class="path">File: ${escapeHtml(envPath)}</div>

    <h2>CodeQL (server)</h2>
    ${codeql}

    <h2>LLM (agente)</h2>
    <div class="field">
      <label>Provider LLM</label>
      <label class="radio"><input type="radio" name="llmmode" value="local"${checked('local')} onchange="toggleMode()"> Locale (Ollama)</label>
      <label class="radio"><input type="radio" name="llmmode" value="remote"${checked('remote')} onchange="toggleMode()"> Remoto (OpenAI-compatibile)</label>
    </div>
    <div id="local-fields">${localFields}</div>
    <div id="remote-fields">${remoteFields}</div>

    <div class="actions">
      <button type="button" onclick="save()">Salva nel .env</button>
      <span id="status"></span>
    </div>
  </div>
  <script>
    const vscode = acquireVsCodeApi();
    function pick(key, folder) { vscode.postMessage({ command: 'pick', key, folder }); }
    function currentMode() {
      const r = document.querySelector('input[name=llmmode]:checked');
      return r ? r.value : 'local';
    }
    function toggleMode() {
      const m = currentMode();
      document.getElementById('local-fields').style.display = m === 'local' ? 'block' : 'none';
      document.getElementById('remote-fields').style.display = m === 'remote' ? 'block' : 'none';
    }
    function save() {
      const values = {};
      document.querySelectorAll('[data-key]').forEach((el) => {
        values[el.getAttribute('data-key')] = el.value;
      });
      values['AGENT_LLM_PROVIDER'] = currentMode() === 'local' ? 'ollama' : 'openai';
      vscode.postMessage({ command: 'save', values });
    }
    window.addEventListener('message', (e) => {
      const m = e.data;
      if (m.command === 'setValue') {
        const el = document.querySelector('[data-key="' + m.key + '"]');
        if (el) { el.value = m.value; }
      } else if (m.command === 'status') {
        document.getElementById('status').textContent = m.text;
      }
    });
    toggleMode();
  </script>
</body>
</html>`;
}
