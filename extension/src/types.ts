// types.ts — tipi per il telecomando della CLI di Sibyl.

export type Provider = 'ollama' | 'gemini' | 'openai';

/** Configurazione risolta a partire dai settings dell'estensione. */
export interface SibylConfig {
  /** Cartella che contiene agent/ e server/ (cwd dei sottoprocessi). */
  rootPath: string;
  /** Interprete Python da usare per `-m agent` / `-m server`. */
  pythonPath: string;
  /** Provider LLM; 'auto' = non forza nulla, usa AGENT_LLM_PROVIDER del .env. */
  provider: string;
  /** Modello LLM; stringa vuota = default del provider lato agent. */
  model: string;
  /** URL del server MCP a cui l'agent si connette (MCP_SERVER_URL). */
  mcpServerUrl: string;
  /** Se true l'estensione può avviare/fermare il server; se false si collega soltanto. */
  manageServer: boolean;
  maxSteps: number;
}

/** Opzioni per un singolo run dell'agent. */
export interface RunOptions {
  repoPath: string;
  reportPath: string;
}

/** Esito di un run dell'agent. */
export interface RunResult {
  exitCode: number;
  reportPath: string;
}
