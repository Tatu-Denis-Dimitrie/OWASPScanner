import * as vscode from 'vscode';

let outputChannel: vscode.OutputChannel | undefined;

export function getLogger(): vscode.OutputChannel {
  if (!outputChannel) {
    outputChannel = vscode.window.createOutputChannel('OWASP Scanner');
  }
  return outputChannel;
}

export function log(message: string): void {
  getLogger().appendLine(`[${new Date().toISOString()}] ${message}`);
}

export function logError(message: string, error?: unknown): void {
  const suffix = error instanceof Error ? `: ${error.message}` : '';
  getLogger().appendLine(`[${new Date().toISOString()}] ERROR ${message}${suffix}`);
}

export function disposeLogger(): void {
  outputChannel?.dispose();
  outputChannel = undefined;
}
