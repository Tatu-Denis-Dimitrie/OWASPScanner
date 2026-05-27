import * as vscode from 'vscode';
import { analyzeDocument } from '../analyzer/index';
import type { ScanResult } from '../analyzer/types';
import { logError } from '../utils/logger';
import { minimatch } from 'minimatch';
import { getConfig } from './config-service';

const SUPPORTED_LANGUAGES = new Set([
  'javascript', 'typescript', 'javascriptreact', 'typescriptreact',
  'python', 'java', 'php', 'csharp', 'go', 'yaml',
]);

export class ScanService {
  private timers = new Map<string, NodeJS.Timeout>();
  private cancelTokenSources = new Map<string, vscode.CancellationTokenSource>();
  private onResult: (result: ScanResult) => void;

  constructor(onResult: (result: ScanResult) => void) {
    this.onResult = onResult;
  }

  scheduleScan(document: vscode.TextDocument): void {
    if (!this.shouldScan(document)) { return; }

    const key = document.uri.toString();
    const config = getConfig();

    // Cancel any pending scan for this document
    clearTimeout(this.timers.get(key));
    this.cancelTokenSources.get(key)?.cancel();
5
    const timer = setTimeout(() => {
      this.runScan(document);
    }, config.debounceDelay);

    this.timers.set(key, timer);
  }

  async runScan(document: vscode.TextDocument): Promise<void> {
    if (!this.shouldScan(document)) { return; }

    const key = document.uri.toString();
    const cts = new vscode.CancellationTokenSource();
    this.cancelTokenSources.set(key, cts);

    try {
      const result = await analyzeDocument(document);
      if (!cts.token.isCancellationRequested) {
        this.onResult(result);
      }
    } catch (err) {
      logError(`Scan failed for ${document.fileName}`, err);
    } finally {
      this.cancelTokenSources.delete(key);
    }
  }

  async scanWorkspace(): Promise<void> {
    const config = getConfig();
    const files = await vscode.workspace.findFiles(
      '**/*.{js,ts,jsx,tsx,py,java,php,cs,go,yaml,yml}',
      `{${config.excludePatterns.join(',')}}`
    );

    for (const fileUri of files) {
      try {
        const doc = await vscode.workspace.openTextDocument(fileUri);
        await this.runScan(doc);
      } catch (err) {
        logError(`Failed to open ${fileUri.fsPath}`, err);
      }
    }
  }

  cancelScan(uri: vscode.Uri): void {
    const key = uri.toString();
    clearTimeout(this.timers.get(key));
    this.cancelTokenSources.get(key)?.cancel();
    this.timers.delete(key);
    this.cancelTokenSources.delete(key);
  }

  dispose(): void {
    for (const timer of this.timers.values()) { clearTimeout(timer); }
    for (const cts of this.cancelTokenSources.values()) { cts.cancel(); }
    this.timers.clear();
    this.cancelTokenSources.clear();
  }

  private shouldScan(document: vscode.TextDocument): boolean {
    if (document.uri.scheme !== 'file') { return false; }
    if (!SUPPORTED_LANGUAGES.has(document.languageId)) { return false; }

    const config = getConfig();
    const relativePath = vscode.workspace.asRelativePath(document.uri);
    return !config.excludePatterns.some(pattern => minimatch(relativePath, pattern, { nocase: true }));
  }
}
