import * as vscode from 'vscode';
import { DiagnosticProvider } from './providers/diagnostic-provider';
import { OWASPCodeActionProvider } from './providers/code-action-provider';
import { OWASPHoverProvider } from './providers/hover-provider';
import { VulnerabilityTreeProvider } from './providers/tree-view-provider';
import { ScanService } from './services/scan-service';
import { getConfig, onConfigChange } from './services/config-service';
import { log, disposeLogger } from './utils/logger';
import type { ScanResult } from './analyzer/types';

export function activate(context: vscode.ExtensionContext): void {
  log('OWASP Scanner activating');

  const diagnosticProvider = new DiagnosticProvider();
  const treeProvider = new VulnerabilityTreeProvider();

  const scanService = new ScanService((result: ScanResult) => {
    diagnosticProvider.update(result.uri, result.findings);
    treeProvider.update(result.uri, result.findings);
  });

  // Register tree view
  const treeView = vscode.window.createTreeView('owaspScanner.vulnerabilityTree', {
    treeDataProvider: treeProvider,
    showCollapseAll: true,
  });

  // Register language feature providers
  const DOCUMENT_SELECTOR: vscode.DocumentSelector = [
    { scheme: 'file', language: 'javascript' },
    { scheme: 'file', language: 'typescript' },
    { scheme: 'file', language: 'javascriptreact' },
    { scheme: 'file', language: 'typescriptreact' },
    { scheme: 'file', language: 'python' },
    { scheme: 'file', language: 'java' },
    { scheme: 'file', language: 'php' },
    { scheme: 'file', language: 'csharp' },
    { scheme: 'file', language: 'go' },
    { scheme: 'file', language: 'yaml' },
  ];

  const codeActionProvider = vscode.languages.registerCodeActionsProvider(
    DOCUMENT_SELECTOR,
    new OWASPCodeActionProvider(),
    { providedCodeActionKinds: OWASPCodeActionProvider.providedCodeActionKinds }
  );

  const hoverProvider = vscode.languages.registerHoverProvider(
    DOCUMENT_SELECTOR,
    new OWASPHoverProvider()
  );

  // Commands
  const scanFileCmd = vscode.commands.registerCommand('owaspScanner.scanFile', () => {
    const editor = vscode.window.activeTextEditor;
    if (editor) {
      scanService.runScan(editor.document);
    }
  });

  const scanWorkspaceCmd = vscode.commands.registerCommand('owaspScanner.scanWorkspace', async () => {
    await vscode.window.withProgress(
      { location: vscode.ProgressLocation.Notification, title: 'OWASP Scanner: Scanning workspace...', cancellable: false },
      () => scanService.scanWorkspace()
    );
  });

  const clearCmd = vscode.commands.registerCommand('owaspScanner.clearDiagnostics', () => {
    diagnosticProvider.clear();
    treeProvider.clear();
  });

  const revealFindingCmd = vscode.commands.registerCommand(
    'owaspScanner.revealFinding',
    (uri: vscode.Uri, finding: import('./analyzer/types').Finding) => {
      vscode.window.showTextDocument(uri, {
        selection: new vscode.Range(
          new vscode.Position(finding.range.start.line, finding.range.start.character),
          new vscode.Position(finding.range.end.line, finding.range.end.character)
        ),
      });
    }
  );

  // Event listeners
  const config = getConfig();

  const onSave = vscode.workspace.onDidSaveTextDocument(doc => {
    if (getConfig().scanOnSave) {
      scanService.runScan(doc);
    }
  });

  const onChange = vscode.workspace.onDidChangeTextDocument(event => {
    if (getConfig().scanOnChange) {
      scanService.scheduleScan(event.document);
    }
  });

  const onClose = vscode.workspace.onDidCloseTextDocument(doc => {
    scanService.cancelScan(doc.uri);
  });

  const onCfgChange = onConfigChange(_cfg => {
    log('Configuration changed, re-scanning active document');
    if (vscode.window.activeTextEditor) {
      scanService.runScan(vscode.window.activeTextEditor.document);
    }
  });

  // Scan the active document on startup
  if (vscode.window.activeTextEditor && config.scanOnChange) {
    scanService.runScan(vscode.window.activeTextEditor.document);
  }

  context.subscriptions.push(
    diagnosticProvider,
    treeView,
    codeActionProvider,
    hoverProvider,
    scanFileCmd,
    scanWorkspaceCmd,
    clearCmd,
    revealFindingCmd,
    onSave,
    onChange,
    onClose,
    onCfgChange,
    scanService,
    { dispose: disposeLogger },
  );

  log('OWASP Scanner activated');
}

export function deactivate(): void {
  log('OWASP Scanner deactivated');
}
