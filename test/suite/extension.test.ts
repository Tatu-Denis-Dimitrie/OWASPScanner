import * as assert from 'assert';
import * as vscode from 'vscode';

suite('Extension Activation', () => {
  test('Extension is registered', () => {
    const ext = vscode.extensions.getExtension('owasp-scanner.owasp-scanner');
    assert.ok(ext, 'Extension should be present');
  });

  test('Commands are registered', async () => {
    const commands = await vscode.commands.getCommands(true);
    assert.ok(commands.includes('owaspScanner.scanFile'), 'scanFile command missing');
    assert.ok(commands.includes('owaspScanner.scanWorkspace'), 'scanWorkspace command missing');
    assert.ok(commands.includes('owaspScanner.clearDiagnostics'), 'clearDiagnostics command missing');
  });
});
