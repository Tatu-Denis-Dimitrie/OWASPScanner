import * as vscode from 'vscode';
import type { Finding } from '../analyzer/types';

export class OWASPCodeActionProvider implements vscode.CodeActionProvider {
  static readonly providedCodeActionKinds = [vscode.CodeActionKind.QuickFix];

  provideCodeActions(
    document: vscode.TextDocument,
    range: vscode.Range,
    context: vscode.CodeActionContext
  ): vscode.CodeAction[] {
    const actions: vscode.CodeAction[] = [];

    for (const diagnostic of context.diagnostics) {
      const finding: Finding | undefined = (diagnostic as any).owaspFinding;
      if (!finding) { continue; }

      const fix = this.buildFix(document, range, finding);
      if (fix) { actions.push(fix); }

      // Always offer "View OWASP documentation" action
      actions.push(this.buildDocsAction(finding));
    }

    return actions;
  }

  private buildFix(
    document: vscode.TextDocument,
    range: vscode.Range,
    finding: Finding
  ): vscode.CodeAction | undefined {
    // A02: Replace MD5/SHA1 with SHA256
    if (finding.ruleId === 'A02-CRYPTO-001') {
      const line = document.lineAt(range.start.line).text;
      if (/createHash\s*\(\s*["']md5["']/i.test(line)) {
        const action = new vscode.CodeAction('Replace MD5 with SHA-256', vscode.CodeActionKind.QuickFix);
        action.edit = new vscode.WorkspaceEdit();
        const md5Range = new vscode.Range(range.start.line, 0, range.start.line, line.length);
        action.edit.replace(document.uri, md5Range, line.replace(/createHash\s*\(\s*["']md5["']/i, "createHash('sha256'"));
        action.diagnostics = [];
        action.isPreferred = true;
        return action;
      }
      if (/createHash\s*\(\s*["']sha1["']/i.test(line)) {
        const action = new vscode.CodeAction('Replace SHA-1 with SHA-256', vscode.CodeActionKind.QuickFix);
        action.edit = new vscode.WorkspaceEdit();
        const sha1Range = new vscode.Range(range.start.line, 0, range.start.line, line.length);
        action.edit.replace(document.uri, sha1Range, line.replace(/createHash\s*\(\s*["']sha1["']/i, "createHash('sha256'"));
        action.isPreferred = true;
        return action;
      }
    }

    // A05: Replace CORS wildcard
    if (finding.ruleId === 'A05-CORS-001') {
      const line = document.lineAt(range.start.line).text;
      if (/origin\s*:\s*["']\*["']/i.test(line)) {
        const action = new vscode.CodeAction('Replace CORS wildcard with origin array', vscode.CodeActionKind.QuickFix);
        action.edit = new vscode.WorkspaceEdit();
        const lineRange = new vscode.Range(range.start.line, 0, range.start.line, line.length);
        action.edit.replace(document.uri, lineRange, line.replace(/origin\s*:\s*["']\*["']/i, "origin: ['https://your-domain.com']"));
        return action;
      }
    }

    return undefined;
  }

  private buildDocsAction(finding: Finding): vscode.CodeAction {
    const categoryCode = finding.category.substring(0, 3);
    const action = new vscode.CodeAction(
      `View OWASP ${categoryCode} documentation`,
      vscode.CodeActionKind.Empty
    );
    action.command = {
      command: 'vscode.open',
      title: 'Open OWASP Docs',
      arguments: [vscode.Uri.parse(`https://owasp.org/Top10/${categoryCode}_2021-${finding.category.replace(':', '-').replace(/\s/g, '_')}/`)],
    };
    return action;
  }
}
