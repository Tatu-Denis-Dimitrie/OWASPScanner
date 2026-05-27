import * as vscode from 'vscode';
import type { Finding } from '../analyzer/types';

export class OWASPHoverProvider implements vscode.HoverProvider {
  provideHover(
    document: vscode.TextDocument,
    position: vscode.Position,
    _token: vscode.CancellationToken
  ): vscode.Hover | undefined {
    // Find a diagnostic at this position that has an OWASP finding attached
    const diagnostics = vscode.languages
      .getDiagnostics(document.uri)
      .filter(d => d.range.contains(position));

    const finding: Finding | undefined = diagnostics
      .map(d => (d as any).owaspFinding as Finding | undefined)
      .find(Boolean);

    if (!finding) { return undefined; }

    const md = new vscode.MarkdownString(undefined, true);
    md.isTrusted = true;

    md.appendMarkdown(`### $(shield) ${finding.title}\n\n`);
    md.appendMarkdown(`**Category:** ${finding.category}  \n`);
    md.appendMarkdown(`**Severity:** \`${finding.severity.toUpperCase()}\`  \n`);
    md.appendMarkdown(`**Confidence:** \`${finding.confidence}\`  \n\n`);
    md.appendMarkdown(`**Description:**  \n${finding.description}\n\n`);
    md.appendMarkdown(`**Remediation:**  \n${finding.remediation}\n\n`);

    if (finding.cweId) {
      md.appendMarkdown(`[CWE-${finding.cweId}](https://cwe.mitre.org/data/definitions/${finding.cweId}.html)  `);
    }
    md.appendMarkdown(`[OWASP ${finding.category.substring(0, 3)}](https://owasp.org/Top10/)  `);

    return new vscode.Hover(md);
  }
}
