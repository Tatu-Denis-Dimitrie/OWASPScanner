import * as vscode from 'vscode';
import type { Finding } from '../analyzer/types';
import { toVscodeRange } from '../utils/range-utils';
import { toVscodeSeverity } from '../utils/severity-mapper';

const DIAGNOSTIC_SOURCE = 'OWASP Scanner';

export class DiagnosticProvider {
  private collection: vscode.DiagnosticCollection;

  constructor() {
    this.collection = vscode.languages.createDiagnosticCollection('owaspScanner');
  }

  update(uri: vscode.Uri, findings: Finding[]): void {
    const diagnostics = findings.map(f => this.findingToDiagnostic(f));
    this.collection.set(uri, diagnostics);
  }

  clear(uri?: vscode.Uri): void {
    if (uri) {
      this.collection.delete(uri);
    } else {
      this.collection.clear();
    }
  }

  dispose(): void {
    this.collection.dispose();
  }

  private findingToDiagnostic(finding: Finding): vscode.Diagnostic {
    const range = toVscodeRange(finding.range);
    const diagnostic = new vscode.Diagnostic(
      range,
      `[${finding.category}] ${finding.title}`,
      toVscodeSeverity(finding.severity)
    );
    diagnostic.source = DIAGNOSTIC_SOURCE;
    diagnostic.code = {
      value: finding.ruleId,
      target: vscode.Uri.parse(`https://owasp.org/Top10/`),
    };
    // Embed full finding data for use by CodeAction/Hover providers
    (diagnostic as any).owaspFinding = finding;
    return diagnostic;
  }
}
