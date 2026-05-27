import * as vscode from 'vscode';
import type { Severity } from '../analyzer/types';

export function toVscodeSeverity(severity: Severity): vscode.DiagnosticSeverity {
  switch (severity) {
    case 'critical':
    case 'high':
      return vscode.DiagnosticSeverity.Error;
    case 'medium':
      return vscode.DiagnosticSeverity.Warning;
    case 'low':
      return vscode.DiagnosticSeverity.Information;
    case 'info':
      return vscode.DiagnosticSeverity.Hint;
  }
}

const SEVERITY_ORDER: Record<Severity, number> = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  info: 1,
};

export function severityOrder(severity: Severity): number {
  return SEVERITY_ORDER[severity];
}

export function meetsMinimumSeverity(severity: Severity, minimum: Severity): boolean {
  return severityOrder(severity) >= severityOrder(minimum);
}
