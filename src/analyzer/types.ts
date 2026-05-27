import * as vscode from 'vscode';

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type Confidence = 'high' | 'medium' | 'low';

export enum OwaspCategory {
  A01 = 'A01:Broken Access Control',
  A02 = 'A02:Cryptographic Failures',
  A03 = 'A03:Injection',
  A04 = 'A04:Insecure Design',
  A05 = 'A05:Security Misconfiguration',
  A06 = 'A06:Vulnerable and Outdated Components',
  A07 = 'A07:Identification and Authentication Failures',
  A08 = 'A08:Software and Data Integrity Failures',
  A09 = 'A09:Security Logging and Monitoring Failures',
  A10 = 'A10:Server-Side Request Forgery',
}

export interface Position {
  line: number;
  character: number;
}

export interface Range {
  start: Position;
  end: Position;
}

export interface Finding {
  id: string;
  category: OwaspCategory;
  title: string;
  description: string;
  remediation: string;
  severity: Severity;
  range: Range;
  ruleId: string;
  confidence: Confidence;
  cweId?: string;
  references?: string[];
}

export interface Rule {
  id: string;
  category: OwaspCategory;
  title: string;
  description: string;
  remediation: string;
  severity: Severity;
  languages: string[];
  analyze(document: vscode.TextDocument, text: string): Finding[];
}

export interface ScanResult {
  uri: vscode.Uri;
  findings: Finding[];
  scannedAt: Date;
  durationMs: number;
}
