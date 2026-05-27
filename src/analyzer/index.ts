import * as vscode from 'vscode';
import type { Finding, ScanResult } from './types';
import { getRulesForDocument } from './rules/index';
import { refineWithLlm } from './engines/llm-engine';
import { getConfig } from '../services/config-service';
import { meetsMinimumSeverity } from '../utils/severity-mapper';
import { log, logError } from '../utils/logger';

export async function analyzeDocument(document: vscode.TextDocument): Promise<ScanResult> {
  const start = Date.now();
  const config = getConfig();
  const text = document.getText();
  const rules = getRulesForDocument(document.languageId, config.enabledCategories);

  let findings: Finding[] = [];

  for (const rule of rules) {
    try {
      const ruleFindings = rule.analyze(document, text);
      findings.push(...ruleFindings);
    } catch (err) {
      logError(`Rule ${rule.id} threw an error`, err);
    }
  }

  // Filter by minimum severity before LLM call to save tokens
  findings = findings.filter(f => meetsMinimumSeverity(f.severity, config.minimumSeverity));

  if (config.llmEnabled && config.llmApiKey && findings.length > 0) {
    try {
      const { refinedFindings } = await refineWithLlm(document, text, findings, config.llmApiKey);
      findings = refinedFindings;
    } catch (err) {
      logError('LLM refinement failed, using raw findings', err);
    }
  }

  const durationMs = Date.now() - start;
  log(`Scanned ${document.fileName}: ${findings.length} findings in ${durationMs}ms`);

  return {
    uri: document.uri,
    findings,
    scannedAt: new Date(),
    durationMs,
  };
}
