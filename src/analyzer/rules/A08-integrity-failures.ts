import * as vscode from 'vscode';
import type { Rule, Finding } from '../types';
import { OwaspCategory } from '../types';
import { runRegexPatterns } from '../engines/regex-engine';

const UNSAFE_DESERIALIZATION: Rule = {
  id: 'A08-DESER-001',
  category: OwaspCategory.A08,
  title: 'Unsafe Deserialization',
  description: 'User-supplied data is deserialized without schema validation. An attacker may craft malicious payloads that execute code or corrupt application state during deserialization.',
  remediation: 'Validate deserialized data against a strict schema (e.g., Zod, Joi, JSON Schema) before use. Avoid deserializing data from untrusted sources using formats that support arbitrary object types (pickle, Java serialization).',
  severity: 'high',
  languages: ['javascript', 'typescript', 'python', 'java'],
  analyze(document: vscode.TextDocument, text: string): Finding[] {
    return runRegexPatterns(document, text, this, [
      // JSON.parse(req.body) without validation
      { pattern: /JSON\.parse\s*\(\s*(?:req\.body|req\.query|req\.params)\b/gi },
      // Python pickle.loads with request data
      { pattern: /pickle\.loads\s*\(\s*(?:request\.|req\.)/gi },
      // Java ObjectInputStream — often used for deserialization
      { pattern: /new\s+ObjectInputStream\s*\(/gi },
      // YAML.load (unsafe) — yaml.safeLoad is fine
      { pattern: /(?:yaml|YAML)\.load\s*\(\s*(?!.*safeLoa)[^)]+\)/gi },
    ]);
  },
};

const CI_CD_INLINE_SCRIPT: Rule = {
  id: 'A08-CICD-001',
  category: OwaspCategory.A08,
  title: 'Inline Script Injection in CI/CD Pipeline',
  description: 'A GitHub Actions or CI workflow uses ${{ github.event.* }} directly inside a run: shell command. An attacker with PR access can inject arbitrary commands via the event payload.',
  remediation: 'Assign the untrusted value to an environment variable first, then reference that variable in the shell: env: VAL: ${{ github.event.head_commit.message }}, then use $VAL in the run block.',
  severity: 'critical',
  languages: ['yaml'],
  analyze(document: vscode.TextDocument, text: string): Finding[] {
    return runRegexPatterns(document, text, this, [
      // run: ... ${{ github.event. ... }} pattern in YAML
      { pattern: /run\s*:\s*[|>]?[^\n]*\$\{\{\s*github\.event\./gi },
    ]);
  },
};

export const integrityFailuresRules: Rule[] = [UNSAFE_DESERIALIZATION, CI_CD_INLINE_SCRIPT];
