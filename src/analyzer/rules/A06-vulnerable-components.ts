import * as vscode from 'vscode';
import type { Rule, Finding } from '../types';
import { OwaspCategory } from '../types';
import { runRegexPatterns } from '../engines/regex-engine';

// NOTE: Deep vulnerability scanning (CVE lookups) requires runtime package resolution.
// These rules detect static patterns indicating known-bad usage of specific packages.

const KNOWN_VULNERABLE_USAGE: Rule = {
  id: 'A06-VULN-001',
  category: OwaspCategory.A06,
  title: 'Known Vulnerable Package Usage Pattern',
  description: 'Usage of a package or API known to have security issues in common configurations.',
  remediation: 'Check the package\'s security advisories (npm audit, Snyk, GitHub Advisory Database) and upgrade to a patched version.',
  severity: 'medium',
  languages: ['javascript', 'typescript'],
  analyze(document: vscode.TextDocument, text: string): Finding[] {
    return runRegexPatterns(document, text, this, [
      // serialize-javascript: known XSS in older versions
      { pattern: /require\s*\(\s*["']serialize-javascript["']\s*\)/gi },
      // node-serialize: known RCE vulnerability
      { pattern: /require\s*\(\s*["']node-serialize["']\s*\)/gi },
      // lodash merge with user input — prototype pollution risk
      { pattern: /(?:_|lodash)\.merge\s*\([^)]*(?:req\.body|req\.query|req\.params)[^)]*\)/gi },
      // eval-like packages
      { pattern: /require\s*\(\s*["'](?:vm2|node-eval|safe-eval)["']\s*\)/gi },
    ]);
  },
};

const PROTOTYPE_POLLUTION: Rule = {
  id: 'A06-PROTO-001',
  category: OwaspCategory.A06,
  title: 'Potential Prototype Pollution',
  description: 'Object.assign or spread with untrusted user input can pollute Object.prototype if keys like __proto__ or constructor are not filtered.',
  remediation: 'Use a safe merge library or filter dangerous keys before merging user input. Consider using Object.create(null) for data objects.',
  severity: 'high',
  languages: ['javascript', 'typescript'],
  analyze(document: vscode.TextDocument, text: string): Finding[] {
    return runRegexPatterns(document, text, this, [
      // Object.assign({}, req.body) / Object.assign(target, req.body)
      { pattern: /Object\.assign\s*\([^)]*(?:req\.body|req\.query|req\.params)[^)]*\)/gi },
      // JSON.parse without schema validation piped to merge
      { pattern: /JSON\.parse\s*\([^)]*\)\s*(?:;|\n|\/\/[^\n]*)?\s*(?:Object\.assign|_\.merge|merge)\s*\(/gi },
    ]);
  },
};

export const vulnerableComponentsRules: Rule[] = [KNOWN_VULNERABLE_USAGE, PROTOTYPE_POLLUTION];
