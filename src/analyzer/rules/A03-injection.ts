import * as vscode from 'vscode';
import type { Rule, Finding } from '../types';
import { OwaspCategory } from '../types';
import { runRegexPatterns } from '../engines/regex-engine';

const SQL_INJECTION: Rule = {
  id: 'A03-SQL-001',
  category: OwaspCategory.A03,
  title: 'SQL Injection',
  description: 'User-controlled data is concatenated directly into a SQL query string. An attacker can modify the query structure to bypass authentication, exfiltrate data, or destroy records.',
  remediation: 'Use parameterized queries or prepared statements. Never build SQL by string concatenation. Example: db.query("SELECT * FROM users WHERE id = ?", [userId])',
  severity: 'critical',
  languages: ['javascript', 'typescript', 'python', 'java', 'php'],
  analyze(document: vscode.TextDocument, text: string): Finding[] {
    return runRegexPatterns(document, text, this, [
      // "SELECT ... " + variable
      { pattern: /["'`][^"'`]*(?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE)\b[^"'`]*["'`]\s*\+/gi },
      // db.query( "..." + / template literal with ${
      { pattern: /\.(?:query|execute|exec|prepare|raw)\s*\(\s*`[^`]*\$\{/gi },
      // db.query("..." + variable
      { pattern: /\.(?:query|execute|exec)\s*\(\s*["'][^"']*["']\s*\+/gi },
      // knex.raw / sequelize.query with template literal
      { pattern: /(?:knex\.raw|sequelize\.query|connection\.query)\s*\(\s*`[^`]*\$\{/gi },
    ]);
  },
};

const CMD_INJECTION: Rule = {
  id: 'A03-CMD-001',
  category: OwaspCategory.A03,
  title: 'Command Injection',
  description: 'User-controlled data is passed to a shell command. An attacker can inject arbitrary OS commands.',
  remediation: 'Avoid shell execution with user input. Use execFile() with an argument array instead of exec() with a string. Validate and whitelist input strictly.',
  severity: 'critical',
  languages: ['javascript', 'typescript', 'python', 'java', 'php'],
  analyze(document: vscode.TextDocument, text: string): Finding[] {
    return runRegexPatterns(document, text, this, [
      // exec("..." + var) or exec(`... ${var}`)
      { pattern: /(?:child_process\.)?exec\s*\(\s*(?:`[^`]*\$\{|["'][^"']*["']\s*\+)/gi },
      // execSync with template literal or concatenation
      { pattern: /execSync\s*\(\s*(?:`[^`]*\$\{|["'][^"']*["']\s*\+)/gi },
      // Python: os.system, subprocess.call with format/concat
      { pattern: /os\.(?:system|popen)\s*\(\s*(?:f["']|["'][^"']*["']\s*%|["'][^"']*["']\s*\.format)/gi },
      // PHP: shell_exec, system, passthru, exec
      { pattern: /(?:shell_exec|system|passthru|exec)\s*\(\s*\$/gi },
    ]);
  },
};

const XSS: Rule = {
  id: 'A03-XSS-001',
  category: OwaspCategory.A03,
  title: 'Cross-Site Scripting (XSS)',
  description: 'Unsanitized data is written to the DOM via innerHTML, document.write, or similar sinks. An attacker can inject malicious scripts executed in the victim\'s browser.',
  remediation: 'Use textContent instead of innerHTML. Sanitize HTML with DOMPurify before insertion. Avoid document.write entirely.',
  severity: 'high',
  languages: ['javascript', 'typescript'],
  analyze(document: vscode.TextDocument, text: string): Finding[] {
    return runRegexPatterns(document, text, this, [
      // element.innerHTML = variable (not a string literal)
      { pattern: /\.innerHTML\s*=\s*(?!["'`][^"'`]*["'`]\s*;)[^;,\n]+/gi },
      // document.write(variable)
      { pattern: /document\.write(?:ln)?\s*\(\s*(?!\s*["'`])[^)]+\)/gi },
      // $(...).html(variable) — jQuery
      { pattern: /\$\([^)]+\)\.html\s*\(\s*(?!\s*["'`])[^)]+\)/gi },
      // dangerouslySetInnerHTML={{ __html: variable }}
      { pattern: /dangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html\s*:/gi },
    ]);
  },
};

const EVAL_INJECTION: Rule = {
  id: 'A03-EVAL-001',
  category: OwaspCategory.A03,
  title: 'Code Injection via eval()',
  description: 'eval() or Function() constructor is called with dynamic content. An attacker controlling the input can execute arbitrary JavaScript.',
  remediation: 'Remove eval() entirely. Use JSON.parse() for data parsing, or refactor to avoid dynamic code execution.',
  severity: 'critical',
  languages: ['javascript', 'typescript'],
  analyze(document: vscode.TextDocument, text: string): Finding[] {
    return runRegexPatterns(document, text, this, [
      // eval(variable) — not eval("literal")
      { pattern: /\beval\s*\(\s*(?!["'`][^"'`]*["'`]\s*\))[^)]+\)/gi },
      // new Function(variable)
      { pattern: /new\s+Function\s*\([^)]*[^"'`\s)][^)]*\)/gi },
      // setTimeout/setInterval with string argument
      { pattern: /(?:setTimeout|setInterval)\s*\(\s*["'`]/gi },
    ]);
  },
};

export const injectionRules: Rule[] = [SQL_INJECTION, CMD_INJECTION, XSS, EVAL_INJECTION];
