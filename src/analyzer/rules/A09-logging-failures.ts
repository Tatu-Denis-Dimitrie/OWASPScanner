import * as vscode from 'vscode';
import type { Rule, Finding } from '../types';
import { OwaspCategory } from '../types';
import { runRegexPatterns } from '../engines/regex-engine';

const SENSITIVE_DATA_LOGGED: Rule = {
  id: 'A09-LOG-001',
  category: OwaspCategory.A09,
  title: 'Sensitive Data in Logs',
  description: 'Passwords, tokens, or credit card numbers may be logged. Logs are often stored insecurely, aggregated to third-party services, or accessible to a wider audience than intended.',
  remediation: 'Never log raw credentials or PII. Redact or mask sensitive fields before logging: log({ user: user.id }) instead of log({ user }).',
  severity: 'high',
  languages: ['javascript', 'typescript', 'python', 'java', 'php'],
  analyze(document: vscode.TextDocument, text: string): Finding[] {
    return runRegexPatterns(document, text, this, [
      // console.log with password/token variable
      { pattern: /(?:console\.log|console\.info|logger\.info|log\.info)\s*\([^)]*(?:password|passwd|token|secret|apiKey|creditCard|ssn)\b/gi },
      // Logging entire request body (may contain credentials)
      { pattern: /(?:console\.log|logger\.(?:info|debug|warn))\s*\([^)]*req\.body\b/gi },
    ]);
  },
};

const EMPTY_CATCH: Rule = {
  id: 'A09-LOG-002',
  category: OwaspCategory.A09,
  title: 'Security Event Not Logged (Empty Catch Block)',
  description: 'An exception is silently swallowed with an empty catch block. Security-relevant failures (auth errors, access denied) need to be logged for incident detection and forensics.',
  remediation: 'Always log caught exceptions, especially in authentication, authorization, and data access code.',
  severity: 'low',
  languages: ['javascript', 'typescript'],
  analyze(document: vscode.TextDocument, text: string): Finding[] {
    return runRegexPatterns(document, text, this, [
      // catch (e) {} or catch (_) {}
      { pattern: /\}\s*catch\s*\(\s*[a-zA-Z_$][a-zA-Z0-9_$]*\s*\)\s*\{\s*\}/gi },
      // catch {} (TS 2.5+)
      { pattern: /\}\s*catch\s*\{\s*\}/gi },
    ]);
  },
};

const CONSOLE_LOG_PRODUCTION: Rule = {
  id: 'A09-LOG-003',
  category: OwaspCategory.A09,
  title: 'console.log in Production Code',
  description: 'console.log statements are left in production code. These may leak sensitive data to browser DevTools or server stdout without log retention or access controls.',
  remediation: 'Replace console.log with a structured logger (winston, pino) that supports log levels and can be disabled in production.',
  severity: 'info',
  languages: ['javascript', 'typescript'],
  analyze(document: vscode.TextDocument, text: string): Finding[] {
    return runRegexPatterns(document, text, this, [
      { pattern: /\bconsole\.(?:log|debug|info)\s*\(/gi },
    ]);
  },
};

export const loggingFailuresRules: Rule[] = [SENSITIVE_DATA_LOGGED, EMPTY_CATCH, CONSOLE_LOG_PRODUCTION];
