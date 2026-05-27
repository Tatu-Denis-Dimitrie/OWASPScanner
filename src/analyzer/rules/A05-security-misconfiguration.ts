import * as vscode from 'vscode';
import type { Rule, Finding } from '../types';
import { OwaspCategory } from '../types';
import { runRegexPatterns } from '../engines/regex-engine';

const CORS_WILDCARD: Rule = {
  id: 'A05-CORS-001',
  category: OwaspCategory.A05,
  title: 'CORS Wildcard Origin',
  description: 'CORS is configured to allow all origins (*). This nullifies the Same-Origin Policy, allowing any website to make credentialed requests to your API.',
  remediation: 'Restrict CORS to specific trusted origins. Use an allowlist: cors({ origin: ["https://app.example.com"] }). Never use wildcard with credentials.',
  severity: 'high',
  languages: ['javascript', 'typescript'],
  analyze(document: vscode.TextDocument, text: string): Finding[] {
    return runRegexPatterns(document, text, this, [
      // cors({ origin: "*" }) or Access-Control-Allow-Origin: *
      { pattern: /(?:origin\s*:\s*["']\*["']|Access-Control-Allow-Origin['"]\s*[,:]\s*['"]\*)/gi },
      // res.header("Access-Control-Allow-Origin", "*")
      { pattern: /(?:res\.header|res\.set|response\.header)\s*\([^)]*Access-Control-Allow-Origin[^)]*\*[^)]*\)/gi },
    ]);
  },
};

const DEBUG_PRODUCTION: Rule = {
  id: 'A05-DEBUG-001',
  category: OwaspCategory.A05,
  title: 'Debug Mode / Stack Traces in Production',
  description: 'Debug mode is enabled or stack traces are exposed to clients. Detailed error information helps attackers understand the application internals.',
  remediation: 'Disable debug mode in production. Catch errors and return generic messages to clients. Log full errors server-side only.',
  severity: 'medium',
  languages: ['javascript', 'typescript', 'python', 'java', 'php'],
  analyze(document: vscode.TextDocument, text: string): Finding[] {
    return runRegexPatterns(document, text, this, [
      // DEBUG = true / debug: true
      { pattern: /\bdebug\s*[=:]\s*true\b/gi },
      // app.set('env', 'development') in non-test files
      { pattern: /app\.set\s*\(\s*["']env["']\s*,\s*["']development["']\s*\)/gi },
      // Flask debug=True
      { pattern: /app\.run\s*\([^)]*debug\s*=\s*True/gi },
      // Spring Boot management.endpoints.web.exposure.include=*
      { pattern: /management\.endpoints\.web\.exposure\.include\s*=\s*\*/gi },
    ]);
  },
};

const MISSING_HELMET: Rule = {
  id: 'A05-HEADERS-001',
  category: OwaspCategory.A05,
  title: 'Missing Security Headers (helmet not used)',
  description: 'Express application does not appear to use helmet middleware for security headers. Without these headers, the application is vulnerable to clickjacking, MIME sniffing, and other attacks.',
  remediation: 'Add helmet() middleware: app.use(helmet()). This sets X-Frame-Options, X-Content-Type-Options, HSTS, CSP, and other security headers.',
  severity: 'medium',
  languages: ['javascript', 'typescript'],
  analyze(document: vscode.TextDocument, text: string): Finding[] {
    return runRegexPatterns(document, text, this, [
      // express() used but no helmet import
      { pattern: /(?:const|let|var)\s+app\s*=\s*express\s*\(\s*\)(?![\s\S]{0,500}require\s*\(\s*["']helmet["']\))/gi },
    ]);
  },
};

const SQL_ERROR_LEAK: Rule = {
  id: 'A05-ERRLEAK-001',
  category: OwaspCategory.A05,
  title: 'Error Details Exposed to Client',
  description: 'Database errors or stack traces are sent directly to the HTTP response. This leaks internal implementation details, table names, and file paths to attackers.',
  remediation: 'Catch errors, log them server-side, and return a generic error message to the client.',
  severity: 'medium',
  languages: ['javascript', 'typescript'],
  analyze(document: vscode.TextDocument, text: string): Finding[] {
    return runRegexPatterns(document, text, this, [
      // res.send(err) / res.json(err) / res.status(...).send(err)
      { pattern: /res\.(?:send|json)\s*\(\s*(?:err|error|e)\s*\)/gi },
      { pattern: /res\.status\s*\([^)]+\)\.(?:send|json)\s*\(\s*(?:err|error|e)\s*\)/gi },
    ]);
  },
};

export const securityMisconfigurationRules: Rule[] = [CORS_WILDCARD, DEBUG_PRODUCTION, MISSING_HELMET, SQL_ERROR_LEAK];
