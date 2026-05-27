import * as vscode from 'vscode';
import type { Rule, Finding } from '../types';
import { OwaspCategory } from '../types';
import { runRegexPatterns } from '../engines/regex-engine';

const SSRF_FETCH: Rule = {
  id: 'A10-SSRF-001',
  category: OwaspCategory.A10,
  title: 'Server-Side Request Forgery (SSRF) — fetch/axios',
  description: 'A URL constructed from request parameters is passed directly to fetch() or axios. An attacker can redirect the server to make requests to internal infrastructure, cloud metadata services, or other sensitive endpoints.',
  remediation: 'Validate and whitelist allowed URL schemes and domains before making server-side HTTP requests. Use an allowlist approach: only permit specific known-good URLs/hostnames.',
  severity: 'high',
  languages: ['javascript', 'typescript'],
  analyze(document: vscode.TextDocument, text: string): Finding[] {
    return runRegexPatterns(document, text, this, [
      // fetch(req.query.url) / fetch(req.body.url)
      { pattern: /(?:fetch|axios\.get|axios\.post|axios\.request)\s*\(\s*(?:req\.(?:query|body|params)|request\.(?:query|body|params))\b/gi },
      // fetch with template literal containing req
      { pattern: /(?:fetch|axios\.get|axios\.post)\s*\(\s*`[^`]*\$\{(?:req|request)\./gi },
      // http.get(userUrl) / https.get(userUrl)
      { pattern: /(?:http|https)\.(?:get|request)\s*\(\s*(?:req\.(?:query|body|params)|request\.(?:query|body|params))\b/gi },
      // new URL(req.query.url) piped to fetch
      { pattern: /new\s+URL\s*\(\s*(?:req\.(?:query|body|params)|request\.(?:query|body|params))\b/gi },
    ]);
  },
};

const SSRF_REDIRECT: Rule = {
  id: 'A10-SSRF-002',
  category: OwaspCategory.A10,
  title: 'Open Redirect / SSRF via res.redirect()',
  description: 'User-supplied input is passed directly to res.redirect(). An attacker can redirect users to malicious external sites or cause the server to make unintended requests.',
  remediation: 'Validate redirect targets against an allowlist of permitted domains/paths. Use relative redirects where possible. Never redirect to URLs derived from unvalidated user input.',
  severity: 'medium',
  languages: ['javascript', 'typescript'],
  analyze(document: vscode.TextDocument, text: string): Finding[] {
    return runRegexPatterns(document, text, this, [
      { pattern: /res\.redirect\s*\(\s*(?:req\.(?:query|body|params)|request\.(?:query|body|params))\b/gi },
      { pattern: /res\.redirect\s*\(\s*`[^`]*\$\{(?:req|request)\./gi },
    ]);
  },
};

export const ssrfRules: Rule[] = [SSRF_FETCH, SSRF_REDIRECT];
