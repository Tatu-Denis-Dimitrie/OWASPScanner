import * as vscode from 'vscode';
import type { Rule, Finding } from '../types';
import { OwaspCategory } from '../types';
import { runRegexPatterns } from '../engines/regex-engine';

const NO_RATE_LIMIT: Rule = {
  id: 'A04-RATELIMIT-001',
  category: OwaspCategory.A04,
  title: 'Missing Rate Limiting on Sensitive Endpoint',
  description: 'A login, registration, or password reset route lacks visible rate limiting middleware. Without rate limiting, these endpoints are vulnerable to brute-force and credential stuffing attacks.',
  remediation: 'Apply express-rate-limit or similar middleware to all authentication endpoints. Limit to ~5-10 attempts per 15 minutes per IP.',
  severity: 'medium',
  languages: ['javascript', 'typescript'],
  analyze(document: vscode.TextDocument, text: string): Finding[] {
    return runRegexPatterns(document, text, this, [
      // login/register routes with no rate limiter visible in the chain
      { pattern: /(?:router|app)\.post\s*\(\s*["'`][^"'`]*(?:\/login|\/signin|\/register|\/signup|\/forgot-password|\/reset-password)[^"'`]*["'`]\s*,\s*(?:async\s*)?\([^)]*req/gi },
    ]);
  },
};

const MASS_ASSIGNMENT: Rule = {
  id: 'A04-MASSASSIGN-001',
  category: OwaspCategory.A04,
  title: 'Mass Assignment Vulnerability',
  description: 'req.body is spread or passed directly to a model create/update call. An attacker can inject extra fields (e.g., isAdmin: true) that get persisted to the database.',
  remediation: 'Explicitly pick allowed fields from req.body before persisting: const { name, email } = req.body; Model.create({ name, email }). Never spread req.body into a model.',
  severity: 'high',
  languages: ['javascript', 'typescript'],
  analyze(document: vscode.TextDocument, text: string): Finding[] {
    return runRegexPatterns(document, text, this, [
      // Model.create(req.body) / Model.update(req.body)
      { pattern: /\.(?:create|update|updateOne|updateMany|save|insert)\s*\(\s*req\.body\s*[,)]/gi },
      // ...req.body spread into object literal
      { pattern: /\{[^}]*\.\.\.req\.body[^}]*\}/gi },
      // new Model(req.body)
      { pattern: /new\s+[A-Z][a-zA-Z]+\s*\(\s*req\.body\s*\)/g },
    ]);
  },
};

export const insecureDesignRules: Rule[] = [NO_RATE_LIMIT, MASS_ASSIGNMENT];
