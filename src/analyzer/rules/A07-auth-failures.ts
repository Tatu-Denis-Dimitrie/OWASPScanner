import * as vscode from 'vscode';
import type { Rule, Finding } from '../types';
import { OwaspCategory } from '../types';
import { runRegexPatterns } from '../engines/regex-engine';

const JWT_NO_VERIFY: Rule = {
  id: 'A07-JWT-001',
  category: OwaspCategory.A07,
  title: 'JWT Signature Verification Disabled',
  description: 'JWT verification is disabled via algorithms:[] or verify:false. Tokens with forged signatures will be accepted, allowing authentication bypass.',
  remediation: 'Always verify JWT signatures. Never set algorithms to an empty array. Use a strong secret (>= 256 bits) or RS256/ES256 with proper key management.',
  severity: 'critical',
  languages: ['javascript', 'typescript'],
  analyze(document: vscode.TextDocument, text: string): Finding[] {
    return runRegexPatterns(document, text, this, [
      // jwt.verify with { algorithms: [] }
      { pattern: /jwt\.verify\s*\([^)]*algorithms\s*:\s*\[\s*\]/gi },
      // verify: false in any object context
      { pattern: /\bverify\s*:\s*false\b/gi },
      // jwt.decode without jwt.verify (simplified detection)
      { pattern: /jwt\.decode\s*\([^)]+\)(?![\s\S]{0,200}jwt\.verify)/gi },
      // ignoreExpiration: true
      { pattern: /ignoreExpiration\s*:\s*true/gi },
    ]);
  },
};

const HARDCODED_CREDENTIALS: Rule = {
  id: 'A07-CRED-001',
  category: OwaspCategory.A07,
  title: 'Hardcoded Authentication Credentials',
  description: 'Authentication credentials are hardcoded in the codebase. These are trivially discoverable and cannot be rotated without a code deployment.',
  remediation: 'Load credentials from environment variables or a secrets manager. Use a configuration library like dotenv for local development.',
  severity: 'critical',
  languages: ['javascript', 'typescript', 'python', 'java', 'php', 'go', 'csharp'],
  analyze(document: vscode.TextDocument, text: string): Finding[] {
    return runRegexPatterns(document, text, this, [
      // username/password hardcoded in object
      { pattern: /(?:username|user)\s*:\s*["'][^"']{2,}["']\s*,\s*(?:password|pwd|pass)\s*:\s*["'][^"']{2,}["']/gi },
      // Basic auth with credentials in URL — \n excluded to prevent cross-line false positives
      { pattern: /["']https?:\/\/[^:\n]+:[^@\n]{3,}@[^"'\n]+["']/gi },
      // admin:password, root:password patterns
      { pattern: /["'](?:admin|root|administrator)\s*[:/]\s*(?:admin|password|root|123456|pass)[^"']*["']/gi },
    ]);
  },
};

const EMPTY_CATCH_AUTH: Rule = {
  id: 'A07-AUTH-001',
  category: OwaspCategory.A07,
  title: 'Authentication Error Silently Swallowed',
  description: 'An authentication or authorization check is inside a try/catch block with an empty or trivial catch handler. Failed auth checks may be silently ignored, granting unintended access.',
  remediation: 'Always handle authentication errors explicitly. Log the failure and return an appropriate error response. Never allow execution to continue after a failed auth check.',
  severity: 'high',
  languages: ['javascript', 'typescript'],
  analyze(document: vscode.TextDocument, text: string): Finding[] {
    return runRegexPatterns(document, text, this, [
      // try { ...verify/authenticate... } catch (e) {}
      { pattern: /try\s*\{[^}]*(?:verify|authenticate|authorize|checkAuth)[^}]*\}\s*catch\s*\([^)]*\)\s*\{\s*\}/gi },
    ]);
  },
};

const WEAK_SESSION: Rule = {
  id: 'A07-SESSION-001',
  category: OwaspCategory.A07,
  title: 'Insecure Session Configuration',
  description: 'Session cookies are missing security flags (httpOnly, secure, sameSite). Without these flags, cookies are vulnerable to XSS theft and CSRF attacks.',
  remediation: 'Set httpOnly: true, secure: true, sameSite: "strict" on all session cookies.',
  severity: 'high',
  languages: ['javascript', 'typescript'],
  analyze(document: vscode.TextDocument, text: string): Finding[] {
    return runRegexPatterns(document, text, this, [
      // httpOnly: false
      { pattern: /httpOnly\s*:\s*false/gi },
      // secure: false
      { pattern: /secure\s*:\s*false/gi },
      // res.cookie without security options (simplified)
      { pattern: /res\.cookie\s*\(\s*["'][^"']+["']\s*,\s*[^,)]+\s*\)/gi },
    ]);
  },
};

export const authFailuresRules: Rule[] = [JWT_NO_VERIFY, HARDCODED_CREDENTIALS, EMPTY_CATCH_AUTH, WEAK_SESSION];
