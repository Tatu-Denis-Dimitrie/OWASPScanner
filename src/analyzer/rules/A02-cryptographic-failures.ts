import * as vscode from 'vscode';
import type { Rule, Finding } from '../types';
import { OwaspCategory } from '../types';
import { runRegexPatterns } from '../engines/regex-engine';

const HARDCODED_SECRETS: Rule = {
  id: 'A02-SECRET-001',
  category: OwaspCategory.A02,
  title: 'Hardcoded Secret / Credential',
  description: 'A secret, password, or API key appears to be hardcoded in source code. Credentials in source control are exposed to anyone with repository access and leak into build artifacts.',
  remediation: 'Store secrets in environment variables or a secret manager (AWS Secrets Manager, HashiCorp Vault, Azure Key Vault). Access via process.env.SECRET_NAME.',
  severity: 'critical',
  languages: ['javascript', 'typescript', 'python', 'java', 'php', 'go', 'csharp'],
  analyze(document: vscode.TextDocument, text: string): Finding[] {
    return runRegexPatterns(document, text, this, [
      // password = "..."
      { pattern: /(?:password|passwd|pwd|secret|api_?key|auth_?token|access_?token|private_?key)\s*[=:]\s*["'][^"']{4,}["']/gi },
      // AWS access key pattern
      { pattern: /(?:AKIA|ASIA|AROA)[A-Z0-9]{16}/g },
      // Generic high-entropy secret assignment (base64-like long strings)
      { pattern: /(?:secret|token|key)\s*[=:]\s*["'][A-Za-z0-9+/]{32,}={0,2}["']/gi },
      // Connection strings with embedded credentials — \n excluded to prevent cross-line false positives
      { pattern: /(?:mongodb|mysql|postgres|redis|amqp):\/\/[^:\n]+:[^@\n]{3,}@/gi },
    ]);
  },
};

const WEAK_CRYPTO: Rule = {
  id: 'A02-CRYPTO-001',
  category: OwaspCategory.A02,
  title: 'Weak Cryptographic Algorithm',
  description: 'A broken or weak cryptographic algorithm (MD5, SHA-1, DES, RC4, ECB mode) is used. These algorithms are cryptographically broken and unsuitable for security purposes.',
  remediation: 'Use SHA-256 or SHA-3 for hashing. Use AES-256-GCM for symmetric encryption. Never use MD5 or SHA-1 for security purposes.',
  severity: 'high',
  languages: ['javascript', 'typescript', 'python', 'java', 'php', 'go', 'csharp'],
  analyze(document: vscode.TextDocument, text: string): Finding[] {
    return runRegexPatterns(document, text, this, [
      // createHash('md5') / createHash('sha1')
      { pattern: /createHash\s*\(\s*["'](?:md5|sha1|sha-1|des|rc4)["']/gi },
      // Python hashlib.md5, hashlib.sha1
      { pattern: /hashlib\.(?:md5|sha1)\s*\(/gi },
      // Java MessageDigest.getInstance("MD5")
      { pattern: /MessageDigest\.getInstance\s*\(\s*["'](?:MD5|SHA-1|SHA1)["']/gi },
      // PHP md5(), sha1()
      { pattern: /\b(?:md5|sha1)\s*\(/gi },
      // ECB mode
      { pattern: /["']AES\/ECB|Cipher\.getInstance\s*\(\s*["']AES["']/gi },
    ]);
  },
};

const HTTP_SENSITIVE: Rule = {
  id: 'A02-HTTP-001',
  category: OwaspCategory.A02,
  title: 'Sensitive Data Over Unencrypted HTTP',
  description: 'An HTTP (not HTTPS) URL is used for what appears to be an API or authentication endpoint. Data transmitted over plain HTTP is visible to network observers.',
  remediation: 'Use HTTPS for all external communications. Enforce HSTS. Redirect HTTP to HTTPS.',
  severity: 'medium',
  languages: ['javascript', 'typescript', 'python', 'java', 'php', 'go', 'csharp'],
  analyze(document: vscode.TextDocument, text: string): Finding[] {
    return runRegexPatterns(document, text, this, [
      // http:// URL assigned to variable or in fetch/axios call (exclude localhost)
      { pattern: /["']http:\/\/(?!localhost|127\.0\.0\.1|0\.0\.0\.0)[a-z0-9.-]+[^"']*(?:login|auth|api|token|password|secret)[^"']*["']/gi },
    ]);
  },
};

const WEAK_RANDOM: Rule = {
  id: 'A02-RAND-001',
  category: OwaspCategory.A02,
  title: 'Weak Random Number Generator',
  description: 'Math.random() is used in a security-sensitive context (token generation, UUID, session ID). Math.random() is not cryptographically secure.',
  remediation: 'Use crypto.randomBytes() or crypto.randomUUID() for security tokens. Use crypto.getRandomValues() in the browser.',
  severity: 'high',
  languages: ['javascript', 'typescript'],
  analyze(document: vscode.TextDocument, text: string): Finding[] {
    return runRegexPatterns(document, text, this, [
      // Math.random() assigned to token/session/id variable
      { pattern: /(?:token|session|secret|id|key|nonce|salt)\s*[=:][^=\n]*Math\.random\s*\(\s*\)/gi },
      // Math.random() used directly in string template for auth
      { pattern: /Math\.random\s*\(\s*\)\.toString\s*\([^)]*\)\.slice/gi },
    ]);
  },
};

export const cryptographicFailuresRules: Rule[] = [HARDCODED_SECRETS, WEAK_CRYPTO, HTTP_SENSITIVE, WEAK_RANDOM];
