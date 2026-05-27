import type { Rule } from '../types';
import { brokenAccessControlRules } from './A01-broken-access-control';
import { cryptographicFailuresRules } from './A02-cryptographic-failures';
import { injectionRules } from './A03-injection';
import { insecureDesignRules } from './A04-insecure-design';
import { securityMisconfigurationRules } from './A05-security-misconfiguration';
import { vulnerableComponentsRules } from './A06-vulnerable-components';
import { authFailuresRules } from './A07-auth-failures';
import { integrityFailuresRules } from './A08-integrity-failures';
import { loggingFailuresRules } from './A09-logging-failures';
import { ssrfRules } from './A10-ssrf';

const ALL_RULES: Rule[] = [
  ...brokenAccessControlRules,
  ...cryptographicFailuresRules,
  ...injectionRules,
  ...insecureDesignRules,
  ...securityMisconfigurationRules,
  ...vulnerableComponentsRules,
  ...authFailuresRules,
  ...integrityFailuresRules,
  ...loggingFailuresRules,
  ...ssrfRules,
];

/** Returns rules matching the given language ID and enabled OWASP categories */
export function getRulesForDocument(languageId: string, enabledCategories: string[]): Rule[] {
  return ALL_RULES.filter(rule => {
    const categoryCode = rule.category.substring(0, 3); // e.g. "A03"
    return (
      enabledCategories.includes(categoryCode) &&
      (rule.languages.includes(languageId) || rule.languages.includes('*'))
    );
  });
}

export { ALL_RULES };
