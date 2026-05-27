import * as vscode from 'vscode';
import type { Finding, Rule } from '../types';
import { offsetToPosition } from '../../utils/range-utils';

export interface RegexPattern {
  pattern: RegExp;
  messageFactory?: (match: RegExpExecArray) => Partial<Finding>;
}

// Returns true if the offset falls inside a line comment (//) or block comment. Heuristic only.
function isInComment(text: string, offset: number): boolean {
  const lineStart = text.lastIndexOf('\n', offset - 1) + 1;
  const linePrefix = text.substring(lineStart, offset);

  // Whole-line comment (possibly indented): // ...
  if (/^\s*\/\//.test(linePrefix)) { return true; }

  // Inline comment: code // comment — match is after the //
  const slashIdx = linePrefix.indexOf('//');
  if (slashIdx !== -1) {
    const before = linePrefix.substring(0, slashIdx);
    // Only treat // as a comment if it's outside string literals
    const singles = (before.match(/'/g) ?? []).length;
    const doubles = (before.match(/"/g) ?? []).length;
    if (singles % 2 === 0 && doubles % 2 === 0) { return true; }
  }

  // Block comment: /* ... */
  const textBefore = text.substring(0, offset);
  const lastOpen = textBefore.lastIndexOf('/*');
  const lastClose = textBefore.lastIndexOf('*/');
  return lastOpen !== -1 && lastClose < lastOpen;
}

export function runRegexPatterns(
  _document: vscode.TextDocument,
  text: string,
  rule: Omit<Rule, 'analyze'>,
  patterns: RegexPattern[]
): Finding[] {
  const findings: Finding[] = [];
  let counter = 0;

  for (const { pattern, messageFactory } of patterns) {
    const flags = pattern.flags.includes('g') ? pattern.flags : pattern.flags + 'g';
    const re = new RegExp(pattern.source, flags);
    let match: RegExpExecArray | null;

    while ((match = re.exec(text)) !== null) {
      // Skip matches that are inside comments
      if (isInComment(text, match.index)) {
        if (match[0].length === 0) { re.lastIndex++; }
        continue;
      }

      const start = offsetToPosition(text, match.index);
      const end = offsetToPosition(text, match.index + match[0].length);
      const overrides = messageFactory ? messageFactory(match) : {};

      findings.push({
        id: `${rule.id}-${++counter}`,
        category: rule.category,
        title: rule.title,
        description: rule.description,
        remediation: rule.remediation,
        severity: rule.severity,
        confidence: 'medium',
        ruleId: rule.id,
        range: { start, end },
        ...overrides,
      });

      if (match[0].length === 0) { re.lastIndex++; }
    }
  }

  return findings;
}
