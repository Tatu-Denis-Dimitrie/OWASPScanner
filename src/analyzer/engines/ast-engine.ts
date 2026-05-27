import * as vscode from 'vscode';
import type { Finding } from '../types';
import { log, logError } from '../../utils/logger';

// Loaded lazily — extension remains functional even if parser is absent
let tsParser: typeof import('@typescript-eslint/parser') | undefined;

async function loadParser() {
  if (!tsParser) {
    try {
      tsParser = await import('@typescript-eslint/parser');
    } catch {
      log('AST engine: @typescript-eslint/parser unavailable, regex-only mode active');
    }
  }
  return tsParser;
}

export type AstVisitor = (node: any, text: string, document: vscode.TextDocument) => Finding[];

export async function runAstVisitors(
  document: vscode.TextDocument,
  text: string,
  visitors: AstVisitor[]
): Promise<Finding[]> {
  const parser = await loadParser();
  if (!parser) { return []; }

  let ast: any;
  try {
    ast = parser.parse(text, {
      range: true,
      loc: true,
      comment: false,
      tokens: false,
      jsx: document.languageId === 'javascriptreact' || document.languageId === 'typescriptreact',
    });
  } catch (err) {
    logError(`AST parse failed for ${document.fileName}`, err);
    return [];
  }

  const findings: Finding[] = [];
  walkAst(ast, node => {
    for (const visitor of visitors) {
      findings.push(...visitor(node, text, document));
    }
  });
  return findings;
}

function walkAst(node: any, visit: (node: any) => void): void {
  if (!node || typeof node !== 'object') { return; }
  visit(node);
  for (const key of Object.keys(node)) {
    if (key === 'parent') { continue; }
    const child = node[key];
    if (Array.isArray(child)) {
      child.forEach(c => walkAst(c, visit));
    } else if (child && typeof child === 'object' && typeof child.type === 'string') {
      walkAst(child, visit);
    }
  }
}
