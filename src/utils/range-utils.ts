import * as vscode from 'vscode';
import type { Range, Position } from '../analyzer/types';

export function toVscodeRange(range: Range): vscode.Range {
  return new vscode.Range(
    new vscode.Position(range.start.line, range.start.character),
    new vscode.Position(range.end.line, range.end.character)
  );
}

export function fromVscodeRange(range: vscode.Range): Range {
  return {
    start: { line: range.start.line, character: range.start.character },
    end: { line: range.end.line, character: range.end.character },
  };
}

export function offsetToPosition(text: string, offset: number): Position {
  const before = text.substring(0, offset);
  const lines = before.split('\n');
  return {
    line: lines.length - 1,
    character: lines[lines.length - 1].length,
  };
}

export function regexMatchToRange(
  text: string,
  match: RegExpExecArray,
  groupIndex = 0
): Range {
  const groupOffset = groupIndex > 0 ? match[0].indexOf(match[groupIndex]) : 0;
  const startOffset = match.index + groupOffset;
  const length = groupIndex > 0 ? match[groupIndex].length : match[0].length;
  return {
    start: offsetToPosition(text, startOffset),
    end: offsetToPosition(text, startOffset + length),
  };
}
