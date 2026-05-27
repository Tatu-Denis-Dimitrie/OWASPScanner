import * as assert from 'assert';
import * as vscode from 'vscode';
import * as path from 'path';
import { analyzeDocument } from '../../src/analyzer/index';

const FIXTURES_DIR = path.resolve(__dirname, '../../test/fixtures');

async function openFixture(relativePath: string): Promise<vscode.TextDocument> {
  const uri = vscode.Uri.file(path.join(FIXTURES_DIR, relativePath));
  return vscode.workspace.openTextDocument(uri);
}

suite('Analyzer', () => {
  test('Finds SQL injection in vulnerable fixture', async () => {
    const doc = await openFixture('vulnerable/sql-injection.js');
    const result = await analyzeDocument(doc);
    const sqlFindings = result.findings.filter(f => f.ruleId.startsWith('A03-SQL'));
    assert.ok(sqlFindings.length > 0, `Expected SQL injection findings, got ${sqlFindings.length}`);
  });

  test('No false positives in safe fixture', async () => {
    const doc = await openFixture('safe/clean-code.js');
    const result = await analyzeDocument(doc);
    const highSeverity = result.findings.filter(f => f.severity === 'critical' || f.severity === 'high');
    assert.strictEqual(highSeverity.length, 0, `Expected 0 high/critical findings in safe fixture, got ${highSeverity.length}`);
  });

  test('Finds hardcoded secrets', async () => {
    const doc = await openFixture('vulnerable/hardcoded-secrets.js');
    const result = await analyzeDocument(doc);
    const secretFindings = result.findings.filter(f => f.ruleId === 'A02-SECRET-001');
    assert.ok(secretFindings.length > 0, 'Expected hardcoded secret findings');
  });
});
