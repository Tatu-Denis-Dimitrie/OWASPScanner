import * as assert from 'assert';
import { injectionRules } from '../../../src/analyzer/rules/A03-injection';
import * as vscode from 'vscode';

function makeDoc(content: string, languageId = 'javascript'): vscode.TextDocument {
  return {
    getText: () => content,
    languageId,
    uri: vscode.Uri.parse('file:///test.js'),
    lineCount: content.split('\n').length,
    lineAt: (line: number) => ({ text: content.split('\n')[line] } as any),
  } as any;
}

suite('A03 Injection Rules', () => {
  const sqlRule = injectionRules.find(r => r.id === 'A03-SQL-001')!;
  const cmdRule = injectionRules.find(r => r.id === 'A03-CMD-001')!;
  const xssRule = injectionRules.find(r => r.id === 'A03-XSS-001')!;
  const evalRule = injectionRules.find(r => r.id === 'A03-EVAL-001')!;

  suite('SQL Injection', () => {
    test('Detects string concatenation in query', () => {
      const doc = makeDoc(`db.query("SELECT * FROM users WHERE id = " + userId);`);
      const findings = sqlRule.analyze(doc, doc.getText());
      assert.ok(findings.length > 0, 'Should flag SQL string concatenation');
    });

    test('Detects template literal in query', () => {
      const doc = makeDoc('db.query(`SELECT * FROM users WHERE id = ${userId}`);');
      const findings = sqlRule.analyze(doc, doc.getText());
      assert.ok(findings.length > 0, 'Should flag SQL template literal');
    });

    test('No false positive on safe parameterized query', () => {
      const doc = makeDoc(`db.query("SELECT * FROM users WHERE id = ?", [userId]);`);
      const findings = sqlRule.analyze(doc, doc.getText());
      assert.strictEqual(findings.length, 0, 'Should not flag parameterized query');
    });
  });

  suite('Command Injection', () => {
    test('Detects exec with concatenation', () => {
      const doc = makeDoc(`exec("ls " + userInput);`);
      const findings = cmdRule.analyze(doc, doc.getText());
      assert.ok(findings.length > 0, 'Should flag exec with concatenation');
    });

    test('Detects exec with template literal', () => {
      const doc = makeDoc('exec(`git clone ${repoUrl}`);');
      const findings = cmdRule.analyze(doc, doc.getText());
      assert.ok(findings.length > 0, 'Should flag exec with template literal');
    });
  });

  suite('XSS', () => {
    test('Detects innerHTML assignment', () => {
      const doc = makeDoc(`element.innerHTML = userInput;`);
      const findings = xssRule.analyze(doc, doc.getText());
      assert.ok(findings.length > 0, 'Should flag innerHTML assignment');
    });

    test('No false positive on static innerHTML', () => {
      const doc = makeDoc(`element.innerHTML = '<span>static content</span>';`);
      const findings = xssRule.analyze(doc, doc.getText());
      assert.strictEqual(findings.length, 0, 'Should not flag static innerHTML');
    });
  });

  suite('eval()', () => {
    test('Detects eval with variable', () => {
      const doc = makeDoc(`eval(userCode);`);
      const findings = evalRule.analyze(doc, doc.getText());
      assert.ok(findings.length > 0, 'Should flag eval with variable');
    });
  });
});
