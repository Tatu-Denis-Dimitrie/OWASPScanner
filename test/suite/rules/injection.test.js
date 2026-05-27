"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
const assert = __importStar(require("assert"));
const A03_injection_1 = require("../../../src/analyzer/rules/A03-injection");
const vscode = __importStar(require("vscode"));
function makeDoc(content, languageId = 'javascript') {
    return {
        getText: () => content,
        languageId,
        uri: vscode.Uri.parse('file:///test.js'),
        lineCount: content.split('\n').length,
        lineAt: (line) => ({ text: content.split('\n')[line] }),
    };
}
suite('A03 Injection Rules', () => {
    const sqlRule = A03_injection_1.injectionRules.find(r => r.id === 'A03-SQL-001');
    const cmdRule = A03_injection_1.injectionRules.find(r => r.id === 'A03-CMD-001');
    const xssRule = A03_injection_1.injectionRules.find(r => r.id === 'A03-XSS-001');
    const evalRule = A03_injection_1.injectionRules.find(r => r.id === 'A03-EVAL-001');
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
//# sourceMappingURL=injection.test.js.map