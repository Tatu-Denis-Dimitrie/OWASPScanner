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
const vscode = __importStar(require("vscode"));
const path = __importStar(require("path"));
const index_1 = require("../../src/analyzer/index");
const FIXTURES_DIR = path.resolve(__dirname, '../../test/fixtures');
async function openFixture(relativePath) {
    const uri = vscode.Uri.file(path.join(FIXTURES_DIR, relativePath));
    return vscode.workspace.openTextDocument(uri);
}
suite('Analyzer', () => {
    test('Finds SQL injection in vulnerable fixture', async () => {
        const doc = await openFixture('vulnerable/sql-injection.js');
        const result = await (0, index_1.analyzeDocument)(doc);
        const sqlFindings = result.findings.filter(f => f.ruleId.startsWith('A03-SQL'));
        assert.ok(sqlFindings.length > 0, `Expected SQL injection findings, got ${sqlFindings.length}`);
    });
    test('No false positives in safe fixture', async () => {
        const doc = await openFixture('safe/clean-code.js');
        const result = await (0, index_1.analyzeDocument)(doc);
        const highSeverity = result.findings.filter(f => f.severity === 'critical' || f.severity === 'high');
        assert.strictEqual(highSeverity.length, 0, `Expected 0 high/critical findings in safe fixture, got ${highSeverity.length}`);
    });
    test('Finds hardcoded secrets', async () => {
        const doc = await openFixture('vulnerable/hardcoded-secrets.js');
        const result = await (0, index_1.analyzeDocument)(doc);
        const secretFindings = result.findings.filter(f => f.ruleId === 'A02-SECRET-001');
        assert.ok(secretFindings.length > 0, 'Expected hardcoded secret findings');
    });
});
//# sourceMappingURL=analyzer.test.js.map