import * as vscode from 'vscode';
import type { Rule, Finding } from '../types';
import { OwaspCategory } from '../types';
import { runRegexPatterns } from '../engines/regex-engine';

const IDOR: Rule = {
  id: 'A01-IDOR-001',
  category: OwaspCategory.A01,
  title: 'Potential Insecure Direct Object Reference (IDOR)',
  description: 'A database lookup uses a user-supplied ID directly without an ownership check. An attacker may enumerate IDs to access other users\' data.',
  remediation: 'Always verify the authenticated user owns the requested resource. Add a WHERE clause filtering by userId: findById(id, { where: { userId: currentUser.id } })',
  severity: 'high',
  languages: ['javascript', 'typescript'],
  analyze(document: vscode.TextDocument, text: string): Finding[] {
    return runRegexPatterns(document, text, this, [
      // findById(req.params.id) without ownership filter
      { pattern: /\.findById\s*\(\s*(?:req\.params|req\.query|req\.body)\.[a-zA-Z_]+\s*\)/gi },
      // findOne({ id: req.params.id }) without user filter
      { pattern: /\.findOne\s*\(\s*\{\s*(?:id|_id)\s*:\s*(?:req\.params|req\.query|req\.body)/gi },
    ]);
  },
};

const PATH_TRAVERSAL: Rule = {
  id: 'A01-PATH-001',
  category: OwaspCategory.A01,
  title: 'Path Traversal',
  description: 'A file path is constructed from user input without sanitization. An attacker can use ../ sequences to read or write files outside the intended directory.',
  remediation: 'Use path.resolve() and verify the result starts with the expected base directory. Never concatenate user input into file paths without normalization.',
  severity: 'high',
  languages: ['javascript', 'typescript', 'python', 'php'],
  analyze(document: vscode.TextDocument, text: string): Finding[] {
    return runRegexPatterns(document, text, this, [
      // Node.js: fs.readFile(req.params.file)
      { pattern: /fs\.(?:readFile|readFileSync|writeFile|writeFileSync|unlink|stat)\s*\(\s*(?:req\.(?:params|query|body)|request\.(?:params|query|body))\b/gi },
      // Node.js: path.join/resolve with req input
      { pattern: /path\.(?:join|resolve)\s*\([^)]*(?:req\.(?:params|query|body)|request\.(?:params|query|body))[^)]*\)/gi },
      // Python (Flask/Django): open() with request.args / request.form / request.json
      { pattern: /\bopen\s*\(\s*(?:request\.(?:args|form|json|data)\.get\s*\(|request\.(?:args|form|json)\[)/gi },
      // Python: os.path.join / Path() with request input
      { pattern: /(?:os\.path\.join|Path)\s*\([^)]*request\.(?:args|form|json|GET|POST|params)/gi },
      // PHP: file_get_contents / include / require with $_GET, $_POST, $_REQUEST
      { pattern: /(?:file_get_contents|file|readfile|include|require|include_once|require_once)\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)\s*\[/gi },
      // PHP: fopen with user-controlled variable
      { pattern: /fopen\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)\s*\[/gi },
    ]);
  },
};

const MISSING_AUTH_MIDDLEWARE: Rule = {
  id: 'A01-AUTH-001',
  category: OwaspCategory.A01,
  title: 'Route Defined Without Authentication Middleware',
  description: 'An Express route handler is defined with no authentication middleware visible on the same line or in the route chain. Sensitive routes may be publicly accessible.',
  remediation: 'Add authentication middleware to all protected routes: router.get("/admin/...", authenticate, authorize("admin"), handler). Apply globally with app.use(authenticate) where appropriate.',
  severity: 'medium',
  languages: ['javascript', 'typescript'],
  analyze(document: vscode.TextDocument, text: string): Finding[] {
    return runRegexPatterns(document, text, this, [
      // router.get("/admin/...", directHandlerWithNoMiddleware)
      { pattern: /(?:router|app)\.(?:get|post|put|patch|delete)\s*\(\s*["'`][^"'`]*(?:admin|dashboard|settings|config|users\/\d)[^"'`]*["'`]\s*,\s*(?:async\s*)?\([^)]*req/gi },
    ]);
  },
};

export const brokenAccessControlRules: Rule[] = [IDOR, PATH_TRAVERSAL, MISSING_AUTH_MIDDLEWARE];
