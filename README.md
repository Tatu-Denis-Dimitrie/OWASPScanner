# OWASP Top 10 Vulnerability Scanner

A VS Code extension that scans your code in real time for security issues mapped to the [OWASP Top 10](https://owasp.org/www-project-top-ten/), combining fast static analysis with an optional LLM-based second pass for contextual triage.

## Features

- **Real-time scanning** — findings appear as you type (debounced) and on save.
- **OWASP Top 10 coverage** — 30 rules across all ten categories (A01–A10).
- **Multi-language** — JavaScript, TypeScript, JSX/TSX, Python, Java, PHP, C#, Go, YAML.
- **Problems panel integration** — findings show up as native diagnostics with severity, CWE ID, and remediation advice.
- **Quick fixes** — one-click code actions for common issues (e.g. swapping MD5/SHA1 for SHA-256), plus a link to OWASP documentation for every finding.
- **Hover details** — hovering a flagged line shows the vulnerability description and how to fix it.
- **Security Findings sidebar** — a dedicated Explorer tree view listing every finding, grouped and clickable to jump to the exact location.
- **Workspace-wide scan** — `OWASP: Scan Workspace` command scans every supported file in the project at once.
- **Optional AI triage** — when enabled with an API key, an Anthropic Claude model reviews flagged snippets to reduce false positives (opt-in, disabled by default).
- **Configurable** — choose which categories to scan, minimum severity, exclude patterns, debounce delay, and scan-on-save/scan-on-change behavior.

## How it works

The scanner uses a hybrid static-analysis pipeline:

```
Document change/save
        │
        ▼
  ScanService (debounced, cancellable)
        │
        ▼
  analyzeDocument()
        │
        ├── Regex engine   — fast pattern matching, always on
        ├── AST engine     — @typescript-eslint/parser, lazy-loaded
        └── LLM engine     — Anthropic API, opt-in only
        │
        ▼
  Findings → DiagnosticProvider / TreeView / Hover / CodeActions
```

Each OWASP category (A01–A10) is implemented as an independent rule set under [src/analyzer/rules/](src/analyzer/rules/), aggregated by [src/analyzer/rules/index.ts](src/analyzer/rules/index.ts) and run through [src/analyzer/index.ts](src/analyzer/index.ts).

## OWASP categories covered

| Code | Category |
|------|----------|
| A01 | Broken Access Control |
| A02 | Cryptographic Failures |
| A03 | Injection (SQL, command, XSS, `eval`) |
| A04 | Insecure Design |
| A05 | Security Misconfiguration |
| A06 | Vulnerable and Outdated Components |
| A07 | Identification and Authentication Failures |
| A08 | Software and Data Integrity Failures |
| A09 | Security Logging and Monitoring Failures |
| A10 | Server-Side Request Forgery (SSRF) |

## Getting started

### Prerequisites

- [Node.js](https://nodejs.org/) 18+
- [VS Code](https://code.visualstudio.com/) 1.85+

### Setup

```bash
npm install
npm run compile
```

### Run in the Extension Development Host

Open the project in VS Code and press `F5` (or run the "Launch Extension" debug configuration). This opens a new VS Code window with the extension loaded — open or edit a supported file to see live findings in the **Problems** panel and the **Security Findings** sidebar (Explorer view).

### Commands

| Command | Description |
|---------|-------------|
| `OWASP: Scan Workspace` | Scans every supported file in the workspace |
| `OWASP: Scan Current File` | Scans the active editor's document |
| `OWASP: Clear All Diagnostics` | Clears all reported findings |
| `OWASP: Show Security Report` | Opens the security findings summary |

## Configuration

All settings live under `owaspScanner.*` in your VS Code settings:

| Setting | Default | Description |
|---------|---------|-------------|
| `owaspScanner.enabledCategories` | all (`A01`–`A10`) | Which OWASP categories to scan for |
| `owaspScanner.severity.minimum` | `low` | Minimum severity level to report (`critical`, `high`, `medium`, `low`, `info`) |
| `owaspScanner.scanOnSave` | `true` | Scan a file automatically when it's saved |
| `owaspScanner.scanOnChange` | `true` | Scan automatically as you type (debounced) |
| `owaspScanner.debounceDelay` | `500` | Milliseconds to wait after the last keystroke before scanning |
| `owaspScanner.excludePatterns` | node_modules, build output, tests, vendored code, etc. | Glob patterns excluded from scanning |
| `owaspScanner.llm.enabled` | `false` | Enable LLM-based triage for deeper, contextual analysis |
| `owaspScanner.llm.apiKey` | *(empty)* | Anthropic API key, required only if `llm.enabled` is `true` |

> **Note:** the LLM pass is fully opt-in. With `llm.enabled` left at its default (`false`), no code is ever sent to any external API — all detection is done locally via regex/AST.

## Testing

```bash
npm test
```

This compiles the extension, lints it, and runs the Mocha test suite (via `@vscode/test-electron`) against the fixtures in [test/fixtures/](test/fixtures/) — including known-vulnerable and known-safe samples used to check for false positives/negatives.

## Project structure

```
src/
├── extension.ts                 # Activation: wires providers, commands, and events
├── analyzer/
│   ├── index.ts                 # analyzeDocument() — orchestrates the scan pipeline
│   ├── types.ts                 # Finding, Rule, ScanResult, OwaspCategory contracts
│   ├── engines/
│   │   ├── regex-engine.ts      # Pattern-based detection (always on)
│   │   ├── ast-engine.ts        # AST-based detection (lazy-loaded parser)
│   │   └── llm-engine.ts        # Anthropic-based triage (opt-in)
│   └── rules/
│       ├── A01-broken-access-control.ts
│       ├── A02-cryptographic-failures.ts
│       ├── A03-injection.ts
│       ├── A04-insecure-design.ts
│       ├── A05-security-misconfiguration.ts
│       ├── A06-vulnerable-components.ts
│       ├── A07-auth-failures.ts
│       ├── A08-integrity-failures.ts
│       ├── A09-logging-failures.ts
│       ├── A10-ssrf.ts
│       └── index.ts             # Aggregates and filters rules per document/config
├── providers/
│   ├── diagnostic-provider.ts   # Problems panel integration
│   ├── code-action-provider.ts  # Quick fixes
│   ├── hover-provider.ts        # Hover details
│   └── tree-view-provider.ts    # Explorer sidebar view
├── services/
│   ├── scan-service.ts          # Debouncing, cancellation, workspace scan
│   ├── config-service.ts        # Reads/watches owaspScanner.* settings
│   └── telemetry-service.ts     # Opt-in telemetry (placeholder)
└── utils/
    ├── logger.ts
    ├── range-utils.ts
    └── severity-mapper.ts
```

## Adding a new rule

1. Pick the relevant `A0X-*.ts` file under `src/analyzer/rules/` (or create one for a new category).
2. Implement the `Rule` interface from [src/analyzer/types.ts](src/analyzer/types.ts): give it an `id`, `category`, `severity`, target `languages`, and an `analyze(document, text)` function returning `Finding[]`.
3. Export it from that file's `Rule[]` array — it's picked up automatically by [src/analyzer/rules/index.ts](src/analyzer/rules/index.ts).
4. Add a fixture under `test/fixtures/vulnerable/` (should trigger) and, if relevant, `test/fixtures/safe/` (should not trigger).

## Disclaimer

This tool is intended for educational use and as a first line of defense. It does not replace a full security audit, SAST/DAST tooling, or manual code review. Findings should be triaged by a developer before being treated as confirmed vulnerabilities.
