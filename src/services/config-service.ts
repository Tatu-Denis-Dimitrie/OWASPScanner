import * as vscode from 'vscode';
import type { Severity } from '../analyzer/types';

const SECTION = 'owaspScanner';

export interface ScannerConfig {
  enabledCategories: string[];
  minimumSeverity: Severity;
  llmEnabled: boolean;
  llmApiKey: string;
  scanOnSave: boolean;
  scanOnChange: boolean;
  excludePatterns: string[];
  debounceDelay: number;
}

export function getConfig(): ScannerConfig {
  const cfg = vscode.workspace.getConfiguration(SECTION);
  return {
    enabledCategories: cfg.get<string[]>('enabledCategories', ['A01','A02','A03','A04','A05','A06','A07','A08','A09','A10']),
    minimumSeverity: cfg.get<Severity>('severity.minimum', 'low'),
    llmEnabled: cfg.get<boolean>('llm.enabled', false),
    llmApiKey: cfg.get<string>('llm.apiKey', ''),
    scanOnSave: cfg.get<boolean>('scanOnSave', true),
    scanOnChange: cfg.get<boolean>('scanOnChange', true),
    excludePatterns: cfg.get<string[]>('excludePatterns', [
      '**/node_modules/**',
      '**/dist/**',
      '**/build/**',
      '**/out/**',
      '**/.git/**',
      '**/.github/**',
      '**/.vscode/**',
      '**/.venv/**',
      '**/venv/**',
      '**/env/**',
      '**/.env/**',
      '**/.claude/**',
      '**/.idea/**',
      '**/__pycache__/**',
      '**/*.pyc',
      '**/coverage/**',
      '**/.nyc_output/**',
      '**/vendor/**',
      '**/target/**',
      '**/.cache/**',
      '**/.next/**',
      '**/.nuxt/**',
      '**/tmp/**',
      '**/temp/**',
      '**/.angular/**',
      '**/test/**',
      '**/tests/**',
      '**/__tests__/**',
      '**/e2e/**',
      '**/*.test.ts',
      '**/*.test.js',
      '**/*.spec.ts',
      '**/*.spec.js',
      '**/*.Tests/**',
      '**/*.Test/**',
      '**/*.UnitTests/**',
      '**/*.IntegrationTests/**',
      '**/*.Specs/**',
      '**/*.min.js',
      '**/*.min.css',
      '**/*.bundle.js',
      '**/*.chunk.js',
      '**/*.compiled.js',
      '**/*.map',
      '**/bundle/**',
      '**/bundles/**',
      '**/seeders/**',
      '**/seeds/**',
      '**/seed/**',
      '**/*seeder*',
      '**/*Seeder*',
      '**/*.razor',
      '**/wwwroot/**',
    ]),
    debounceDelay: cfg.get<number>('debounceDelay', 500),
  };
}

export function onConfigChange(callback: (config: ScannerConfig) => void): vscode.Disposable {
  return vscode.workspace.onDidChangeConfiguration(event => {
    if (event.affectsConfiguration(SECTION)) {
      callback(getConfig());
    }
  });
}
