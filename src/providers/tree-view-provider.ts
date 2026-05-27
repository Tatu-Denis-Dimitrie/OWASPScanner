import * as vscode from 'vscode';
import type { Finding } from '../analyzer/types';
import { toVscodeSeverity } from '../utils/severity-mapper';

type TreeItem = CategoryItem | FindingItem;

class CategoryItem extends vscode.TreeItem {
  constructor(
    public readonly categoryLabel: string,
    public readonly findings: FindingItem[]
  ) {
    super(categoryLabel, vscode.TreeItemCollapsibleState.Expanded);
    this.description = `${findings.length} finding${findings.length !== 1 ? 's' : ''}`;
    this.iconPath = new vscode.ThemeIcon('shield');
    this.contextValue = 'owaspCategory';
  }
}

class FindingItem extends vscode.TreeItem {
  constructor(
    public readonly finding: Finding,
    public readonly documentUri: vscode.Uri
  ) {
    super(finding.title, vscode.TreeItemCollapsibleState.None);
    this.description = `${finding.severity} · ${finding.confidence} confidence`;
    this.tooltip = finding.description;
    this.iconPath = new vscode.ThemeIcon(
      toVscodeSeverity(finding.severity) <= 1 ? 'error' : 'warning'
    );
    this.command = {
      command: 'owaspScanner.revealFinding',
      title: 'Go to Finding',
      arguments: [documentUri, finding],
    };
    this.contextValue = 'owaspFinding';
  }
}

export class VulnerabilityTreeProvider implements vscode.TreeDataProvider<TreeItem> {
  private _onDidChangeTreeData = new vscode.EventEmitter<TreeItem | undefined | null | void>();
  readonly onDidChangeTreeData = this._onDidChangeTreeData.event;

  // uri.toString() → findings
  private findingsByFile = new Map<string, Finding[]>();

  update(uri: vscode.Uri, findings: Finding[]): void {
    this.findingsByFile.set(uri.toString(), findings);
    this._onDidChangeTreeData.fire();
  }

  clear(): void {
    this.findingsByFile.clear();
    this._onDidChangeTreeData.fire();
  }

  getTreeItem(element: TreeItem): vscode.TreeItem {
    return element;
  }

  getChildren(element?: TreeItem): TreeItem[] {
    if (element instanceof CategoryItem) {
      return element.findings;
    }

    // Root: group all findings by OWASP category
    const allFindings: Array<[vscode.Uri, Finding]> = [];
    for (const [uriStr, findings] of this.findingsByFile) {
      const uri = vscode.Uri.parse(uriStr);
      findings.forEach(f => allFindings.push([uri, f]));
    }

    if (allFindings.length === 0) { return []; }

    const grouped = new Map<string, Array<[vscode.Uri, Finding]>>();
    for (const [uri, f] of allFindings) {
      const cat = f.category;
      if (!grouped.has(cat)) { grouped.set(cat, []); }
      grouped.get(cat)!.push([uri, f]);
    }

    return Array.from(grouped.entries()).map(([cat, pairs]) => {
      const items = pairs.map(([uri, f]) => new FindingItem(f, uri));
      return new CategoryItem(cat, items);
    });
  }
}
