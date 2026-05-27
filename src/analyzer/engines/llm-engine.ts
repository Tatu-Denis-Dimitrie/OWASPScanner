import * as vscode from 'vscode';
import type { Finding } from '../types';
import { log, logError } from '../../utils/logger';

export interface LlmRefinementResult {
  /** Net-new findings discovered by LLM beyond regex/AST */
  newFindings: Finding[];
  /** Existing findings, potentially with updated confidence/description */
  refinedFindings: Finding[];
}

export async function refineWithLlm(
  document: vscode.TextDocument,
  text: string,
  existingFindings: Finding[],
  apiKey: string
): Promise<LlmRefinementResult> {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  let AnthropicClass: any;
  try {
    const mod = await import('@anthropic-ai/sdk');
    AnthropicClass = mod.default;
  } catch {
    logError('LLM engine: @anthropic-ai/sdk not installed');
    return { newFindings: [], refinedFindings: existingFindings };
  }

  const client = new AnthropicClass({ apiKey }) as import('@anthropic-ai/sdk').default;

  // Send only 3-line context windows around each finding to limit token usage
  const snippets = existingFindings.slice(0, 15).map((f, i) => {
    const startLine = Math.max(0, f.range.start.line - 2);
    const endLine = Math.min(document.lineCount - 1, f.range.end.line + 2);
    const lines = text.split('\n').slice(startLine, endLine + 1).join('\n');
    return `[${i}] rule=${f.ruleId} lines=${startLine + 1}-${endLine + 1}\n${lines}`;
  }).join('\n\n---\n\n');

  const systemPrompt = `You are a senior application security engineer performing code review.
Assess each flagged code snippet. Respond ONLY with valid JSON, no markdown.
Schema: {"assessments":[{"index":number,"isTruePositive":boolean,"confidence":"high"|"medium"|"low","reason":string}]}`;

  try {
    const response = await client.messages.create({
      model: 'claude-sonnet-4-6',
      max_tokens: 1024,
      system: systemPrompt,
      messages: [{ role: 'user', content: snippets }],
    });

    const block = response.content[0];
    if (block.type !== 'text') { return { newFindings: [], refinedFindings: existingFindings }; }

    const json = block.text.match(/\{[\s\S]*\}/)?.[0];
    if (!json) { return { newFindings: [], refinedFindings: existingFindings }; }

    const { assessments } = JSON.parse(json) as {
      assessments: { index: number; isTruePositive: boolean; confidence: 'high' | 'medium' | 'low'; reason: string }[];
    };

    const indexMap = new Map(assessments.map(a => [a.index, a]));
    const refinedFindings = existingFindings
      .map((f, i) => {
        const a = indexMap.get(i);
        if (!a) { return f; }
        return {
          ...f,
          confidence: a.confidence,
          description: `${f.description}\n\nLLM: ${a.reason}`,
        };
      })
      .filter((_, i) => {
        const a = indexMap.get(i);
        return !a || a.isTruePositive;
      });

    log(`LLM: ${existingFindings.length} findings → ${refinedFindings.length} after refinement`);
    return { newFindings: [], refinedFindings };
  } catch (err) {
    logError('LLM refinement failed', err);
    return { newFindings: [], refinedFindings: existingFindings };
  }
}
