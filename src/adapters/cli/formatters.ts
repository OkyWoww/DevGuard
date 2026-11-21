import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { generateSarifReport } from '../../core/sarif.ts';
import type {
  FileAuditSummary,
  SkippedFileReportItem,
  WorkspaceDiagnosticNotice,
} from '../../core/types.ts';
import type { CliFormat } from './args.ts';

export interface CliCheckResult {
  version: string;
  minScore: number;
  overallScore: number | null;
  passed: boolean;
  summaries: FileAuditSummary[];
  partialFiles: string[];
  skippedFiles: SkippedFileReportItem[];
  workspaceDiagnostics: WorkspaceDiagnosticNotice[];
}

export function formatTextReport(result: CliCheckResult): string {
  const lines: string[] = [];
  const scoreDisplay = result.overallScore === null ? 'N/A' : `${result.overallScore}/100`;

  lines.push(`DevGuard v${result.version} — Offline Deterministic CLI`);
  lines.push(
    `Score: ${scoreDisplay} (min: ${result.minScore}/100) | Analyzed: ${result.summaries.length} | Skipped: ${result.skippedFiles.length} | Verdict: ${result.passed ? 'PASS' : 'FAIL'}`
  );

  for (const s of result.summaries) {
    const icon = s.passed ? 'PASS' : 'FAIL';
    lines.push(
      `  [${icon}] ${s.filePath} — ${s.overall}/100 (Sec ${s.security}, Corr ${s.correctness}, Maint ${s.maintainability})`
    );
    const findings = s.inlineFindings ?? [];
    for (const f of findings) {
      const tag = f.scoring === false ? 'non-scoring' : f.severity;
      lines.push(`    L${f.line} [${f.ruleId}][${tag}] ${f.message}`);
    }
    if (findings.length === 0 && !s.passed && s.fatalFlaws.length > 0) {
      for (const flaw of s.fatalFlaws) {
        lines.push(`    [FATAL] ${flaw}`);
      }
    }
  }

  for (const sk of result.skippedFiles) {
    lines.push(`  [SKIP] ${sk.filePath} (${sk.reason})`);
  }

  for (const diag of result.workspaceDiagnostics) {
    lines.push(`  [NOTICE][${diag.ruleId}] ${diag.sourceFile}: ${diag.message}`);
  }

  return lines.join('\n') + '\n';
}

export function formatJsonReport(result: CliCheckResult): string {
  return (
    JSON.stringify(
      {
        version: result.version,
        minScore: result.minScore,
        overallScore: result.overallScore,
        passed: result.passed,
        analyzedCount: result.summaries.length,
        skippedCount: result.skippedFiles.length,
        files: result.summaries,
        partialFiles: result.partialFiles,
        skippedFiles: result.skippedFiles,
        workspaceDiagnostics: result.workspaceDiagnostics,
      },
      null,
      2
    ) + '\n'
  );
}

/**
 * Generates SARIF v2.1.0 string using `src/core/sarif.ts` so `--format sarif`
 * is guaranteed byte-for-byte identical to `src/core/` and `adapters/action/`.
 */
export function formatSarifReport(result: CliCheckResult): string {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'devguard-cli-sarif-'));
  try {
    const tmpFile = path.join(tmpDir, 'report.sarif');
    generateSarifReport(result.summaries, tmpFile, result.skippedFiles, {
      partialFiles: result.partialFiles,
      hasAnalysisFailure: false,
      workspaceDiagnostics: result.workspaceDiagnostics,
    });
    return fs.readFileSync(tmpFile, 'utf-8');
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
}

export function formatCliOutput(format: CliFormat, result: CliCheckResult): string {
  switch (format) {
    case 'json':
      return formatJsonReport(result);
    case 'sarif':
      return formatSarifReport(result);
    case 'text':
    default:
      return formatTextReport(result);
  }
}
