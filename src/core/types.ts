import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import type {
  AllowlistRuleId,
  AuditAnalyzeOptions,
  DevGuardRuleId,
  FoldTextEdit,
  InlineFinding,
  LexicalRegion,
  LexicalRegionKind,
  LineFinding,
  ParsedSuppression,
  SpanMap,
  SpanMapSeg,
  VirtualViewResult,
} from './rules/lexicalMasker.ts';
import type {
  ResolutionSource,
  WorkspaceContext,
  WorkspaceDiagnosticNotice,
  WorkspaceFileAccessor,
  WorkspaceResolutionResult,
} from './rules/packageAndExceptionRules.ts';
import type { PrepareLlmOptions } from './rules/secretAndResilienceRules.ts';

export type {
  AllowlistRuleId,
  AuditAnalyzeOptions,
  DevGuardRuleId,
  FoldTextEdit,
  InlineFinding,
  LexicalRegion,
  LexicalRegionKind,
  LineFinding,
  ParsedSuppression,
  PrepareLlmOptions,
  ResolutionSource,
  SpanMap,
  SpanMapSeg,
  VirtualViewResult,
  WorkspaceContext,
  WorkspaceDiagnosticNotice,
  WorkspaceFileAccessor,
  WorkspaceResolutionResult,
};

export type SkippedReason =
  | 'unsupported_language'
  | 'file_too_large'
  | 'parse_error'
  | 'internal_error';

export interface SkippedFileReportItem {
  filePath: string;
  reason: SkippedReason;
}

export interface FileAuditSummary {
  filePath: string;
  security: number;
  correctness: number;
  maintainability: number;
  overall: number;
  passed: boolean;
  fatalFlaws: string[];
  defenseInDepth: string[];
  inlineFindings?: InlineFinding[];
  suppressions?: ParsedSuppression[];
  invalidAllowlistEntries?: string[];
  allowlistModifiedInPr?: boolean;
  layer2Status?: string;
  dynScopeUncertain?: number;
  foldLimitExceeded?: boolean;
}

export const PARTIAL_COVERAGE_REASON_TEXT = 'Partial: language-agnostic rules only';
export const INVARIANT_MISMATCH_SENTINEL = '<invariant-mismatch>';

let cachedDevGuardVersion: string | null = null;

/**
 * Resolves DevGuard package version dynamically by walking upward up to 4 levels
 * from `startDir` (or this module's directory) for a `package.json` named `devguard`.
 */
export function getDevGuardVersion(startDir?: string): string {
  if (startDir === undefined && cachedDevGuardVersion !== null) {
    return cachedDevGuardVersion;
  }

  let currentDir = path.resolve(startDir ?? path.dirname(fileURLToPath(import.meta.url)));
  let resolvedVersion = 'unknown';

  for (let depth = 0; depth <= 4; depth++) {
    const pkgPath = path.join(currentDir, 'package.json');
    if (fs.existsSync(pkgPath)) {
      try {
        const parsed = JSON.parse(fs.readFileSync(pkgPath, 'utf-8')) as {
          name?: unknown;
          version?: unknown;
        };
        if (
          parsed?.name === 'devguard' &&
          typeof parsed.version === 'string' &&
          parsed.version.trim().length > 0
        ) {
          resolvedVersion = parsed.version.trim();
          break;
        }
      } catch {
        // Malformed or unreadable package.json; continue walking up within bounded depth
        resolvedVersion = 'unknown';
      }
    }
    const parentDir = path.dirname(currentDir);
    if (parentDir === currentDir) break;
    currentDir = parentDir;
  }

  if (startDir === undefined) {
    cachedDevGuardVersion = resolvedVersion;
  }
  return resolvedVersion;
}

/** Formats canonical human-readable skipped reason text for PR comments and SARIF notifications. */
export function formatSkippedReasonText(reason: SkippedReason): string {
  switch (reason) {
    case 'unsupported_language':
      return 'Skipped: Unsupported language';
    case 'file_too_large':
      return 'Skipped: File too large (> 1 MiB)';
    case 'parse_error':
      return 'Skipped: Parse error';
    case 'internal_error':
      return 'Skipped: Internal error';
  }
}
