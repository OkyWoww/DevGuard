import * as fs from 'node:fs';
import * as path from 'node:path';
import {
  analyzeCodeDeterministically,
  buildWorkspaceContext,
  hasAnalyzableExtension,
  hasPartialAnalysisExtension,
  isValidSuppressionReason,
  matchLinearGlob,
  type AllowlistRuleId,
  type WorkspaceContext,
  type WorkspaceFileAccessor,
} from '../../core/analyzer.ts';
import {
  getDevGuardVersion,
  type FileAuditSummary,
  type SkippedFileReportItem,
} from '../../core/types.ts';
import { explainDevGuardRule } from './rulesCatalog.ts';
import {
  MCP_LIMITS,
  UNTRUSTED_SOURCE_NOTICE,
  extractSafeQuotedSourceFromRedactedLines,
  prepareRedactedSourceLines,
  redactAdvisoryText,
  resolveJailedWorkspacePath,
  sanitizeVirtualPath,
  truncateUtf16Safe,
} from './security.ts';

const ALLOWED_ALLOWLIST_RULES = new Set<string>([
  'DG004',
  'DG004-DYN-01',
  'DG004-DYN-02',
  'DG004-REG-01',
  'DG006',
]);

const CHECK_FILES_ALLOWED_KEYS = new Set<string>(['paths', 'min_score']);
const CHECK_SNIPPET_ALLOWED_KEYS = new Set<string>(['language', 'code', 'virtual_path', 'min_score']);
const EXPLAIN_RULE_ALLOWED_KEYS = new Set<string>(['rule_id']);

const MCP_ENVELOPE_MARGIN_BYTES = 512;
const MAX_BOUNDED_MESSAGE_CHARS = 300;
const MAX_BOUNDED_SUGGESTION_CHARS = 300;
const MAX_BOUNDED_QUOTED_CHARS = 120;

export interface McpStructuredFinding {
  ruleId: string;
  filePath: string;
  line: number;
  endLine?: number;
  severity: 'error' | 'warning' | 'note';
  scoring: boolean;
  message: string;
  suggestion: string;
  quoted_source: string;
}

export interface McpToolExecutionResult {
  isError?: boolean;
  payload: Record<string, unknown>;
}

interface ParsedLocalConfig {
  workspacesMode: 'auto' | 'off';
  rulesByPath: Map<string, Array<{ rule: AllowlistRuleId; reason: string }>>;
}

function validateAllowedArgs(
  args: Record<string, unknown>,
  allowedKeys: ReadonlySet<string>
): string | null {
  const unknownKeys = Object.keys(args).filter((k) => !allowedKeys.has(k));
  if (unknownKeys.length === 0) return null;
  return `Unknown argument(s): ${unknownKeys.join(', ')}. Allowed: ${[...allowedKeys].join(', ')}.`;
}

function getSafeRuleRemediation(ruleId: string): string {
  const ruleMeta = explainDevGuardRule(ruleId);
  return ruleMeta.found
    ? ruleMeta.rule.remediation
    : 'Review and remediate the flagged security or reliability issue.';
}

function loadLocalConfigReadOnly(
  workspaceRoot: string
): { ok: true; config: ParsedLocalConfig } | { ok: false; error: string } {
  const rulesByPath = new Map<string, Array<{ rule: AllowlistRuleId; reason: string }>>();
  const jailed = resolveJailedWorkspacePath(workspaceRoot, '.devguard.json');
  if (!jailed.ok) {
    if (jailed.code === 'NOT_FOUND') {
      return { ok: true, config: { workspacesMode: 'auto', rulesByPath } };
    }
    return { ok: false, error: jailed.error };
  }

  let rawText: string;
  try {
    const stat = fs.statSync(jailed.fullPath);
    if (!stat.isFile() || stat.size > MCP_LIMITS.maxSnippetBytes) {
      return { ok: false, error: 'Config file .devguard.json is unreadable or exceeds 256 KiB.' };
    }
    rawText = fs.readFileSync(jailed.fullPath, 'utf-8');
  } catch (err) {
    return {
      ok: false,
      error: `Unable to read .devguard.json: ${err instanceof Error ? err.message : String(err)}`,
    };
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(rawText);
  } catch (err) {
    return {
      ok: false,
      error: `Invalid JSON in .devguard.json: ${err instanceof Error ? err.message : String(err)}`,
    };
  }

  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    return { ok: false, error: 'Invalid .devguard.json schema: expected a JSON object.' };
  }

  const obj = parsed as Record<string, unknown>;
  let workspacesMode: 'auto' | 'off' = 'auto';

  if (obj.workspaces !== undefined) {
    if (!obj.workspaces || typeof obj.workspaces !== 'object' || Array.isArray(obj.workspaces)) {
      return { ok: false, error: 'Invalid "workspaces" field in .devguard.json.' };
    }
    const wsObj = obj.workspaces as Record<string, unknown>;
    for (const key of Object.keys(wsObj)) {
      if (key !== 'mode') {
        return {
          ok: false,
          error: `Unsupported property "workspaces.${key}" in .devguard.json: only "mode" is allowed.`,
        };
      }
    }
    if (wsObj.mode !== 'auto' && wsObj.mode !== 'off') {
      return { ok: false, error: 'Invalid "workspaces.mode" in .devguard.json.' };
    }
    workspacesMode = wsObj.mode;
  }

  if (obj.ignoreRulesByPath !== undefined) {
    if (
      !obj.ignoreRulesByPath ||
      typeof obj.ignoreRulesByPath !== 'object' ||
      Array.isArray(obj.ignoreRulesByPath)
    ) {
      return { ok: false, error: 'Invalid "ignoreRulesByPath" field in .devguard.json.' };
    }
    for (const [pattern, entries] of Object.entries(obj.ignoreRulesByPath as Record<string, unknown>)) {
      if (!Array.isArray(entries)) {
        return { ok: false, error: `Invalid allowlist entries for "${pattern}".` };
      }
      const allowedEntries: Array<{ rule: AllowlistRuleId; reason: string }> = [];
      for (const entry of entries) {
        if (!entry || typeof entry !== 'object') {
          return { ok: false, error: `Invalid allowlist entry under "${pattern}".` };
        }
        const e = entry as { rule?: unknown; reason?: unknown };
        if (typeof e.rule !== 'string' || !ALLOWED_ALLOWLIST_RULES.has(e.rule)) {
          return { ok: false, error: `Invalid allowlist rule "${String(e.rule)}".` };
        }
        if (typeof e.reason !== 'string' || !isValidSuppressionReason(e.reason)) {
          return { ok: false, error: `Invalid allowlist reason for "${e.rule}".` };
        }
        allowedEntries.push({ rule: e.rule as AllowlistRuleId, reason: e.reason.trim() });
      }
      rulesByPath.set(pattern, allowedEntries);
    }
  }

  return { ok: true, config: { workspacesMode, rulesByPath } };
}

function createJailedFsAccessor(workspaceRoot: string): WorkspaceFileAccessor {
  const realRoot = fs.realpathSync(path.resolve(workspaceRoot));
  const safeResolve = (relPath: string): string | null => {
    if (relPath === '' || relPath === '.') return realRoot;
    const jailed = resolveJailedWorkspacePath(realRoot, relPath);
    return jailed.ok ? jailed.fullPath : null;
  };

  return {
    rootDir: realRoot,
    readFile(relPath: string): string | null {
      const full = safeResolve(relPath);
      if (!full) return null;
      try {
        const stat = fs.statSync(full);
        if (!stat.isFile() || stat.size > MCP_LIMITS.maxFileBytes) return null;
        return fs.readFileSync(full, 'utf-8');
      } catch {
        return null;
      }
    },
    fileExists(relPath: string): boolean {
      const full = safeResolve(relPath);
      if (!full) return false;
      try {
        return fs.statSync(full).isFile();
      } catch {
        return false;
      }
    },
    readDir(relDir: string): string[] | null {
      const full = safeResolve(relDir);
      if (!full) return null;
      try {
        if (!fs.statSync(full).isDirectory()) return null;
        return fs.readdirSync(full);
      } catch {
        return null;
      }
    },
  };
}

function getAllowedRulesForPath(
  relPath: string,
  rulesByPath: Map<string, Array<{ rule: AllowlistRuleId; reason: string }>>
): Array<{ rule: AllowlistRuleId; reason: string }> {
  const matched: Array<{ rule: AllowlistRuleId; reason: string }> = [];
  const posix = relPath.replace(/\\/g, '/').replace(/^\.\//, '');
  for (const [pattern, entries] of rulesByPath.entries()) {
    if (matchLinearGlob(pattern, posix)) {
      for (const entry of entries) matched.push(entry);
    }
  }
  return matched;
}

function parseMinScore(raw: unknown): { ok: true; value: number } | { ok: false; error: string } {
  if (raw === undefined) return { ok: true, value: 85 };
  if (typeof raw !== 'number' || !Number.isInteger(raw) || raw < 0 || raw > 100) {
    return { ok: false, error: 'Parameter "min_score" must be an integer between 0 and 100.' };
  }
  return { ok: true, value: raw };
}

function buildStructuredFindingsForFile(
  filePath: string,
  code: string,
  report: ReturnType<typeof analyzeCodeDeterministically>,
  passedFile: boolean,
  minScore: number
): McpStructuredFinding[] {
  const out: McpStructuredFinding[] = [];
  const inline = report.inlineFindings ?? [];
  // Pre-redact the full file once per file to avoid O(findings * file_size) repeated scans
  const redactedLines = prepareRedactedSourceLines(code);

  for (const f of inline) {
    // SPEC §8.3: Never copy raw-line core suggestions (DG004/DG007/DG008) into advisory fields;
    // untrusted source text must appear exclusively inside `quoted_source`.
    const safeSuggestion = getSafeRuleRemediation(f.ruleId);

    out.push({
      ruleId: f.ruleId,
      filePath,
      line: f.line,
      ...(f.endLine !== undefined ? { endLine: f.endLine } : {}),
      severity: f.severity,
      scoring: f.scoring !== false,
      message: redactAdvisoryText(f.message),
      suggestion: safeSuggestion,
      quoted_source: extractSafeQuotedSourceFromRedactedLines(redactedLines, f.line),
    });
  }

  if (out.length === 0 && !passedFile) {
    out.push({
      ruleId: 'DG003',
      filePath,
      line: 1,
      severity: 'error',
      scoring: true,
      message: `DevGuard overall score (${report.skor.totalScore}/100) is below minimum threshold (${minScore}/100).`,
      suggestion: getSafeRuleRemediation('DG003'),
      quoted_source: extractSafeQuotedSourceFromRedactedLines(redactedLines, 1),
    });
  }

  return out;
}

function measureMcpWireBytes(payload: Record<string, unknown>): number {
  const innerJson = JSON.stringify(payload);
  // Account for double-JSON escaping when protocol wraps payload in content[0].text
  const escapedInner = JSON.stringify(innerJson);
  return Buffer.byteLength(escapedInner, 'utf-8') + MCP_ENVELOPE_MARGIN_BYTES;
}

function severityRank(severity: unknown): number {
  if (severity === 'error') return 0;
  if (severity === 'warning') return 1;
  return 2;
}

function sortFindingsBySeverity(
  findings: readonly McpStructuredFinding[]
): McpStructuredFinding[] {
  return findings
    .map((finding, idx) => ({ finding, idx }))
    .sort((a, b) => {
      const diff = severityRank(a.finding.severity) - severityRank(b.finding.severity);
      return diff !== 0 ? diff : a.idx - b.idx;
    })
    .map((entry) => entry.finding);
}

function compactFinding(f: McpStructuredFinding): McpStructuredFinding {
  return {
    ...f,
    message: truncateUtf16Safe(
      typeof f.message === 'string' ? f.message : '',
      MAX_BOUNDED_MESSAGE_CHARS,
      '... [truncated]'
    ),
    suggestion: truncateUtf16Safe(
      typeof f.suggestion === 'string' ? f.suggestion : '',
      MAX_BOUNDED_SUGGESTION_CHARS,
      '... [truncated]'
    ),
    quoted_source: truncateUtf16Safe(
      typeof f.quoted_source === 'string' ? f.quoted_source : '',
      MAX_BOUNDED_QUOTED_CHARS,
      '... [truncated]'
    ),
  };
}

export function enforceOutputBudget(payload: Record<string, unknown>): Record<string, unknown> {
  if (measureMcpWireBytes(payload) <= MCP_LIMITS.maxOutputBytes) {
    return payload;
  }

  const findings = Array.isArray(payload.findings)
    ? (payload.findings as McpStructuredFinding[])
    : [];
  const prioritized = sortFindingsBySeverity(findings);
  const trimmedFindings = prioritized
    .slice(0, Math.min(prioritized.length, 50))
    .map(compactFinding);

  const bounded: Record<string, unknown> = {
    ...payload,
    findings: trimmedFindings,
    total_findings_count: findings.length,
    truncated: true,
    truncation_note: `Output exceeded ${MCP_LIMITS.maxOutputBytes} bytes (including MCP JSON-RPC envelope) and was bounded for safety.`,
  };

  if (measureMcpWireBytes(bounded) <= MCP_LIMITS.maxOutputBytes) {
    return bounded;
  }

  // Secondary bound: trim verbose per-file inline arrays while preserving core file metadata
  if (Array.isArray(bounded.files)) {
    bounded.files = (bounded.files as FileAuditSummary[]).map((f) => ({
      filePath: f.filePath,
      security: f.security,
      correctness: f.correctness,
      maintainability: f.maintainability,
      overall: f.overall,
      passed: f.passed,
      fatalFlaws: f.fatalFlaws
        .slice(0, 2)
        .map((msg) => truncateUtf16Safe(msg, MAX_BOUNDED_MESSAGE_CHARS, '... [truncated]')),
      defenseInDepth: f.defenseInDepth
        .slice(0, 2)
        .map((msg) => truncateUtf16Safe(msg, MAX_BOUNDED_MESSAGE_CHARS, '... [truncated]')),
      inlineFindings: (f.inlineFindings ?? []).slice(0, 10).map((inf) => ({
        ...inf,
        message: truncateUtf16Safe(inf.message, MAX_BOUNDED_MESSAGE_CHARS, '... [truncated]'),
        ...(inf.suggestion
          ? {
              suggestion: truncateUtf16Safe(
                inf.suggestion,
                MAX_BOUNDED_SUGGESTION_CHARS,
                '... [truncated]'
              ),
            }
          : {}),
      })),
      ...(f.suppressions ? { suppressions: f.suppressions } : {}),
      ...(f.layer2Status ? { layer2Status: f.layer2Status } : {}),
      ...(f.dynScopeUncertain !== undefined ? { dynScopeUncertain: f.dynScopeUncertain } : {}),
      ...(f.foldLimitExceeded !== undefined ? { foldLimitExceeded: f.foldLimitExceeded } : {}),
    }));
  }

  if (measureMcpWireBytes(bounded) <= MCP_LIMITS.maxOutputBytes) {
    return bounded;
  }

  // Final deterministic compact fallback: preserve tool-specific schema fields and
  // guarantee verified wire byte size <= MCP_LIMITS.maxOutputBytes.
  const isSnippetPayload =
    Object.prototype.hasOwnProperty.call(payload, 'virtual_path') ||
    Object.prototype.hasOwnProperty.call(payload, 'language');

  const safeSecurityBoundary = {
    untrusted_source_field: 'quoted_source',
    notice: UNTRUSTED_SOURCE_NOTICE,
  };
  const safeVersion =
    typeof payload.version === 'string'
      ? truncateUtf16Safe(payload.version, 64)
      : getDevGuardVersion();
  const safeMinScore =
    typeof payload.minScore === 'number' && Number.isFinite(payload.minScore)
      ? payload.minScore
      : null;
  const safeOverallScore =
    typeof payload.overallScore === 'number' && Number.isFinite(payload.overallScore)
      ? payload.overallScore
      : null;
  const safePassed = typeof payload.passed === 'boolean' ? payload.passed : false;

  const buildCompact = (maxFindings: number): Record<string, unknown> => {
    const base: Record<string, unknown> = {
      version: safeVersion,
      ...(isSnippetPayload
        ? {
            virtual_path:
              typeof payload.virtual_path === 'string'
                ? truncateUtf16Safe(payload.virtual_path, 200)
                : payload.virtual_path,
            language:
              typeof payload.language === 'string'
                ? truncateUtf16Safe(payload.language, 32)
                : payload.language,
            partial_coverage: payload.partial_coverage,
            security: payload.security,
            correctness: payload.correctness,
            maintainability: payload.maintainability,
          }
        : {
            analyzedCount: payload.analyzedCount,
            skippedCount: payload.skippedCount,
            ...(Array.isArray(payload.partialFiles)
              ? { partialFiles: payload.partialFiles.slice(0, 25) }
              : {}),
            ...(Array.isArray(payload.skippedFiles)
              ? { skippedFiles: payload.skippedFiles.slice(0, 25) }
              : {}),
          }),
      minScore: safeMinScore,
      overallScore: safeOverallScore,
      passed: safePassed,
      total_findings_count: findings.length,
      findings: trimmedFindings.slice(0, maxFindings),
      truncated: true,
      truncation_note: truncateUtf16Safe(
        `Output exceeded ${MCP_LIMITS.maxOutputBytes} bytes and was compacted to summary form.`,
        160
      ),
      security_boundary: safeSecurityBoundary,
    };
    return base;
  };

  for (const count of [10, 5, 3, 1, 0]) {
    const candidate = buildCompact(count);
    if (measureMcpWireBytes(candidate) <= MCP_LIMITS.maxOutputBytes) {
      return candidate;
    }
  }

  // Absolute minimal fail-safe verified strictly <= MCP_LIMITS.maxOutputBytes
  const minimalSummary: Record<string, unknown> = {
    version: safeVersion,
    minScore: safeMinScore,
    overallScore: safeOverallScore,
    passed: safePassed,
    total_findings_count: findings.length,
    findings: [],
    truncated: true,
    wire_budget_exceeded: true,
    max_output_bytes: MCP_LIMITS.maxOutputBytes,
    truncation_note: truncateUtf16Safe(
      `Output exceeded ${MCP_LIMITS.maxOutputBytes} bytes and was compacted to minimal summary.`,
      160
    ),
    security_boundary: safeSecurityBoundary,
  };

  if (measureMcpWireBytes(minimalSummary) <= MCP_LIMITS.maxOutputBytes) {
    return minimalSummary;
  }

  return {
    version: getDevGuardVersion(),
    total_findings_count: findings.length,
    findings: [],
    truncated: true,
    wire_budget_exceeded: true,
    max_output_bytes: MCP_LIMITS.maxOutputBytes,
    truncation_note: truncateUtf16Safe('Output compacted to stay within wire budget.', 64),
    security_boundary: {
      untrusted_source_field: 'quoted_source',
      notice: truncateUtf16Safe(UNTRUSTED_SOURCE_NOTICE, 120),
    },
  };
}

/**
 * MCP Tool 1: `devguard_check_files` (read-only, jailed to workspaceRoot, CLI JSON parity).
 */
export function handleMcpCheckFiles(
  workspaceRoot: string,
  args: Record<string, unknown>
): McpToolExecutionResult {
  const unknownArgsError = validateAllowedArgs(args, CHECK_FILES_ALLOWED_KEYS);
  if (unknownArgsError !== null) {
    return { isError: true, payload: { error: unknownArgsError } };
  }

  const rawPaths = args.paths;
  if (!Array.isArray(rawPaths) || rawPaths.length === 0) {
    return {
      isError: true,
      payload: { error: 'Parameter "paths" must be a non-empty array of workspace-relative file paths.' },
    };
  }
  if (rawPaths.length > MCP_LIMITS.maxFilesPerCall) {
    return {
      isError: true,
      payload: {
        error: `Too many files requested (${rawPaths.length}). Maximum allowed per call is ${MCP_LIMITS.maxFilesPerCall}.`,
      },
    };
  }

  const minScoreRes = parseMinScore(args.min_score);
  if (!minScoreRes.ok) {
    return { isError: true, payload: { error: minScoreRes.error } };
  }
  const minScore = minScoreRes.value;

  // Validate and jail ALL paths up front (fail-closed)
  const resolvedTargets: Array<{ fullPath: string; relPath: string }> = [];
  const seenRel = new Set<string>();
  for (const item of rawPaths) {
    if (typeof item !== 'string') {
      return {
        isError: true,
        payload: { error: 'Every entry in "paths" must be a string.' },
      };
    }
    const jailed = resolveJailedWorkspacePath(workspaceRoot, item);
    if (!jailed.ok) {
      return { isError: true, payload: { error: jailed.error } };
    }
    if (!seenRel.has(jailed.relativePosixPath)) {
      seenRel.add(jailed.relativePosixPath);
      resolvedTargets.push({ fullPath: jailed.fullPath, relPath: jailed.relativePosixPath });
    }
  }
  resolvedTargets.sort((a, b) => a.relPath.localeCompare(b.relPath));

  const cfgRes = loadLocalConfigReadOnly(workspaceRoot);
  if (!cfgRes.ok) {
    return { isError: true, payload: { error: cfgRes.error } };
  }

  const localFsAccessor = createJailedFsAccessor(workspaceRoot);
  let workspaceContext: WorkspaceContext | undefined;
  if (cfgRes.config.workspacesMode === 'auto') {
    workspaceContext = buildWorkspaceContext(localFsAccessor, { mode: 'auto' });
  }

  const summaries: FileAuditSummary[] = [];
  const partialFiles: string[] = [];
  const skippedFiles: SkippedFileReportItem[] = [];
  const structuredFindings: McpStructuredFinding[] = [];
  let hasBlockingFailure = false;

  for (const target of resolvedTargets) {
    let stat: fs.Stats;
    try {
      stat = fs.statSync(target.fullPath);
    } catch (err) {
      const reason = err instanceof Error ? err.message : String(err);
      return { isError: true, payload: { error: `Unable to inspect "${target.relPath}": ${reason}` } };
    }

    if (!stat.isFile()) {
      return {
        isError: true,
        payload: { error: `Target "${target.relPath}" is not a regular file.` },
      };
    }

    const isJsTs = hasAnalyzableExtension(target.relPath);
    const isPy = hasPartialAnalysisExtension(target.relPath);
    if (!isJsTs && !isPy) {
      skippedFiles.push({ filePath: target.relPath, reason: 'unsupported_language' });
      continue;
    }

    if (stat.size > MCP_LIMITS.maxFileBytes) {
      skippedFiles.push({ filePath: target.relPath, reason: 'file_too_large' });
      continue;
    }

    if (isPy) {
      partialFiles.push(target.relPath);
    }

    let code: string;
    try {
      code = fs.readFileSync(target.fullPath, 'utf-8');
    } catch (err) {
      const reason = err instanceof Error ? err.message : String(err);
      return { isError: true, payload: { error: `Unable to read "${target.relPath}": ${reason}` } };
    }

    const allowlistRules = getAllowedRulesForPath(target.relPath, cfgRes.config.rulesByPath);
    const report = analyzeCodeDeterministically(code, {
      filePath: target.relPath,
      externalAllowlist: allowlistRules.length > 0 ? allowlistRules : undefined,
      workspaceContext,
      workspaceFileAccessor: localFsAccessor,
      workspacesMode: cfgRes.config.workspacesMode,
    });

    const blockingFindings = (report.inlineFindings ?? []).filter(
      (f) => f.scoring !== false && f.severity === 'error'
    );
    const hasFatalText =
      Boolean(report.temuanUtama.description) &&
      !report.isHardened &&
      report.skor.totalScore < minScore;
    const passedFile =
      report.skor.totalScore >= minScore &&
      blockingFindings.length === 0 &&
      !hasFatalText;

    if (!passedFile) {
      hasBlockingFailure = true;
    }

    summaries.push({
      filePath: target.relPath,
      security: report.skor.security,
      correctness: report.skor.correctness,
      maintainability: report.skor.maintainability,
      overall: report.skor.totalScore,
      passed: passedFile,
      fatalFlaws:
        !passedFile &&
        report.temuanUtama.description &&
        !report.temuanUtama.description.startsWith('Mitigasi utama terverifikasi') &&
        !report.temuanUtama.description.startsWith('Kode telah melewati')
          ? [redactAdvisoryText(report.temuanUtama.description)]
          : [],
      defenseInDepth:
        report.residualNotes && report.residualNotes.length > 0
          ? report.residualNotes.map(redactAdvisoryText)
          : report.temuanLain
              .filter((t) => t.includes('[Defense-in-Depth]'))
              .map(redactAdvisoryText),
      inlineFindings: report.inlineFindings?.map((f) => ({
        ...f,
        message: redactAdvisoryText(f.message),
        ...(f.suggestion ? { suggestion: getSafeRuleRemediation(f.ruleId) } : {}),
      })),
      suppressions: report.suppressions,
      layer2Status: 'Layer 2 (Gemini): Skipped [Offline]',
      dynScopeUncertain: report.dynScopeUncertain,
      foldLimitExceeded: report.virtualView?.limitExceeded,
    });

    structuredFindings.push(
      ...buildStructuredFindingsForFile(target.relPath, code, report, passedFile, minScore)
    );
  }

  const overallScore =
    summaries.length === 0
      ? null
      : Math.round(summaries.reduce((acc, s) => acc + s.overall, 0) / summaries.length);
  const passed =
    !hasBlockingFailure && (overallScore === null || overallScore >= minScore);

  const payload = enforceOutputBudget({
    version: getDevGuardVersion(),
    minScore,
    overallScore,
    passed,
    analyzedCount: summaries.length,
    skippedCount: skippedFiles.length,
    files: summaries,
    partialFiles,
    skippedFiles,
    workspaceDiagnostics: workspaceContext?.diagnostics ?? [],
    findings: structuredFindings,
    security_boundary: {
      untrusted_source_field: 'quoted_source',
      notice: UNTRUSTED_SOURCE_NOTICE,
    },
  });

  return { payload };
}

/**
 * MCP Tool 2: `devguard_check_snippet` (in-memory only, zero disk access).
 */
export function handleMcpCheckSnippet(
  args: Record<string, unknown>
): McpToolExecutionResult {
  const unknownArgsError = validateAllowedArgs(args, CHECK_SNIPPET_ALLOWED_KEYS);
  if (unknownArgsError !== null) {
    return { isError: true, payload: { error: unknownArgsError } };
  }

  const language = args.language;
  const code = args.code;

  if (typeof language !== 'string' || language.trim().length === 0) {
    return {
      isError: true,
      payload: { error: 'Parameter "language" must be a non-empty string (e.g. "ts", "js", "py").' },
    };
  }
  if (typeof code !== 'string') {
    return {
      isError: true,
      payload: { error: 'Parameter "code" must be a string.' },
    };
  }
  if (Buffer.byteLength(code, 'utf-8') > MCP_LIMITS.maxSnippetBytes) {
    return {
      isError: true,
      payload: {
        error: `Snippet exceeds maximum allowed size of ${MCP_LIMITS.maxSnippetBytes} bytes.`,
      },
    };
  }

  const minScoreRes = parseMinScore(args.min_score);
  if (!minScoreRes.ok) {
    return { isError: true, payload: { error: minScoreRes.error } };
  }
  const minScore = minScoreRes.value;

  const vpRes = sanitizeVirtualPath(language, args.virtual_path);
  if (!vpRes.ok) {
    return { isError: true, payload: { error: vpRes.error } };
  }
  const virtualPath = vpRes.virtualPath;
  const isJsTs = hasAnalyzableExtension(virtualPath);
  const isPy = hasPartialAnalysisExtension(virtualPath);
  if (!isJsTs && !isPy) {
    return {
      isError: true,
      payload: {
        error: `Unsupported language or virtual_path extension for "${virtualPath}". Supported: ts, tsx, js, jsx, mjs, cjs, py.`,
      },
    };
  }

  const report = analyzeCodeDeterministically(code, {
    filePath: virtualPath,
    workspacesMode: 'off',
  });

  const blockingFindings = (report.inlineFindings ?? []).filter(
    (f) => f.scoring !== false && f.severity === 'error'
  );
  const hasFatalText =
    Boolean(report.temuanUtama.description) &&
    !report.isHardened &&
    report.skor.totalScore < minScore;
  const passed =
    report.skor.totalScore >= minScore &&
    blockingFindings.length === 0 &&
    !hasFatalText;

  const findings = buildStructuredFindingsForFile(virtualPath, code, report, passed, minScore);

  const payload = enforceOutputBudget({
    version: getDevGuardVersion(),
    virtual_path: virtualPath,
    language: language.trim(),
    partial_coverage: isPy,
    minScore,
    overallScore: report.skor.totalScore,
    security: report.skor.security,
    correctness: report.skor.correctness,
    maintainability: report.skor.maintainability,
    passed,
    findings,
    security_boundary: {
      untrusted_source_field: 'quoted_source',
      notice: UNTRUSTED_SOURCE_NOTICE,
    },
  });

  return { payload };
}

/**
 * MCP Tool 3: `devguard_explain_rule` (read-only rule catalog lookup).
 */
export function handleMcpExplainRule(
  args: Record<string, unknown>
): McpToolExecutionResult {
  const unknownArgsError = validateAllowedArgs(args, EXPLAIN_RULE_ALLOWED_KEYS);
  if (unknownArgsError !== null) {
    return { isError: true, payload: { error: unknownArgsError } };
  }

  const ruleId = args.rule_id;
  if (typeof ruleId !== 'string' || ruleId.trim().length === 0) {
    return {
      isError: true,
      payload: { error: 'Parameter "rule_id" must be a non-empty string (e.g. "DG006").' },
    };
  }

  const res = explainDevGuardRule(ruleId);
  if (!res.found) {
    return {
      isError: true,
      payload: {
        error: `Unknown DevGuard rule_id "${ruleId.trim()}".`,
        supported_rule_ids: res.supportedRuleIds,
      },
    };
  }

  return {
    payload: {
      version: getDevGuardVersion(),
      ...res.rule,
    },
  };
}
