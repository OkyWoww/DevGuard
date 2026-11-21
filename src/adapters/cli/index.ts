#!/usr/bin/env node
import * as fs from 'node:fs';
import * as path from 'node:path';
import { pathToFileURL } from 'node:url';
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
import { getCliUsageText, parseCliArgs } from './args.ts';
import { formatCliOutput, type CliCheckResult } from './formatters.ts';
import { getChangedFilesSince, getStagedFiles } from './git.ts';
import { installPreCommitHook } from './hook.ts';

const MAX_AUDIT_FILE_SIZE = 1_048_576; // 1 MiB ReDoS safety limit
const ALLOWED_ALLOWLIST_RULES = new Set<string>([
  'DG004',
  'DG004-DYN-01',
  'DG004-DYN-02',
  'DG006',
]);
const EXCLUDED_DIRS = new Set<string>([
  'node_modules',
  '.git',
  'dist',
  'build',
  'coverage',
  '.test-dist',
  'remotion',
  'out',
  'tests',
  'scripts',
]);

export interface CliIo {
  cwd?: string;
  stdout?: (chunk: string) => void;
  stderr?: (chunk: string) => void;
}

interface ParsedLocalConfig {
  workspacesMode: 'auto' | 'off';
  rulesByPath: Map<string, Array<{ rule: AllowlistRuleId; reason: string }>>;
}

function loadLocalConfigStrict(
  cwd: string,
  explicitConfigPath: string | null
): { ok: true; config: ParsedLocalConfig } | { ok: false; error: string } {
  const rulesByPath = new Map<string, Array<{ rule: AllowlistRuleId; reason: string }>>();
  const targetPath = explicitConfigPath
    ? path.resolve(cwd, explicitConfigPath)
    : path.join(cwd, '.devguard.json');

  if (!fs.existsSync(targetPath)) {
    if (explicitConfigPath !== null) {
      return { ok: false, error: `Config file not found: ${explicitConfigPath}` };
    }
    return { ok: true, config: { workspacesMode: 'auto', rulesByPath } };
  }

  let rawText: string;
  try {
    rawText = fs.readFileSync(targetPath, 'utf-8');
  } catch (err) {
    return {
      ok: false,
      error: `Unable to read config file "${targetPath}": ${err instanceof Error ? err.message : String(err)}`,
    };
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(rawText);
  } catch (err) {
    return {
      ok: false,
      error: `Invalid JSON in config file "${targetPath}": ${err instanceof Error ? err.message : String(err)}`,
    };
  }

  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    return { ok: false, error: `Invalid config schema in "${targetPath}": expected a JSON object.` };
  }

  const obj = parsed as Record<string, unknown>;
  let workspacesMode: 'auto' | 'off' = 'auto';

  if (obj.workspaces !== undefined) {
    if (!obj.workspaces || typeof obj.workspaces !== 'object' || Array.isArray(obj.workspaces)) {
      return { ok: false, error: 'Invalid "workspaces" field in .devguard.json: expected an object.' };
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
      return {
        ok: false,
        error: `Invalid "workspaces.mode" in .devguard.json: expected "auto" or "off".`,
      };
    }
    workspacesMode = wsObj.mode;
  }

  if (obj.ignoreRulesByPath !== undefined) {
    if (
      !obj.ignoreRulesByPath ||
      typeof obj.ignoreRulesByPath !== 'object' ||
      Array.isArray(obj.ignoreRulesByPath)
    ) {
      return {
        ok: false,
        error: 'Invalid "ignoreRulesByPath" field in .devguard.json: expected an object map.',
      };
    }

    for (const [pattern, entries] of Object.entries(obj.ignoreRulesByPath as Record<string, unknown>)) {
      if (!Array.isArray(entries)) {
        return {
          ok: false,
          error: `Invalid allowlist entries for "${pattern}" in .devguard.json: expected an array.`,
        };
      }
      const allowedEntries: Array<{ rule: AllowlistRuleId; reason: string }> = [];
      for (const entry of entries) {
        if (!entry || typeof entry !== 'object') {
          return { ok: false, error: `Invalid allowlist entry under "${pattern}" in .devguard.json.` };
        }
        const e = entry as { rule?: unknown; reason?: unknown };
        if (typeof e.rule !== 'string' || !ALLOWED_ALLOWLIST_RULES.has(e.rule)) {
          return {
            ok: false,
            error: `Disallowed or invalid rule "${String(e.rule)}" under "${pattern}" in .devguard.json.`,
          };
        }
        if (typeof e.reason !== 'string' || !isValidSuppressionReason(e.reason)) {
          return {
            ok: false,
            error: `Allowlist entry for "${e.rule}" under "${pattern}" requires a meaningful reason.`,
          };
        }
        allowedEntries.push({ rule: e.rule as AllowlistRuleId, reason: e.reason.trim() });
      }
      rulesByPath.set(pattern, allowedEntries);
    }
  }

  return { ok: true, config: { workspacesMode, rulesByPath } };
}

function createLocalFsAccessor(rootDir: string): WorkspaceFileAccessor {
  const safeResolve = (relPath: string): string | null => {
    const resolved = path.resolve(rootDir, relPath);
    const rel = path.relative(rootDir, resolved);
    if (rel.startsWith('..') || path.isAbsolute(rel)) return null;
    return resolved;
  };

  return {
    rootDir,
    readFile(relPath: string): string | null {
      const full = safeResolve(relPath);
      if (!full) return null;
      try {
        if (!fs.existsSync(full) || !fs.statSync(full).isFile()) return null;
        return fs.readFileSync(full, 'utf-8');
      } catch {
        return null;
      }
    },
    fileExists(relPath: string): boolean {
      const full = safeResolve(relPath);
      if (!full) return false;
      try {
        return fs.existsSync(full) && fs.statSync(full).isFile();
      } catch {
        return false;
      }
    },
    readDir(relDir: string): string[] | null {
      const full = safeResolve(relDir);
      if (!full) return null;
      try {
        if (!fs.existsSync(full) || !fs.statSync(full).isDirectory()) return null;
        return fs.readdirSync(full);
      } catch {
        return null;
      }
    },
  };
}

function collectDirectoryFiles(dir: string, rootDir: string, out: string[]): void {
  let entries: fs.Dirent[];
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true });
  } catch {
    return;
  }

  for (const entry of entries) {
    if (entry.name.startsWith('.') || EXCLUDED_DIRS.has(entry.name)) {
      continue;
    }
    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      collectDirectoryFiles(fullPath, rootDir, out);
    } else if (entry.isFile()) {
      const rel = path.relative(rootDir, fullPath).replace(/\\/g, '/');
      if (
        !rel.endsWith('.d.ts') &&
        !/\.(?:test|spec)\.[cm]?[jt]sx?$/i.test(rel) &&
        (hasAnalyzableExtension(rel) || hasPartialAnalysisExtension(rel))
      ) {
        out.push(rel);
      }
    }
  }
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

/**
 * Executes the zero-dependency DevGuard CLI adapter (offline deterministic by default).
 * Exit codes:
 *   0 = pass
 *   1 = audit gate failed
 *   2 = operational / argument / config / git error
 */
export function runCli(argv: readonly string[], io?: CliIo): number {
  const cwd = path.resolve(io?.cwd ?? process.cwd());
  const writeOut = io?.stdout ?? ((s: string) => process.stdout.write(s));
  const writeErr = io?.stderr ?? ((s: string) => process.stderr.write(s));

  const parsed = parseCliArgs(argv);
  if (parsed.kind === 'help') {
    writeOut(getCliUsageText() + '\n');
    return 0;
  }
  if (parsed.kind === 'version') {
    writeOut(getDevGuardVersion() + '\n');
    return 0;
  }
  if (parsed.kind === 'error') {
    writeErr(`Error: ${parsed.message}\n`);
    return 2;
  }
  if (parsed.kind === 'install-hook') {
    const hookRes = installPreCommitHook(cwd);
    if (!hookRes.ok) {
      writeErr(`Error: ${hookRes.error}\n`);
      return 2;
    }
    writeOut(`DevGuard pre-commit hook (${hookRes.status}): ${hookRes.hookPath}\n`);
    return 0;
  }

  // 1. Load & validate local .devguard.json (strict fail-closed -> exit 2)
  const cfgRes = loadLocalConfigStrict(cwd, parsed.configPath);
  if (!cfgRes.ok) {
    writeErr(`Error: ${cfgRes.error}\n`);
    return 2;
  }

  // 2. Resolve target file list
  let baseDir = cwd;
  const candidateRelFiles: string[] = [];
  let isExplicitList = false;

  if (parsed.staged) {
    const gitRes = getStagedFiles(cwd);
    if (!gitRes.ok) {
      writeErr(`Error: ${gitRes.error}\n`);
      return 2;
    }
    baseDir = gitRes.repoRoot;
    candidateRelFiles.push(...gitRes.files);
  } else if (parsed.changedSince !== null) {
    const gitRes = getChangedFilesSince(parsed.changedSince, cwd);
    if (!gitRes.ok) {
      writeErr(`Error: ${gitRes.error}\n`);
      return 2;
    }
    baseDir = gitRes.repoRoot;
    candidateRelFiles.push(...gitRes.files);
  } else if (parsed.paths.length > 0) {
    isExplicitList = true;
    for (const rawTarget of parsed.paths) {
      const resolvedTarget = path.resolve(cwd, rawTarget);
      if (!fs.existsSync(resolvedTarget)) {
        writeErr(`Error: Target path not found: ${rawTarget}\n`);
        return 2;
      }
      const stat = fs.statSync(resolvedTarget);
      if (stat.isDirectory()) {
        collectDirectoryFiles(resolvedTarget, cwd, candidateRelFiles);
      } else if (stat.isFile()) {
        candidateRelFiles.push(path.relative(cwd, resolvedTarget).replace(/\\/g, '/'));
      }
    }
  } else {
    collectDirectoryFiles(cwd, cwd, candidateRelFiles);
  }

  // Deduplicate & sort deterministically
  const uniqueFiles = Array.from(new Set(candidateRelFiles)).sort();

  // 3. Build local workspace context (offline, zero network)
  const localFsAccessor = createLocalFsAccessor(baseDir);
  let workspaceContext: WorkspaceContext | undefined;
  if (cfgRes.config.workspacesMode === 'auto') {
    workspaceContext = buildWorkspaceContext(localFsAccessor, {
      mode: 'auto',
    });
  }

  // 4. Audit files deterministically (Layer 2 Gemini OFF by default)
  const summaries: FileAuditSummary[] = [];
  const partialFiles: string[] = [];
  const skippedFiles: SkippedFileReportItem[] = [];
  let hasBlockingFailure = false;

  for (const relPath of uniqueFiles) {
    const fullPath = path.resolve(baseDir, relPath);
    if (!fs.existsSync(fullPath)) continue;

    const isJsTs = hasAnalyzableExtension(relPath);
    const isPy = hasPartialAnalysisExtension(relPath);

    if (!isJsTs && !isPy) {
      if (isExplicitList) {
        skippedFiles.push({ filePath: relPath, reason: 'unsupported_language' });
      }
      continue;
    }

    const stat = fs.statSync(fullPath);
    if (stat.size > MAX_AUDIT_FILE_SIZE) {
      skippedFiles.push({ filePath: relPath, reason: 'file_too_large' });
      continue;
    }

    if (isPy) {
      partialFiles.push(relPath);
    }

    const code = fs.readFileSync(fullPath, 'utf-8');
    const allowlistRules = getAllowedRulesForPath(relPath, cfgRes.config.rulesByPath);

    const report = analyzeCodeDeterministically(code, {
      filePath: relPath,
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
      report.skor.totalScore < parsed.minScore;
    const passedFile =
      report.skor.totalScore >= parsed.minScore &&
      blockingFindings.length === 0 &&
      !hasFatalText;

    if (!passedFile) {
      hasBlockingFailure = true;
    }

    summaries.push({
      filePath: relPath,
      security: report.skor.security,
      correctness: report.skor.correctness,
      maintainability: report.skor.maintainability,
      overall: report.skor.totalScore,
      passed: passedFile,
      fatalFlaws:
        !passedFile && report.temuanUtama.description ? [report.temuanUtama.description] : [],
      defenseInDepth: report.temuanLain,
      inlineFindings: report.inlineFindings,
      suppressions: report.suppressions,
      layer2Status: 'Layer 2 (Gemini): Skipped [Offline]',
      dynScopeUncertain: report.dynScopeUncertain,
      foldLimitExceeded: report.virtualView?.limitExceeded,
    });
  }

  const overallScore =
    summaries.length === 0
      ? null
      : Math.round(summaries.reduce((acc, s) => acc + s.overall, 0) / summaries.length);
  const passed =
    !hasBlockingFailure && (overallScore === null || overallScore >= parsed.minScore);

  const checkResult: CliCheckResult = {
    version: getDevGuardVersion(),
    minScore: parsed.minScore,
    overallScore,
    passed,
    summaries,
    partialFiles,
    skippedFiles,
    workspaceDiagnostics: workspaceContext?.diagnostics ?? [],
  };

  const formatted = formatCliOutput(parsed.format, checkResult);
  if (parsed.outputPath !== null) {
    const resolvedOut = path.resolve(cwd, parsed.outputPath);
    fs.writeFileSync(resolvedOut, formatted, 'utf-8');
  } else {
    writeOut(formatted);
  }

  return passed ? 0 : 1;
}

function isDirectCliInvocation(): boolean {
  const entry = process.argv[1];
  if (!entry) return false;
  try {
    return pathToFileURL(path.resolve(entry)).href === import.meta.url;
  } catch {
    return false;
  }
}

if (isDirectCliInvocation()) {
  const code = runCli(process.argv.slice(2));
  process.exitCode = code;
}
