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
  verifyWorkspaceRegistryPackages,
  type AllowlistRuleId,
  type AuditedRegistryFileTarget,
  type AuditedRegistryManifestTarget,
  type RegistryFetchFn,
  type RegistryVerifyOptions,
  type WorkspaceContext,
  type WorkspaceFileAccessor,
} from '../../core/analyzer.ts';
import {
  getDevGuardVersion,
  type FileAuditSummary,
  type SkippedFileReportItem,
} from '../../core/types.ts';
import { getCliUsageText, parseCliArgs, type CliCheckOptions } from './args.ts';
import { formatCliOutput, type CliCheckResult } from './formatters.ts';
import { getChangedFilesSince, getStagedFiles } from './git.ts';
import { installPreCommitHook } from './hook.ts';
import { startMcpStdioServer } from '../mcp/index.ts';

const MAX_AUDIT_FILE_SIZE = 1_048_576; // 1 MiB ReDoS safety limit
const ALLOWED_ALLOWLIST_RULES = new Set<string>([
  'DG004',
  'DG004-DYN-01',
  'DG004-DYN-02',
  'DG004-REG-01',
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
  fetchImpl?: RegistryFetchFn;
  registryOptions?: Omit<RegistryVerifyOptions, 'fetchImpl'>;
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

interface PreparedCheckExecution {
  kind: 'ready';
  cwd: string;
  writeOut: (chunk: string) => void;
  writeErr: (chunk: string) => void;
  parsed: CliCheckOptions;
  checkResult: CliCheckResult;
  hasOperationalError: boolean;
  workspaceContext?: WorkspaceContext;
  localFsAccessor: WorkspaceFileAccessor;
  registryFileTargets: AuditedRegistryFileTarget[];
  registryManifestTargets: AuditedRegistryManifestTarget[];
}

function prepareCliExecution(
  argv: readonly string[],
  io: CliIo | undefined,
  allowAsyncVerifyRegistry: boolean
): { kind: 'early'; exitCode: number } | PreparedCheckExecution {
  const cwd = path.resolve(io?.cwd ?? process.cwd());
  const writeOut = io?.stdout ?? ((s: string) => process.stdout.write(s));
  const writeErr = io?.stderr ?? ((s: string) => process.stderr.write(s));

  const parsed = parseCliArgs(argv);
  if (parsed.kind === 'help') {
    writeOut(getCliUsageText() + '\n');
    return { kind: 'early', exitCode: 0 };
  }
  if (parsed.kind === 'version') {
    writeOut(getDevGuardVersion() + '\n');
    return { kind: 'early', exitCode: 0 };
  }
  if (parsed.kind === 'error') {
    writeErr(`Error: ${parsed.message}\n`);
    return { kind: 'early', exitCode: 2 };
  }
  if (parsed.kind === 'install-hook') {
    const hookRes = installPreCommitHook(cwd);
    if (!hookRes.ok) {
      writeErr(`Error: ${hookRes.error}\n`);
      return { kind: 'early', exitCode: 2 };
    }
    writeOut(`DevGuard pre-commit hook (${hookRes.status}): ${hookRes.hookPath}\n`);
    return { kind: 'early', exitCode: 0 };
  }
  if (parsed.kind === 'mcp') {
    const workspaceRoot = parsed.workspaceRoot ? path.resolve(cwd, parsed.workspaceRoot) : cwd;
    try {
      const stat = fs.statSync(workspaceRoot);
      if (!stat.isDirectory()) {
        writeErr(`Error: MCP workspace root is not a directory: ${workspaceRoot}\n`);
        return { kind: 'early', exitCode: 2 };
      }
    } catch (err) {
      const reason = err instanceof Error ? err.message : String(err);
      writeErr(`Error: Unable to access MCP workspace root "${workspaceRoot}": ${reason}\n`);
      return { kind: 'early', exitCode: 2 };
    }
    startMcpStdioServer({
      workspaceRoot,
      output: { write: writeOut },
      stderr: { write: writeErr },
    });
    return { kind: 'early', exitCode: 0 };
  }

  if (parsed.verifyRegistry && !allowAsyncVerifyRegistry) {
    writeErr(
      'Error: Option --verify-registry requires asynchronous execution; call await runCliAsync(argv, io) instead of synchronous runCli().\n'
    );
    return { kind: 'early', exitCode: 2 };
  }

  // 1. Load & validate local .devguard.json (strict fail-closed -> exit 2)
  const cfgRes = loadLocalConfigStrict(cwd, parsed.configPath);
  if (!cfgRes.ok) {
    writeErr(`Error: ${cfgRes.error}\n`);
    return { kind: 'early', exitCode: 2 };
  }

  // 2. Resolve target file list
  let baseDir = cwd;
  const candidateRelFiles: string[] = [];
  let isExplicitList = false;
  let hasDirectoryScan = false;

  if (parsed.staged) {
    const gitRes = getStagedFiles(cwd);
    if (!gitRes.ok) {
      writeErr(`Error: ${gitRes.error}\n`);
      return { kind: 'early', exitCode: 2 };
    }
    baseDir = gitRes.repoRoot;
    candidateRelFiles.push(...gitRes.files);
  } else if (parsed.changedSince !== null) {
    const gitRes = getChangedFilesSince(parsed.changedSince, cwd);
    if (!gitRes.ok) {
      writeErr(`Error: ${gitRes.error}\n`);
      return { kind: 'early', exitCode: 2 };
    }
    baseDir = gitRes.repoRoot;
    candidateRelFiles.push(...gitRes.files);
  } else if (parsed.paths.length > 0) {
    isExplicitList = true;
    for (const rawTarget of parsed.paths) {
      const resolvedTarget = path.resolve(cwd, rawTarget);
      let stat: fs.Stats;
      try {
        stat = fs.statSync(resolvedTarget);
      } catch (err) {
        const reason = err instanceof Error ? err.message : String(err);
        writeErr(`Error: Target path not accessible (${rawTarget}): ${reason}\n`);
        return { kind: 'early', exitCode: 2 };
      }
      if (stat.isDirectory()) {
        hasDirectoryScan = true;
        collectDirectoryFiles(resolvedTarget, cwd, candidateRelFiles);
      } else if (stat.isFile()) {
        candidateRelFiles.push(path.relative(cwd, resolvedTarget).replace(/\\/g, '/'));
      }
    }
  } else {
    hasDirectoryScan = true;
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
  const registryFileTargets: AuditedRegistryFileTarget[] = [];
  const inScopeManifestSet = new Set<string>();
  let hasBlockingFailure = false;
  let hasOperationalError = false;

  if (parsed.verifyRegistry && hasDirectoryScan && localFsAccessor.fileExists('package.json')) {
    inScopeManifestSet.add('package.json');
  }

  for (const relPath of uniqueFiles) {
    const fullPath = path.resolve(baseDir, relPath);
    if (parsed.staged || parsed.changedSince !== null) {
      const contained = path.relative(baseDir, fullPath);
      if (contained.startsWith('..') || path.isAbsolute(contained)) {
        writeErr(`Error: Refusing path outside repository root: ${relPath}\n`);
        return { kind: 'early', exitCode: 2 };
      }
    }

    let stat: fs.Stats;
    try {
      stat = fs.statSync(fullPath);
    } catch (err) {
      const codeErr = (err as { code?: string })?.code;
      if (!isExplicitList && codeErr === 'ENOENT') {
        continue;
      }
      const reason = err instanceof Error ? err.message : String(err);
      writeErr(`Error: Unable to inspect file "${relPath}": ${reason}\n`);
      skippedFiles.push({ filePath: relPath, reason: 'internal_error' });
      hasOperationalError = true;
      continue;
    }

    if (!stat.isFile()) {
      continue;
    }

    const isJsTs = hasAnalyzableExtension(relPath);
    const isPy = hasPartialAnalysisExtension(relPath);

    if (!isJsTs && !isPy) {
      if (parsed.verifyRegistry && /(?:^|\/)package\.json$/.test(relPath)) {
        inScopeManifestSet.add(relPath);
      } else if (isExplicitList) {
        skippedFiles.push({ filePath: relPath, reason: 'unsupported_language' });
      }
      continue;
    }

    if (stat.size > MAX_AUDIT_FILE_SIZE) {
      skippedFiles.push({ filePath: relPath, reason: 'file_too_large' });
      continue;
    }

    if (isPy) {
      partialFiles.push(relPath);
    }

    let code: string;
    try {
      code = fs.readFileSync(fullPath, 'utf-8');
    } catch (err) {
      const reason = err instanceof Error ? err.message : String(err);
      writeErr(`Error: Unable to read file "${relPath}": ${reason}\n`);
      skippedFiles.push({ filePath: relPath, reason: 'internal_error' });
      hasOperationalError = true;
      continue;
    }

    const allowlistRules = getAllowedRulesForPath(relPath, cfgRes.config.rulesByPath);

    if (parsed.verifyRegistry && isJsTs) {
      registryFileTargets.push({
        filePath: relPath,
        code,
        allowlistRules: allowlistRules.length > 0 ? allowlistRules : undefined,
      });
    }

    let report: ReturnType<typeof analyzeCodeDeterministically>;
    try {
      report = analyzeCodeDeterministically(code, {
        filePath: relPath,
        externalAllowlist: allowlistRules.length > 0 ? allowlistRules : undefined,
        workspaceContext,
        workspaceFileAccessor: localFsAccessor,
        workspacesMode: cfgRes.config.workspacesMode,
      });
    } catch (err) {
      const reason = err instanceof Error ? err.message : String(err);
      writeErr(`Error: Internal analyzer failure on "${relPath}": ${reason}\n`);
      skippedFiles.push({ filePath: relPath, reason: 'internal_error' });
      hasOperationalError = true;
      continue;
    }

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
        !passedFile &&
        report.temuanUtama.description &&
        !report.temuanUtama.description.startsWith('Mitigasi utama terverifikasi') &&
        !report.temuanUtama.description.startsWith('Kode telah melewati')
          ? [report.temuanUtama.description]
          : [],
      defenseInDepth:
        report.residualNotes && report.residualNotes.length > 0
          ? report.residualNotes
          : report.temuanLain.filter((t) => t.includes('[Defense-in-Depth]')),
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
    !hasOperationalError &&
    !hasBlockingFailure &&
    (overallScore === null || overallScore >= parsed.minScore);

  const registryManifestTargets: AuditedRegistryManifestTarget[] = Array.from(inScopeManifestSet)
    .sort()
    .map((manifestPath) => {
      const rules = getAllowedRulesForPath(manifestPath, cfgRes.config.rulesByPath);
      return {
        manifestPath,
        allowlistRules: rules.length > 0 ? rules : undefined,
      };
    });

  const checkResult: CliCheckResult = {
    version: getDevGuardVersion(),
    minScore: parsed.minScore,
    overallScore,
    passed,
    summaries,
    partialFiles,
    skippedFiles,
    workspaceDiagnostics: [...(workspaceContext?.diagnostics ?? [])],
  };

  return {
    kind: 'ready',
    cwd,
    writeOut,
    writeErr,
    parsed,
    checkResult,
    hasOperationalError,
    workspaceContext,
    localFsAccessor,
    registryFileTargets,
    registryManifestTargets,
  };
}

function finalizeCliCheckOutput(prep: PreparedCheckExecution): number {
  let formatted: string;
  try {
    formatted = formatCliOutput(prep.parsed.format, prep.checkResult);
  } catch (err) {
    const reason = err instanceof Error ? err.message : String(err);
    prep.writeErr(`Error: Failed to format CLI output: ${reason}\n`);
    return 2;
  }

  if (prep.parsed.outputPath !== null) {
    const resolvedOut = path.resolve(prep.cwd, prep.parsed.outputPath);
    try {
      fs.writeFileSync(resolvedOut, formatted, 'utf-8');
    } catch (err) {
      const reason = err instanceof Error ? err.message : String(err);
      prep.writeErr(`Error: Unable to write output file "${prep.parsed.outputPath}": ${reason}\n`);
      return 2;
    }
  } else {
    prep.writeOut(formatted);
  }

  if (prep.hasOperationalError) {
    return 2;
  }

  return prep.checkResult.passed ? 0 : 1;
}

/**
 * Executes the zero-dependency DevGuard CLI adapter synchronously (offline deterministic).
 * Note: `--verify-registry` requires `await runCliAsync(argv, io)`.
 * Exit codes:
 *   0 = pass
 *   1 = audit gate failed
 *   2 = operational / argument / config / git error
 */
export function runCli(argv: readonly string[], io?: CliIo): number {
  const prep = prepareCliExecution(argv, io, false);
  if (prep.kind === 'early') {
    return prep.exitCode;
  }
  return finalizeCliCheckOutput(prep);
}

/**
 * Asynchronous DevGuard CLI entrypoint supporting opt-in `--verify-registry` online verification
 * while preserving 100% identical deterministic behavior when `--verify-registry` is omitted.
 */
export async function runCliAsync(argv: readonly string[], io?: CliIo): Promise<number> {
  const prep = prepareCliExecution(argv, io, true);
  if (prep.kind === 'early') {
    return prep.exitCode;
  }

  if (prep.parsed.verifyRegistry) {
    const regRes = await verifyWorkspaceRegistryPackages({
      auditedFiles: prep.registryFileTargets,
      inScopeManifests: prep.registryManifestTargets,
      workspaceContext: prep.workspaceContext,
      workspaceFileAccessor: prep.localFsAccessor,
      options: {
        ...io?.registryOptions,
        ...(io?.fetchImpl ? { fetchImpl: io.fetchImpl } : {}),
      },
    });

    for (const summary of prep.checkResult.summaries) {
      const regInline = regRes.inlineFindingsByFile.get(summary.filePath);
      if (regInline && regInline.length > 0) {
        const merged = [...(summary.inlineFindings ?? []), ...regInline];
        merged.sort((a, b) => a.line - b.line);
        summary.inlineFindings = merged;
      }
      const regSup = regRes.suppressionsByFile.get(summary.filePath);
      if (regSup && regSup.length > 0) {
        const mergedSup = [...(summary.suppressions ?? []), ...regSup];
        mergedSup.sort((a, b) => a.targetLine - b.targetLine);
        summary.suppressions = mergedSup;
      }
    }

    if (regRes.diagnostics.length > 0) {
      prep.checkResult.workspaceDiagnostics.push(...regRes.diagnostics);
    }
  }

  return finalizeCliCheckOutput(prep);
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
  void runCliAsync(process.argv.slice(2)).then((code) => {
    process.exitCode = code;
  });
}
