#!/usr/bin/env node
import * as fs from 'node:fs';
import * as path from 'node:path';
import { execFileSync } from 'node:child_process';
import { builtinModules } from 'node:module';
import {
  analyzeCodeDeterministically,
  isValidSuppressionReason,
  prepareRedactedCodeForLlm,
  redactSecretsPreservingLayout,
  type ParsedDevGuardReport,
} from './devguardAnalyzer.js';
import {
  detectPrEnvironment,
  postInlineReviewComments,
  postPullRequestComment,
  type FileAuditSummary,
  type PrEnvironmentInfo,
} from './githubCommenter.js';
import { generateSarifReport } from './sarifGenerator.js';

function loadDotEnvIfPresent(): void {
  try {
    const envPath = path.resolve(process.cwd(), '.env');
    if (!fs.existsSync(envPath)) return;
    const raw = fs.readFileSync(envPath, 'utf-8');
    for (const line of raw.split(/\r?\n/)) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith('#')) continue;
      const eqIdx = trimmed.indexOf('=');
      if (eqIdx <= 0) continue;
      const key = trimmed.slice(0, eqIdx).trim();
      let value = trimmed.slice(eqIdx + 1).trim();
      if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) {
        value = value.slice(1, -1);
      }
      if (key && process.env[key] === undefined) {
        process.env[key] = value;
      }
    }
  } catch {
    return;
  }
}

loadDotEnvIfPresent();

function writeGitHubOutput(outputFile: string | undefined, key: string, value: string | number): void {
  if (!outputFile || !fs.existsSync(outputFile)) return;
  const safeKey = String(key).replace(/[\r\n=]/g, '');
  const safeValue = String(value).replace(/[\r\n]+/g, ' ').trim();
  fs.appendFileSync(outputFile, `${safeKey}=${safeValue}\n`);
}

export interface CliAuditResult {
  mode: 'zero-api' | 'hybrid';
  isLiveApi: boolean;
  layer2Status?: string;
  parsedReport: ParsedDevGuardReport;
}

let loggedRedactedTransmissionNotice = false;

export interface AllowlistRuleEntry {
  rule: 'DG004' | 'DG006';
  reason: string;
}

export interface LoadAllowlistOptions {
  cwd?: string;
  baseRef?: string;
  eventName?: string;
  beforeSha?: string;
  eventPath?: string;
  isCi?: boolean;
  readBaseFile?: (refSpec: string) => string | null;
  readWorkingFile?: (filePath: string) => string | null;
}

export interface VerifiedAllowlistResult {
  rulesByPath: Map<string, AllowlistRuleEntry[]>;
  invalidAllowlistEntries: string[];
  allowlistModifiedInPr: boolean;
  sourceMode: 'base-pr' | 'base-push' | 'local' | 'empty';
}

function readBeforeShaFromEventFile(eventPath: string | undefined): string | undefined {
  if (!eventPath || !fs.existsSync(eventPath)) return undefined;
  try {
    const parsed = JSON.parse(fs.readFileSync(eventPath, 'utf-8')) as { before?: string };
    return typeof parsed.before === 'string' ? parsed.before : undefined;
  } catch {
    return undefined;
  }
}

function isValidAllowlistPathKey(rawKey: string): string | null {
  const norm = rawKey.trim().replace(/\\/g, '/').replace(/^\.\//, '');
  if (
    !norm ||
    norm === '*' ||
    norm === '**' ||
    norm.startsWith('**/') ||
    norm.startsWith('/') ||
    norm.split('/').includes('..')
  ) {
    return null;
  }
  if (norm.includes('*')) {
    return /^[^*]+\/\*\*$/.test(norm) ? norm : null;
  }
  return norm;
}

function ensureOriginBaseRefFetched(baseRef: string | undefined, cwd: string): void {
  if (!baseRef || baseRef.startsWith('-')) return;
  try {
    execFileSync('git', ['rev-parse', '--verify', `origin/${baseRef}`], {
      cwd,
      stdio: ['ignore', 'ignore', 'ignore'],
    });
    return;
  } catch {
    // Shallow clone lacks origin/<baseRef>; perform best-effort fetch
  }
  try {
    execFileSync('git', ['fetch', '--no-tags', '--depth=1', 'origin', baseRef], {
      cwd,
      stdio: ['ignore', 'ignore', 'ignore'],
    });
  } catch {
    // Fail safe if remote/git is unavailable
  }
}

/**
 * Loads `.devguard.json` using base-branch verification on PR/push CI events so PR authors
 * cannot weaken security rules inside the same PR. Fails closed to empty allowlist on git errors.
 */
export function loadVerifiedAllowlist(options?: LoadAllowlistOptions): VerifiedAllowlistResult {
  const cwd = options?.cwd || process.cwd();
  const baseRef = options?.baseRef !== undefined ? options.baseRef : process.env.GITHUB_BASE_REF;
  const eventName =
    options?.eventName !== undefined
      ? options.eventName
      : options?.baseRef
        ? 'pull_request'
        : process.env.GITHUB_EVENT_NAME;
  const beforeSha =
    options?.beforeSha !== undefined
      ? options.beforeSha
      : readBeforeShaFromEventFile(options?.eventPath ?? process.env.GITHUB_EVENT_PATH);
  const isCi =
    options?.isCi !== undefined ? options.isCi : process.env.GITHUB_ACTIONS === 'true';

  if (baseRef && eventName !== 'push' && !options?.readBaseFile) {
    ensureOriginBaseRefFetched(baseRef, cwd);
  }

  const readBase =
    options?.readBaseFile ||
    ((refSpec: string): string | null => {
      try {
        return execFileSync('git', ['show', refSpec], {
          cwd,
          encoding: 'utf-8',
          stdio: ['ignore', 'pipe', 'ignore'],
        });
      } catch {
        return null;
      }
    });

  const readWorking =
    options?.readWorkingFile ||
    ((filePath: string): string | null => {
      try {
        return fs.existsSync(filePath) ? fs.readFileSync(filePath, 'utf-8') : null;
      } catch {
        return null;
      }
    });

  const workingRaw = readWorking(path.join(cwd, '.devguard.json'));
  let activeRaw: string | null = null;
  let sourceMode: VerifiedAllowlistResult['sourceMode'] = 'empty';
  let allowlistModifiedInPr = false;

  if (baseRef && eventName !== 'push') {
    sourceMode = 'base-pr';
    activeRaw = readBase(`origin/${baseRef}:.devguard.json`);
    if (workingRaw !== null && (activeRaw === null || workingRaw.trim() !== activeRaw.trim())) {
      allowlistModifiedInPr = true;
    }
  } else if (eventName === 'push' && beforeSha && !/^0+$/.test(beforeSha)) {
    sourceMode = 'base-push';
    activeRaw = readBase(`${beforeSha}:.devguard.json`);
    if (workingRaw !== null && (activeRaw === null || workingRaw.trim() !== activeRaw.trim())) {
      allowlistModifiedInPr = true;
    }
  } else if (!isCi && workingRaw !== null) {
    sourceMode = 'local';
    activeRaw = workingRaw;
    console.warn('Warning: local mode, unverified allowlist (.devguard.json)');
  }

  const rulesByPath = new Map<string, AllowlistRuleEntry[]>();
  const invalidAllowlistEntries: string[] = [];

  if (!activeRaw) {
    return { rulesByPath, invalidAllowlistEntries, allowlistModifiedInPr, sourceMode };
  }

  let parsedJson: unknown;
  try {
    parsedJson = JSON.parse(activeRaw);
  } catch {
    invalidAllowlistEntries.push('Malformed JSON in .devguard.json');
    return { rulesByPath, invalidAllowlistEntries, allowlistModifiedInPr, sourceMode };
  }

  const rawMap = (parsedJson as { ignoreRulesByPath?: unknown })?.ignoreRulesByPath;
  if (!rawMap || typeof rawMap !== 'object' || Array.isArray(rawMap)) {
    invalidAllowlistEntries.push('.devguard.json must contain an ignoreRulesByPath object');
    return { rulesByPath, invalidAllowlistEntries, allowlistModifiedInPr, sourceMode };
  }

  for (const [rawKey, rawEntries] of Object.entries(rawMap as Record<string, unknown>)) {
    const validKey = isValidAllowlistPathKey(rawKey);
    if (!validKey) {
      invalidAllowlistEntries.push(`Rejected invalid path pattern: "${rawKey}"`);
      continue;
    }
    if (!Array.isArray(rawEntries)) {
      invalidAllowlistEntries.push(`Rejected non-array allowlist entry list for "${rawKey}"`);
      continue;
    }

    const accepted: AllowlistRuleEntry[] = [];
    for (const item of rawEntries) {
      const candidate = item as { rule?: unknown; reason?: unknown };
      if (candidate.rule !== 'DG004' && candidate.rule !== 'DG006') {
        invalidAllowlistEntries.push(`Rejected disallowed allowlist rule "${String(candidate.rule)}" for "${validKey}"`);
        continue;
      }
      if (!isValidSuppressionReason(candidate.reason)) {
        invalidAllowlistEntries.push(`Rejected short/missing reason for ${candidate.rule} under "${validKey}"`);
        continue;
      }
      accepted.push({ rule: candidate.rule, reason: candidate.reason.trim() });
    }
    if (accepted.length > 0) {
      rulesByPath.set(validKey, accepted);
    }
  }

  return { rulesByPath, invalidAllowlistEntries, allowlistModifiedInPr, sourceMode };
}

export function matchAllowlistForFile(
  allowlist: VerifiedAllowlistResult,
  filePath: string,
  cwd: string = process.cwd()
): AllowlistRuleEntry[] {
  const relPath = path.isAbsolute(filePath) ? path.relative(cwd, filePath) : filePath;
  const posixRel = relPath.replace(/\\/g, '/').replace(/^\.\//, '');
  const matched: AllowlistRuleEntry[] = [];

  for (const [pattern, entries] of allowlist.rulesByPath.entries()) {
    if (pattern.endsWith('/**')) {
      const dirPrefix = pattern.slice(0, -2); // keep trailing '/'
      if (posixRel.startsWith(dirPrefix)) {
        matched.push(...entries);
      }
    } else if (posixRel === pattern) {
      matched.push(...entries);
    }
  }
  return matched;
}

function resolveNearestPackageInfo(filePath: string): {
  declaredDependencies?: Set<string>;
  subpathImports?: Record<string, unknown>;
} {
  try {
    const mergedDeps = new Set<string>();
    let foundAny = false;
    let mergedImports: Record<string, unknown> | undefined;

    let currentDir = path.dirname(path.resolve(filePath));
    while (true) {
      const pkgPath = path.join(currentDir, 'package.json');
      if (fs.existsSync(pkgPath)) {
        foundAny = true;
        const parsed = JSON.parse(fs.readFileSync(pkgPath, 'utf-8')) as {
          dependencies?: Record<string, unknown>;
          devDependencies?: Record<string, unknown>;
          peerDependencies?: Record<string, unknown>;
          imports?: Record<string, unknown>;
        };
        for (const dep of [
          ...Object.keys(parsed.dependencies || {}),
          ...Object.keys(parsed.devDependencies || {}),
          ...Object.keys(parsed.peerDependencies || {}),
        ]) {
          mergedDeps.add(dep);
        }
        if (parsed.imports && typeof parsed.imports === 'object') {
          mergedImports = { ...parsed.imports, ...(mergedImports || {}) };
        }
      }
      const parentDir = path.dirname(currentDir);
      if (parentDir === currentDir) break;
      currentDir = parentDir;
    }

    return {
      declaredDependencies: foundAny ? mergedDeps : undefined,
      subpathImports: mergedImports,
    };
  } catch {
    return {};
  }
}

function resolvePrEnvironmentFromEnv(): PrEnvironmentInfo {
  const eventPath = process.env.GITHUB_EVENT_PATH;
  if (!eventPath || !fs.existsSync(eventPath)) {
    return { isPullRequest: false, isFork: false };
  }
  try {
    const raw = fs.readFileSync(eventPath, 'utf-8');
    return detectPrEnvironment(JSON.parse(raw));
  } catch {
    return { isPullRequest: false, isFork: false };
  }
}

export async function evaluateCodeHybrid(
  code: string,
  apiKey?: string,
  precomputedL1?: ParsedDevGuardReport,
  filePath?: string,
  externalAllowlist?: ReadonlyArray<AllowlistRuleEntry>,
  isFork?: boolean
): Promise<CliAuditResult> {
  const pkgInfo = filePath ? resolveNearestPackageInfo(filePath) : {};
  const l1Result = precomputedL1 || analyzeCodeDeterministically(code, {
    filePath,
    declaredDependencies: pkgInfo.declaredDependencies,
    subpathImports: pkgInfo.subpathImports,
    builtinModules,
    externalAllowlist,
  });

  const effectiveIsFork = isFork ?? resolvePrEnvironmentFromEnv().isFork;
  if (effectiveIsFork) {
    return {
      mode: 'zero-api',
      isLiveApi: false,
      layer2Status: 'Skipped: Fork PR',
      parsedReport: l1Result,
    };
  }

  const activeKey = apiKey !== undefined ? apiKey : process.env.GEMINI_API_KEY;

  if (!activeKey) {
    return {
      mode: 'zero-api',
      isLiveApi: false,
      layer2Status: 'Skipped: No API Key',
      parsedReport: l1Result,
    };
  }

  if (activeKey === 'MY_GEMINI_API_KEY' || !activeKey.startsWith('AIzaSy')) {
    return {
      mode: 'zero-api',
      isLiveApi: false,
      layer2Status: 'Skipped: Offline',
      parsedReport: l1Result,
    };
  }

  const redactionGate = prepareRedactedCodeForLlm(filePath || 'input.ts', code);
  if (redactionGate.aborted) {
    console.warn(`🛡️  Layer 2 dilewati (fail-closed abort pada ${filePath || 'input'}): ${redactionGate.reason}`);
    return {
      mode: 'zero-api',
      isLiveApi: false,
      layer2Status: 'Skipped: Redaction Abort',
      parsedReport: l1Result,
    };
  }

  if (!loggedRedactedTransmissionNotice) {
    console.log('ℹ️  Layer 2 Gemini aktif: kode sumber yang telah diredaksi dikirim ke Gemini API untuk evaluasi semantik.');
    loggedRedactedTransmissionNotice = true;
  }

  try {
    const prompt = [
      'Anda adalah Principal AppSec Engineer & Zero-Leniency Adversarial Code Auditor.',
      'Evaluasi kode di dalam <code_to_review> secara jujur, ketat, dan tanpa kompromi.',
      'DILARANG memberikan skor buta 100/100.',
      '',
      `Hasil deteksi Layer 1 Single-Pass Lexical & Heuristic Engine (wajib dihormati sebagai batas atas skor):`,
      `- Security=${l1Result.skor.security}, Correctness=${l1Result.skor.correctness}, Maintainability=${l1Result.skor.maintainability}`,
      `- Baris Temuan: ${l1Result.temuanUtama.line}`,
      `- Detail: ${redactSecretsPreservingLayout(l1Result.temuanUtama.description)}`,
      '',
      '<code_to_review>',
      redactionGate.safeCode,
      '</code_to_review>',
    ].join('\n');

    const model = 'gemini-3.8-flash';
    const geminiUrl = `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent`;
    const apiResponse = await fetch(geminiUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-goog-api-key': activeKey,
      },
      signal: AbortSignal.timeout(6500),
      body: JSON.stringify({
        contents: [{ parts: [{ text: prompt }] }],
        generationConfig: {
          temperature: 0.1,
          responseMimeType: 'application/json',
          responseSchema: {
            type: 'OBJECT',
            properties: {
              apresiasi: { type: 'STRING' },
              skor: {
                type: 'OBJECT',
                properties: {
                  security: { type: 'INTEGER' },
                  securityDeductions: { type: 'ARRAY', items: { type: 'STRING' } },
                  correctness: { type: 'INTEGER' },
                  correctnessDeductions: { type: 'ARRAY', items: { type: 'STRING' } },
                  maintainability: { type: 'INTEGER' },
                  maintainabilityDeductions: { type: 'ARRAY', items: { type: 'STRING' } },
                },
                required: ['security', 'correctness', 'maintainability'],
              },
              temuanUtama: {
                type: 'OBJECT',
                properties: {
                  line: { type: 'STRING' },
                  description: { type: 'STRING' },
                },
                required: ['line', 'description'],
              },
              temuanLain: { type: 'ARRAY', items: { type: 'STRING' } },
              analogi: {
                type: 'OBJECT',
                properties: {
                  story: { type: 'STRING' },
                  technicalTerm: { type: 'STRING' },
                },
                required: ['story', 'technicalTerm'],
              },
              perbaikanSummary: { type: 'STRING' },
            },
            required: ['apresiasi', 'skor', 'temuanUtama', 'analogi'],
          },
        },
      }),
    });

    if (!apiResponse.ok) {
      const errBody = await apiResponse.text();
      throw new Error(`Gemini HTTP ${apiResponse.status}: ${errBody}`);
    }

    const payload = (await apiResponse.json()) as {
      candidates?: Array<{ content?: { parts?: Array<{ text?: string }> } }>;
      text?: string;
    };
    const candidateText =
      payload.candidates?.[0]?.content?.parts?.map((p) => p.text || '').join('') ??
      payload.text ??
      '';

    const rawResponseText = redactSecretsPreservingLayout(candidateText.trim());
    const geminiData = JSON.parse(rawResponseText);

    // Ceilings enforced by Layer 1 zero-leniency rubric; hallucination gate prevents unverified LLM prose
    // from dragging a clean Layer 1 file (0 findings, totalScore >= 90) below minScore.
    const rawMinScore = parseInt(process.env.DEVGUARD_MIN_SCORE || '85', 10);
    const minScore = Number.isFinite(rawMinScore) ? rawMinScore : 85;
    const isLayer1Clean =
      (l1Result.inlineFindings?.length ?? 0) === 0 &&
      l1Result.temuanUtama.line === '-' &&
      l1Result.skor.totalScore >= 90;

    const rawSecurity = Math.min(l1Result.skor.security, geminiData.skor?.security ?? 100);
    const rawCorrectness = Math.min(l1Result.skor.correctness, geminiData.skor?.correctness ?? 100);
    const rawMaintainability = Math.min(l1Result.skor.maintainability, geminiData.skor?.maintainability ?? 100);

    const reconciledSecurity = isLayer1Clean ? Math.max(minScore, rawSecurity) : rawSecurity;
    const reconciledCorrectness = isLayer1Clean ? Math.max(minScore, rawCorrectness) : rawCorrectness;
    const reconciledMaintainability = isLayer1Clean ? Math.max(minScore, rawMaintainability) : rawMaintainability;
    const rawTotal = Math.round((reconciledSecurity + reconciledCorrectness + reconciledMaintainability) / 3);
    const reconciledTotal = isLayer1Clean ? Math.max(minScore, rawTotal) : rawTotal;

    const redactList = (items?: string[]): string[] | undefined =>
      items?.length ? items.map((s) => redactSecretsPreservingLayout(String(s))) : undefined;

    return {
      mode: 'hybrid',
      isLiveApi: true,
      layer2Status: 'Verified',
      parsedReport: {
        ...l1Result,
        apresiasi: geminiData.apresiasi ? redactSecretsPreservingLayout(String(geminiData.apresiasi)) : l1Result.apresiasi,
        skor: {
          security: reconciledSecurity,
          securityDeductions: redactList(geminiData.skor?.securityDeductions) || l1Result.skor.securityDeductions,
          correctness: reconciledCorrectness,
          correctnessDeductions: redactList(geminiData.skor?.correctnessDeductions) || l1Result.skor.correctnessDeductions,
          maintainability: reconciledMaintainability,
          maintainabilityDeductions:
            redactList(geminiData.skor?.maintainabilityDeductions) || l1Result.skor.maintainabilityDeductions,
          totalScore: reconciledTotal,
        },
        temuanUtama: {
          line: l1Result.temuanUtama.line !== '-' ? l1Result.temuanUtama.line : (geminiData.temuanUtama?.line || '-'),
          description: geminiData.temuanUtama?.description
            ? redactSecretsPreservingLayout(String(geminiData.temuanUtama.description))
            : l1Result.temuanUtama.description,
        },
        temuanLain: redactList(geminiData.temuanLain) || l1Result.temuanLain,
        analogi: {
          story: geminiData.analogi?.story
            ? redactSecretsPreservingLayout(String(geminiData.analogi.story))
            : l1Result.analogi.story,
          technicalTerm: geminiData.analogi?.technicalTerm
            ? redactSecretsPreservingLayout(String(geminiData.analogi.technicalTerm))
            : l1Result.analogi.technicalTerm,
        },
      },
    };
  } catch (err: unknown) {
    const errMsg = redactSecretsPreservingLayout(err instanceof Error ? err.message : String(err));
    console.warn(`⚠️  Gemini API error (${errMsg}). Otomatis dialihkan ke Layer 1 Single-Pass Lexical & Heuristic Engine.`);
    return {
      mode: 'zero-api',
      isLiveApi: false,
      layer2Status: 'Skipped: Quota/Error Fallback',
      parsedReport: l1Result,
    };
  }
}

function resolveCliFileArgs(args: string[]): string[] {
  const resolved: string[] = [];
  for (const rawArg of args) {
    if (rawArg.startsWith('--')) continue;
    if (fs.existsSync(rawArg)) {
      resolved.push(rawArg);
      continue;
    }
    if (rawArg.includes('*')) {
      const dir = path.dirname(rawArg);
      const pattern = path.basename(rawArg).replace(/[.+?^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*');
      const matcher = new RegExp(`^${pattern}$`);
      if (fs.existsSync(dir)) {
        for (const entry of fs.readdirSync(dir)) {
          if (matcher.test(entry)) {
            resolved.push(path.join(dir, entry));
          }
        }
      }
    }
  }
  return Array.from(new Set(resolved));
}

export const MAX_AUDIT_FILE_BYTES = 1_048_576;

const AUTO_DISCOVERY_EXCLUDED_DIRS = new Set([
  'node_modules',
  'dist',
  'build',
  'coverage',
  'remotion',
  'out',
  'tests',
  'scripts',
]);

/** Returns true when a path belongs to tests, scripts, build artifacts, or excluded self-reference files. */
export function isExcludedFromAutoDiscovery(filePath: string, cwd: string = process.cwd()): boolean {
  const rel = path.isAbsolute(filePath) ? path.relative(cwd, filePath) : filePath;
  const posix = rel.replace(/\\/g, '/').replace(/^\.\//, '');
  if (!posix || posix.startsWith('..')) return true;

  const segments = posix.split('/');
  const fileName = segments[segments.length - 1] || '';
  if (segments.some((seg) => seg.startsWith('.') && seg !== '.')) return true;
  if (segments.some((seg) => AUTO_DISCOVERY_EXCLUDED_DIRS.has(seg))) return true;

  return (
    !/\.(py|ts|js|jsx|tsx)$/.test(fileName) ||
    fileName.endsWith('.d.ts') ||
    fileName.includes('.test.') ||
    fileName.includes('.spec.') ||
    fileName === 'devguardAnalyzer.ts' ||
    fileName === 'devguard_verify.py'
  );
}

/** Discovers workspace audit targets automatically for `'modified'` (git diff) or `'all'` mode. */
export function discoverWorkspaceFiles(mode: 'modified' | 'all', cwd: string = process.cwd()): string[] {
  if (mode === 'all') {
    const scanDir = (dir: string): string[] => {
      const results: string[] = [];
      const list = fs.readdirSync(dir, { withFileTypes: true });
      for (const item of list) {
        if (item.name.startsWith('.') || AUTO_DISCOVERY_EXCLUDED_DIRS.has(item.name)) {
          continue;
        }
        const full = path.join(dir, item.name);
        if (item.isDirectory()) {
          results.push(...scanDir(full));
        } else if (!isExcludedFromAutoDiscovery(full, cwd)) {
          results.push(full);
        }
      }
      return results;
    };
    return scanDir(cwd);
  }

  const baseRef = process.env.GITHUB_BASE_REF;
  if (baseRef) {
    ensureOriginBaseRefFetched(baseRef, cwd);
  }

  const runGitDiff = (args: string[]): string | null => {
    try {
      return execFileSync('git', args, {
        cwd,
        encoding: 'utf-8',
        stdio: ['ignore', 'pipe', 'ignore'],
      });
    } catch {
      return null;
    }
  };

  let diffOutput: string | null = null;
  if (baseRef && !baseRef.startsWith('-')) {
    diffOutput = runGitDiff(['diff', '--name-only', `origin/${baseRef}...HEAD`]);
  }
  if (diffOutput === null) {
    diffOutput = runGitDiff(['diff', '--name-only', 'HEAD~1', 'HEAD']) ?? runGitDiff(['diff', '--name-only', 'HEAD']);
  }

  if (diffOutput === null) {
    console.warn('⚠️  Git diff tidak menemukan riwayat commit; beralih ke pengecekan berkas lokal.');
    return [];
  }

  return diffOutput
    .split('\n')
    .map((f) => f.trim())
    .filter((f) => Boolean(f) && !isExcludedFromAutoDiscovery(f, cwd));
}

export async function runAction() {
  if (process.env.GITHUB_EVENT_NAME === 'pull_request_target') {
    console.error(
      '🚨 Fatal Security Error: Running DevGuard on pull_request_target is forbidden due to pwn-request secret-exfiltration risks. Switch workflow trigger to pull_request.'
    );
    process.exit(1);
  }

  const apiKey = process.env.GEMINI_API_KEY;
  const minScore = parseInt(process.env.DEVGUARD_MIN_SCORE || '85', 10);
  const targetPattern = process.env.DEVGUARD_TARGET || 'modified';
  const prEnv = resolvePrEnvironmentFromEnv();
  const explicitFileArgs = resolveCliFileArgs(process.argv.slice(2));
  const engineMode: 'HYBRID' | 'OFFLINE_AST' =
    !prEnv.isFork && apiKey && apiKey !== 'MY_GEMINI_API_KEY' && apiKey.startsWith('AIzaSy')
      ? 'HYBRID'
      : 'OFFLINE_AST';

  console.log('======================================================================');
  console.log('           🛡️  DEVGUARD ADVERSARIAL CODE AUDITOR (CI GATE)            ');
  console.log('======================================================================');
  console.log(`Ambang Batas Kelulusan CI : Minimal ${minScore}/100`);

  if (prEnv.isFork) {
    console.log('Mode Eksekusi             : 🛡️  Zero-API (Fork PR — Layer 2 Gemini dinonaktifkan)');
  } else if (engineMode === 'OFFLINE_AST') {
    console.log('Mode Eksekusi             : 🛡️  Zero-API (100% Offline Single-Pass Lexical & Heuristic Engine - Gratis)');
  } else {
    console.log('Mode Eksekusi             : 🤖 Hybrid Dual-Layer (Lexical & Heuristic + Gemini 3.8 Flash)');
  }

  // 1. Dapatkan daftar berkas target
  const filesToAudit: string[] =
    explicitFileArgs.length > 0
      ? explicitFileArgs
      : discoverWorkspaceFiles(targetPattern === 'all' ? 'all' : 'modified', process.cwd());

  if (filesToAudit.length === 0) {
    console.log('\n✅ Tidak ada berkas target (.py, .ts, .js) yang diubah. DevGuard quality check lolos.');
    const sarifFile = process.env.DEVGUARD_SARIF_OUTPUT || 'devguard-results.sarif';
    generateSarifReport([], sarifFile);
    const outputFile = process.env.GITHUB_OUTPUT;
    writeGitHubOutput(outputFile, 'overall_score', 100);
    writeGitHubOutput(outputFile, 'audit_status', 'PASS');
    writeGitHubOutput(outputFile, 'sarif_file', sarifFile);
    process.exit(0);
  }

  console.log(`\n📂 Jumlah berkas yang akan diaudit: ${filesToAudit.length}`);
  console.log('----------------------------------------------------------------------');

  const verifiedAllowlist = loadVerifiedAllowlist();

  let hasFatalFailure = false;
  let totalScoreSum = 0;
  let auditedCount = 0;
  const summaries: FileAuditSummary[] = [];

  for (const filePath of filesToAudit) {
    if (!fs.existsSync(filePath)) continue;
    const stats = fs.statSync(filePath);
    if (stats.size > MAX_AUDIT_FILE_BYTES) {
      console.warn(`⚠️  Skipped: File exceeds 1MB ReDoS safety limit (${filePath}, ${stats.size} bytes)`);
      continue;
    }

    const codeContent = fs.readFileSync(filePath, 'utf-8');
    auditedCount++;

    console.log(`\n🔍 Menganalisis: ${filePath}`);
    const fileExternalAllowlist = matchAllowlistForFile(verifiedAllowlist, filePath);
    const result = await evaluateCodeHybrid(
      codeContent,
      apiKey,
      undefined,
      filePath,
      fileExternalAllowlist,
      prEnv.isFork
    );
    const report = result.parsedReport;
    const score = report.skor;
    const hasInlineErrors = report.inlineFindings?.some((f) => f.severity === 'error') ?? false;
    const passed = !(score.totalScore < minScore || (!report.isHardened && score.security < 70) || hasInlineErrors);

    totalScoreSum += score.totalScore;
    summaries.push({
      filePath,
      security: score.security,
      correctness: score.correctness,
      maintainability: score.maintainability,
      overall: score.totalScore,
      passed,
      fatalFlaws:
        !passed && report.temuanUtama.description
          ? [redactSecretsPreservingLayout(report.temuanUtama.description)]
          : [],
      defenseInDepth: (report.residualNotes || []).map((n) => redactSecretsPreservingLayout(n)),
      inlineFindings: report.inlineFindings,
      layer2Status: result.layer2Status,
      suppressions: report.suppressions,
      invalidAllowlistEntries:
        verifiedAllowlist.invalidAllowlistEntries.length > 0 ? verifiedAllowlist.invalidAllowlistEntries : undefined,
      allowlistModifiedInPr: verifiedAllowlist.allowlistModifiedInPr || undefined,
    });

    console.log(`   - Security        : ${score.security}/100`);
    console.log(`   - Correctness     : ${score.correctness}/100`);
    console.log(`   - Maintainability : ${score.maintainability}/100`);
    console.log(`   - Overall Guard   : ${score.totalScore}/100 [Target: ${minScore}]`);

    if (!passed) {
      console.error(`   ❌ GAGAL: ${filePath} mendapatkan skor ${score.totalScore}/100 (Batas: ${minScore})`);
      if (report.temuanUtama && report.temuanUtama.description) {
        console.error(
          `   💣 Temuan Fatal (${report.temuanUtama.line}): ${redactSecretsPreservingLayout(report.temuanUtama.description)}`
        );
      }
      hasFatalFailure = true;
    } else {
      console.log(`   ✅ LOLOS: ${filePath} memenuhi standar keamanan dan mutu kode.`);
    }
  }

  const avgScore = auditedCount > 0 ? Math.round(totalScoreSum / auditedCount) : 100;
  console.log('\n======================================================================');
  console.log(`RATA-RATA SKOR KESELURUHAN: ${avgScore}/100`);

  // GitHub Actions Workflow Output Parameters
  const outputFile = process.env.GITHUB_OUTPUT;
  writeGitHubOutput(outputFile, 'overall_score', avgScore);
  writeGitHubOutput(outputFile, 'audit_status', hasFatalFailure ? 'FAIL' : 'PASS');

  const effectiveEngineMode: 'HYBRID' | 'OFFLINE_AST' =
    prEnv.isFork || engineMode === 'OFFLINE_AST'
      ? 'OFFLINE_AST'
      : summaries.some((s) => s.layer2Status === 'Verified')
        ? 'HYBRID'
        : engineMode;

  // Comment & post inline review suggestions before process.exit so reports are posted on both pass and failure.
  // Fail-open commenting: HTTP errors inside githubCommenter never override the DevGuard exit code.
  await postPullRequestComment(summaries, minScore, effectiveEngineMode);
  await postInlineReviewComments(summaries);

  // Generate SARIF v2.1.0 report before process.exit so findings are always exported
  const sarifFile = process.env.DEVGUARD_SARIF_OUTPUT || 'devguard-results.sarif';
  generateSarifReport(summaries, sarifFile);

  writeGitHubOutput(outputFile, 'sarif_file', sarifFile);

  if (hasFatalFailure) {
    console.error('🚫 DevGuard Quality Gate Rejected: Ditemukan celah keamanan atau regresi logika.');
    console.error('   Perbaiki celah di atas atau terapkan patch perbaikan sebelum melakukan merge PR.\n');
    process.exit(1);
  } else {
    console.log('🎉 Seluruh berkas yang diaudit lolos inspeksi DevGuard Quality Gate!\n');
    process.exit(0);
  }
}

// Check if run directly
const entryBase = process.argv[1] ? path.basename(process.argv[1]) : '';
const isMain = entryBase === 'cli.ts' || entryBase === 'cli.js' || entryBase === 'loader.mjs';

if (isMain) {
  runAction().catch((err) => {
    console.error('Fatal CLI Error:', err);
    process.exit(1);
  });
}
