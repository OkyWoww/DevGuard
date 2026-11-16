#!/usr/bin/env node
import * as fs from 'node:fs';
import * as path from 'node:path';
import { execFileSync, execSync } from 'node:child_process';
import { builtinModules } from 'node:module';
import { GoogleGenAI, Type } from '@google/genai';
import {
  analyzeCodeDeterministically,
  prepareRedactedCodeForLlm,
  redactSecretsPreservingLayout,
  ParsedDevGuardReport,
} from './devguardAnalyzer.js';
import {
  postInlineReviewComments,
  postPullRequestComment,
} from './githubCommenter.js';
import type { FileAuditSummary } from './githubCommenter.js';
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

/**
 * Loads `.devguard.json` using base-branch verification on PR/push CI events so PR authors
 * cannot weaken security rules inside the same PR. Fails closed to empty allowlist on git errors.
 */
export function loadVerifiedAllowlist(options?: LoadAllowlistOptions): VerifiedAllowlistResult {
  const cwd = options?.cwd || process.cwd();
  const baseRef = options?.baseRef !== undefined ? options.baseRef : process.env.GITHUB_BASE_REF;
  const eventName = options?.eventName !== undefined ? options.eventName : process.env.GITHUB_EVENT_NAME;
  const beforeSha =
    options?.beforeSha !== undefined
      ? options.beforeSha
      : readBeforeShaFromEventFile(options?.eventPath ?? process.env.GITHUB_EVENT_PATH);
  const isCi =
    options?.isCi !== undefined ? options.isCi : process.env.GITHUB_ACTIONS === 'true';

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

  if (baseRef) {
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
      if (typeof candidate.reason !== 'string' || candidate.reason.trim().length < 8) {
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

export async function evaluateCodeHybrid(
  code: string,
  apiKey?: string,
  precomputedL1?: ParsedDevGuardReport,
  filePath?: string,
  externalAllowlist?: ReadonlyArray<AllowlistRuleEntry>
): Promise<CliAuditResult> {
  const pkgInfo = filePath ? resolveNearestPackageInfo(filePath) : {};
  const l1Result = precomputedL1 || analyzeCodeDeterministically(code, {
    filePath,
    declaredDependencies: pkgInfo.declaredDependencies,
    subpathImports: pkgInfo.subpathImports,
    builtinModules,
    externalAllowlist,
  });

  const activeKey = apiKey || process.env.GEMINI_API_KEY;

  if (!activeKey || activeKey === 'MY_GEMINI_API_KEY' || !activeKey.startsWith('AIzaSy')) {
    return {
      mode: 'zero-api',
      isLiveApi: false,
      layer2Status: 'Skipped: Offline AST Only',
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
    const ai = new GoogleGenAI({ apiKey: activeKey });
    const prompt = [
      'Anda adalah Principal AppSec Engineer & Zero-Leniency Adversarial Code Auditor.',
      'Evaluasi kode di dalam <code_to_review> secara jujur, ketat, dan tanpa kompromi.',
      'DILARANG memberikan skor buta 100/100.',
      '',
      `Hasil deteksi Layer 1 AST Analyzer (wajib dihormati sebagai batas atas skor):`,
      `- Security=${l1Result.skor.security}, Correctness=${l1Result.skor.correctness}, Maintainability=${l1Result.skor.maintainability}`,
      `- Baris Temuan: ${l1Result.temuanUtama.line}`,
      `- Detail: ${redactSecretsPreservingLayout(l1Result.temuanUtama.description)}`,
      '',
      '<code_to_review>',
      redactionGate.safeCode,
      '</code_to_review>',
    ].join('\n');

    const timeoutPromise = new Promise<never>((_, reject) =>
      setTimeout(() => reject(new Error('Gemini API timeout')), 6500)
    );

    const response = (await Promise.race([
      ai.models.generateContent({
        model: 'gemini-3.8-flash',
        contents: prompt,
        config: {
          temperature: 0.1,
          responseMimeType: 'application/json',
          responseSchema: {
            type: Type.OBJECT,
            properties: {
              apresiasi: { type: Type.STRING },
              skor: {
                type: Type.OBJECT,
                properties: {
                  security: { type: Type.INTEGER },
                  securityDeductions: { type: Type.ARRAY, items: { type: Type.STRING } },
                  correctness: { type: Type.INTEGER },
                  correctnessDeductions: { type: Type.ARRAY, items: { type: Type.STRING } },
                  maintainability: { type: Type.INTEGER },
                  maintainabilityDeductions: { type: Type.ARRAY, items: { type: Type.STRING } },
                },
                required: ['security', 'correctness', 'maintainability'],
              },
              temuanUtama: {
                type: Type.OBJECT,
                properties: {
                  line: { type: Type.STRING },
                  description: { type: Type.STRING },
                },
                required: ['line', 'description'],
              },
              temuanLain: { type: Type.ARRAY, items: { type: Type.STRING } },
              analogi: {
                type: Type.OBJECT,
                properties: {
                  story: { type: Type.STRING },
                  technicalTerm: { type: Type.STRING },
                },
                required: ['story', 'technicalTerm'],
              },
              perbaikanSummary: { type: Type.STRING },
            },
            required: ['apresiasi', 'skor', 'temuanUtama', 'analogi'],
          },
        },
      }),
      timeoutPromise,
    ])) as { text?: string };

    const rawResponseText = redactSecretsPreservingLayout((response.text || '').trim());
    const geminiData = JSON.parse(rawResponseText);

    // Ceilings enforced by Layer 1 zero-leniency rubric
    const reconciledSecurity = Math.min(l1Result.skor.security, geminiData.skor?.security ?? 100);
    const reconciledCorrectness = Math.min(l1Result.skor.correctness, geminiData.skor?.correctness ?? 100);
    const reconciledMaintainability = Math.min(l1Result.skor.maintainability, geminiData.skor?.maintainability ?? 100);
    const reconciledTotal = Math.round((reconciledSecurity + reconciledCorrectness + reconciledMaintainability) / 3);

    const redactList = (items?: string[]): string[] | undefined =>
      items?.length ? items.map((s) => redactSecretsPreservingLayout(String(s))) : undefined;

    return {
      mode: 'hybrid',
      isLiveApi: true,
      layer2Status: 'Executed: Redacted',
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
    console.warn(`⚠️  Gemini API error (${errMsg}). Otomatis dialihkan ke Layer 1 AST Engine.`);
    return {
      mode: 'zero-api',
      isLiveApi: false,
      layer2Status: 'Skipped: Gemini API Error Fallback',
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

export async function runAction() {
  const apiKey = process.env.GEMINI_API_KEY;
  const minScore = parseInt(process.env.DEVGUARD_MIN_SCORE || '85', 10);
  const targetPattern = process.env.DEVGUARD_TARGET || 'modified';
  const explicitFileArgs = resolveCliFileArgs(process.argv.slice(2));
  const engineMode: 'HYBRID' | 'OFFLINE_AST' =
    apiKey && apiKey !== 'MY_GEMINI_API_KEY' && apiKey.startsWith('AIzaSy') ? 'HYBRID' : 'OFFLINE_AST';

  console.log('======================================================================');
  console.log('           🛡️  DEVGUARD ADVERSARIAL CODE AUDITOR (CI GATE)            ');
  console.log('======================================================================');
  console.log(`Ambang Batas Kelulusan CI : Minimal ${minScore}/100`);

  if (engineMode === 'OFFLINE_AST') {
    console.log('Mode Eksekusi             : 🛡️  Zero-API (100% Offline AST Engine - Gratis)');
  } else {
    console.log('Mode Eksekusi             : 🤖 Hybrid Dual-Layer (AST + Gemini 3.8 Flash)');
  }

  // 1. Dapatkan daftar berkas target
  let filesToAudit: string[] = [];

  if (explicitFileArgs.length > 0) {
    filesToAudit = explicitFileArgs;
  } else if (targetPattern === 'all') {
    // Scan recursively for py, ts, js excluding node_modules, dist, etc.
    const scanDir = (dir: string): string[] => {
      let results: string[] = [];
      const list = fs.readdirSync(dir, { withFileTypes: true });
      for (const item of list) {
        if (
          item.name.startsWith('.') ||
          ['node_modules', 'dist', 'build', 'coverage', 'remotion', 'out'].includes(item.name) ||
          item.name.includes('.test.') ||
          item.name.includes('.spec.') ||
          item.name === 'devguardAnalyzer.ts' ||
          item.name === 'devguard_verify.py'
        ) {
          continue;
        }
        const full = path.join(dir, item.name);
        if (item.isDirectory()) {
          results = results.concat(scanDir(full));
        } else if (/\.(py|ts|js|jsx|tsx)$/.test(item.name) && !item.name.endsWith('.d.ts')) {
          results.push(full);
        }
      }
      return results;
    };
    filesToAudit = scanDir(process.cwd());
  } else {
    // Modified files via git diff
    try {
      const gitDiff = execSync('git diff --name-only HEAD~1 HEAD || git diff --name-only HEAD', {
        encoding: 'utf-8',
        stdio: ['ignore', 'pipe', 'ignore'],
      });
      filesToAudit = gitDiff
        .split('\n')
        .map((f) => f.trim())
        .filter(
          (f) =>
            f &&
            /\.(py|ts|js|jsx|tsx)$/.test(f) &&
            !f.endsWith('.d.ts') &&
            !f.startsWith('remotion/') &&
            !f.includes('.test.') &&
            !f.includes('.spec.') &&
            !f.endsWith('devguardAnalyzer.ts') &&
            !f.endsWith('devguard_verify.py')
        );
    } catch {
      console.warn('⚠️  Git diff tidak menemukan riwayat commit; beralih ke pengecekan berkas lokal.');
      filesToAudit = [];
    }
  }

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

    const codeContent = fs.readFileSync(filePath, 'utf-8');
    auditedCount++;

    console.log(`\n🔍 Menganalisis: ${filePath}`);
    const fileExternalAllowlist = matchAllowlistForFile(verifiedAllowlist, filePath);
    const result = await evaluateCodeHybrid(codeContent, apiKey, undefined, filePath, fileExternalAllowlist);
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

  // Comment & post inline review suggestions before process.exit so reports are posted on both pass and failure.
  await postPullRequestComment(summaries, minScore, engineMode);
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
const isMain = process.argv[1] && (
  process.argv[1].endsWith('cli.ts') ||
  process.argv[1].endsWith('cli.js') ||
  process.argv[1].includes('cli')
);

if (isMain) {
  runAction().catch((err) => {
    console.error('Fatal CLI Error:', err);
    process.exit(1);
  });
}
