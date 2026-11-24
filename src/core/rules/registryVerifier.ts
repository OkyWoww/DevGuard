import {
  analyzeLexicalStructure,
  buildVirtualView,
  isCommentOrEmptyLine,
  toOrigLineAndCol,
  type AllowlistRuleId,
  type InlineFinding,
  type ParsedSuppression,
} from './lexicalMasker.ts';
import { parseJsonc } from './workspaceParser.ts';
import {
  findNearestPackageManifest,
  getBasePackageName,
  resolveWorkspaceImportSpecifier,
  type WorkspaceContext,
  type WorkspaceDiagnosticNotice,
  type WorkspaceFileAccessor,
} from './workspaceResolver.ts';

export const PUBLIC_NPM_REGISTRY_BASE = 'https://registry.npmjs.org';
export const DEFAULT_REGISTRY_TIMEOUT_MS = 5_000;
export const DEFAULT_TOTAL_BUDGET_MS = 15_000;
export const DEFAULT_REGISTRY_CONCURRENCY = 6;
export const DEFAULT_MIN_PACKAGE_AGE_DAYS = 30;
export const MAX_REGISTRY_RESPONSE_BYTES = 32 * 1024 * 1024; // 32 MiB bounded packument stream cap
export const MAX_PACKAGES_PER_RUN = 250;

const MS_PER_DAY = 86_400_000;

const DEFAULT_BUILTIN_NODE_MODULES = [
  'assert', 'assert/strict', 'async_hooks', 'buffer', 'child_process', 'cluster',
  'console', 'constants', 'crypto', 'dgram', 'diagnostics_channel', 'dns',
  'dns/promises', 'domain', 'events', 'fs', 'fs/promises', 'http', 'http2',
  'https', 'inspector', 'inspector/promises', 'module', 'net', 'os', 'path',
  'path/posix', 'path/win32', 'perf_hooks', 'process', 'punycode', 'querystring',
  'readline', 'readline/promises', 'repl', 'sqlite', 'stream', 'stream/consumers',
  'stream/promises', 'stream/web', 'string_decoder', 'sys', 'test',
  'test/reporters', 'timers', 'timers/promises', 'tls', 'trace_events', 'tty',
  'url', 'util', 'util/types', 'v8', 'vm', 'wasi', 'worker_threads', 'zlib',
];

const VALID_NPM_PACKAGE_RE = /^(?:@[a-z0-9-~][a-z0-9-._~]*\/)?[a-z0-9-~][a-z0-9-._~]*$/i;
const LIFECYCLE_HOOK_KEYS = ['preinstall', 'install', 'postinstall'] as const;

export type RegistryFetchFn = (input: string, init?: RequestInit) => Promise<Response>;

export type RegistryRiskReason =
  | 'not_found'
  | 'security_holding'
  | 'unpublished'
  | 'newly_registered';

export type RegistryUnreachableReason =
  | 'network_error'
  | 'timeout'
  | 'run_timeout'
  | 'rate_limited'
  | 'http_error'
  | 'response_too_large'
  | 'invalid_response'
  | 'package_limit_exceeded';

export interface RegistryVerifyOptions {
  fetchImpl?: RegistryFetchFn;
  nowMs?: number;
  perRequestTimeoutMs?: number;
  totalTimeoutMs?: number;
  concurrency?: number;
  minPackageAgeDays?: number;
  maxResponseBytes?: number;
  maxPackagesPerRun?: number;
  builtinModules?: readonly string[];
}

export interface AuditedRegistryFileTarget {
  filePath: string;
  code: string;
  allowlistRules?: ReadonlyArray<{ rule: AllowlistRuleId; reason: string }>;
}

export interface AuditedRegistryManifestTarget {
  manifestPath: string;
  allowlistRules?: ReadonlyArray<{ rule: AllowlistRuleId; reason: string }>;
}

export type PackageRegistryLookupOutcome =
  | { kind: 'ok'; packageName: string }
  | {
      kind: 'risk';
      packageName: string;
      reason: RegistryRiskReason;
      message: string;
    }
  | {
      kind: 'unreachable';
      packageName: string;
      reason: RegistryUnreachableReason;
      message: string;
    };

export interface RegistryVerificationBatchResult {
  outcomesByPackage: Map<string, PackageRegistryLookupOutcome>;
  inlineFindingsByFile: Map<string, InlineFinding[]>;
  suppressionsByFile: Map<string, ParsedSuppression[]>;
  diagnostics: WorkspaceDiagnosticNotice[];
}

interface PackumentProjection {
  createdIso?: string;
  hasUnpublished: boolean;
  latestTag?: string;
  versionCount: number;
  hasSecurityHolderVersion: boolean;
  latestDeprecated?: string;
  installLifecycleHooks: string[];
}

interface ManifestDepClassification {
  excludedKeys: Set<string>;
  aliasTargetByKey: Map<string, string>;
  externalPackages: Map<string, number>;
}

interface ExtractedFileImport {
  line: number;
  packageName: string;
}

function compareCodePoints(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

function getBuiltinModuleSet(extraBuiltins?: readonly string[]): Set<string> {
  const set = new Set<string>(DEFAULT_BUILTIN_NODE_MODULES);
  if (extraBuiltins) {
    for (const mod of extraBuiltins) {
      set.add(mod.replace(/^node:/, ''));
    }
  }
  const proc = (globalThis as { process?: { getBuiltinModule?: (id: string) => unknown } }).process;
  if (proc && typeof proc.getBuiltinModule === 'function') {
    try {
      const mod = proc.getBuiltinModule('node:module') as { builtinModules?: string[] } | undefined;
      if (mod?.builtinModules) {
        for (const item of mod.builtinModules) {
          set.add(item.replace(/^node:/, ''));
        }
      }
    } catch {
      return set;
    }
  }
  return set;
}

/**
 * Strictly validates npm package names prior to URL construction (anti-SSRF & path traversal).
 */
export function isValidNpmPackageName(pkgName: string): boolean {
  if (typeof pkgName !== 'string') return false;
  const trimmed = pkgName.trim();
  if (trimmed.length === 0 || trimmed.length > 214) return false;
  if (trimmed !== pkgName) return false;
  if (trimmed.includes('..') || trimmed.includes('\\') || /[\s?#%\0\r\n]/.test(trimmed)) {
    return false;
  }
  return VALID_NPM_PACKAGE_RE.test(trimmed);
}

/**
 * Encodes a validated package name for `https://registry.npmjs.org/<encoded>`.
 * Scoped packages `@scope/pkg` encode to `@scope%2fpkg`.
 */
export function encodeNpmPackagePath(pkgName: string): string {
  if (pkgName.startsWith('@')) {
    const slashIdx = pkgName.indexOf('/');
    if (slashIdx > 1) {
      const scope = pkgName.slice(1, slashIdx);
      const name = pkgName.slice(slashIdx + 1);
      return `@${encodeURIComponent(scope)}%2f${encodeURIComponent(name)}`;
    }
  }
  return encodeURIComponent(pkgName);
}

function unwrapNpmProtocolTarget(spec: string): string | null {
  if (!spec.startsWith('npm:')) return null;
  const after = spec.slice(4).trim();
  if (!after) return null;
  let target: string;
  if (after.startsWith('@')) {
    const verIdx = after.indexOf('@', 1);
    target = verIdx !== -1 ? after.slice(0, verIdx) : after;
  } else {
    const verIdx = after.indexOf('@');
    target = verIdx !== -1 ? after.slice(0, verIdx) : after;
  }
  if (!target || /^\d+(\.\d+)*(-|$)/.test(target)) return null;
  const base = getBasePackageName(target);
  return isValidNpmPackageName(base) ? base : null;
}

function isNonRegistryDepSpec(rawVal: string): boolean {
  const val = rawVal.trim();
  if (!val) return false;
  if (
    val.startsWith('workspace:') ||
    val.startsWith('file:') ||
    val.startsWith('link:') ||
    val.startsWith('portal:') ||
    val.startsWith('patch:') ||
    val.startsWith('git+') ||
    val.startsWith('git:') ||
    val.startsWith('github:') ||
    val.startsWith('gitlab:') ||
    val.startsWith('bitbucket:') ||
    val.startsWith('http://') ||
    val.startsWith('https://') ||
    val.startsWith('./') ||
    val.startsWith('../') ||
    val.startsWith('/') ||
    val.startsWith('~/')
  ) {
    return true;
  }
  if (/\.(?:tgz|tar\.gz|tar)$/i.test(val)) {
    return true;
  }
  // GitHub shorthand "owner/repo" or "owner/repo#ref" (never starts with '@')
  if (!val.startsWith('@') && /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+(?:#.+)?$/.test(val)) {
    return true;
  }
  return false;
}

function findDepKeyLineNumber(rawJsonText: string, depKey: string): number {
  const lines = rawJsonText.split('\n');
  const needle = `"${depKey}"`;
  for (let i = 0; i < lines.length; i++) {
    if (lines[i].includes(needle)) {
      return i + 1;
    }
  }
  return 1;
}

function classifyRawManifestText(
  rawManifest: string | null,
  builtinSet: ReadonlySet<string>,
  workspacePkgNames: ReadonlySet<string>,
  selfNames: ReadonlySet<string>
): ManifestDepClassification {
  const excludedKeys = new Set<string>();
  const aliasTargetByKey = new Map<string, string>();
  const externalPackages = new Map<string, number>();

  if (rawManifest === null) {
    return { excludedKeys, aliasTargetByKey, externalPackages };
  }

  const parsed = parseJsonc(rawManifest);
  if (!parsed.success || !parsed.data || typeof parsed.data !== 'object' || Array.isArray(parsed.data)) {
    return { excludedKeys, aliasTargetByKey, externalPackages };
  }

  const pkgObj = parsed.data as {
    name?: unknown;
    dependencies?: Record<string, unknown>;
    devDependencies?: Record<string, unknown>;
    peerDependencies?: Record<string, unknown>;
    optionalDependencies?: Record<string, unknown>;
  };

  const localSelfNames = new Set<string>(selfNames);
  if (typeof pkgObj.name === 'string' && pkgObj.name.trim()) {
    localSelfNames.add(pkgObj.name.trim());
  }

  const depFields = [
    pkgObj.dependencies,
    pkgObj.devDependencies,
    pkgObj.peerDependencies,
    pkgObj.optionalDependencies,
  ];

  for (const field of depFields) {
    if (!field || typeof field !== 'object' || Array.isArray(field)) continue;
    for (const [depKey, depVal] of Object.entries(field)) {
      if (typeof depVal === 'string') {
        const trimmedVal = depVal.trim();
        if (trimmedVal.startsWith('npm:')) {
          const unwrapped = unwrapNpmProtocolTarget(trimmedVal);
          if (
            unwrapped &&
            !builtinSet.has(unwrapped) &&
            !workspacePkgNames.has(unwrapped) &&
            !localSelfNames.has(unwrapped)
          ) {
            aliasTargetByKey.set(depKey, unwrapped);
            if (!externalPackages.has(unwrapped)) {
              externalPackages.set(unwrapped, findDepKeyLineNumber(rawManifest, depKey));
            }
          } else {
            excludedKeys.add(depKey);
          }
          continue;
        }
        if (isNonRegistryDepSpec(trimmedVal)) {
          excludedKeys.add(depKey);
          continue;
        }
      }

      if (
        builtinSet.has(depKey) ||
        builtinSet.has(depKey.replace(/^node:/, '')) ||
        workspacePkgNames.has(depKey) ||
        localSelfNames.has(depKey) ||
        !isValidNpmPackageName(depKey)
      ) {
        excludedKeys.add(depKey);
        continue;
      }

      if (!externalPackages.has(depKey)) {
        externalPackages.set(depKey, findDepKeyLineNumber(rawManifest, depKey));
      }
    }
  }

  return { excludedKeys, aliasTargetByKey, externalPackages };
}

function collectRawImportSpecifiers(
  code: string,
  maskedCode: string
): Array<{ line: number; rawSpec: string }> {
  const rawLines = code.split('\n');
  const maskedLines = maskedCode.split('\n');
  const execLines: Array<{ num: number; text: string }> = [];
  for (let i = 0; i < rawLines.length; i++) {
    if (!isCommentOrEmptyLine(rawLines[i])) {
      execLines.push({ num: i + 1, text: rawLines[i] });
    }
  }

  const staticImportRe = /^\s*(?:(?:import|export)\b[^'"]*\bfrom\s+|import\s+|\}\s*from\s+)['"]([^'"]+)['"]/;
  const dynamicOrRequireRe =
    /(?:^|[^\w.'"`])\b(?:require|import)\s*\(\s*['"]([^'"]+)['"]\s*(?:,|\))/g;
  const maskedImportOrRequireRe =
    /^\s*(?:import\b|export\b[^\n;]*\bfrom\b|\}\s*from\b)|(?:^|[^\w.'"`])\b(?:require|import)\s*\(/;

  const collected: Array<{ line: number; rawSpec: string }> = [];
  const seen = new Set<string>();

  for (const { num, text } of execLines) {
    if (!maskedImportOrRequireRe.test(maskedLines[num - 1] ?? '')) continue;
    const specs: string[] = [];
    const staticMatch = text.match(staticImportRe);
    if (staticMatch?.[1]) specs.push(staticMatch[1]);
    for (const m of text.matchAll(dynamicOrRequireRe)) {
      if (m[1]) specs.push(m[1]);
    }
    for (const rawSpec of specs) {
      const key = `${num}:${rawSpec}`;
      if (!seen.has(key)) {
        seen.add(key);
        collected.push({ line: num, rawSpec });
      }
    }
  }

  if (execLines.length > 1) {
    const joinedExec = execLines.map((l) => l.text).join('\n');
    const joinedMasked = execLines.map((l) => maskedLines[l.num - 1] ?? '').join('\n');
    const multiLineCallRe = /(?:^|[^\w.'"`])\b(?:require|import)\s*\(\s*\n\s*['"]([^'"]+)['"]\s*(?:,|\))/g;
    let mm: RegExpExecArray | null;
    while ((mm = multiLineCallRe.exec(joinedExec)) !== null) {
      const prefixOffset = mm.index + (mm[0].search(/\b(?:require|import)\b/) || 0);
      const execIdx = joinedExec.slice(0, prefixOffset).split('\n').length - 1;
      const lineEntry = execLines[execIdx];
      if (!lineEntry) continue;
      const maskedSlice = joinedMasked.slice(mm.index, mm.index + mm[0].length);
      if (!/\b(?:require|import)\s*\(/.test(maskedSlice)) continue;
      const rawSpec = mm[1];
      const key = `${lineEntry.num}:${rawSpec}`;
      if (!seen.has(key)) {
        seen.add(key);
        collected.push({ line: lineEntry.num, rawSpec });
      }
    }
  }

  return collected;
}

function extractExternalFileImports(
  filePath: string,
  code: string,
  builtinSet: ReadonlySet<string>,
  workspaceContext: WorkspaceContext | undefined,
  accessor: WorkspaceFileAccessor | undefined,
  rootClassification: ManifestDepClassification,
  manifestCache: Map<string, ManifestDepClassification>,
  workspacePkgNames: ReadonlySet<string>,
  selfNames: ReadonlySet<string>
): { imports: ExtractedFileImport[]; inlineSuppressions: ParsedSuppression[] } {
  const lexical = analyzeLexicalStructure(code, false);
  const rawSpecs = collectRawImportSpecifiers(code, lexical.maskedCode);

  // Also extract constant-folded Pass-V specifiers (e.g. require('slop' + 'squat'))
  const virtualView = buildVirtualView(code, { isPython: false, initialLex: lexical });
  if (virtualView.editsApplied > 0) {
    const vLex = analyzeLexicalStructure(virtualView.virtualCode, false);
    const vSpecs = collectRawImportSpecifiers(virtualView.virtualCode, vLex.maskedCode);
    const vLineStarts = [0];
    for (let i = 0; i < virtualView.virtualCode.length; i++) {
      if (virtualView.virtualCode[i] === '\n') vLineStarts.push(i + 1);
    }
    for (const vs of vSpecs) {
      const idx = Math.max(0, Math.min(vs.line - 1, vLineStarts.length - 1));
      const vStart = vLineStarts[idx];
      const vEnd =
        idx + 1 < vLineStarts.length
          ? Math.max(vStart, vLineStarts[idx + 1] - 1)
          : virtualView.virtualCode.length;
      const orig = toOrigLineAndCol(code, virtualView.spanMap, vStart, vEnd);
      if (!rawSpecs.some((existing) => existing.line === orig.line && existing.rawSpec === vs.rawSpec)) {
        rawSpecs.push({ line: orig.line, rawSpec: vs.rawSpec });
      }
    }
  }

  let nearestClassification: ManifestDepClassification | null = null;
  let nearestName: string | undefined;
  if (accessor) {
    const rootPkgPath = workspaceContext?.rootPkgPath ?? 'package.json';
    const nearest = findNearestPackageManifest(filePath, accessor, rootPkgPath, workspaceContext);
    if (nearest) {
      nearestName = nearest.manifestData.name;
      const cached = manifestCache.get(nearest.pkgPath);
      if (cached) {
        nearestClassification = cached;
      } else {
        const localSelf = new Set<string>(selfNames);
        if (nearestName) localSelf.add(nearestName);
        const classified = classifyRawManifestText(
          accessor.readFile(nearest.pkgPath),
          builtinSet,
          workspacePkgNames,
          localSelf
        );
        manifestCache.set(nearest.pkgPath, classified);
        nearestClassification = classified;
      }
    }
  }

  const results: ExtractedFileImport[] = [];
  const seenLinePkg = new Set<string>();

  for (const { line, rawSpec } of rawSpecs) {
    if (!rawSpec) continue;
    if (
      rawSpec.startsWith('.') ||
      rawSpec.startsWith('/') ||
      rawSpec.startsWith('@/') ||
      rawSpec.startsWith('~/') ||
      rawSpec.startsWith('#') ||
      rawSpec.startsWith('virtual:') ||
      rawSpec.startsWith('workspace:') ||
      rawSpec.startsWith('file:') ||
      rawSpec.startsWith('link:') ||
      (/^[a-z][a-z0-9+.-]*:/i.test(rawSpec) && !rawSpec.startsWith('node:') && !rawSpec.startsWith('npm:'))
    ) {
      continue;
    }

    if (!rawSpec.startsWith('npm:')) {
      const strippedNode = rawSpec.startsWith('node:') ? rawSpec.slice(5) : rawSpec;
      const baseNode = getBasePackageName(strippedNode);
      if (rawSpec.startsWith('node:') || builtinSet.has(strippedNode) || builtinSet.has(baseNode)) {
        continue;
      }
    }

    if (workspaceContext && accessor && workspaceContext.mode !== 'off') {
      const wsRes = resolveWorkspaceImportSpecifier(rawSpec, filePath, workspaceContext, accessor);
      if (
        wsRes.resolved &&
        (wsRes.resolvedVia === 'workspace' ||
          wsRes.resolvedVia === 'tsconfig' ||
          wsRes.resolvedVia === 'imports')
      ) {
        continue;
      }
    }

    let targetPkg: string | null;
    if (rawSpec.startsWith('npm:')) {
      targetPkg = unwrapNpmProtocolTarget(rawSpec);
    } else {
      const basePkg = getBasePackageName(rawSpec);
      if (
        workspacePkgNames.has(basePkg) ||
        selfNames.has(basePkg) ||
        nearestName === basePkg ||
        nearestClassification?.excludedKeys.has(basePkg) ||
        rootClassification.excludedKeys.has(basePkg)
      ) {
        continue;
      }
      targetPkg =
        nearestClassification?.aliasTargetByKey.get(basePkg) ??
        rootClassification.aliasTargetByKey.get(basePkg) ??
        basePkg;
    }

    if (
      !targetPkg ||
      builtinSet.has(targetPkg) ||
      workspacePkgNames.has(targetPkg) ||
      selfNames.has(targetPkg) ||
      !isValidNpmPackageName(targetPkg)
    ) {
      continue;
    }

    const dedupKey = `${line}:${targetPkg}`;
    if (!seenLinePkg.has(dedupKey)) {
      seenLinePkg.add(dedupKey);
      results.push({ line, packageName: targetPkg });
    }
  }

  results.sort((a, b) => (a.line !== b.line ? a.line - b.line : compareCodePoints(a.packageName, b.packageName)));
  return { imports: results, inlineSuppressions: lexical.suppressions };
}

async function cancelBodySafely(body: ReadableStream<Uint8Array> | null): Promise<boolean> {
  if (!body) return false;
  try {
    await body.cancel();
    return true;
  } catch {
    return false;
  }
}

function releaseReaderLockSafely(reader: ReadableStreamDefaultReader<Uint8Array>): boolean {
  try {
    reader.releaseLock();
    return true;
  } catch {
    return false;
  }
}

async function readBoundedPackumentProjection(
  res: Response,
  maxBytes: number
): Promise<
  | { ok: true; projection: PackumentProjection }
  | { ok: false; reason: 'response_too_large' | 'invalid_response'; detail: string }
> {
  let rawText: string;

  if (res.body && typeof res.body.getReader === 'function') {
    const reader = res.body.getReader();
    const chunks: Uint8Array[] = [];
    let totalBytes = 0;
    try {
      for (let chunkCount = 0; chunkCount <= maxBytes + 1; chunkCount++) {
        const step = await reader.read();
        if (step.done) break;
        const value = step.value;
        if (value instanceof Uint8Array) {
          totalBytes += value.byteLength;
          if (totalBytes > maxBytes) {
            await cancelBodySafely(res.body);
            return {
              ok: false,
              reason: 'response_too_large',
              detail: `Registry packument exceeded ${maxBytes} bytes safety cap`,
            };
          }
          chunks.push(value);
        }
      }
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      return { ok: false, reason: 'invalid_response', detail: msg };
    } finally {
      releaseReaderLockSafely(reader);
    }

    const merged = new Uint8Array(totalBytes);
    let offset = 0;
    for (const chunk of chunks) {
      merged.set(chunk, offset);
      offset += chunk.byteLength;
    }
    rawText = new TextDecoder('utf-8').decode(merged);
  } else {
    const buf = await res.arrayBuffer();
    if (buf.byteLength > maxBytes) {
      return {
        ok: false,
        reason: 'response_too_large',
        detail: `Registry packument exceeded ${maxBytes} bytes safety cap`,
      };
    }
    rawText = new TextDecoder('utf-8').decode(buf);
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(rawText);
  } catch {
    return { ok: false, reason: 'invalid_response', detail: 'Malformed JSON from registry endpoint' };
  }

  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    return { ok: false, reason: 'invalid_response', detail: 'Unexpected non-object JSON packument' };
  }

  const doc = parsed as {
    time?: Record<string, unknown>;
    'dist-tags'?: Record<string, unknown>;
    versions?: Record<string, unknown>;
  };

  const timeObj = doc.time && typeof doc.time === 'object' && !Array.isArray(doc.time) ? doc.time : undefined;
  const createdIso = typeof timeObj?.created === 'string' ? timeObj.created : undefined;
  const hasUnpublished = Boolean(timeObj && Object.prototype.hasOwnProperty.call(timeObj, 'unpublished') && timeObj.unpublished);

  const distTags =
    doc['dist-tags'] && typeof doc['dist-tags'] === 'object' && !Array.isArray(doc['dist-tags'])
      ? doc['dist-tags']
      : undefined;
  const latestTag = typeof distTags?.latest === 'string' ? distTags.latest : undefined;

  const versionsObj =
    doc.versions && typeof doc.versions === 'object' && !Array.isArray(doc.versions)
      ? doc.versions
      : undefined;
  const versionKeys = versionsObj ? Object.keys(versionsObj) : [];
  const versionCount = versionKeys.length;
  const hasSecurityHolderVersion = versionKeys.some((v) => v === '0.0.1-security' || v.endsWith('-security'));

  let latestDeprecated: string | undefined;
  const installLifecycleHooks: string[] = [];

  const targetVerKey = latestTag && versionsObj && versionsObj[latestTag] ? latestTag : versionKeys[versionKeys.length - 1];
  if (targetVerKey && versionsObj) {
    const verMeta = versionsObj[targetVerKey];
    if (verMeta && typeof verMeta === 'object' && !Array.isArray(verMeta)) {
      const vRec = verMeta as { deprecated?: unknown; scripts?: Record<string, unknown> };
      if (typeof vRec.deprecated === 'string' && vRec.deprecated.trim().length > 0) {
        latestDeprecated = vRec.deprecated.trim();
      }
      if (vRec.scripts && typeof vRec.scripts === 'object' && !Array.isArray(vRec.scripts)) {
        for (const hookKey of LIFECYCLE_HOOK_KEYS) {
          if (typeof vRec.scripts[hookKey] === 'string' && vRec.scripts[hookKey].trim().length > 0) {
            installLifecycleHooks.push(hookKey);
          }
        }
      }
    }
  }

  return {
    ok: true,
    projection: {
      createdIso,
      hasUnpublished,
      latestTag,
      versionCount,
      hasSecurityHolderVersion,
      latestDeprecated,
      installLifecycleHooks,
    },
  };
}

function evaluatePackumentProjection(
  pkgName: string,
  proj: PackumentProjection,
  nowMs: number,
  minPackageAgeDays: number
): PackageRegistryLookupOutcome {
  if (
    proj.latestTag === '0.0.1-security' ||
    (proj.versionCount === 1 && proj.hasSecurityHolderVersion) ||
    (proj.latestDeprecated !== undefined &&
      /\b(?:security\s+holding|malicious\s+package|malware)\b/i.test(proj.latestDeprecated))
  ) {
    return {
      kind: 'risk',
      packageName: pkgName,
      reason: 'security_holding',
      message: `[DG004-REG-01] Package '${pkgName}' is marked as an npm security holding placeholder ('0.0.1-security') — review dependency legitimacy before installing.`,
    };
  }

  if (proj.hasUnpublished || proj.versionCount === 0) {
    return {
      kind: 'risk',
      packageName: pkgName,
      reason: 'unpublished',
      message: `[DG004-REG-01] Package '${pkgName}' has no active published versions on the public npm registry (unpublished) — verify package availability and name spelling.`,
    };
  }

  if (proj.createdIso !== undefined) {
    const createdMs = Date.parse(proj.createdIso);
    if (Number.isFinite(createdMs)) {
      const ageMs = nowMs - createdMs;
      const thresholdMs = minPackageAgeDays * MS_PER_DAY;
      if (ageMs < thresholdMs) {
        const ageDays = Math.max(0, Math.floor(ageMs / MS_PER_DAY));
        const hookDetail =
          proj.installLifecycleHooks.length > 0
            ? `, defines ${proj.installLifecycleHooks.join('/')} lifecycle script`
            : '';
        return {
          kind: 'risk',
          packageName: pkgName,
          reason: 'newly_registered',
          message: `[DG004-REG-01] Package '${pkgName}' was published recently on npm (${ageDays} day(s) ago, ${proj.versionCount} version(s)${hookDetail}) — verify publisher identity and package name spelling.`,
        };
      }
    }
  }

  return { kind: 'ok', packageName: pkgName };
}

/**
 * Queries `https://registry.npmjs.org` for a deduplicated list of external package names
 * with bounded concurrency, per-request timeout, total run wall-clock budget, and clean
 * AbortController teardown. Never reads `.npmrc` credentials (INV-3).
 */
export async function verifyPackageListAgainstNpm(
  packageNames: readonly string[],
  options?: RegistryVerifyOptions
): Promise<Map<string, PackageRegistryLookupOutcome>> {
  const uniqueSorted = Array.from(new Set(packageNames))
    .filter((name) => typeof name === 'string' && name.length > 0)
    .sort(compareCodePoints);

  const outcomes = new Map<string, PackageRegistryLookupOutcome>();
  if (uniqueSorted.length === 0) {
    return outcomes;
  }

  const fetchFn: RegistryFetchFn | undefined =
    options?.fetchImpl ?? (typeof globalThis.fetch === 'function' ? globalThis.fetch.bind(globalThis) : undefined);
  const nowMs = options?.nowMs ?? Date.now();
  const perRequestTimeoutMs = Math.max(10, options?.perRequestTimeoutMs ?? DEFAULT_REGISTRY_TIMEOUT_MS);
  const totalTimeoutMs = Math.max(10, options?.totalTimeoutMs ?? DEFAULT_TOTAL_BUDGET_MS);
  const concurrency = Math.max(1, Math.min(16, options?.concurrency ?? DEFAULT_REGISTRY_CONCURRENCY));
  const minPackageAgeDays = Math.max(1, options?.minPackageAgeDays ?? DEFAULT_MIN_PACKAGE_AGE_DAYS);
  const maxResponseBytes = Math.max(1024, options?.maxResponseBytes ?? MAX_REGISTRY_RESPONSE_BYTES);
  const maxPackagesPerRun = Math.max(1, options?.maxPackagesPerRun ?? MAX_PACKAGES_PER_RUN);

  if (!fetchFn) {
    for (const pkgName of uniqueSorted) {
      outcomes.set(pkgName, {
        kind: 'unreachable',
        packageName: pkgName,
        reason: 'network_error',
        message: `[DG004-REG-UNREACHABLE] (network_error) Global fetch API is unavailable while verifying '${pkgName}' against ${PUBLIC_NPM_REGISTRY_BASE}.`,
      });
    }
    return outcomes;
  }

  const allowedQueue = uniqueSorted.slice(0, maxPackagesPerRun);
  const overflowPackages = uniqueSorted.slice(maxPackagesPerRun);
  for (const pkgName of overflowPackages) {
    outcomes.set(pkgName, {
      kind: 'unreachable',
      packageName: pkgName,
      reason: 'package_limit_exceeded',
      message: `[DG004-REG-UNREACHABLE] (package_limit_exceeded) Skipped online verification for '${pkgName}': exceeded ${maxPackagesPerRun} unique packages per run.`,
    });
  }

  const runController = new AbortController();
  let runTimedOut = false;
  const runDeadlineMs = Date.now() + totalTimeoutMs;
  const runTimer = setTimeout(() => {
    runTimedOut = true;
    runController.abort();
  }, totalTimeoutMs);

  let nextIndex = 0;

  const lookupSinglePackage = async (pkgName: string): Promise<PackageRegistryLookupOutcome> => {
    if (!isValidNpmPackageName(pkgName)) {
      return {
        kind: 'unreachable',
        packageName: pkgName,
        reason: 'invalid_response',
        message: `[DG004-REG-UNREACHABLE] (invalid_response) Refused online lookup for syntactically invalid package specifier '${pkgName}'.`,
      };
    }

    const remainingRunMs = runDeadlineMs - Date.now();
    if (runTimedOut || remainingRunMs <= 0) {
      return {
        kind: 'unreachable',
        packageName: pkgName,
        reason: 'run_timeout',
        message: `[DG004-REG-UNREACHABLE] (run_timeout) Total registry verification budget (${totalTimeoutMs} ms) expired before verifying '${pkgName}'.`,
      };
    }

    const reqController = new AbortController();
    let reqTimedOut = false;
    const effectiveReqMs = Math.max(1, Math.min(perRequestTimeoutMs, remainingRunMs));

    const onRunAbort = (): void => {
      reqController.abort();
    };
    runController.signal.addEventListener('abort', onRunAbort, { once: true });

    const reqTimer = setTimeout(() => {
      reqTimedOut = true;
      reqController.abort();
    }, effectiveReqMs);

    const url = `${PUBLIC_NPM_REGISTRY_BASE}/${encodeNpmPackagePath(pkgName)}`;

    try {
      const res = await fetchFn(url, {
        method: 'GET',
        headers: {
          Accept: 'application/json',
          'User-Agent': 'DevGuard-Registry-Verifier',
        },
        signal: reqController.signal,
      });

      if (res.status === 404) {
        await cancelBodySafely(res.body);
        return {
          kind: 'risk',
          packageName: pkgName,
          reason: 'not_found',
          message: `[DG004-REG-01] Package '${pkgName}' was not found on the public npm registry (HTTP 404) — verify package spelling or allowlist in .devguard.json if hosted on a private registry.`,
        };
      }

      if (res.status === 429) {
        await cancelBodySafely(res.body);
        return {
          kind: 'unreachable',
          packageName: pkgName,
          reason: 'rate_limited',
          message: `[DG004-REG-UNREACHABLE] (rate_limited) npm registry returned HTTP 429 (rate limit) while verifying '${pkgName}'.`,
        };
      }

      if (res.status !== 200) {
        await cancelBodySafely(res.body);
        const privateHint =
          res.status === 401 || res.status === 403
            ? ' (note: --verify-registry checks public registry.npmjs.org only without .npmrc credentials)'
            : '';
        return {
          kind: 'unreachable',
          packageName: pkgName,
          reason: 'http_error',
          message: `[DG004-REG-UNREACHABLE] (http_error) npm registry returned HTTP ${res.status} while verifying '${pkgName}'${privateHint}.`,
        };
      }

      const bodyRes = await readBoundedPackumentProjection(res, maxResponseBytes);
      if (!bodyRes.ok) {
        return {
          kind: 'unreachable',
          packageName: pkgName,
          reason: bodyRes.reason,
          message: `[DG004-REG-UNREACHABLE] (${bodyRes.reason}) Failed to read registry metadata for '${pkgName}': ${bodyRes.detail}.`,
        };
      }

      return evaluatePackumentProjection(pkgName, bodyRes.projection, nowMs, minPackageAgeDays);
    } catch (err) {
      if (runTimedOut) {
        return {
          kind: 'unreachable',
          packageName: pkgName,
          reason: 'run_timeout',
          message: `[DG004-REG-UNREACHABLE] (run_timeout) Total registry verification budget (${totalTimeoutMs} ms) expired while verifying '${pkgName}'.`,
        };
      }
      const errName = err instanceof Error ? err.name : '';
      if (reqTimedOut || errName === 'AbortError' || errName === 'TimeoutError') {
        return {
          kind: 'unreachable',
          packageName: pkgName,
          reason: 'timeout',
          message: `[DG004-REG-UNREACHABLE] (timeout) Registry request timed out after ${perRequestTimeoutMs} ms while verifying '${pkgName}'.`,
        };
      }
      const reasonText = err instanceof Error ? err.message : String(err);
      return {
        kind: 'unreachable',
        packageName: pkgName,
        reason: 'network_error',
        message: `[DG004-REG-UNREACHABLE] (network_error) Unable to reach ${PUBLIC_NPM_REGISTRY_BASE} for '${pkgName}': ${reasonText}.`,
      };
    } finally {
      clearTimeout(reqTimer);
      runController.signal.removeEventListener('abort', onRunAbort);
    }
  };

  const workerCount = Math.min(concurrency, allowedQueue.length);
  const runWorker = async (): Promise<void> => {
    for (let step = 0; step < allowedQueue.length; step++) {
      const currentIdx = nextIndex;
      if (currentIdx >= allowedQueue.length) break;
      nextIndex++;
      const pkgName = allowedQueue[currentIdx];
      const outcome = await lookupSinglePackage(pkgName);
      outcomes.set(pkgName, outcome);
    }
  };

  try {
    const workers: Array<Promise<void>> = [];
    for (let w = 0; w < workerCount; w++) {
      workers.push(runWorker());
    }
    await Promise.all(workers);
  } finally {
    clearTimeout(runTimer);
  }

  return outcomes;
}

/**
 * Orchestrates end-to-end opt-in npm registry verification across audited JS/TS files and
 * in-scope `package.json` manifests, returning non-scoring `DG004-REG-01` inline findings
 * and non-scoring `DG004-REG-UNREACHABLE` diagnostic notices.
 */
export async function verifyWorkspaceRegistryPackages(params: {
  auditedFiles: ReadonlyArray<AuditedRegistryFileTarget>;
  inScopeManifests?: ReadonlyArray<AuditedRegistryManifestTarget>;
  workspaceContext?: WorkspaceContext;
  workspaceFileAccessor?: WorkspaceFileAccessor;
  options?: RegistryVerifyOptions;
}): Promise<RegistryVerificationBatchResult> {
  const builtinSet = getBuiltinModuleSet(params.options?.builtinModules);
  const wsContext = params.workspaceContext;
  const accessor = params.workspaceFileAccessor;

  const workspacePkgNames = new Set<string>();
  const selfNames = new Set<string>();
  if (wsContext && wsContext.mode !== 'off') {
    for (const name of wsContext.packagesByName.keys()) {
      workspacePkgNames.add(name);
    }
    if (wsContext.rootPackageName) {
      selfNames.add(wsContext.rootPackageName);
    }
  } else if (wsContext?.rootPackageName) {
    selfNames.add(wsContext.rootPackageName);
  }

  const rootPkgPath = wsContext?.rootPkgPath ?? 'package.json';
  const rootRaw = accessor ? accessor.readFile(rootPkgPath) : null;
  const rootClassification = classifyRawManifestText(rootRaw, builtinSet, workspacePkgNames, selfNames);

  const manifestCache = new Map<string, ManifestDepClassification>();
  manifestCache.set(rootPkgPath, rootClassification);

  const importsByFile = new Map<
    string,
    {
      imports: ExtractedFileImport[];
      inlineSuppressions: ParsedSuppression[];
      allowlistRules: ReadonlyArray<{ rule: AllowlistRuleId; reason: string }>;
    }
  >();
  const allCandidatePackages = new Set<string>();
  const importedPackagesAnywhere = new Set<string>();
  const firstSourceByPackage = new Map<string, string>();

  const sortedFiles = [...params.auditedFiles].sort((a, b) => compareCodePoints(a.filePath, b.filePath));
  for (const target of sortedFiles) {
    const extracted = extractExternalFileImports(
      target.filePath,
      target.code,
      builtinSet,
      wsContext,
      accessor,
      rootClassification,
      manifestCache,
      workspacePkgNames,
      selfNames
    );
    importsByFile.set(target.filePath, {
      imports: extracted.imports,
      inlineSuppressions: extracted.inlineSuppressions,
      allowlistRules: target.allowlistRules ?? [],
    });
    for (const imp of extracted.imports) {
      allCandidatePackages.add(imp.packageName);
      importedPackagesAnywhere.add(imp.packageName);
      if (!firstSourceByPackage.has(imp.packageName)) {
        firstSourceByPackage.set(imp.packageName, target.filePath);
      }
    }
  }

  const manifestTargets = [...(params.inScopeManifests ?? [])].sort((a, b) =>
    compareCodePoints(a.manifestPath, b.manifestPath)
  );
  const manifestExternalByPath = new Map<
    string,
    {
      externalPackages: Map<string, number>;
      allowlistRules: ReadonlyArray<{ rule: AllowlistRuleId; reason: string }>;
    }
  >();

  if (accessor) {
    for (const mf of manifestTargets) {
      let classified = manifestCache.get(mf.manifestPath);
      if (!classified) {
        classified = classifyRawManifestText(
          accessor.readFile(mf.manifestPath),
          builtinSet,
          workspacePkgNames,
          selfNames
        );
        manifestCache.set(mf.manifestPath, classified);
      }
      manifestExternalByPath.set(mf.manifestPath, {
        externalPackages: classified.externalPackages,
        allowlistRules: mf.allowlistRules ?? [],
      });
      for (const pkgName of classified.externalPackages.keys()) {
        allCandidatePackages.add(pkgName);
        if (!firstSourceByPackage.has(pkgName)) {
          firstSourceByPackage.set(pkgName, mf.manifestPath);
        }
      }
    }
  }

  const outcomesByPackage = await verifyPackageListAgainstNpm(
    Array.from(allCandidatePackages),
    params.options
  );

  const inlineFindingsByFile = new Map<string, InlineFinding[]>();
  const suppressionsByFile = new Map<string, ParsedSuppression[]>();
  const diagnostics: WorkspaceDiagnosticNotice[] = [];

  // 1. Emit inline DG004-REG-01 findings on importing JS/TS files (respecting .devguard.json allowlist & INV-6)
  for (const target of sortedFiles) {
    const fileMeta = importsByFile.get(target.filePath);
    if (!fileMeta || fileMeta.imports.length === 0) continue;

    const extAllowReason =
      fileMeta.allowlistRules.find((r) => r.rule === 'DG004-REG-01')?.reason ??
      fileMeta.allowlistRules.find((r) => r.rule === 'DG004')?.reason;

    const fileFindings: InlineFinding[] = [];
    const fileSuppressions: ParsedSuppression[] = [];

    for (const imp of fileMeta.imports) {
      const outcome = outcomesByPackage.get(imp.packageName);
      if (!outcome || outcome.kind !== 'risk') continue;

      if (extAllowReason) {
        fileSuppressions.push({
          ruleId: 'DG004-REG-01',
          targetLine: imp.line,
          commentLine: 0,
          reason: extAllowReason,
          kind: 'external',
          filePath: target.filePath,
          severity: 'warning',
          message: outcome.message,
        });
        continue;
      }

      const attemptedInline = fileMeta.inlineSuppressions.some(
        (s) =>
          s.targetLine === imp.line &&
          (s.ruleId === 'DG004-REG-01' || s.ruleId === 'DG004')
      );
      const finalMsg = attemptedInline
        ? `${outcome.message} [Suppression ignored: DG004-REG-01 cannot be suppressed inline]`
        : outcome.message;

      fileFindings.push({
        ruleId: 'DG004-REG-01',
        line: imp.line,
        severity: 'warning',
        scoring: false,
        message: finalMsg,
      });
    }

    if (fileFindings.length > 0) {
      inlineFindingsByFile.set(target.filePath, fileFindings);
    }
    if (fileSuppressions.length > 0) {
      suppressionsByFile.set(target.filePath, fileSuppressions);
    }
  }

  // 2. Emit manifest-level DG004-REG-01 notices for unimported packages declared in in-scope package.json files
  for (const mf of manifestTargets) {
    const mfMeta = manifestExternalByPath.get(mf.manifestPath);
    if (!mfMeta) continue;

    const extAllowReason =
      mfMeta.allowlistRules.find((r) => r.rule === 'DG004-REG-01')?.reason ??
      mfMeta.allowlistRules.find((r) => r.rule === 'DG004')?.reason;
    if (extAllowReason) continue;

    const sortedManifestPkgs = Array.from(mfMeta.externalPackages.keys()).sort(compareCodePoints);
    for (const pkgName of sortedManifestPkgs) {
      if (importedPackagesAnywhere.has(pkgName)) continue;
      const outcome = outcomesByPackage.get(pkgName);
      if (!outcome || outcome.kind !== 'risk') continue;
      diagnostics.push({
        ruleId: 'DG004-REG-01',
        sourceFile: mf.manifestPath,
        reason: outcome.reason,
        message: outcome.message,
        scoring: false,
      });
    }
  }

  // 3. Emit deterministic non-scoring DG004-REG-UNREACHABLE notices for any failed lookups (INV-7)
  const sortedEvaluatedPkgs = Array.from(outcomesByPackage.keys()).sort(compareCodePoints);
  for (const pkgName of sortedEvaluatedPkgs) {
    const outcome = outcomesByPackage.get(pkgName);
    if (!outcome || outcome.kind !== 'unreachable') continue;
    const sourceFile = firstSourceByPackage.get(pkgName) ?? rootPkgPath;
    diagnostics.push({
      ruleId: 'DG004-REG-UNREACHABLE',
      sourceFile,
      reason: outcome.reason,
      message: outcome.message,
      scoring: false,
    });
  }

  return {
    outcomesByPackage,
    inlineFindingsByFile,
    suppressionsByFile,
    diagnostics,
  };
}
