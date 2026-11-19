/**
 * DevGuard Stage 6.0/6.1 Workspace Resolver & Package Map Infrastructure
 *
 * Implements deterministic workspace package mapping and manifest resolution
 * in strict accordance with SPEC-v1.4 rev 1.2 (§6.2, §6.2a, D-6.1 - D-6.6, A6-9, A6-10, A6-12).
 *
 * Core Invariants:
 * 1. Strict Resolution Order (§6.2):
 *    (1) nearest package.json
 *    (2) root package.json ONLY (never intermediate ancestors or siblings)
 *    (3) workspace package name map (pnpm-workspace.yaml & root workspaces)
 *    (4) tsconfig compilerOptions (paths, baseUrl, relative extends) & package.json imports/self-reference
 * 2. Hard Sibling & Intermediate Ancestor Prohibition (§6.2 butir 2 & 3, A6-9):
 *    Dependencies from sibling packages or intermediate ancestors are NEVER merged.
 * 3. Fail-Closed per Source & Size Limit (256 KiB):
 *    Parsing errors, unsupported constructs, or > 256 KiB files emit DG004-WS-UNPARSED notices.
 * 4. Anti-Bypass DG004-WS-NEW:
 *    Packages newly added in PR emit non-scoring DG004-WS-NEW notices (§6.3).
 * 5. Browser-Safe Parity:
 *    Zero top-level node:* imports; filesystem access is injected via WorkspaceFileAccessor.
 */

import {
  MAX_CONFIG_FILE_SIZE,
  parseJsonc,
  parsePnpmWorkspaceYaml,
  parseTsconfig,
  matchesWorkspaceGlobList,
  type WorkspaceBailoutReason,
  type TsconfigData,
  type TsconfigFileAccessor,
} from './workspaceParser.js';

export type ResolutionSource =
  | 'nearest'
  | 'root'
  | 'workspace'
  | 'tsconfig'
  | 'imports'
  | 'unresolved';

export interface WorkspaceResolutionResult {
  specifier: string;
  basePackage: string;
  resolved: boolean;
  resolvedVia: ResolutionSource;
  isUndeclaredWorkspaceImport?: boolean;
}

export interface WorkspacePackageInfo {
  name: string;
  relDir: string;
  pkgJsonPath: string;
  declaredDeps: Set<string>;
  subpathImports?: Record<string, unknown>;
  isNewInPr?: boolean;
}

export interface WorkspaceDiagnosticNotice {
  ruleId: 'DG004-WS-UNPARSED' | 'DG004-WS-NEW';
  sourceFile: string;
  reason?: WorkspaceBailoutReason | string;
  message: string;
  scoring: false;
}

export interface WorkspaceFileAccessor {
  readFile(relPath: string): string | null;
  fileExists(relPath: string): boolean;
  readDir?(relDir: string): string[] | null;
  listFiles?(): string[];
}

export interface WorkspaceContext {
  mode: 'auto' | 'off';
  rootPkgPath: string;
  rootDeclaredDeps: Set<string>;
  rootPackageName?: string;
  rootSubpathImports?: Record<string, unknown>;
  packagesByName: Map<string, WorkspacePackageInfo>;
  packagesByDir: Map<string, WorkspacePackageInfo>;
  workspaceGlobs: string[];
  diagnostics: WorkspaceDiagnosticNotice[];
  tsconfigData?: TsconfigData;
  undeclaredWorkspaceImportsCount: number;
  nearestManifestCache?: Map<
    string,
    { relDir: string; pkgPath: string; manifestData: ReturnType<typeof extractPackageManifestData> } | null
  >;
  resolutionCache?: Map<string, WorkspaceResolutionResult>;
}

const DEFAULT_BUILTIN_NODE_MODULES = new Set<string>([
  'assert', 'assert/strict', 'async_hooks', 'buffer', 'child_process', 'cluster',
  'console', 'constants', 'crypto', 'dgram', 'diagnostics_channel', 'dns',
  'dns/promises', 'domain', 'events', 'fs', 'fs/promises', 'http', 'http2',
  'https', 'inspector', 'inspector/promises', 'module', 'net', 'os', 'path',
  'path/posix', 'path/win32', 'perf_hooks', 'process', 'punycode', 'querystring',
  'readline', 'readline/promises', 'repl', 'sqlite', 'stream', 'stream/consumers',
  'stream/promises', 'stream/web', 'string_decoder', 'sys', 'test',
  'test/reporters', 'timers', 'timers/promises', 'tls', 'trace_events', 'tty',
  'url', 'util', 'util/types', 'v8', 'vm', 'wasi', 'worker_threads', 'zlib',
]);

const BASE_URL_EXTENSIONS = [
  '',
  '.ts',
  '.tsx',
  '.js',
  '.jsx',
  '.mjs',
  '.cjs',
  '.mts',
  '.cts',
  '/index.ts',
  '/index.tsx',
  '/index.js',
  '/index.jsx',
  '/index.mjs',
  '/index.cjs',
  '/package.json',
];

export interface ResolveOptions {
  context?: WorkspaceContext;
  fileAccessor?: WorkspaceFileAccessor;
  baseBranchPackageNames?: ReadonlySet<string>;
  workspacesMode?: 'auto' | 'off';
}

function normalizePosix(p: string): string {
  const norm = p.replace(/\\/g, '/');
  const isAbs = norm.startsWith('/') || /^[a-zA-Z]:[\\/]/.test(norm);
  const drive = /^[a-zA-Z]:/.exec(norm)?.[0] || '';
  const withoutDrive = drive ? norm.slice(drive.length) : norm;
  const parts = withoutDrive.split('/');
  const segs: string[] = [];
  for (const part of parts) {
    if (!part || part === '.') continue;
    if (part === '..') {
      if (segs.length > 0 && segs[segs.length - 1] !== '..') {
        segs.pop();
      } else if (!isAbs) {
        segs.push('..');
      }
    } else {
      segs.push(part);
    }
  }
  const joined = (isAbs ? '/' : '') + segs.join('/');
  return drive ? drive + (joined.startsWith('/') ? joined : '/' + joined) : joined || '.';
}

function getDirname(p: string): string {
  const norm = normalizePosix(p);
  const lastSlash = norm.lastIndexOf('/');
  if (lastSlash === -1) return '.';
  if (lastSlash === 0) return '/';
  return norm.slice(0, lastSlash);
}

export function getBasePackageName(rawSpec: string): string {
  const stripped = rawSpec.startsWith('node:') ? rawSpec.slice(5) : rawSpec;
  if (stripped.startsWith('@')) {
    const parts = stripped.split('/');
    return parts.length >= 2 ? `${parts[0]}/${parts[1]}` : stripped;
  }
  return stripped.split('/')[0];
}

function compareCodePoints(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

function parseProtocolAliasTarget(protocolPrefix: 'npm:' | 'workspace:', depVal: string): string | undefined {
  const after = depVal.slice(protocolPrefix.length).trim();
  if (!after) return undefined;
  if (protocolPrefix === 'workspace:' && !after.startsWith('@') && !/^[a-zA-Z0-9]/.test(after)) {
    return undefined;
  }
  let target: string;
  if (after.startsWith('@')) {
    const verIdx = after.indexOf('@', 1);
    target = verIdx !== -1 ? after.slice(0, verIdx) : after;
  } else {
    const verIdx = after.indexOf('@');
    target = verIdx !== -1 ? after.slice(0, verIdx) : after;
  }
  if (!target || /^\d+(\.\d+)*(-|$)/.test(target)) {
    return undefined;
  }
  return getBasePackageName(target);
}

function matchesSubpathImport(specifier: string, subpathImports?: Record<string, unknown>): boolean {
  if (!subpathImports) return false;
  if (Object.prototype.hasOwnProperty.call(subpathImports, specifier)) return true;
  const keys = Object.keys(subpathImports).sort(compareCodePoints);
  for (const key of keys) {
    const starIdx = key.indexOf('*');
    if (starIdx !== -1) {
      const prefix = key.slice(0, starIdx);
      const suffix = key.slice(starIdx + 1);
      if (
        specifier.length >= prefix.length + suffix.length &&
        specifier.startsWith(prefix) &&
        specifier.endsWith(suffix)
      ) {
        return true;
      }
    }
  }
  return false;
}

function matchesTsconfigPaths(rawSpec: string, paths?: Record<string, string[]>): boolean {
  if (!paths || rawSpec.startsWith('#')) return false;
  if (Object.prototype.hasOwnProperty.call(paths, rawSpec)) {
    return true;
  }
  const keys = Object.keys(paths).sort(compareCodePoints);
  for (const pat of keys) {
    if (pat === '*') continue;
    const starIdx = pat.indexOf('*');
    if (starIdx !== -1) {
      const prefix = pat.slice(0, starIdx);
      const suffix = pat.slice(starIdx + 1);
      if (
        rawSpec.length >= prefix.length + suffix.length &&
        rawSpec.startsWith(prefix) &&
        rawSpec.endsWith(suffix)
      ) {
        return true;
      }
    }
  }
  return false;
}

function matchesTsconfigBaseUrl(
  rawSpec: string,
  baseUrl: string | undefined,
  accessor: WorkspaceFileAccessor
): boolean {
  if (!baseUrl || rawSpec.startsWith('#')) return false;
  const normBase = normalizePosix(baseUrl);
  const candidateBase =
    normBase === '.' || normBase === '/' ? rawSpec : normalizePosix(`${normBase}/${rawSpec}`);
  if (!candidateBase || candidateBase.startsWith('..')) return false;
  for (const ext of BASE_URL_EXTENSIONS) {
    if (accessor.fileExists(`${candidateBase}${ext}`)) {
      return true;
    }
  }
  return false;
}

/**
 * Extracts declared dependencies, name, subpath imports, and workspace patterns from parsed package.json.
 */
export function extractPackageManifestData(pkgObj: unknown): {
  name?: string;
  declaredDeps: Set<string>;
  subpathImports?: Record<string, unknown>;
  workspaces?: string[];
} {
  const declaredDeps = new Set<string>();
  if (!pkgObj || typeof pkgObj !== 'object' || Array.isArray(pkgObj)) {
    return { declaredDeps };
  }
  const p = pkgObj as {
    name?: unknown;
    dependencies?: Record<string, unknown>;
    devDependencies?: Record<string, unknown>;
    peerDependencies?: Record<string, unknown>;
    optionalDependencies?: Record<string, unknown>;
    imports?: Record<string, unknown>;
    workspaces?: unknown;
  };

  const name = typeof p.name === 'string' && p.name.trim() ? p.name.trim() : undefined;

  for (const field of [p.dependencies, p.devDependencies, p.peerDependencies, p.optionalDependencies]) {
    if (field && typeof field === 'object' && !Array.isArray(field)) {
      for (const [depKey, depVal] of Object.entries(field)) {
        declaredDeps.add(depKey);
        if (typeof depVal === 'string') {
          if (depVal.startsWith('npm:')) {
            const aliasTarget = parseProtocolAliasTarget('npm:', depVal);
            if (aliasTarget) declaredDeps.add(aliasTarget);
          } else if (depVal.startsWith('workspace:')) {
            const wsTarget = parseProtocolAliasTarget('workspace:', depVal);
            if (wsTarget) declaredDeps.add(wsTarget);
          }
        }
      }
    }
  }

  let workspaces: string[] | undefined;
  if (Array.isArray(p.workspaces)) {
    workspaces = p.workspaces.filter((w): w is string => typeof w === 'string');
  } else if (p.workspaces && typeof p.workspaces === 'object') {
    const pkgs = (p.workspaces as { packages?: unknown }).packages;
    if (Array.isArray(pkgs)) {
      workspaces = pkgs.filter((w): w is string => typeof w === 'string');
    }
  }

  const subpathImports =
    p.imports && typeof p.imports === 'object' && !Array.isArray(p.imports)
      ? (p.imports as Record<string, unknown>)
      : undefined;

  return { name, declaredDeps, subpathImports, workspaces };
}

/**
 * Builds the workspace map and context from pnpm-workspace.yaml and root package.json.
 * Fail-closed per source: errors in one config file never crash the entire run.
 */
export function buildWorkspaceContext(
  accessor: WorkspaceFileAccessor,
  options?: {
    baseBranchPackageNames?: ReadonlySet<string>;
    mode?: 'auto' | 'off';
    rootPkgPath?: string;
    rootYamlPath?: string;
    rootTsconfigPath?: string;
  }
): WorkspaceContext {
  const mode = options?.mode ?? 'auto';
  const rootPkgPath = normalizePosix(options?.rootPkgPath ?? 'package.json');
  const rootYamlPath = normalizePosix(options?.rootYamlPath ?? 'pnpm-workspace.yaml');
  const rootTsconfigPath = normalizePosix(options?.rootTsconfigPath ?? 'tsconfig.json');

  const diagnostics: WorkspaceDiagnosticNotice[] = [];
  const workspaceGlobs: string[] = [];
  let rootDeclaredDeps = new Set<string>();
  let rootPackageName: string | undefined;
  let rootSubpathImports: Record<string, unknown> | undefined;

  // 1. Parse root package.json
  const rootPkgRaw = accessor.readFile(rootPkgPath);
  if (rootPkgRaw !== null) {
    const parseRes = parseJsonc(rootPkgRaw);
    if (parseRes.success) {
      const manifest = extractPackageManifestData(parseRes.data);
      rootDeclaredDeps = manifest.declaredDeps;
      rootPackageName = manifest.name;
      rootSubpathImports = manifest.subpathImports;
      if (manifest.workspaces) {
        workspaceGlobs.push(...manifest.workspaces);
      }
    } else {
      diagnostics.push({
        ruleId: 'DG004-WS-UNPARSED',
        sourceFile: rootPkgPath,
        reason: parseRes.reason,
        message: `Failed to parse root package.json: ${parseRes.error}`,
        scoring: false,
      });
    }
  }

  // 2. Parse pnpm-workspace.yaml if present
  if (accessor.fileExists(rootYamlPath)) {
    const yamlRaw = accessor.readFile(rootYamlPath);
    if (yamlRaw !== null) {
      const yamlRes = parsePnpmWorkspaceYaml(yamlRaw);
      if (yamlRes.success) {
        workspaceGlobs.push(...yamlRes.data.packages);
      } else {
        diagnostics.push({
          ruleId: 'DG004-WS-UNPARSED',
          sourceFile: rootYamlPath,
          reason: yamlRes.reason,
          message: `Failed to parse pnpm-workspace.yaml: ${yamlRes.error}`,
          scoring: false,
        });
      }
    }
  }

  // 3. Parse root tsconfig.json if present
  let tsconfigData: TsconfigData | undefined;
  if (accessor.fileExists(rootTsconfigPath)) {
    const tsconfigRaw = accessor.readFile(rootTsconfigPath);
    if (tsconfigRaw !== null) {
      const tsAccessor: TsconfigFileAccessor = (p) => accessor.readFile(p);
      const tsRes = parseTsconfig(tsconfigRaw, rootTsconfigPath, tsAccessor);
      if (tsRes.success) {
        tsconfigData = tsRes.data;
      } else {
        diagnostics.push({
          ruleId: 'DG004-WS-UNPARSED',
          sourceFile: rootTsconfigPath,
          reason: tsRes.reason,
          message: `Failed to parse tsconfig.json: ${tsRes.error}`,
          scoring: false,
        });
      }
    }
  }

  const packagesByName = new Map<string, WorkspacePackageInfo>();
  const packagesByDir = new Map<string, WorkspacePackageInfo>();

  // If workspaces mode is off or no globs defined, return early
  if (mode === 'off' || workspaceGlobs.length === 0) {
    return {
      mode,
      rootPkgPath,
      rootDeclaredDeps,
      rootPackageName,
      rootSubpathImports,
      packagesByName,
      packagesByDir,
      workspaceGlobs,
      diagnostics,
      tsconfigData,
      undeclaredWorkspaceImportsCount: 0,
      nearestManifestCache: new Map(),
      resolutionCache: new Map(),
    };
  }

  // 4. Discover workspace package.json files
  const candidatePkgPaths: string[] = [];

  if (typeof accessor.listFiles === 'function') {
    const allFiles = accessor.listFiles();
    for (const f of allFiles) {
      const norm = normalizePosix(f);
      if (norm !== rootPkgPath && (norm.endsWith('/package.json') || norm === 'package.json')) {
        candidatePkgPaths.push(norm);
      }
    }
  } else if (typeof accessor.readDir === 'function') {
    const scanDirs = (dir: string): void => {
      const entries = accessor.readDir!(dir);
      if (!entries) return;
      const sortedEntries = [...entries].sort(compareCodePoints);
      for (const entry of sortedEntries) {
        if (entry === '.git' || entry === 'node_modules' || entry === 'dist' || entry === '.test-dist') {
          continue;
        }
        const sub = dir === '.' ? entry : `${dir}/${entry}`;
        const pkgCand = `${sub}/package.json`;
        if (accessor.fileExists(pkgCand)) {
          candidatePkgPaths.push(normalizePosix(pkgCand));
        }
        // Recurse bounded depth
        if (sub.split('/').length <= 5) {
          scanDirs(sub);
        }
      }
    };
    scanDirs('.');
  }

  // Sort candidate paths lexicographically for determinism (SPEC §6.2 butir 7)
  candidatePkgPaths.sort(compareCodePoints);

  for (const pkgJsonPath of candidatePkgPaths) {
    const relDir = getDirname(pkgJsonPath);
    if (!matchesWorkspaceGlobList(workspaceGlobs, relDir)) {
      continue;
    }

    const raw = accessor.readFile(pkgJsonPath);
    if (raw === null) continue;

    const parseRes = parseJsonc(raw);
    if (!parseRes.success) {
      diagnostics.push({
        ruleId: 'DG004-WS-UNPARSED',
        sourceFile: pkgJsonPath,
        reason: parseRes.reason,
        message: `Failed to parse workspace package.json at ${pkgJsonPath}: ${parseRes.error}`,
        scoring: false,
      });
      continue;
    }

    const manifest = extractPackageManifestData(parseRes.data);
    if (!manifest.name) {
      continue; // Skip packages without a name
    }

    const isNewInPr = Boolean(
      options?.baseBranchPackageNames && !options.baseBranchPackageNames.has(manifest.name)
    );

    if (isNewInPr) {
      diagnostics.push({
        ruleId: 'DG004-WS-NEW',
        sourceFile: pkgJsonPath,
        message: `New workspace package '${manifest.name}' added in this PR: verify package name integrity.`,
        scoring: false,
      });
    }

    const pkgInfo: WorkspacePackageInfo = {
      name: manifest.name,
      relDir,
      pkgJsonPath,
      declaredDeps: manifest.declaredDeps,
      subpathImports: manifest.subpathImports,
      isNewInPr,
    };

    packagesByName.set(manifest.name, pkgInfo);
    packagesByDir.set(relDir, pkgInfo);
  }

  return {
    mode,
    rootPkgPath,
    rootDeclaredDeps,
    rootPackageName,
    rootSubpathImports,
    packagesByName,
    packagesByDir,
    workspaceGlobs,
    diagnostics,
    tsconfigData,
    undeclaredWorkspaceImportsCount: 0,
    nearestManifestCache: new Map(),
    resolutionCache: new Map(),
  };
}

/**
 * Finds the nearest package.json manifest walking upwards from filePath's directory,
 * strictly stopping BEFORE or AT repo root.
 *
 * Invariant (SPEC §6.2 butir 2 & 3, A6-9, A6-10):
 * Intermediate ancestor manifests and sibling packages are NEVER returned or merged.
 * Also fail-closed: if the nearest package.json fails to parse, emits DG004-WS-UNPARSED
 * and never falls through to an intermediate ancestor.
 */
export function findNearestPackageManifest(
  targetFilePath: string,
  accessor: WorkspaceFileAccessor,
  rootPkgPath: string = 'package.json',
  context?: WorkspaceContext
): { relDir: string; pkgPath: string; manifestData: ReturnType<typeof extractPackageManifestData> } | null {
  const normFile = normalizePosix(targetFilePath);
  const normRoot = normalizePosix(rootPkgPath);
  const startDir = getDirname(normFile);

  if (context?.nearestManifestCache?.has(startDir)) {
    return context.nearestManifestCache.get(startDir) ?? null;
  }

  let curDir = startDir;
  let found: { relDir: string; pkgPath: string; manifestData: ReturnType<typeof extractPackageManifestData> } | null = null;

  while (curDir && curDir !== '.') {
    const candPath = normalizePosix(`${curDir}/package.json`);
    if (candPath === normRoot) {
      // Reached root manifest
      break;
    }
    if (accessor.fileExists(candPath)) {
      const raw = accessor.readFile(candPath);
      if (raw !== null) {
        const parsed = parseJsonc(raw);
        if (parsed.success) {
          found = {
            relDir: curDir,
            pkgPath: candPath,
            manifestData: extractPackageManifestData(parsed.data),
          };
        } else {
          if (
            context &&
            !context.diagnostics.some(
              (d) => d.ruleId === 'DG004-WS-UNPARSED' && d.sourceFile === candPath
            )
          ) {
            context.diagnostics.push({
              ruleId: 'DG004-WS-UNPARSED',
              sourceFile: candPath,
              reason: parsed.reason,
              message: `Failed to parse nearest package.json at ${candPath}: ${parsed.error}`,
              scoring: false,
            });
          }
          found = {
            relDir: curDir,
            pkgPath: candPath,
            manifestData: { declaredDeps: new Set() },
          };
        }
      } else {
        if (
          context &&
          !context.diagnostics.some(
            (d) => d.ruleId === 'DG004-WS-UNPARSED' && d.sourceFile === candPath
          )
        ) {
          context.diagnostics.push({
            ruleId: 'DG004-WS-UNPARSED',
            sourceFile: candPath,
            reason: 'jsonc_syntax',
            message: `Unreadable nearest package.json at ${candPath}`,
            scoring: false,
          });
        }
        found = {
          relDir: curDir,
          pkgPath: candPath,
          manifestData: { declaredDeps: new Set() },
        };
      }
      // Strict nearest-stop invariant: never walk past a present package.json to an intermediate ancestor
      break;
    }
    const parent = getDirname(curDir);
    if (parent === curDir) break;
    curDir = parent;
  }

  context?.nearestManifestCache?.set(startDir, found);
  return found;
}

/**
 * Resolves an imported specifier for targetFilePath using the strict fixed resolution order:
 *
 * 1. nearest package.json declared dependencies (§6.2.1) -> resolvedVia: 'nearest'
 * 2. root repo package.json ONLY (§6.2.2) -> resolvedVia: 'root'
 * 3. workspace package name map (§6.2.3) -> resolvedVia: 'workspace'
 * 4. tsconfig paths/baseUrl & package.json imports/self-reference (§6.2.4) -> resolvedVia: 'tsconfig' | 'imports'
 *
 * Sibling packages and intermediate ancestors are NEVER merged (A6-9, A6-10).
 */
export function resolveWorkspaceImportSpecifier(
  rawSpec: string,
  targetFilePath: string,
  context: WorkspaceContext,
  accessor: WorkspaceFileAccessor
): WorkspaceResolutionResult {
  if (!rawSpec || typeof rawSpec !== 'string') {
    return { specifier: rawSpec, basePackage: '', resolved: false, resolvedVia: 'unresolved' };
  }

  // Relative/absolute/alias path imports and internal URL/workspace/file/link protocols
  if (
    rawSpec.startsWith('.') ||
    rawSpec.startsWith('/') ||
    rawSpec.startsWith('~/') ||
    rawSpec.startsWith('@/') ||
    rawSpec.startsWith('virtual:') ||
    rawSpec.startsWith('workspace:') ||
    rawSpec.startsWith('file:') ||
    rawSpec.startsWith('link:') ||
    (/^[a-z][a-z0-9+.-]*:/i.test(rawSpec) && !rawSpec.startsWith('node:') && !rawSpec.startsWith('npm:'))
  ) {
    return { specifier: rawSpec, basePackage: rawSpec, resolved: true, resolvedVia: 'unresolved' };
  }

  const isNpmProtocol = rawSpec.startsWith('npm:');
  if (!isNpmProtocol && !rawSpec.startsWith('#')) {
    const strippedNode = rawSpec.startsWith('node:') ? rawSpec.slice(5) : rawSpec;
    const basePkgForBuiltin = getBasePackageName(strippedNode);
    if (
      rawSpec.startsWith('node:') ||
      DEFAULT_BUILTIN_NODE_MODULES.has(strippedNode) ||
      DEFAULT_BUILTIN_NODE_MODULES.has(basePkgForBuiltin)
    ) {
      return { specifier: rawSpec, basePackage: basePkgForBuiltin, resolved: true, resolvedVia: 'unresolved' };
    }
  }

  let basePkg: string;
  const isSubpathImport = rawSpec.startsWith('#');
  if (isSubpathImport) {
    basePkg = rawSpec;
  } else if (isNpmProtocol) {
    const npmTarget = parseProtocolAliasTarget('npm:', rawSpec);
    if (!npmTarget) {
      return { specifier: rawSpec, basePackage: '', resolved: false, resolvedVia: 'unresolved' };
    }
    basePkg = npmTarget;
  } else {
    basePkg = getBasePackageName(rawSpec);
  }

  const normTarget = normalizePosix(targetFilePath);
  const nearest = findNearestPackageManifest(normTarget, accessor, context.rootPkgPath, context);
  const cacheKey = `${context.mode}\0${nearest?.pkgPath ?? ''}\0${rawSpec}`;
  const cached = context.resolutionCache?.get(cacheKey);
  if (cached) {
    if (cached.isUndeclaredWorkspaceImport) {
      context.undeclaredWorkspaceImportsCount++;
    }
    return { ...cached };
  }

  const finalize = (result: WorkspaceResolutionResult): WorkspaceResolutionResult => {
    context.resolutionCache?.set(cacheKey, { ...result });
    return result;
  };

  // If workspaces mode is 'off', only nearest and root dependencies (plus # imports) apply without workspace map
  if (context.mode === 'off') {
    if (!isSubpathImport && nearest && nearest.manifestData.declaredDeps.has(basePkg)) {
      return finalize({ specifier: rawSpec, basePackage: basePkg, resolved: true, resolvedVia: 'nearest' });
    }
    if (!isSubpathImport && context.rootDeclaredDeps.has(basePkg)) {
      return finalize({ specifier: rawSpec, basePackage: basePkg, resolved: true, resolvedVia: 'root' });
    }
    if (
      isSubpathImport &&
      (matchesSubpathImport(rawSpec, nearest?.manifestData.subpathImports) ||
        matchesSubpathImport(rawSpec, context.rootSubpathImports))
    ) {
      return finalize({ specifier: rawSpec, basePackage: rawSpec, resolved: true, resolvedVia: 'imports' });
    }
    return finalize({ specifier: rawSpec, basePackage: basePkg, resolved: false, resolvedVia: 'unresolved' });
  }

  // 1. Nearest package.json (§6.2.1)
  if (!isSubpathImport && nearest && nearest.manifestData.declaredDeps.has(basePkg)) {
    return finalize({ specifier: rawSpec, basePackage: basePkg, resolved: true, resolvedVia: 'nearest' });
  }

  // 2. Root repo package.json ONLY (§6.2.2 & 6.2a)
  if (!isSubpathImport && context.rootDeclaredDeps.has(basePkg)) {
    return finalize({ specifier: rawSpec, basePackage: basePkg, resolved: true, resolvedVia: 'root' });
  }

  // 3. Workspace package name map (§6.2.3)
  if (!isSubpathImport && context.packagesByName.has(basePkg)) {
    const isSelfRef = nearest?.manifestData.name === basePkg;
    const isDeclaredInNearestOrRoot =
      Boolean(nearest && nearest.manifestData.declaredDeps.has(basePkg)) ||
      context.rootDeclaredDeps.has(basePkg);

    const isUndeclared = !isDeclaredInNearestOrRoot && !isSelfRef;
    if (isUndeclared) {
      context.undeclaredWorkspaceImportsCount++;
    }

    return finalize({
      specifier: rawSpec,
      basePackage: basePkg,
      resolved: true,
      resolvedVia: 'workspace',
      isUndeclaredWorkspaceImport: isUndeclared,
    });
  }

  // 4. tsconfig paths / baseUrl & package.json imports / self-reference (§6.2.4)
  if (!isNpmProtocol) {
    if (
      matchesTsconfigPaths(rawSpec, context.tsconfigData?.paths) ||
      matchesTsconfigBaseUrl(rawSpec, context.tsconfigData?.baseUrl, accessor)
    ) {
      return finalize({ specifier: rawSpec, basePackage: basePkg, resolved: true, resolvedVia: 'tsconfig' });
    }

    if (
      isSubpathImport &&
      (matchesSubpathImport(rawSpec, nearest?.manifestData.subpathImports) ||
        matchesSubpathImport(rawSpec, context.rootSubpathImports))
    ) {
      return finalize({ specifier: rawSpec, basePackage: rawSpec, resolved: true, resolvedVia: 'imports' });
    }

    if (!isSubpathImport && (nearest?.manifestData.name === basePkg || context.rootPackageName === basePkg)) {
      return finalize({ specifier: rawSpec, basePackage: basePkg, resolved: true, resolvedVia: 'imports' });
    }
  }

  return finalize({ specifier: rawSpec, basePackage: basePkg, resolved: false, resolvedVia: 'unresolved' });
}
