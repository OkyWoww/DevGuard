import {
  CRITICAL_FLOW_IDENTIFIERS,
  analyzeLexicalStructure,
  damerauLevenshtein,
  isCommentOrEmptyLine,
  type AuditAnalyzeOptions,
  type DevGuardRuleId,
  type ExtractedStringLiteral,
  type InlineFinding,
  type LineFinding,
} from './lexicalMasker.ts';
import { redactSecretsPreservingLayout } from './secretAndResilienceRules.ts';

export { CRITICAL_FLOW_IDENTIFIERS };

export const POPULAR_NPM_PACKAGES = [
  'express', 'lodash', 'axios', 'zod', 'jsonwebtoken', 'stripe', 'prisma',
  '@prisma/client', 'mongoose', 'bcrypt', 'bcryptjs', 'dotenv', 'cors', 'uuid',
  'moment', 'dayjs', 'chalk', 'commander', 'ws', 'pg', 'mysql2', 'redis',
  'ioredis', 'bullmq', 'next', 'react', 'vue', 'svelte', 'vite', 'vitest',
  'jest', 'typescript', 'tsx', 'openai', '@google/genai',
] as const;

const POPULAR_NPM_SET = new Set<string>(POPULAR_NPM_PACKAGES);

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

function getNodeBuiltinModuleSet(extraBuiltins?: readonly string[]): Set<string> {
  const set = new Set<string>(DEFAULT_BUILTIN_NODE_MODULES);
  if (extraBuiltins) {
    for (const mod of extraBuiltins) set.add(mod.replace(/^node:/, ''));
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

function getBasePackageName(specifier: string): string {
  if (specifier.startsWith('@')) {
    const parts = specifier.split('/');
    return parts.length >= 2 ? `${parts[0]}/${parts[1]}` : specifier;
  }
  return specifier.split('/')[0];
}

interface ResolvedPackageMetadata {
  declaredDeps?: ReadonlySet<string>;
  subpathImports?: Record<string, unknown>;
}

function matchesSubpathImport(specifier: string, subpathImports: Record<string, unknown>): boolean {
  if (Object.prototype.hasOwnProperty.call(subpathImports, specifier)) return true;
  for (const key of Object.keys(subpathImports)) {
    const starIdx = key.indexOf('*');
    if (starIdx !== -1) {
      const prefix = key.slice(0, starIdx);
      const suffix = key.slice(starIdx + 1);
      if (specifier.startsWith(prefix) && specifier.endsWith(suffix)) return true;
    }
  }
  return false;
}

function resolvePackageMetadata(options?: AuditAnalyzeOptions): ResolvedPackageMetadata {
  const result: ResolvedPackageMetadata = {
    declaredDeps:
      options?.declaredDependencies !== undefined
        ? options.declaredDependencies instanceof Set
          ? options.declaredDependencies
          : new Set(options.declaredDependencies)
        : undefined,
    subpathImports: options?.subpathImports,
  };

  if (result.declaredDeps !== undefined && result.subpathImports !== undefined) return result;
  if (!options?.filePath || typeof options.filePath !== 'string') return result;

  const proc = (globalThis as { process?: { getBuiltinModule?: (id: string) => unknown } }).process;
  if (!proc || typeof proc.getBuiltinModule !== 'function') return result;

  try {
    const fsMod = proc.getBuiltinModule('node:fs') as {
      existsSync: (p: string) => boolean;
      readFileSync: (p: string, enc: string) => string;
    };
    const pathMod = proc.getBuiltinModule('node:path') as {
      resolve: (...parts: string[]) => string;
      dirname: (p: string) => string;
      join: (...parts: string[]) => string;
    };

    const mergedDeps = new Set<string>();
    let foundAnyPkg = false;
    let mergedImports: Record<string, unknown> | undefined;

    let currentDir = pathMod.dirname(pathMod.resolve(options.filePath));
    while (true) {
      const pkgPath = pathMod.join(currentDir, 'package.json');
      if (fsMod.existsSync(pkgPath)) {
        foundAnyPkg = true;
        const parsed = JSON.parse(fsMod.readFileSync(pkgPath, 'utf-8')) as {
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
      const parentDir = pathMod.dirname(currentDir);
      if (parentDir === currentDir) break;
      currentDir = parentDir;
    }

    if (result.declaredDeps === undefined && foundAnyPkg) {
      result.declaredDeps = mergedDeps;
    }
    if (result.subpathImports === undefined && mergedImports) {
      result.subpathImports = mergedImports;
    }
  } catch {
    return result;
  }
  return result;
}

/** DG004: Detects typosquatted and undeclared phantom package imports. */
export function detectHallucinatedPackages(
  execLines: Array<{ num: number; text: string }>,
  maskedLines: string[],
  options: AuditAnalyzeOptions | undefined,
  findings: LineFinding[],
  inlineFindings: InlineFinding[]
): void {
  const builtinSet = getNodeBuiltinModuleSet(options?.builtinModules);
  const { declaredDeps, subpathImports } = resolvePackageMetadata(options);
  const staticImportRe = /^\s*(?:(?:import|export)\b[^'"]*\bfrom\s+|import\s+|\}\s*from\s+)['"]([^'"]+)['"]/;
  const dynamicOrRequireRe =
    /(?:^|[^\w.'"`])\b(?:require|import)\s*\(\s*['"]([^'"]+)['"]\s*(?:,|\))/g;
  const maskedImportOrRequireRe = /^\s*(?:import\b|export\b[^\n;]*\bfrom\b|\}\s*from\b)|(?:^|[^\w.'"`])\b(?:require|import)\s*\(/;

  const evalSpec = (num: number, rawSpec: string, lineText: string): void => {
    if (!rawSpec) return;

    if (rawSpec.startsWith('#')) {
      if (subpathImports && !matchesSubpathImport(rawSpec, subpathImports)) {
        const msg = `Subpath import '${rawSpec}' tidak terdaftar pada field "imports" di package.json (baris ${num}).`;
        findings.push({
          line: num,
          category: 'security',
          penalty: 35,
          shortReason: `-35 [DG004] Undeclared subpath import '${rawSpec}' (baris ${num})`,
          detailedReason: msg,
          isCritical: true,
        });
        inlineFindings.push({ ruleId: 'DG004', line: num, severity: 'error', message: msg });
      }
      return;
    }

    if (
      rawSpec.startsWith('.') ||
      rawSpec.startsWith('/') ||
      rawSpec.startsWith('@/') ||
      rawSpec.startsWith('~/') ||
      rawSpec.startsWith('virtual:') ||
      (/^[a-z]+:/i.test(rawSpec) && !rawSpec.startsWith('node:'))
    ) {
      return;
    }

    const strippedNode = rawSpec.startsWith('node:') ? rawSpec.slice(5) : rawSpec;
    const baseStripped = getBasePackageName(strippedNode);
    if (builtinSet.has(strippedNode) || builtinSet.has(baseStripped)) return;

    const basePkg = getBasePackageName(rawSpec);

    if (!POPULAR_NPM_SET.has(basePkg)) {
      let bestCandidate: string | undefined;
      let bestDist = Number.POSITIVE_INFINITY;

      for (const popular of POPULAR_NPM_PACKAGES) {
        const dist = damerauLevenshtein(basePkg, popular);
        const isMatch = (dist === 1 && basePkg.length >= 5) || (dist === 2 && basePkg.length >= 8);
        if (isMatch && dist < bestDist) {
          bestDist = dist;
          bestCandidate = popular;
        }
      }

      if (bestCandidate) {
        const replacementPkg = rawSpec === basePkg ? bestCandidate : rawSpec.replace(basePkg, bestCandidate);
        const suggestion = lineText.replace(rawSpec, replacementPkg);
        const msg = `Potensi slopsquatting / typosquatting pada paket '${rawSpec}' (jarak edit ${bestDist} dari '${bestCandidate}').`;
        findings.push({
          line: num,
          category: 'security',
          penalty: 40,
          shortReason: `-40 [DG004] Typosquatting paket '${rawSpec}' -> '${bestCandidate}' (baris ${num})`,
          detailedReason: msg,
          isCritical: true,
        });
        inlineFindings.push({
          ruleId: 'DG004',
          line: num,
          severity: 'error',
          message: msg,
          suggestion,
        });
        return;
      }
    }

    if (declaredDeps && !declaredDeps.has(basePkg)) {
      const msg = `Phantom dependency '${basePkg}' diimpor pada baris ${num} namun tidak terdaftar di package.json.`;
      findings.push({
        line: num,
        category: 'security',
        penalty: 35,
        shortReason: `-35 [DG004] Phantom dependency '${basePkg}' absen dari package.json (baris ${num})`,
        detailedReason: msg,
        isCritical: true,
      });
      inlineFindings.push({
        ruleId: 'DG004',
        line: num,
        severity: 'error',
        message: msg,
      });
    }
  };

  const seenSpecs = new Set<string>();
  const lineTextByNum = new Map<number, string>();
  for (const l of execLines) lineTextByNum.set(l.num, l.text);

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
      if (seenSpecs.has(key)) continue;
      seenSpecs.add(key);
      evalSpec(num, rawSpec, text);
    }
  }

  // Also catch multi-line dynamic import(\n 'pkg'\n) / require(\n 'pkg'\n) spanning lines
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
      if (seenSpecs.has(key)) continue;
      seenSpecs.add(key);
      evalSpec(lineEntry.num, rawSpec, lineEntry.text);
    }
  }
}

const METHOD_PREFIX_KEYWORDS = new Set(['function', 'async', 'get', 'set', 'static']);

function isIdentCharCode(code: number): boolean {
  return (
    (code >= 48 && code <= 57) ||
    (code >= 65 && code <= 90) ||
    (code >= 97 && code <= 122) ||
    code === 95 ||
    code === 36
  );
}

function buildLineStarts(text: string): number[] {
  const starts: number[] = [0];
  for (let i = 0; i < text.length; i++) {
    if (text.charCodeAt(i) === 10) {
      starts.push(i + 1);
    }
  }
  return starts;
}

function offsetToLine(offset: number, lineStarts: number[]): number {
  let lo = 0;
  let hi = lineStarts.length - 1;
  while (lo <= hi) {
    const mid = (lo + hi) >>> 1;
    if (lineStarts[mid] <= offset) {
      lo = mid + 1;
    } else {
      hi = mid - 1;
    }
  }
  return Math.max(1, hi + 1);
}

function skipWsForward(str: string, idx: number): number {
  let i = idx;
  while (i < str.length && /\s/.test(str[i])) i++;
  return i;
}

function skipWsBackward(str: string, idx: number): number {
  let i = idx;
  while (i >= 0 && /\s/.test(str[i])) i--;
  return i;
}

function readPrevTokenInfo(str: string, idxBeforeIdent: number): {
  prevNonWsChar: string;
  prevNonWsIdx: number;
  prevWord: string;
} {
  const prevNonWsIdx = skipWsBackward(str, idxBeforeIdent);
  if (prevNonWsIdx < 0) {
    return { prevNonWsChar: '', prevNonWsIdx: -1, prevWord: '' };
  }
  const prevNonWsChar = str[prevNonWsIdx];
  let prevWord = '';
  if (isIdentCharCode(str.charCodeAt(prevNonWsIdx))) {
    let start = prevNonWsIdx;
    while (start > 0 && isIdentCharCode(str.charCodeAt(start - 1))) {
      start--;
    }
    prevWord = str.slice(start, prevNonWsIdx + 1);
  }
  return { prevNonWsChar, prevNonWsIdx, prevWord };
}

function findCallParenSpan(
  maskedCode: string,
  openParenIdx: number
): { closeParenIdx: number; firstCommaIdx: number } | null {
  let parenDepth = 1;
  let braceDepth = 0;
  let bracketDepth = 0;
  let firstCommaIdx = -1;

  for (let i = openParenIdx + 1; i < maskedCode.length; i++) {
    const ch = maskedCode[i];
    if (ch === '(') parenDepth++;
    else if (ch === ')') {
      parenDepth--;
      if (parenDepth === 0) {
        return { closeParenIdx: i, firstCommaIdx };
      }
    } else if (ch === '{') braceDepth++;
    else if (ch === '}') {
      if (braceDepth > 0) braceDepth--;
    } else if (ch === '[') bracketDepth++;
    else if (ch === ']') {
      if (bracketDepth > 0) bracketDepth--;
    } else if (ch === ',' && parenDepth === 1 && braceDepth === 0 && bracketDepth === 0 && firstCommaIdx === -1) {
      firstCommaIdx = i;
    }
  }
  return null;
}

function hasTernaryOrCaseColonContext(maskedCode: string, identStart: number, prevWord: string): boolean {
  if (prevWord === 'case') return true;
  let parenDepth = 0;
  let bracketDepth = 0;
  let braceDepth = 0;

  for (let i = identStart - 1; i >= 0; i--) {
    const ch = maskedCode[i];
    if (ch === ')') parenDepth++;
    else if (ch === '(') {
      if (parenDepth === 0) return false;
      parenDepth--;
    } else if (ch === ']') bracketDepth++;
    else if (ch === '[') {
      if (bracketDepth === 0) return false;
      bracketDepth--;
    } else if (ch === '}') braceDepth++;
    else if (ch === '{') {
      if (braceDepth === 0) return false;
      braceDepth--;
    } else if (parenDepth === 0 && bracketDepth === 0 && braceDepth === 0) {
      if (ch === ';' || ch === ',' || ch === '=') {
        if (ch === '=' && maskedCode[i + 1] === '>') continue;
        return false;
      }
      if (ch === '?') {
        const nextCh = maskedCode[i + 1];
        const prevCh = i > 0 ? maskedCode[i - 1] : '';
        if (nextCh !== '.' && nextCh !== '?' && prevCh !== '?') {
          return true;
        }
      }
    }
  }
  return false;
}

function isMethodOrFunctionDef(
  maskedCode: string,
  identStart: number,
  closeParenIdx: number,
  prevWord: string,
  prevNonWsChar: string,
  prevNonWsIdx: number
): boolean {
  if (METHOD_PREFIX_KEYWORDS.has(prevWord)) {
    return true;
  }
  if (prevNonWsChar === '*') {
    const beforeStar = readPrevTokenInfo(maskedCode, prevNonWsIdx - 1);
    if (beforeStar.prevWord === 'function' || METHOD_PREFIX_KEYWORDS.has(beforeStar.prevWord)) {
      return true;
    }
  }

  const afterParen = skipWsForward(maskedCode, closeParenIdx + 1);
  if (afterParen >= maskedCode.length) return false;
  if (maskedCode[afterParen] === '{') return true;
  if (maskedCode[afterParen] !== ':') return false;
  if (hasTernaryOrCaseColonContext(maskedCode, identStart, prevWord)) return false;

  let parenDepth = 0;
  let bracketDepth = 0;
  let angleDepth = 0;

  for (let i = afterParen + 1; i < maskedCode.length; i++) {
    const ch = maskedCode[i];
    if (ch === '(') parenDepth++;
    else if (ch === ')') {
      if (parenDepth === 0) return false;
      parenDepth--;
    } else if (ch === '[') bracketDepth++;
    else if (ch === ']') {
      if (bracketDepth === 0) return false;
      bracketDepth--;
    } else if (ch === '<') angleDepth++;
    else if (ch === '>') {
      if (maskedCode[i - 1] !== '=' && angleDepth > 0) angleDepth--;
    } else if (parenDepth === 0 && bracketDepth === 0 && angleDepth === 0) {
      if (ch === '{' || ch === ';') return true;
      if (ch === ',' || (ch === '=' && maskedCode[i + 1] !== '>')) return false;
    }
  }
  return false;
}

function findLiteralsInSpan(
  stringLiterals: ReadonlyArray<ExtractedStringLiteral>,
  rangeStart: number,
  rangeEnd: number
): ExtractedStringLiteral[] {
  let lo = 0;
  let hi = stringLiterals.length;
  while (lo < hi) {
    const mid = (lo + hi) >>> 1;
    if (stringLiterals[mid].startOffset < rangeStart) {
      lo = mid + 1;
    } else {
      hi = mid;
    }
  }
  const matches: ExtractedStringLiteral[] = [];
  for (let i = lo; i < stringLiterals.length; i++) {
    const lit = stringLiterals[i];
    if (lit.startOffset >= rangeEnd) break;
    if (lit.endOffset <= rangeEnd) {
      matches.push(lit);
    }
  }
  return matches;
}

function getEnclosingOpenDelimiter(maskedCode: string, idx: number): string {
  let parenDepth = 0;
  let braceDepth = 0;
  for (let i = idx - 1; i >= 0; i--) {
    const ch = maskedCode[i];
    if (ch === ')') parenDepth++;
    else if (ch === '(') {
      if (parenDepth === 0) return '(';
      parenDepth--;
    } else if (ch === '}') braceDepth++;
    else if (ch === '{') {
      if (braceDepth === 0) return '{';
      braceDepth--;
    }
  }
  return '';
}

function hasShadowedRequireInCode(maskedCode: string): boolean {
  let pos = 0;
  while (pos < maskedCode.length) {
    const idx = maskedCode.indexOf('require', pos);
    if (idx === -1) break;
    pos = idx + 7;

    const beforeOk = idx === 0 || !isIdentCharCode(maskedCode.charCodeAt(idx - 1));
    const afterOk = idx + 7 >= maskedCode.length || !isIdentCharCode(maskedCode.charCodeAt(idx + 7));
    if (!beforeOk || !afterOk) continue;

    const prev = readPrevTokenInfo(maskedCode, idx - 1);
    if (prev.prevNonWsChar === '.') continue; // obj.require or foo?.require property name
    if (prev.prevWord === 'typeof') continue; // typeof require check

    const afterIdx = skipWsForward(maskedCode, idx + 7);
    const nextCh = maskedCode[afterIdx];
    if (
      nextCh === ':' &&
      prev.prevWord !== 'case' &&
      prev.prevWord !== 'const' &&
      prev.prevWord !== 'let' &&
      prev.prevWord !== 'var' &&
      getEnclosingOpenDelimiter(maskedCode, idx) === '{'
    ) {
      continue; // Object literal / TypeScript interface property key `{ require: ... }`
    }
    if (nextCh === '.' || (nextCh === '?' && maskedCode[afterIdx + 1] === '.')) {
      continue; // require.resolve, require.cache, require.main, etc.
    }
    if (nextCh === '(') {
      const span = findCallParenSpan(maskedCode, afterIdx);
      const isFunctionDecl =
        prev.prevWord === 'function' ||
        (prev.prevNonWsChar === '*' && readPrevTokenInfo(maskedCode, prev.prevNonWsIdx - 1).prevWord === 'function');
      if (span && !isFunctionDecl) {
        continue; // valid call require(...) or non-shadowing class/object method definition
      }
    }
    return true;
  }
  return false;
}

function scanDynamicKind(
  kind: 'import' | 'require',
  maskedCode: string,
  stringLiterals: ReadonlyArray<ExtractedStringLiteral>,
  lineStarts: number[],
  displayFile: string,
  inlineFindings: InlineFinding[]
): void {
  const token = kind;
  const tokenLen = token.length;
  let pos = 0;

  while (pos < maskedCode.length) {
    const idx = maskedCode.indexOf(token, pos);
    if (idx === -1) break;
    pos = idx + tokenLen;

    const beforeOk = idx === 0 || !isIdentCharCode(maskedCode.charCodeAt(idx - 1));
    const afterOk = idx + tokenLen >= maskedCode.length || !isIdentCharCode(maskedCode.charCodeAt(idx + tokenLen));
    if (!beforeOk || !afterOk) continue;

    const prev = readPrevTokenInfo(maskedCode, idx - 1);
    if (prev.prevNonWsChar === '.') continue; // obj.import(x), module.require(x), foo?.require(x)

    const afterIdx = skipWsForward(maskedCode, idx + tokenLen);
    if (maskedCode[afterIdx] !== '(') continue;

    const span = findCallParenSpan(maskedCode, afterIdx);
    if (!span) continue;

    if (isMethodOrFunctionDef(maskedCode, idx, span.closeParenIdx, prev.prevWord, prev.prevNonWsChar, prev.prevNonWsIdx)) {
      continue;
    }

    const argStart = afterIdx + 1;
    const firstArgEnd = span.firstCommaIdx !== -1 ? span.firstCommaIdx : span.closeParenIdx;
    const argMasked = maskedCode.slice(argStart, firstArgEnd).trim();
    const literalsInArg = findLiteralsInSpan(stringLiterals, argStart, firstArgEnd);

    // Skip zero-argument calls: import() / require()
    if (span.firstCommaIdx === -1 && argMasked.length === 0 && literalsInArg.length === 0) {
      continue;
    }

    // Literal specifier iff first arg has zero residual code tokens and exactly one literal without ${...}
    const validCommaDelim = kind === 'import' || span.firstCommaIdx === -1;
    const isSingleLiteral =
      validCommaDelim &&
      argMasked.length === 0 &&
      literalsInArg.length === 1 &&
      !literalsInArg[0].hasInterpolation;

    if (isSingleLiteral) {
      continue;
    }

    const line = offsetToLine(idx, lineStarts);
    const ruleId: DevGuardRuleId = kind === 'import' ? 'DG004-DYN-01' : 'DG004-DYN-02';
    const callLabel = kind === 'import' ? 'import()' : 'require()';
    inlineFindings.push({
      ruleId,
      line,
      severity: 'warning',
      scoring: false,
      message: `[${ruleId}] Unanalyzable dynamic ${callLabel} specifier at ${displayFile}:${line} (supply-chain static verification skipped; allowlist in base-branch .devguard.json if intentional).`,
    });
  }
}

/**
 * Lexically detects non-literal `import()` (`DG004-DYN-01`) and `require()` (`DG004-DYN-02`)
 * specifiers as non-scoring warnings (`scoring: false`), applying syntactic and file-level
 * conservative shadow guards to prevent false positives.
 */
export function detectDynamicModuleSpecifiers(
  maskedCode: string,
  stringLiterals: ReadonlyArray<ExtractedStringLiteral>,
  options: AuditAnalyzeOptions | undefined,
  inlineFindings: InlineFinding[]
): { dynScopeUncertain: number } {
  const lineStarts = buildLineStarts(maskedCode);
  const rawFile = (options?.filePath || 'input').replace(/\\/g, '/');
  const displayFile = redactSecretsPreservingLayout(rawFile);

  scanDynamicKind('import', maskedCode, stringLiterals, lineStarts, displayFile, inlineFindings);

  let dynScopeUncertain = 0;
  if (hasShadowedRequireInCode(maskedCode)) {
    dynScopeUncertain = 1;
  } else {
    scanDynamicKind('require', maskedCode, stringLiterals, lineStarts, displayFile, inlineFindings);
  }

  return { dynScopeUncertain };
}

function stripBalancedConsoleCalls(body: string): string {
  let out = body;
  const consoleRe = /\bconsole\s*\.\s*(?:log|warn|error|info|debug)\s*\(/g;
  let match: RegExpExecArray | null;
  while ((match = consoleRe.exec(out)) !== null) {
    let idx = match.index + match[0].length;
    let depth = 1;
    let quote: string | null = null;
    while (idx < out.length && depth > 0) {
      const ch = out[idx];
      if (quote) {
        if (ch === '\\') idx++;
        else if (ch === quote) quote = null;
      } else if (ch === '\'' || ch === '"' || ch === '`') {
        quote = ch;
      } else if (ch === '(') {
        depth++;
      } else if (ch === ')') {
        depth--;
      }
      idx++;
    }
    out = out.slice(0, match.index) + out.slice(idx);
    consoleRe.lastIndex = match.index;
  }
  return out;
}

function stripCommentsFromSnippet(snippet: string): string {
  return snippet
    .replace(/\/\*[\s\S]*?\*\//g, '')
    .replace(/(^|[^:\\])\/\/[^\n]*/g, '$1');
}

function extractBraceBlock(source: string, openBraceIdx: number): { body: string; endIdx: number } | null {
  let depth = 1;
  let idx = openBraceIdx + 1;
  let quote: string | null = null;
  let inLineComment = false;
  let inBlockComment = false;

  while (idx < source.length && depth > 0) {
    const ch = source[idx];
    const next = source[idx + 1];

    if (inLineComment) {
      if (ch === '\n') inLineComment = false;
    } else if (inBlockComment) {
      if (ch === '*' && next === '/') {
        inBlockComment = false;
        idx++;
      }
    } else if (quote) {
      if (ch === '\\') idx++;
      else if (ch === quote) quote = null;
    } else {
      if (ch === '/' && next === '/') {
        inLineComment = true;
        idx++;
      } else if (ch === '/' && next === '*') {
        inBlockComment = true;
        idx++;
      } else if (ch === '\'' || ch === '"' || ch === '`') {
        quote = ch;
      } else if (ch === '{') {
        depth++;
      } else if (ch === '}' && --depth === 0) {
        return { body: source.slice(openBraceIdx + 1, idx), endIdx: idx };
      }
    }
    idx++;
  }
  return null;
}

const CRITICAL_FLOW_ALT = CRITICAL_FLOW_IDENTIFIERS.join('|');
const CRITICAL_FLOW_RE = new RegExp(`(?:^|[^a-z])(?:${CRITICAL_FLOW_ALT})`, 'i');
const CRITICAL_FLOW_CAMEL_RE = new RegExp(
  `[a-z](?:${CRITICAL_FLOW_IDENTIFIERS.map((id) => id[0].toUpperCase() + id.slice(1)).join('|')})`
);

/** Shared critical-flow identifier matcher used by both DG005 try/catch and DG005-EV-01 .catch(). */
export function matchesCriticalFlow(text: string): boolean {
  return CRITICAL_FLOW_RE.test(text) || CRITICAL_FLOW_CAMEL_RE.test(text);
}

const CLEANUP_METHOD_NAMES = new Set([
  'unlink', 'unlinkSync', 'rm', 'rmSync', 'rmdir', 'close', 'closeSync', 'destroy',
]);

const EMPTY_ARROW_CATCH_RE =
  /^(?:async\s+)?(?:\(\s*(?:[A-Za-z_$][\w$]*(?:\s*\??\s*:\s*[^,)=]+)?)?\s*\)|[A-Za-z_$][\w$]*)\s*=>\s*\{\s*\}$/;
const EMPTY_FN_CATCH_RE =
  /^(?:async\s+)?function(?:\s+[A-Za-z_$][\w$]*)?\s*\(\s*(?:[A-Za-z_$][\w$]*(?:\s*\??\s*:\s*[^,)=]+)?)?\s*\)\s*\{\s*\}$/;

function isEmptyCatchCallback(maskedArgText: string): boolean {
  const trimmed = maskedArgText.trim();
  if (!trimmed) return false;
  return EMPTY_ARROW_CATCH_RE.test(trimmed) || EMPTY_FN_CATCH_RE.test(trimmed);
}

function findMatchingParenForward(maskedCode: string, openParenIdx: number): number {
  let depth = 1;
  for (let i = openParenIdx + 1; i < maskedCode.length; i++) {
    const ch = maskedCode[i];
    if (ch === '(') depth++;
    else if (ch === ')') {
      depth--;
      if (depth === 0) return i;
    }
  }
  return -1;
}

function findMatchingParenBackward(maskedCode: string, closeParenIdx: number): number {
  let depth = 1;
  for (let i = closeParenIdx - 1; i >= 0; i--) {
    const ch = maskedCode[i];
    if (ch === ')') depth++;
    else if (ch === '(') {
      depth--;
      if (depth === 0) return i;
    }
  }
  return -1;
}

interface ReceiverChainBackbone {
  segments: string[];
  immediateCallName: string | null;
  immediateObjName: string | null;
}

const RECEIVER_STOP_KEYWORDS = new Set([
  'return', 'await', 'yield', 'typeof', 'void', 'delete', 'new', 'throw', 'case', 'in', 'of', 'else', 'do',
]);

function extractReceiverBackbone(maskedCode: string, dotIdx: number): ReceiverChainBackbone {
  const segments: string[] = [];
  let immediateCallName: string | null = null;
  let immediateObjName: string | null = null;

  let i = dotIdx - 1;
  let isFirstStep = true;
  let steps = 0;
  const MAX_CHAIN_STEPS = 64;

  while (i >= 0 && steps < MAX_CHAIN_STEPS) {
    steps++;
    while (i >= 0 && /\s/.test(maskedCode[i])) i--;
    if (i < 0) break;

    if (maskedCode[i] === '!') {
      i--;
      while (i >= 0 && /\s/.test(maskedCode[i])) i--;
      if (i < 0) break;
    }

    let hadCallParens = false;
    while (i >= 0 && maskedCode[i] === ')') {
      const openIdx = findMatchingParenBackward(maskedCode, i);
      if (openIdx === -1) return { segments, immediateCallName, immediateObjName };
      hadCallParens = true;
      i = openIdx - 1;
      while (i >= 0 && /\s/.test(maskedCode[i])) i--;
    }

    if (i < 0 || !/[A-Za-z0-9_$]/.test(maskedCode[i])) break;

    const identEnd = i + 1;
    while (i >= 0 && /[A-Za-z0-9_$]/.test(maskedCode[i])) i--;
    const ident = maskedCode.slice(i + 1, identEnd);

    if (RECEIVER_STOP_KEYWORDS.has(ident)) break;

    segments.push(ident);
    if (isFirstStep && hadCallParens) {
      immediateCallName = ident;
    } else if (segments.length === 2 && immediateCallName !== null) {
      immediateObjName = ident;
    }
    isFirstStep = false;

    while (i >= 0 && /\s/.test(maskedCode[i])) i--;
    if (i >= 0 && maskedCode[i] === '.') {
      i--;
      if (i >= 0 && maskedCode[i] === '?') i--;
      continue;
    }
    break;
  }

  return { segments, immediateCallName, immediateObjName };
}

/** DG005: Detects empty or console-only catch blocks and empty Promise .catch() on critical flows. */
export function detectSwallowedExceptions(
  rawCode: string,
  findings: LineFinding[],
  inlineFindings: InlineFinding[],
  maskedCode?: string
): void {
  const tryRe = /\btry\s*\{/g;
  const cleanupCallRe = /\b(?:unlink|unlinkSync|rm|rmSync|rmdir|close|closeSync|destroy)\s*\(/;
  const jsonParseRe = /\bJSON\.parse\s*\(/;
  const recoveryRe = /\b(?:throw|return|reject|process\.exit|rollback|abort)\b/;

  let match: RegExpExecArray | null;
  while ((match = tryRe.exec(rawCode)) !== null) {
    const tryOpenBrace = rawCode.indexOf('{', match.index);
    if (tryOpenBrace === -1) continue;
    const tryBlock = extractBraceBlock(rawCode, tryOpenBrace);
    if (!tryBlock) continue;

    const afterTry = rawCode.slice(tryBlock.endIdx + 1);
    const catchHeaderMatch = afterTry.match(/^\s*catch\b(?:\s*\([^)]*\))?\s*\{/);
    if (!catchHeaderMatch) continue;

    const catchStartOffset = tryBlock.endIdx + 1 + catchHeaderMatch[0].length - 1;
    const catchBlock = extractBraceBlock(rawCode, catchStartOffset);
    if (!catchBlock) continue;

    const strippedTry = stripCommentsFromSnippet(tryBlock.body);
    const strippedCatch = stripCommentsFromSnippet(catchBlock.body);

    if (recoveryRe.test(strippedCatch)) continue;
    if (stripBalancedConsoleCalls(strippedCatch).replace(/[;\s]/g, '').length > 0) continue;

    const isCriticalContext = matchesCriticalFlow(strippedTry);
    if (!isCriticalContext && (cleanupCallRe.test(strippedTry) || jsonParseRe.test(strippedTry))) {
      continue;
    }

    const catchLine = rawCode.slice(0, catchStartOffset).split('\n').length;
    const catchEndLine = rawCode.slice(0, catchBlock.endIdx).split('\n').length;

    if (isCriticalContext) {
      const msg = `Swallowed exception pada alur transaksi/keamanan kritis (baris ${catchLine}): blok catch kosong atau hanya logging tanpa propagate/rollback.`;
      findings.push({
        line: catchLine,
        category: 'security',
        penalty: 20,
        shortReason: `-20 [DG005] Swallowed exception pada alur kritis (baris ${catchLine})`,
        detailedReason: msg,
        isCritical: true,
      });
      findings.push({
        line: catchLine,
        category: 'correctness',
        penalty: 15,
        shortReason: `-15 [DG005] Kegagalan transaksi kritis ditelan tanpa throw/rollback (baris ${catchLine})`,
        detailedReason: msg,
      });
      inlineFindings.push({
        ruleId: 'DG005',
        line: catchLine,
        endLine: catchEndLine > catchLine ? catchEndLine : undefined,
        severity: 'error',
        message: msg,
        suggestion: `} catch (err) {\n  console.error('Critical operation failed:', err);\n  throw err;\n}`,
      });
    } else {
      const msg = `Swallowed exception (baris ${catchLine}): blok catch kosong atau hanya memanggil console.* tanpa penanganan eksplisit.`;
      findings.push({
        line: catchLine,
        category: 'maintainability',
        penalty: 10,
        shortReason: `-10 [DG005] Swallowed exception tanpa penanganan/return eksplisit (baris ${catchLine})`,
        detailedReason: msg,
      });
      inlineFindings.push({
        ruleId: 'DG005',
        line: catchLine,
        endLine: catchEndLine > catchLine ? catchEndLine : undefined,
        severity: 'warning',
        message: msg,
      });
    }
  }

  // DG005-EV-01: Empty Promise .catch(<empty_callback>) on critical receiver chains (SPEC §6.3)
  const effectiveMasked = typeof maskedCode === 'string' ? maskedCode : analyzeLexicalStructure(rawCode).maskedCode;
  const dotCatchRe = /(\??\.)\s*catch\s*\(/g;
  const flaggedCatchLines = new Set<number>();
  let dotCatchMatch: RegExpExecArray | null;

  while ((dotCatchMatch = dotCatchRe.exec(effectiveMasked)) !== null) {
    const dotIdx = dotCatchMatch.index;
    const openParenIdx = dotCatchMatch.index + dotCatchMatch[0].length - 1;
    const closeParenIdx = findMatchingParenForward(effectiveMasked, openParenIdx);
    if (closeParenIdx === -1) continue;

    const argText = effectiveMasked.slice(openParenIdx + 1, closeParenIdx);
    if (!isEmptyCatchCallback(argText)) continue;

    const backbone = extractReceiverBackbone(effectiveMasked, dotIdx);
    if (backbone.segments.length === 0) continue;

    // Cleanup exemption applies ONLY to the call immediately preceding .catch
    const isImmediateCleanup =
      backbone.immediateCallName !== null &&
      (CLEANUP_METHOD_NAMES.has(backbone.immediateCallName) ||
        (backbone.immediateObjName === 'JSON' && backbone.immediateCallName === 'parse'));
    if (isImmediateCleanup) continue;

    if (!backbone.segments.some((seg) => matchesCriticalFlow(seg))) continue;

    const catchLine = effectiveMasked.slice(0, dotIdx).split('\n').length;
    const catchEndLine = effectiveMasked.slice(0, closeParenIdx).split('\n').length;
    if (flaggedCatchLines.has(catchLine)) continue;
    flaggedCatchLines.add(catchLine);

    const msg = `[DG005-EV-01] Swallowed Promise rejection via empty .catch() pada alur kritis (baris ${catchLine}): tambahkan error handling atau propagasi eksplisit.`;
    findings.push({
      line: catchLine,
      category: 'maintainability',
      penalty: 10,
      shortReason: `-10 [DG005] [DG005-EV-01] Promise .catch() kosong menelan error pada alur kritis (baris ${catchLine})`,
      detailedReason: msg,
    });
    inlineFindings.push({
      ruleId: 'DG005',
      line: catchLine,
      endLine: catchEndLine > catchLine ? catchEndLine : undefined,
      severity: 'warning',
      message: msg,
      suggestion: `.catch((err) => {\n  console.error('Critical operation failed:', err);\n  throw err;\n})`,
    });
  }
}

/** DG006: Detects check-then-act TOCTOU race conditions on balance/stock across await boundaries. */
export function detectNonAtomicBalanceMutations(
  rawLines: string[],
  findings: LineFinding[],
  inlineFindings: InlineFinding[]
): void {
  const entityCompareRe = /\b((?:\w+\.)?(?:balance|saldo|credits?|wallet|stock|inventory|quota|points))\b\s*(?:>=|<=|>|<)/i;
  const reverseCompareRe = /(?:>=|<=|>|<)\s*\b((?:\w+\.)?(?:balance|saldo|credits?|wallet|stock|inventory|quota|points))\b/i;
  const atomicGuardRe =
    /\$transaction|FOR\s+UPDATE|SERIALIZABLE|\batomic\b|\bmutex\b|\block\b|\$inc|WHERE\s+[\w.]*\b(?:balance|saldo|credits?|wallet|stock|inventory|quota|points)\b\s*>=/i;

  const flaggedMutationLines = new Set<number>();

  for (let i = 0; i < rawLines.length; i++) {
    const line1 = rawLines[i];
    if (isCommentOrEmptyLine(line1)) continue;
    if (/\b(?:SELECT|UPDATE|WHERE)\b/i.test(line1)) continue;

    const cmpMatch = line1.match(entityCompareRe) || line1.match(reverseCompareRe);
    if (!cmpMatch?.[1]) continue;

    const entityFull = cmpMatch[1];
    const entityBase = entityFull.includes('.') ? entityFull.split('.').pop()! : entityFull;
    const escapedEntity = entityBase.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const mutationRe = new RegExp(
      `\\b(?:\\w+\\.)?${escapedEntity}\\b\\s*(?:[-+]=|=\\s*[^;\\n]*\\b(?:\\w+\\.)?${escapedEntity}\\b\\s*[-+]|:\\s*[^;\\n]*\\b(?:\\w+\\.)?${escapedEntity}\\b\\s*[-+])`,
      'i'
    );

    let sawAwait = false;
    const windowEnd = Math.min(rawLines.length - 1, i + 25);

    for (let j = i + 1; j <= windowEnd; j++) {
      const line2 = rawLines[j];
      if (isCommentOrEmptyLine(line2)) continue;
      if (/\bawait\b/.test(line2)) sawAwait = true;

      if (sawAwait && mutationRe.test(line2) && !flaggedMutationLines.has(j + 1)) {
        const contextSlice = rawLines.slice(Math.max(0, i - 15), Math.min(rawLines.length, j + 10)).join('\n');
        if (atomicGuardRe.test(contextSlice)) break;

        const mutLineNum = j + 1;
        flaggedMutationLines.add(mutLineNum);
        const msg = `Non-atomic check-then-act TOCTOU race condition pada '${entityFull}' melintasi boundary await (cek baris ${i + 1}, mutasi baris ${mutLineNum}) tanpa transaksi atomik.`;

        findings.push({
          line: mutLineNum,
          extraLines: [i + 1],
          category: 'security',
          penalty: 35,
          shortReason: `-35 [DG006] Non-atomic TOCTOU race condition pada '${entityFull}' (baris ${i + 1} -> ${mutLineNum})`,
          detailedReason: msg,
          isCritical: true,
        });
        findings.push({
          line: mutLineNum,
          category: 'correctness',
          penalty: 25,
          shortReason: `-25 [DG006] Risiko double-spend / overdraft akibat mutasi '${entityFull}' di luar transaksi atomik (baris ${mutLineNum})`,
          detailedReason: msg,
        });
        inlineFindings.push({
          ruleId: 'DG006',
          line: mutLineNum,
          severity: 'error',
          message: msg,
          suggestion: `await db.$transaction(async (tx) => {\n  const updated = await tx.account.updateMany({ where: { id: account.id, ${entityBase}: { gte: amount } }, data: { ${entityBase}: { decrement: amount } } });\n  if (updated.count === 0) throw new Error('Insufficient ${entityBase}');\n});`,
        });
        break;
      }
    }
  }
}

