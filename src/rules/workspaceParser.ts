/**
 * DevGuard Stage 6.0/6.1 Workspace Config Parser & Tokenizer Infrastructure
 *
 * Provides strictly zero-dependency, browser-safe, stateful tokenizers and parsers for:
 * 1. JSONC (JSON with comments, trailing commas, BOM, and CRLF)
 * 2. pnpm-workspace.yaml restricted subset (fail-closed, packages block list)
 * 3. Workspace Glob matching (*, **, negation !)
 * 4. tsconfig.json compilerOptions (paths, baseUrl, relative extends up to depth 3)
 *
 * Conforms strictly to SPEC-v1.4 rev 1.2 (INV-1, §6.1, §6.1a, Acceptance A6-8, A6-11).
 * NOTE: Contains ZERO top-level node:* built-in imports to preserve complete browser-safe parity.
 */

/**
 * Maximum permitted size for any workspace config file (256 KiB).
 * Inputs exceeding this boundary trigger an immediate deterministic `size_limit` bail-out.
 */
export const MAX_CONFIG_FILE_SIZE = 256 * 1024; // 262,144 bytes

/**
 * Standard bail-out reason codes per SPEC §6.1a and Acceptance A6-11.
 * Bail-outs are strictly fail-closed per source (0 partial package names emitted).
 */
export type WorkspaceBailoutReason =
  | 'size_limit'
  | 'jsonc_syntax'
  | 'yaml_unsupported_construct'
  | 'extends_external'
  | 'extends_cycle';

export type ParseResult<T> =
  | { success: true; data: T }
  | { success: false; reason: WorkspaceBailoutReason; error: string };

function getUtf8ByteLength(str: string): number {
  if (typeof TextEncoder !== 'undefined') {
    return new TextEncoder().encode(str).length;
  }
  let bytes = 0;
  for (let i = 0; i < str.length; i++) {
    const code = str.charCodeAt(i);
    if (code <= 0x7f) bytes += 1;
    else if (code <= 0x7ff) bytes += 2;
    else if (code >= 0xd800 && code <= 0xdbff) {
      bytes += 4;
      i++;
    } else bytes += 3;
  }
  return bytes;
}

function normalizePosixPath(rawPath: string): string {
  const isAbs = rawPath.startsWith('/') || /^[a-zA-Z]:[\\/]/.test(rawPath);
  const drive = /^[a-zA-Z]:/.exec(rawPath)?.[0] || '';
  const withoutDrive = drive ? rawPath.slice(drive.length) : rawPath;
  const segments = withoutDrive.replace(/\\/g, '/').split('/');
  const resolved: string[] = [];
  for (const seg of segments) {
    if (!seg || seg === '.') continue;
    if (seg === '..') {
      if (resolved.length > 0 && resolved[resolved.length - 1] !== '..') {
        resolved.pop();
      } else if (!isAbs) {
        resolved.push('..');
      }
    } else {
      resolved.push(seg);
    }
  }
  const joined = (isAbs ? '/' : '') + resolved.join('/');
  return drive ? drive + (joined.startsWith('/') ? joined : '/' + joined) : joined || '.';
}

function getPathDirname(rawPath: string): string {
  const norm = normalizePosixPath(rawPath);
  const lastSlash = norm.lastIndexOf('/');
  if (lastSlash === -1) return '.';
  if (lastSlash === 0) return '/';
  return norm.slice(0, lastSlash);
}

function resolveRelativePath(baseDir: string, relPath: string): string {
  const normBase = normalizePosixPath(baseDir);
  return normalizePosixPath(normBase + '/' + relPath);
}

/**
 * Stateful character-by-character JSONC scanner and parser.
 *
 * Invariants (SPEC §6.1a):
 * - `//`, `/*`, `* /`, and `#` inside string literals are NOT comments.
 * - BOM (`\uFEFF`) and CRLF are natively supported.
 * - Trailing commas in objects and arrays are accepted ONLY outside strings.
 * - `#` outside string literals is invalid JSONC syntax (`jsonc_syntax`).
 * - Unclosed comments or strings at EOF fail closed with `jsonc_syntax`.
 * - Never throws uncaught exceptions.
 */
export function parseJsonc(raw: string): ParseResult<unknown> {
  if (typeof raw !== 'string') {
    return { success: false, reason: 'jsonc_syntax', error: 'Input must be a string' };
  }

  // Size limit check
  const byteLen = getUtf8ByteLength(raw);
  if (byteLen > MAX_CONFIG_FILE_SIZE) {
    return {
      success: false,
      reason: 'size_limit',
      error: `Input size (${byteLen} bytes) exceeds limit of ${MAX_CONFIG_FILE_SIZE} bytes`,
    };
  }

  const len = raw.length;
  let pos = len > 0 && raw.charCodeAt(0) === 0xfeff ? 1 : 0;
  let out = '';
  let inString = false;
  let escape = false;
  let inLineComment = false;
  let inBlockComment = false;

  while (pos < len) {
    const ch = raw[pos];
    const next = pos + 1 < len ? raw[pos + 1] : '';

    if (inLineComment) {
      if (ch === '\n' || ch === '\r') {
        inLineComment = false;
        out += ch;
      }
      pos++;
      continue;
    }

    if (inBlockComment) {
      if (ch === '*' && next === '/') {
        inBlockComment = false;
        pos += 2;
        continue;
      }
      if (ch === '\n' || ch === '\r') {
        out += ch;
      }
      pos++;
      continue;
    }

    if (inString) {
      out += ch;
      if (escape) {
        escape = false;
      } else if (ch === '\\') {
        escape = true;
      } else if (ch === '"') {
        inString = false;
      }
      pos++;
      continue;
    }

    // Outside string and comments
    if (ch === '"') {
      inString = true;
      out += ch;
      pos++;
      continue;
    }

    if (ch === '/' && next === '/') {
      inLineComment = true;
      pos += 2;
      continue;
    }

    if (ch === '/' && next === '*') {
      inBlockComment = true;
      pos += 2;
      continue;
    }

    // Trailing comma check
    if (ch === ',') {
      let peek = pos + 1;
      let isTrailing = false;
      let peekInLine = false;
      let peekInBlock = false;

      while (peek < len) {
        const pCh = raw[peek];
        const pNext = peek + 1 < len ? raw[peek + 1] : '';

        if (peekInLine) {
          if (pCh === '\n' || pCh === '\r') peekInLine = false;
          peek++;
          continue;
        }
        if (peekInBlock) {
          if (pCh === '*' && pNext === '/') {
            peekInBlock = false;
            peek += 2;
            continue;
          }
          peek++;
          continue;
        }

        if (pCh === '/' && pNext === '/') {
          peekInLine = true;
          peek += 2;
          continue;
        }
        if (pCh === '/' && pNext === '*') {
          peekInBlock = true;
          peek += 2;
          continue;
        }

        if (pCh === ' ' || pCh === '\t' || pCh === '\n' || pCh === '\r') {
          peek++;
          continue;
        }

        if (pCh === '}' || pCh === ']') {
          isTrailing = true;
        }
        break;
      }

      if (isTrailing) {
        out += ' ';
      } else {
        out += ',';
      }
      pos++;
      continue;
    }

    out += ch;
    pos++;
  }

  if (inBlockComment) {
    return { success: false, reason: 'jsonc_syntax', error: 'Unclosed block comment at EOF' };
  }
  if (inString) {
    return { success: false, reason: 'jsonc_syntax', error: 'Unclosed string literal at EOF' };
  }

  try {
    const data = JSON.parse(out);
    return { success: true, data };
  } catch (err: unknown) {
    return {
      success: false,
      reason: 'jsonc_syntax',
      error: err instanceof Error ? err.message : String(err),
    };
  }
}

/**
 * Parses the restricted subset of `pnpm-workspace.yaml`.
 *
 * Invariants (SPEC §6.1, §6.1a):
 * - Supports ONLY `packages:` block list with `- 'glob'` or unquoted globs.
 * - Flow sequences `[...]`, flow mappings `{...}`, anchor/alias `&/*`,
 *   block scalars `|` / `>`, multi-doc `---`/`...`, or tab indentation
 *   strictly trigger fail-closed bail-out with `yaml_unsupported_construct`.
 * - Empty or comment-only files return an empty list without error.
 * - Never throws uncaught exceptions.
 */
export function parsePnpmWorkspaceYaml(raw: string): ParseResult<{ packages: string[] }> {
  if (typeof raw !== 'string') {
    return { success: false, reason: 'yaml_unsupported_construct', error: 'Input must be a string' };
  }

  const byteLen = getUtf8ByteLength(raw);
  if (byteLen > MAX_CONFIG_FILE_SIZE) {
    return {
      success: false,
      reason: 'size_limit',
      error: `Input size (${byteLen} bytes) exceeds limit of ${MAX_CONFIG_FILE_SIZE} bytes`,
    };
  }

  let text = raw;
  if (text.length > 0 && text.charCodeAt(0) === 0xfeff) {
    text = text.slice(1);
  }

  // Reject tabs anywhere
  if (text.includes('\t')) {
    return {
      success: false,
      reason: 'yaml_unsupported_construct',
      error: 'Tabs are strictly forbidden in YAML indentation and content',
    };
  }

  // Reject multi-document markers
  if (/^---(?:\s|$)/m.test(text) || /^\.\.\.(?:\s|$)/m.test(text)) {
    return {
      success: false,
      reason: 'yaml_unsupported_construct',
      error: 'Multi-document YAML (--- or ...) is unsupported',
    };
  }

  const lines = text.split(/\r?\n/);
  let packagesFound = false;
  let inPackagesList = false;
  const packages: string[] = [];

  for (let lineIdx = 0; lineIdx < lines.length; lineIdx++) {
    const line = lines[lineIdx];

    // Strip comments outside quotes and inspect constructs
    let inSingle = false;
    let inDouble = false;
    let escape = false;
    let stripped = '';
    let hasFlowSeq = false;
    let hasFlowMap = false;
    let hasBlockScalar = false;
    let hasAnchor = false;

    for (let i = 0; i < line.length; i++) {
      const ch = line[i];

      if (inSingle) {
        stripped += ch;
        if (ch === "'") {
          if (i + 1 < line.length && line[i + 1] === "'") {
            stripped += "'";
            i++;
          } else {
            inSingle = false;
          }
        }
        continue;
      }

      if (inDouble) {
        stripped += ch;
        if (escape) {
          escape = false;
        } else if (ch === '\\') {
          escape = true;
        } else if (ch === '"') {
          inDouble = false;
        }
        continue;
      }

      if (ch === "'") {
        inSingle = true;
        stripped += ch;
        continue;
      }
      if (ch === '"') {
        inDouble = true;
        stripped += ch;
        continue;
      }

      if (ch === '#') {
        break; // Comment starts
      }

      if (ch === '[' || ch === ']') hasFlowSeq = true;
      if (ch === '{' || ch === '}') hasFlowMap = true;
      if (ch === '|' || ch === '>') hasBlockScalar = true;
      if (ch === '&') hasAnchor = true;

      stripped += ch;
    }

    if (inSingle || inDouble) {
      return {
        success: false,
        reason: 'yaml_unsupported_construct',
        error: `Unclosed quote at line ${lineIdx + 1}`,
      };
    }
    if (hasFlowSeq) {
      return {
        success: false,
        reason: 'yaml_unsupported_construct',
        error: `Flow sequence [...] is unsupported at line ${lineIdx + 1}`,
      };
    }
    if (hasFlowMap) {
      return {
        success: false,
        reason: 'yaml_unsupported_construct',
        error: `Flow mapping {...} is unsupported at line ${lineIdx + 1}`,
      };
    }
    if (hasBlockScalar) {
      return {
        success: false,
        reason: 'yaml_unsupported_construct',
        error: `Block scalar (| or >) is unsupported at line ${lineIdx + 1}`,
      };
    }
    if (hasAnchor) {
      return {
        success: false,
        reason: 'yaml_unsupported_construct',
        error: `YAML anchor (&) is unsupported at line ${lineIdx + 1}`,
      };
    }

    const trimmed = stripped.trim();
    if (trimmed === '') continue;

    // Reject YAML aliases (*alias)
    if (/^\s*-\s*\*([a-zA-Z0-9_-]+)\s*$/.test(stripped)) {
      return {
        success: false,
        reason: 'yaml_unsupported_construct',
        error: `YAML alias is unsupported at line ${lineIdx + 1}`,
      };
    }

    if (/^packages:\s*$/.test(trimmed)) {
      if (packagesFound) {
        return {
          success: false,
          reason: 'yaml_unsupported_construct',
          error: `Duplicate packages key at line ${lineIdx + 1}`,
        };
      }
      packagesFound = true;
      inPackagesList = true;
      continue;
    }

    if (inPackagesList) {
      const matchItem = /^\s*-\s*(.+)$/.exec(stripped);
      if (matchItem) {
        let val = matchItem[1].trim();
        if (val.startsWith("'") && val.endsWith("'") && val.length >= 2) {
          val = val.slice(1, -1).replace(/''/g, "'");
        } else if (val.startsWith('"') && val.endsWith('"') && val.length >= 2) {
          try {
            val = JSON.parse(val);
          } catch {
            return {
              success: false,
              reason: 'yaml_unsupported_construct',
              error: `Malformed double-quoted string at line ${lineIdx + 1}`,
            };
          }
        }
        if (val === '') {
          return {
            success: false,
            reason: 'yaml_unsupported_construct',
            error: `Empty list item at line ${lineIdx + 1}`,
          };
        }
        packages.push(val);
        continue;
      }

      // Any line not starting with '-' is an unsupported construct or unexpected key
      return {
        success: false,
        reason: 'yaml_unsupported_construct',
        error: `Unexpected line in packages list at line ${lineIdx + 1}: "${trimmed}"`,
      };
    }

    // Encountered non-empty line before packages:
    return {
      success: false,
      reason: 'yaml_unsupported_construct',
      error: `Unsupported YAML construct before packages key at line ${lineIdx + 1}: "${trimmed}"`,
    };
  }

  return { success: true, data: { packages } };
}

/**
 * Matches a single workspace glob pattern against a target relative path.
 *
 * Supports:
 * - `*` (matches characters in a single path segment, excluding `/`)
 * - `**` (matches across arbitrary path segments, including `/`)
 * - literal path characters
 */
export function matchGlobPattern(pattern: string, pathStr: string): boolean {
  if (typeof pattern !== 'string' || typeof pathStr !== 'string') return false;
  const normPath = pathStr.replace(/\\/g, '/').replace(/^\/+|\/+$/g, '');
  const normPat = pattern.replace(/\\/g, '/').replace(/^\/+|\/+$/g, '');

  if (!normPat || !normPath) {
    return normPat === normPath;
  }

  // Exact match fast-path
  if (normPat === normPath) return true;

  // Single asterisk matches any single directory
  if (normPat === '*') {
    return !normPath.includes('/');
  }

  // Double asterisk matches anything
  if (normPat === '**') {
    return true;
  }

  // Collapse consecutive redundant wildcards
  const cleanedPat = normPat.replace(/\*\*(\/\*\*)+/g, '**').replace(/\*{3,}/g, '**');

  // Convert glob to safe regex
  let regexStr = '^';
  let i = 0;
  const len = cleanedPat.length;

  while (i < len) {
    const ch = cleanedPat[i];

    if (ch === '*' && i + 1 < len && cleanedPat[i + 1] === '*') {
      // '**'
      i += 2;
      if (i < len && cleanedPat[i] === '/') {
        // '/**/' or '/**'
        i++;
        regexStr += '(?:.*/)?';
      } else {
        regexStr += '.*';
      }
      continue;
    }

    if (ch === '*') {
      regexStr += '[^/]*';
      i++;
      continue;
    }

    if (ch === '/') {
      regexStr += '\\/';
      i++;
      continue;
    }

    // Escape regex special chars: . + ? ^ $ ( ) [ ] { } |
    if (/[.+?^$(){}[\]|\\]/.test(ch)) {
      regexStr += `\\${ch}`;
    } else {
      regexStr += ch;
    }
    i++;
  }

  regexStr += '$';

  try {
    const re = new RegExp(regexStr);
    return re.test(normPath);
  } catch {
    return false;
  }
}

/**
 * Matches a target directory against a list of workspace glob patterns.
 * Supports positive patterns and negation patterns (prefixed with `!`).
 *
 * Returns true if the target path matches at least one positive pattern
 * and matches zero negative patterns.
 */
export function matchesWorkspaceGlobList(
  patterns: readonly string[],
  candidatePath: string
): boolean {
  if (!Array.isArray(patterns) || typeof candidatePath !== 'string') return false;
  const normCandidate = candidatePath.replace(/\\/g, '/').replace(/^\/+|\/+$/g, '');
  if (!normCandidate) return false;

  const positivePatterns: string[] = [];
  const negativePatterns: string[] = [];

  for (const pat of patterns) {
    if (typeof pat !== 'string') continue;
    const trimmed = pat.trim();
    if (!trimmed) continue;
    if (trimmed.startsWith('!')) {
      const neg = trimmed.slice(1).trim();
      if (neg) negativePatterns.push(neg);
    } else {
      positivePatterns.push(trimmed);
    }
  }

  if (positivePatterns.length === 0) {
    return false;
  }

  let positiveMatch = false;
  for (const posPat of positivePatterns) {
    if (matchGlobPattern(posPat, normCandidate)) {
      positiveMatch = true;
      break;
    }
  }

  if (!positiveMatch) return false;

  for (const negPat of negativePatterns) {
    if (matchGlobPattern(negPat, normCandidate)) {
      return false; // Excluded by negation
    }
  }

  return true;
}

export interface TsconfigData {
  paths?: Record<string, string[]>;
  baseUrl?: string;
}

export type TsconfigFileAccessor = (filePath: string) => string | null;

/**
 * Parses `tsconfig.json` and resolves its compilerOptions (`paths`, `baseUrl`).
 *
 * Invariants (SPEC §6.1, §6.1a):
 * - `extends` MUST be a relative path (`./` or `../`); npm packages trigger `extends_external`.
 * - Maximum `extends` depth is 3; cycles or excessive depth trigger `extends_cycle`.
 * - Exceeding 256 KiB triggers `size_limit`.
 * - Invalid JSONC triggers `jsonc_syntax`.
 * - Child properties cleanly override base properties.
 */
export function parseTsconfig(
  content: string,
  filePath: string,
  fileAccessor?: TsconfigFileAccessor,
  depth: number = 0,
  visited: Set<string> = new Set()
): ParseResult<TsconfigData> {
  if (typeof content !== 'string') {
    return { success: false, reason: 'jsonc_syntax', error: 'tsconfig content must be a string' };
  }

  const byteLen = getUtf8ByteLength(content);
  if (byteLen > MAX_CONFIG_FILE_SIZE) {
    return {
      success: false,
      reason: 'size_limit',
      error: `Input size (${byteLen} bytes) exceeds limit of ${MAX_CONFIG_FILE_SIZE} bytes`,
    };
  }

  const jsonResult = parseJsonc(content);
  if (!jsonResult.success) {
    return jsonResult;
  }

  const rawConfig = jsonResult.data;
  if (!rawConfig || typeof rawConfig !== 'object' || Array.isArray(rawConfig)) {
    return { success: false, reason: 'jsonc_syntax', error: 'tsconfig must be a JSON object' };
  }

  const configObj = rawConfig as {
    extends?: unknown;
    compilerOptions?: {
      paths?: unknown;
      baseUrl?: unknown;
    };
  };

  let parentPaths: Record<string, string[]> | undefined;
  let parentBaseUrl: string | undefined;

  if (configObj.extends !== undefined) {
    if (typeof configObj.extends !== 'string') {
      return { success: false, reason: 'jsonc_syntax', error: 'tsconfig extends must be a string' };
    }

    const extendsTarget = configObj.extends.trim();
    if (!extendsTarget.startsWith('./') && !extendsTarget.startsWith('../')) {
      return {
        success: false,
        reason: 'extends_external',
        error: `External npm package extends '${extendsTarget}' is not supported in workspace resolution`,
      };
    }

    if (depth >= 3) {
      return {
        success: false,
        reason: 'extends_cycle',
        error: 'tsconfig extends exceeded maximum allowed depth of 3',
      };
    }

    if (!fileAccessor) {
      return {
        success: false,
        reason: 'jsonc_syntax',
        error: 'File accessor required to resolve extends',
      };
    }

    const currentDir = getPathDirname(filePath);
    const targetWithExt = extendsTarget.endsWith('.json') ? extendsTarget : `${extendsTarget}.json`;
    const resolvedParentPath = resolveRelativePath(currentDir, targetWithExt);
    const currentNormPath = normalizePosixPath(filePath);

    if (resolvedParentPath === currentNormPath || visited.has(resolvedParentPath)) {
      return {
        success: false,
        reason: 'extends_cycle',
        error: `Circular tsconfig extends detected at '${resolvedParentPath}'`,
      };
    }

    const parentContent = fileAccessor(resolvedParentPath);
    if (parentContent === null) {
      return {
        success: false,
        reason: 'jsonc_syntax',
        error: `Cannot read extended tsconfig at '${resolvedParentPath}'`,
      };
    }

    const nextVisited = new Set(visited);
    nextVisited.add(currentNormPath);

    const parentResult = parseTsconfig(
      parentContent,
      resolvedParentPath,
      fileAccessor,
      depth + 1,
      nextVisited
    );

    if (!parentResult.success) {
      return parentResult;
    }

    parentPaths = parentResult.data.paths;
    parentBaseUrl = parentResult.data.baseUrl;
  }

  const compilerOptions = configObj.compilerOptions;
  let currentPaths: Record<string, string[]> | undefined;
  let currentBaseUrl: string | undefined;

  if (compilerOptions && typeof compilerOptions === 'object') {
    if (typeof compilerOptions.baseUrl === 'string') {
      currentBaseUrl = compilerOptions.baseUrl;
    }
    if (
      compilerOptions.paths &&
      typeof compilerOptions.paths === 'object' &&
      !Array.isArray(compilerOptions.paths)
    ) {
      currentPaths = {};
      for (const [key, val] of Object.entries(compilerOptions.paths as Record<string, unknown>)) {
        if (Array.isArray(val)) {
          currentPaths[key] = val.filter((item): item is string => typeof item === 'string');
        }
      }
    }
  }

  const effectiveBaseUrl = currentBaseUrl !== undefined ? currentBaseUrl : parentBaseUrl;
  const effectivePaths =
    currentPaths !== undefined || parentPaths !== undefined
      ? { ...(parentPaths || {}), ...(currentPaths || {}) }
      : undefined;

  return {
    success: true,
    data: {
      paths: effectivePaths,
      baseUrl: effectiveBaseUrl,
    },
  };
}

/**
 * Deterministic PRNG using 32-bit Mulberry32 algorithm.
 * Zero external dependencies.
 */
export function createMulberry32(seed: number): () => number {
  let s = seed >>> 0;
  return function next(): number {
    s = (s + 0x6d2b79f5) | 0;
    let t = Math.imul(s ^ (s >>> 15), 1 | s);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return (t >>> 0) / 4294967296;
  };
}
