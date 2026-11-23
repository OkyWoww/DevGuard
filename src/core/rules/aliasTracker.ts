import type { ExtractedStringLiteral, InlineFinding } from './lexicalMasker.ts';

export const MAX_ALIAS_DEPTH = 2;

export type AliasSinkTarget =
  | 'eval'
  | 'Function'
  | 'child_process.exec'
  | 'child_process.execSync';

export interface AliasFindingMetadata {
  aliasName: string;
  target: AliasSinkTarget;
  depth: number;
  chain: readonly string[];
  line: number;
}

type ScopeBinding =
  | {
      kind: 'sink';
      target: AliasSinkTarget;
      depth: number;
      chain: string[];
    }
  | {
      kind: 'namespace';
      module: 'child_process';
      depth: number;
      chain: string[];
    }
  | null; // Explicit shadow / invalidation

interface ScopeFrame {
  kind: 'module' | 'function' | 'block' | 'arrow-expr';
  bindings: Map<string, ScopeBinding>;
  /** For arrow-expr scopes, the paren/bracket/brace depth when the arrow expression started. */
  exprBracketDepth?: number;
}

type BraceKind = 'block' | 'object' | 'destructure' | 'type';

interface BraceFrame {
  kind: BraceKind;
  pushedScope: boolean;
}

type TokenKind = 'ident' | 'string' | 'number' | 'punct';

interface Token {
  kind: TokenKind;
  value: string;
  start: number;
  end: number;
  line: number;
}

const GLOBAL_OBJECT_NAMES = new Set(['globalThis', 'window', 'global', 'self']);
const CHILD_PROCESS_SPECIFIERS = new Set(['child_process', 'node:child_process']);
const CHILD_PROCESS_SINKS = new Map<string, AliasSinkTarget>([
  ['exec', 'child_process.exec'],
  ['execSync', 'child_process.execSync'],
]);
const DIRECT_SINKS = new Map<string, AliasSinkTarget>([
  ['eval', 'eval'],
  ['Function', 'Function'],
]);

const DECL_KEYWORDS = new Set(['const', 'let', 'var']);
const BLOCK_PRECEDING_KEYWORDS = new Set(['else', 'do', 'try', 'finally', 'static']);
const EXPRESSION_PRECEDING_KEYWORDS = new Set([
  'return',
  'throw',
  'yield',
  'await',
  'typeof',
  'void',
  'delete',
  'in',
  'of',
  'instanceof',
  'new',
  'case',
  'default',
  'export',
]);
const EXPRESSION_PRECEDING_PUNCT = new Set([
  '=',
  '(',
  '[',
  ',',
  ':',
  '?',
  '&&',
  '||',
  '??',
  '+',
  '-',
  '*',
  '/',
  '%',
  '!',
  '~',
  '&',
  '|',
  '^',
  '==',
  '!=',
  '===',
  '!==',
  '<',
  '>',
  '<=',
  '>=',
  '+=',
  '-=',
  '*=',
  '/=',
  '&&=',
  '||=',
  '??=',
]);
const ASSIGNMENT_PUNCT = new Set(['=', '+=', '-=', '*=', '/=', '&&=', '||=', '??=']);
const NON_CALL_PRECEDING_KEYWORDS = new Set([
  'function',
  'if',
  'while',
  'for',
  'with',
  'switch',
  'catch',
  'class',
  'interface',
  'type',
]);

function isIdentStart(code: number): boolean {
  return (
    (code >= 65 && code <= 90) || // A-Z
    (code >= 97 && code <= 122) || // a-z
    code === 95 || // _
    code === 36 // $
  );
}

function isIdentPart(code: number): boolean {
  return isIdentStart(code) || (code >= 48 && code <= 57);
}

function isDigit(code: number): boolean {
  return code >= 48 && code <= 57;
}

const THREE_CHAR_PUNCT = new Set(['===', '!==', '...', '??=', '&&=', '||=']);
const TWO_CHAR_PUNCT = new Set([
  '=>',
  '?.',
  '==',
  '!=',
  '<=',
  '>=',
  '&&',
  '||',
  '??',
  '+=',
  '-=',
  '*=',
  '/=',
  '++',
  '--',
]);

/**
 * Single-pass O(N) tokenizer over `maskedCode` with static string literals
 * reinjected from `stringLiterals` at their exact offsets.
 */
function tokenizeMaskedCode(
  maskedCode: string,
  stringLiterals: ReadonlyArray<ExtractedStringLiteral>
): Token[] {
  const tokens: Token[] = [];
  const len = maskedCode.length;
  let line = 1;
  let strIdx = 0;

  // Sort defensive copy only if out of order (usually already sorted)
  const literals =
    stringLiterals.length <= 1
      ? stringLiterals
      : [...stringLiterals].sort((a, b) => a.startOffset - b.startOffset);

  let i = 0;
  while (i < len) {
    // Advance literal pointer past current offset
    while (strIdx < literals.length && literals[strIdx].endOffset <= i) {
      strIdx++;
    }

    // If we landed on a string literal span, emit a string token (if static) and jump to endOffset
    if (strIdx < literals.length && literals[strIdx].startOffset === i) {
      const lit = literals[strIdx];
      if (!lit.hasInterpolation) {
        tokens.push({
          kind: 'string',
          value: lit.value,
          start: lit.startOffset,
          end: lit.endOffset,
          line: lit.line,
        });
      }
      for (let k = i; k < lit.endOffset && k < len; k++) {
        if (maskedCode.charCodeAt(k) === 10) line++;
      }
      i = Math.max(i + 1, lit.endOffset);
      strIdx++;
      continue;
    }

    const chCode = maskedCode.charCodeAt(i);
    if (chCode === 10) {
      line++;
      i++;
      continue;
    }
    if (chCode === 32 || chCode === 9 || chCode === 13) {
      i++;
      continue;
    }

    if (isIdentStart(chCode)) {
      const start = i;
      i++;
      while (i < len && isIdentPart(maskedCode.charCodeAt(i))) {
        i++;
      }
      tokens.push({
        kind: 'ident',
        value: maskedCode.slice(start, i),
        start,
        end: i,
        line,
      });
      continue;
    }

    if (isDigit(chCode)) {
      const start = i;
      i++;
      while (i < len && (isDigit(maskedCode.charCodeAt(i)) || maskedCode.charCodeAt(i) === 46)) {
        i++;
      }
      tokens.push({
        kind: 'number',
        value: maskedCode.slice(start, i),
        start,
        end: i,
        line,
      });
      continue;
    }

    const tri = i + 3 <= len ? maskedCode.slice(i, i + 3) : '';
    if (tri && THREE_CHAR_PUNCT.has(tri)) {
      tokens.push({ kind: 'punct', value: tri, start: i, end: i + 3, line });
      i += 3;
      continue;
    }

    const bi = i + 2 <= len ? maskedCode.slice(i, i + 2) : '';
    if (bi && TWO_CHAR_PUNCT.has(bi)) {
      tokens.push({ kind: 'punct', value: bi, start: i, end: i + 2, line });
      i += 2;
      continue;
    }

    tokens.push({
      kind: 'punct',
      value: maskedCode[i],
      start: i,
      end: i + 1,
      line,
    });
    i++;
  }

  return tokens;
}

function findMatchingClose(
  tokens: ReadonlyArray<Token>,
  openIdx: number,
  openChar: string,
  closeChar: string
): number {
  let depth = 0;
  for (let i = openIdx; i < tokens.length; i++) {
    const t = tokens[i];
    if (t.kind === 'punct') {
      if (t.value === openChar) depth++;
      else if (t.value === closeChar) {
        depth--;
        if (depth === 0) return i;
      }
    }
  }
  return -1;
}

/**
 * Extracts all bound identifier names from a parameter list or destructuring pattern
 * between `startIdx` and `endIdx` (inclusive), ignoring TypeScript type annotations
 * and default value expressions.
 */
function extractBoundIdentifiers(
  tokens: ReadonlyArray<Token>,
  startIdx: number,
  endIdx: number
): string[] {
  const names: string[] = [];
  let i = startIdx;

  const parseBindingPattern = (limit: number): void => {
    while (i <= limit) {
      const t = tokens[i];
      if (!t) break;

      if (t.kind === 'punct' && (t.value === ',' || t.value === '...')) {
        i++;
        continue;
      }

      // Skip TS parameter modifiers like public/private/protected/readonly
      if (
        t.kind === 'ident' &&
        (t.value === 'public' ||
          t.value === 'private' ||
          t.value === 'protected' ||
          t.value === 'readonly')
      ) {
        i++;
        continue;
      }

      if (t.kind === 'punct' && t.value === '{') {
        const closeIdx = findMatchingClose(tokens, i, '{', '}');
        if (closeIdx === -1 || closeIdx > limit) {
          i++;
          continue;
        }
        parseObjectBinding(i + 1, closeIdx - 1);
        i = closeIdx + 1;
        skipTypeAndDefault(limit);
        continue;
      }

      if (t.kind === 'punct' && t.value === '[') {
        const closeIdx = findMatchingClose(tokens, i, '[', ']');
        if (closeIdx === -1 || closeIdx > limit) {
          i++;
          continue;
        }
        const savedEnd = closeIdx - 1;
        i = i + 1;
        parseBindingPattern(savedEnd);
        i = closeIdx + 1;
        skipTypeAndDefault(limit);
        continue;
      }

      if (t.kind === 'ident') {
        names.push(t.value);
        i++;
        skipTypeAndDefault(limit);
        continue;
      }

      i++;
    }
  };

  const parseObjectBinding = (innerStart: number, innerEnd: number): void => {
    let k = innerStart;
    while (k <= innerEnd) {
      const t = tokens[k];
      if (t.kind === 'punct' && (t.value === ',' || t.value === '...')) {
        k++;
        continue;
      }
      if (t.kind === 'ident' || t.kind === 'string') {
        const next = tokens[k + 1];
        if (next && next.kind === 'punct' && next.value === ':') {
          // `{ prop: localName }` or `{ prop: { nested } }`
          k += 2;
          const prevI = i;
          i = k;
          // Parse single binding item until top-level comma inside innerEnd
          const itemEnd = findTopLevelComma(tokens, i, innerEnd);
          parseBindingPattern(itemEnd - 1);
          k = itemEnd + 1;
          i = prevI;
          continue;
        }
        if (t.kind === 'ident') {
          names.push(t.value);
        }
        k++;
        // Skip default value `= expr`
        const itemEnd = findTopLevelComma(tokens, k, innerEnd);
        k = itemEnd + 1;
        continue;
      }
      k++;
    }
  };

  const skipTypeAndDefault = (limit: number): void => {
    if (i <= limit && tokens[i].kind === 'punct' && tokens[i].value === '?') {
      i++;
    }
    let paren = 0;
    let bracket = 0;
    let brace = 0;
    let angle = 0;
    if (
      i <= limit &&
      tokens[i].kind === 'punct' &&
      (tokens[i].value === ':' || tokens[i].value === '=')
    ) {
      i++;
      while (i <= limit) {
        const t = tokens[i];
        if (t.kind === 'punct') {
          if (t.value === '(') paren++;
          else if (t.value === ')') paren = Math.max(0, paren - 1);
          else if (t.value === '[') bracket++;
          else if (t.value === ']') bracket = Math.max(0, bracket - 1);
          else if (t.value === '{') brace++;
          else if (t.value === '}') brace = Math.max(0, brace - 1);
          else if (t.value === '<') angle++;
          else if (t.value === '>') angle = Math.max(0, angle - 1);
          else if (t.value === ',' && paren === 0 && bracket === 0 && brace === 0 && angle === 0) {
            break;
          }
        }
        i++;
      }
    }
  };

  parseBindingPattern(endIdx);
  return names;
}

function findTopLevelComma(tokens: ReadonlyArray<Token>, start: number, end: number): number {
  let paren = 0;
  let bracket = 0;
  let brace = 0;
  for (let i = start; i <= end; i++) {
    const t = tokens[i];
    if (t.kind === 'punct') {
      if (t.value === '(') paren++;
      else if (t.value === ')') paren = Math.max(0, paren - 1);
      else if (t.value === '[') bracket++;
      else if (t.value === ']') bracket = Math.max(0, bracket - 1);
      else if (t.value === '{') brace++;
      else if (t.value === '}') brace = Math.max(0, brace - 1);
      else if (t.value === ',' && paren === 0 && bracket === 0 && brace === 0) return i;
    }
  }
  return end + 1;
}

/**
 * Skips an optional TypeScript return type annotation (`: ReturnType`) starting at `idx`
 * and returns the index of the next token (`{` or `=>`) if immediately following.
 */
function skipReturnTypeAnnotation(tokens: ReadonlyArray<Token>, idx: number): number {
  if (idx >= tokens.length || tokens[idx].kind !== 'punct' || tokens[idx].value !== ':') {
    return idx;
  }
  let i = idx + 1;
  let paren = 0;
  let bracket = 0;
  let brace = 0;
  let angle = 0;
  while (i < tokens.length) {
    const t = tokens[i];
    if (t.kind === 'punct') {
      if (t.value === '(') paren++;
      else if (t.value === ')') {
        if (paren === 0) break;
        paren--;
      } else if (t.value === '[') bracket++;
      else if (t.value === ']') bracket = Math.max(0, bracket - 1);
      else if (t.value === '<') angle++;
      else if (t.value === '>') angle = Math.max(0, angle - 1);
      else if (t.value === '{') {
        if (paren === 0 && bracket === 0 && angle === 0) {
          // Could be function body `{` if preceded by type token, or inline object type `{ a: number }`
          // Heuristic: if prev token was `=>` or `:` or `|` or `&`, `{` is an object type; otherwise function body
          const prev = tokens[i - 1];
          if (
            prev &&
            prev.kind === 'punct' &&
            (prev.value === ':' || prev.value === '=>' || prev.value === '|' || prev.value === '&')
          ) {
            brace++;
          } else if (brace === 0) {
            return i;
          } else {
            brace++;
          }
        } else {
          brace++;
        }
      } else if (t.value === '}') {
        if (brace === 0) break;
        brace--;
      } else if (
        t.value === '=>' &&
        paren === 0 &&
        bracket === 0 &&
        brace === 0 &&
        angle === 0
      ) {
        // Distinguish arrow function `=>` from function type `(x: string) => void`
        // If followed by `{` or expression after a param list, return i
        return i;
      } else if (
        (t.value === ';' || t.value === '=') &&
        paren === 0 &&
        bracket === 0 &&
        brace === 0 &&
        angle === 0
      ) {
        return i;
      }
    }
    i++;
  }
  return i;
}

/**
 * Checks whether a `(` at `parenIdx` starts a function/method/arrow parameter list,
 * and returns the parameter names plus the index of the body starter (`{` or `=>`).
 */
function detectFunctionHeaderAtParen(
  tokens: ReadonlyArray<Token>,
  parenIdx: number
): { params: string[]; bodyTokenIdx: number; isArrow: boolean } | null {
  const closeIdx = findMatchingClose(tokens, parenIdx, '(', ')');
  if (closeIdx === -1) return null;

  const afterClose = skipReturnTypeAnnotation(tokens, closeIdx + 1);
  if (afterClose >= tokens.length) return null;

  const nextTok = tokens[afterClose];

  // Arrow function: `(...) => ...` or `(...): Ret => ...`
  if (nextTok.kind === 'punct' && nextTok.value === '=>') {
    const params = extractBoundIdentifiers(tokens, parenIdx + 1, closeIdx - 1);
    return { params, bodyTokenIdx: afterClose, isArrow: true };
  }

  // Named/anonymous function or method: `function f(...) {`, `f(...) {`, `async f(...) {`
  if (nextTok.kind === 'punct' && nextTok.value === '{') {
    const prev = tokens[parenIdx - 1];
    if (!prev) return null;
    // Exclude control-flow headers: if (...), while (...), for (...), switch (...), with (...), catch (...)
    if (
      prev.kind === 'ident' &&
      (prev.value === 'if' ||
        prev.value === 'while' ||
        prev.value === 'for' ||
        prev.value === 'switch' ||
        prev.value === 'with' ||
        prev.value === 'catch')
    ) {
      return null;
    }
    // Valid function/method header: preceded by `function`, `*`, or method identifier
    if (
      prev.kind === 'ident' ||
      (prev.kind === 'punct' && (prev.value === '*' || prev.value === '>'))
    ) {
      const params = extractBoundIdentifiers(tokens, parenIdx + 1, closeIdx - 1);
      return { params, bodyTokenIdx: afterClose, isArrow: false };
    }
  }

  return null;
}

/**
 * Resolves an RHS expression starting at `rhsStart` (bounded by `rhsEnd` exclusive)
 * into a ScopeBinding if it refers to a tracked dangerous sink or `child_process` module.
 */
function resolveRhsBinding(
  tokens: ReadonlyArray<Token>,
  rhsStart: number,
  rhsEnd: number,
  lhsName: string,
  lookup: (name: string) => ScopeBinding | undefined
): ScopeBinding {
  // Strip outer parentheses `(eval)`
  let start = rhsStart;
  let end = rhsEnd;
  while (
    start < end - 1 &&
    tokens[start].kind === 'punct' &&
    tokens[start].value === '(' &&
    findMatchingClose(tokens, start, '(', ')') === end - 1
  ) {
    start++;
    end--;
  }

  // Strip TypeScript type assertions `as ...` or `satisfies ...` at top level
  for (let k = start; k < end; k++) {
    if (tokens[k].kind === 'ident' && (tokens[k].value === 'as' || tokens[k].value === 'satisfies')) {
      end = k;
      break;
    }
  }

  const count = end - start;
  if (count <= 0) return null;

  // Case 1: Single identifier `const fn = eval` or `const fn2 = fn` or `const sh = cp`
  if (count === 1 && tokens[start].kind === 'ident') {
    const rhsName = tokens[start].value;
    const existing = lookup(rhsName);
    if (existing !== undefined) {
      // Explicitly shadowed (`null`) or bound to an existing alias/namespace in scope
      if (existing === null) return null;
      return propagateBinding(existing, lhsName);
    }

    const directSink = DIRECT_SINKS.get(rhsName);
    if (directSink) {
      return {
        kind: 'sink',
        target: directSink,
        depth: 1,
        chain: [lhsName, rhsName],
      };
    }

    return null;
  }

  // Case 2: `require('child_process')` or `require('node:child_process')`
  // or `require('child_process').exec` / `require('child_process')['execSync']`
  if (
    count >= 4 &&
    tokens[start].kind === 'ident' &&
    tokens[start].value === 'require' &&
    tokens[start + 1].kind === 'punct' &&
    tokens[start + 1].value === '(' &&
    tokens[start + 2].kind === 'string' &&
    CHILD_PROCESS_SPECIFIERS.has(tokens[start + 2].value) &&
    tokens[start + 3].kind === 'punct' &&
    tokens[start + 3].value === ')'
  ) {
    if (count === 4) {
      // Direct module binding: depth 0 namespace
      return {
        kind: 'namespace',
        module: 'child_process',
        depth: 0,
        chain: [lhsName],
      };
    }
    // Member access on require('child_process'): `.exec` or `['exec']`
    const prop = readMemberProperty(tokens, start + 4, end);
    if (prop) {
      const sink = CHILD_PROCESS_SINKS.get(prop);
      if (sink) {
        return {
          kind: 'sink',
          target: sink,
          depth: 1,
          chain: [lhsName, sink],
        };
      }
    }
    return null;
  }

  // Case 3: Member access on global object or tracked `child_process` namespace
  // e.g. `globalThis.eval`, `window['Function']`, `cp.exec`, `cp['execSync']`
  if (count >= 3 && tokens[start].kind === 'ident') {
    const objName = tokens[start].value;
    const prop = readMemberProperty(tokens, start + 1, end);
    if (!prop) return null;

    // Global object: `globalThis.eval` / `window['Function']`
    if (GLOBAL_OBJECT_NAMES.has(objName)) {
      const directSink = DIRECT_SINKS.get(prop);
      if (directSink) {
        return {
          kind: 'sink',
          target: directSink,
          depth: 1,
          chain: [lhsName, `${objName}.${prop}`],
        };
      }
      return null;
    }

    // Tracked `child_process` namespace ONLY (Guardrail #1: never blind `.exec`)
    const objBinding = lookup(objName);
    if (objBinding && objBinding.kind === 'namespace' && objBinding.module === 'child_process') {
      const sink = CHILD_PROCESS_SINKS.get(prop);
      if (sink) {
        const nextDepth = objBinding.depth + 1;
        if (nextDepth > MAX_ALIAS_DEPTH) return null;
        return {
          kind: 'sink',
          target: sink,
          depth: nextDepth,
          chain: [lhsName, ...objBinding.chain.slice(0, -1), `${objName}.${prop}`],
        };
      }
    }
  }

  return null;
}

function propagateBinding(existing: Exclude<ScopeBinding, null>, lhsName: string): ScopeBinding {
  const nextDepth = existing.depth + 1;
  if (nextDepth > MAX_ALIAS_DEPTH) return null;
  if (existing.kind === 'sink') {
    return {
      kind: 'sink',
      target: existing.target,
      depth: nextDepth,
      chain: [lhsName, ...existing.chain],
    };
  }
  return {
    kind: 'namespace',
    module: existing.module,
    depth: nextDepth,
    chain: [lhsName, ...existing.chain],
  };
}

/**
 * Reads `.prop` or `?.prop` or `['prop']` spanning `[idx, end)` exactly.
 */
function readMemberProperty(
  tokens: ReadonlyArray<Token>,
  idx: number,
  end: number
): string | null {
  const remaining = end - idx;
  if (
    remaining === 2 &&
    tokens[idx].kind === 'punct' &&
    (tokens[idx].value === '.' || tokens[idx].value === '?.') &&
    tokens[idx + 1].kind === 'ident'
  ) {
    return tokens[idx + 1].value;
  }
  if (
    remaining === 3 &&
    tokens[idx].kind === 'punct' &&
    tokens[idx].value === '[' &&
    tokens[idx + 1].kind === 'string' &&
    tokens[idx + 2].kind === 'punct' &&
    tokens[idx + 2].value === ']'
  ) {
    return tokens[idx + 1].value;
  }
  return null;
}

/**
 * Finds the end of a declarator/assignment RHS expression at top-level delimiter
 * (`,`, `;`, `}`, or newline-terminated statement boundary).
 */
function findRhsEnd(tokens: ReadonlyArray<Token>, rhsStart: number): number {
  let paren = 0;
  let bracket = 0;
  let brace = 0;
  for (let i = rhsStart; i < tokens.length; i++) {
    const t = tokens[i];
    if (t.kind === 'punct') {
      if (t.value === '(') paren++;
      else if (t.value === ')') {
        if (paren === 0) return i;
        paren--;
      } else if (t.value === '[') bracket++;
      else if (t.value === ']') {
        if (bracket === 0) return i;
        bracket--;
      } else if (t.value === '{') brace++;
      else if (t.value === '}') {
        if (brace === 0) return i;
        brace--;
      } else if ((t.value === ';' || t.value === ',') && paren === 0 && bracket === 0 && brace === 0) {
        return i;
      }
    }
    // ASI line boundary: if the next token is on a new line and cannot continue a simple alias RHS
    if (paren === 0 && bracket === 0 && brace === 0 && i + 1 < tokens.length) {
      const next = tokens[i + 1];
      if (next.line > t.line) {
        const continuesOnNextLine =
          (next.kind === 'punct' && (next.value === '.' || next.value === '?.' || next.value === '[')) ||
          (t.kind === 'punct' && (t.value === '.' || t.value === '?.'));
        if (!continuesOnNextLine) {
          return i + 1;
        }
      }
    }
  }
  return tokens.length;
}

/**
 * Detects intra-procedural aliased invocations of dangerous dynamic execution sinks
 * (`eval`, `Function`, `child_process.exec`, `child_process.execSync`) up to `MAX_ALIAS_DEPTH = 2`.
 *
 * Guardrails:
 * 1. Never tracks `.exec` / `.execSync` unless the source object is proven bound to `child_process`.
 * 2. Distinguishes block scopes from object literals, and invalidates aliases on parameter shadowing,
 *    catch bindings, loop bindings, local re-declarations, and reassignments.
 * 3. Emits strictly non-scoring (`scoring: false`, `severity: 'warning'`) `DG001-ALIAS-01` findings.
 */
export function detectAliasedExecutionSinks(
  maskedCode: string,
  stringLiterals: ReadonlyArray<ExtractedStringLiteral>,
  inlineFindings?: InlineFinding[]
): AliasFindingMetadata[] {
  if (!maskedCode || maskedCode.length === 0) return [];

  const tokens = tokenizeMaskedCode(maskedCode, stringLiterals);
  if (tokens.length === 0) return [];

  const scopeStack: ScopeFrame[] = [{ kind: 'module', bindings: new Map() }];
  const braceStack: BraceFrame[] = [];
  const pendingFunctionParams = new Map<number, string[]>(); // keyed by body `{` token index
  const pendingCatchParams = new Map<number, string[]>(); // keyed by catch `{` token index
  const pendingLoopParams = new Map<number, string[]>(); // keyed by loop `{` token index
  const handledDeclEqIndices = new Set<number>(); // `=` indices already processed by Section 6 declarations
  const emittedKeys = new Set<string>();
  const results: AliasFindingMetadata[] = [];

  let parenDepth = 0;
  let bracketDepth = 0;

  const currentScope = (): ScopeFrame => scopeStack[scopeStack.length - 1];

  const lookupBinding = (name: string): ScopeBinding | undefined => {
    for (let s = scopeStack.length - 1; s >= 0; s--) {
      if (scopeStack[s].bindings.has(name)) {
        return scopeStack[s].bindings.get(name) ?? null;
      }
    }
    return undefined;
  };

  const setInCurrentScope = (name: string, binding: ScopeBinding): void => {
    currentScope().bindings.set(name, binding);
  };

  const invalidateOrUpdateAssignment = (name: string, binding: ScopeBinding): void => {
    // Update the nearest scope that already declared `name`, or current scope if undeclared
    for (let s = scopeStack.length - 1; s >= 0; s--) {
      if (scopeStack[s].bindings.has(name)) {
        scopeStack[s].bindings.set(name, binding);
        return;
      }
    }
    currentScope().bindings.set(name, binding);
  };

  const isInObjectLiteral = (): boolean =>
    braceStack.length > 0 && braceStack[braceStack.length - 1].kind === 'object';

  const isInTypeContext = (): boolean =>
    braceStack.some((b) => b.kind === 'type');

  const closeExpiredArrowExprScopes = (tok: Token): void => {
    while (scopeStack.length > 1) {
      const top = scopeStack[scopeStack.length - 1];
      if (top.kind !== 'arrow-expr') break;
      const baseDepth = top.exprBracketDepth ?? 0;
      const curDepth = parenDepth + bracketDepth + braceStack.length;
      if (
        curDepth < baseDepth ||
        (curDepth === baseDepth &&
          tok.kind === 'punct' &&
          (tok.value === ';' || tok.value === ',' || tok.value === ')' || tok.value === ']' || tok.value === '}'))
      ) {
        scopeStack.pop();
      } else {
        break;
      }
    }
  };

  const emitFinding = (
    aliasName: string,
    target: AliasSinkTarget,
    depth: number,
    chain: readonly string[],
    line: number
  ): void => {
    const key = `${line}:${aliasName}:${target}`;
    if (emittedKeys.has(key)) return;
    emittedKeys.add(key);

    results.push({ aliasName, target, depth, chain, line });
    if (inlineFindings) {
      const chainText = chain.join(' -> ');
      inlineFindings.push({
        ruleId: 'DG001-ALIAS-01',
        line,
        severity: 'warning',
        scoring: false,
        message: `[DG001-ALIAS-01] Non-scoring warning: aliased dangerous execution sink invocation (${chainText}, depth ${depth}) on line ${line}.`,
      });
    }
  };

  const classifyOpeningBrace = (idx: number): BraceKind => {
    if (pendingFunctionParams.has(idx) || pendingCatchParams.has(idx) || pendingLoopParams.has(idx)) {
      return 'block';
    }
    const prev = idx > 0 ? tokens[idx - 1] : undefined;
    if (!prev) return 'block';

    // `interface Foo {` or `type Foo = {`
    if (prev.kind === 'ident') {
      const prev2 = idx > 1 ? tokens[idx - 2] : undefined;
      if (prev2 && prev2.kind === 'ident' && prev2.value === 'interface') {
        return 'type';
      }
      if (prev2 && prev2.kind === 'ident' && prev2.value === 'class') {
        return 'block';
      }
      if (BLOCK_PRECEDING_KEYWORDS.has(prev.value)) {
        return 'block';
      }
      if (DECL_KEYWORDS.has(prev.value) || prev.value === 'import') {
        return 'destructure';
      }
      if (EXPRESSION_PRECEDING_KEYWORDS.has(prev.value)) {
        return 'object';
      }
    }

    if (prev.kind === 'punct') {
      if (prev.value === '=>' || prev.value === ')' || prev.value === ';' || prev.value === '{' || prev.value === '}') {
        // After `)` could be `if (...) {` or `function() {`; after `=>` is arrow block body
        return 'block';
      }
      if (prev.value === '=') {
        // Check `type Foo = { ... }`
        const prev3 = idx > 2 ? tokens[idx - 3] : undefined;
        if (prev3 && prev3.kind === 'ident' && prev3.value === 'type') {
          return 'type';
        }
        return 'object';
      }
      if (EXPRESSION_PRECEDING_PUNCT.has(prev.value)) {
        return 'object';
      }
    }

    // Default to block for statement-level `{`, object if already inside parens/brackets
    if (parenDepth > 0 || bracketDepth > 0) {
      return 'object';
    }
    return 'block';
  };

  for (let i = 0; i < tokens.length; i++) {
    const tok = tokens[i];
    const prev = i > 0 ? tokens[i - 1] : undefined;
    const next = i + 1 < tokens.length ? tokens[i + 1] : undefined;

    closeExpiredArrowExprScopes(tok);

    // Track parens & brackets
    if (tok.kind === 'punct') {
      if (tok.value === '(') {
        // Detect function/method/arrow parameter list
        const header = detectFunctionHeaderAtParen(tokens, i);
        if (header) {
          if (header.isArrow) {
            const afterArrow = tokens[header.bodyTokenIdx + 1];
            if (afterArrow && afterArrow.kind === 'punct' && afterArrow.value === '{') {
              pendingFunctionParams.set(header.bodyTokenIdx + 1, header.params);
            } else {
              // Expression-bodied arrow function: `(fn) => fn('safe')`
              // Push scope when we reach `=>` (stored via pendingFunctionParams on `=>` index)
              pendingFunctionParams.set(header.bodyTokenIdx, header.params);
            }
          } else {
            pendingFunctionParams.set(header.bodyTokenIdx, header.params);
          }
        }
        parenDepth++;
        continue;
      }
      if (tok.value === ')') {
        parenDepth = Math.max(0, parenDepth - 1);
        continue;
      }
      if (tok.value === '[') {
        bracketDepth++;
        continue;
      }
      if (tok.value === ']') {
        bracketDepth = Math.max(0, bracketDepth - 1);
        continue;
      }
      if (tok.value === '=>') {
        // Check if this arrow has an expression body with pending params
        const exprParams = pendingFunctionParams.get(i);
        if (exprParams !== undefined) {
          pendingFunctionParams.delete(i);
          const bindings = new Map<string, ScopeBinding>();
          for (const p of exprParams) bindings.set(p, null);
          scopeStack.push({
            kind: 'arrow-expr',
            bindings,
            exprBracketDepth: parenDepth + bracketDepth + braceStack.length,
          });
        }
        continue;
      }
      if (tok.value === '{') {
        const kind = classifyOpeningBrace(i);
        let pushedScope = false;
        if (kind === 'block') {
          const bindings = new Map<string, ScopeBinding>();
          const fnParams = pendingFunctionParams.get(i);
          if (fnParams) {
            pendingFunctionParams.delete(i);
            for (const p of fnParams) bindings.set(p, null);
          }
          const catchParams = pendingCatchParams.get(i);
          if (catchParams) {
            pendingCatchParams.delete(i);
            for (const p of catchParams) bindings.set(p, null);
          }
          const loopParams = pendingLoopParams.get(i);
          if (loopParams) {
            pendingLoopParams.delete(i);
            for (const p of loopParams) bindings.set(p, null);
          }
          scopeStack.push({
            kind: fnParams ? 'function' : 'block',
            bindings,
          });
          pushedScope = true;
        }
        braceStack.push({ kind, pushedScope });
        continue;
      }
      if (tok.value === '}') {
        const popped = braceStack.pop();
        if (popped?.pushedScope && scopeStack.length > 1) {
          scopeStack.pop();
        }
        continue;
      }
      continue;
    }

    if (isInTypeContext()) continue;

    // -------------------------------------------------------------------------
    // 1. Single-parameter arrow function without parens: `fn => fn('safe')`
    // -------------------------------------------------------------------------
    if (
      tok.kind === 'ident' &&
      next &&
      next.kind === 'punct' &&
      next.value === '=>' &&
      (!prev || prev.kind !== 'punct' || (prev.value !== '.' && prev.value !== '?.'))
    ) {
      const afterArrow = tokens[i + 2];
      if (afterArrow && afterArrow.kind === 'punct' && afterArrow.value === '{') {
        pendingFunctionParams.set(i + 2, [tok.value]);
      } else {
        pendingFunctionParams.set(i + 1, [tok.value]);
      }
      continue;
    }

    // -------------------------------------------------------------------------
    // 2. `catch (err) { ... }` parameter shadowing
    // -------------------------------------------------------------------------
    if (tok.kind === 'ident' && tok.value === 'catch' && next && next.kind === 'punct' && next.value === '(') {
      const closeIdx = findMatchingClose(tokens, i + 1, '(', ')');
      if (closeIdx !== -1) {
        const catchParams = extractBoundIdentifiers(tokens, i + 2, closeIdx - 1);
        const bodyIdx = closeIdx + 1;
        if (bodyIdx < tokens.length && tokens[bodyIdx].kind === 'punct' && tokens[bodyIdx].value === '{') {
          pendingCatchParams.set(bodyIdx, catchParams);
        }
      }
      continue;
    }

    // -------------------------------------------------------------------------
    // 3. `for (const x of ...)` / `for (let i = 0; ...)` loop variable shadowing
    // -------------------------------------------------------------------------
    if (tok.kind === 'ident' && tok.value === 'for' && next && next.kind === 'punct' && next.value === '(') {
      const closeIdx = findMatchingClose(tokens, i + 1, '(', ')');
      if (closeIdx !== -1) {
        const declTok = tokens[i + 2];
        if (declTok && declTok.kind === 'ident' && DECL_KEYWORDS.has(declTok.value)) {
          // Find where binding ends (`of`, `in`, `=`, `;`)
          let bindEnd = i + 3;
          let nested = 0;
          while (bindEnd < closeIdx) {
            const bt = tokens[bindEnd];
            if (bt.kind === 'punct' && (bt.value === '{' || bt.value === '[' || bt.value === '(')) nested++;
            else if (bt.kind === 'punct' && (bt.value === '}' || bt.value === ']' || bt.value === ')')) nested--;
            else if (
              nested === 0 &&
              ((bt.kind === 'ident' && (bt.value === 'of' || bt.value === 'in')) ||
                (bt.kind === 'punct' && (bt.value === '=' || bt.value === ';')))
            ) {
              break;
            }
            bindEnd++;
          }
          const loopVars = extractBoundIdentifiers(tokens, i + 3, bindEnd - 1);
          const bodyIdx = closeIdx + 1;
          if (bodyIdx < tokens.length && tokens[bodyIdx].kind === 'punct' && tokens[bodyIdx].value === '{') {
            pendingLoopParams.set(bodyIdx, loopVars);
          }
        }
      }
      continue;
    }

    // -------------------------------------------------------------------------
    // 4. `function name(...)` declaration shadows `name` in current scope
    // -------------------------------------------------------------------------
    if (tok.kind === 'ident' && tok.value === 'function') {
      let nameIdx = i + 1;
      if (tokens[nameIdx]?.kind === 'punct' && tokens[nameIdx].value === '*') nameIdx++;
      if (tokens[nameIdx]?.kind === 'ident') {
        setInCurrentScope(tokens[nameIdx].value, null);
      }
      continue;
    }

    // -------------------------------------------------------------------------
    // 5. ESM static imports from `child_process` / `node:child_process`
    // -------------------------------------------------------------------------
    if (tok.kind === 'ident' && tok.value === 'import' && !isInObjectLiteral()) {
      // Find `from '<specifier>'` on this import statement
      let fromIdx = -1;
      for (let k = i + 1; k < tokens.length && k < i + 60; k++) {
        if (tokens[k].kind === 'punct' && tokens[k].value === ';') break;
        if (tokens[k].kind === 'ident' && tokens[k].value === 'from') {
          fromIdx = k;
          break;
        }
      }
      if (fromIdx !== -1 && fromIdx + 1 < tokens.length && tokens[fromIdx + 1].kind === 'string') {
        const modSpec = tokens[fromIdx + 1].value;
        const isChildProcess = CHILD_PROCESS_SPECIFIERS.has(modSpec);
        let k = i + 1;
        // Skip `type` imports: `import type { ... } from ...`
        if (tokens[k]?.kind === 'ident' && tokens[k].value === 'type') {
          i = fromIdx + 1;
          continue;
        }
        // Default import: `import cp from 'child_process'`
        if (k < fromIdx && tokens[k].kind === 'ident') {
          const defaultName = tokens[k].value;
          setInCurrentScope(
            defaultName,
            isChildProcess
              ? { kind: 'namespace', module: 'child_process', depth: 0, chain: [defaultName] }
              : null
          );
          k++;
          if (k < fromIdx && tokens[k].kind === 'punct' && tokens[k].value === ',') k++;
        }
        // Namespace import: `import * as cp from 'child_process'`
        if (
          k + 2 < fromIdx &&
          tokens[k].kind === 'punct' &&
          tokens[k].value === '*' &&
          tokens[k + 1].kind === 'ident' &&
          tokens[k + 1].value === 'as' &&
          tokens[k + 2].kind === 'ident'
        ) {
          const nsName = tokens[k + 2].value;
          setInCurrentScope(
            nsName,
            isChildProcess
              ? { kind: 'namespace', module: 'child_process', depth: 0, chain: [nsName] }
              : null
          );
          i = fromIdx + 1;
          continue;
        }
        // Named imports: `import { exec, execSync as runSync } from 'child_process'`
        if (k < fromIdx && tokens[k].kind === 'punct' && tokens[k].value === '{') {
          const closeBrace = findMatchingClose(tokens, k, '{', '}');
          if (closeBrace !== -1 && closeBrace < fromIdx) {
            let m = k + 1;
            while (m < closeBrace) {
              if (tokens[m].kind === 'punct' && tokens[m].value === ',') {
                m++;
                continue;
              }
              if (tokens[m].kind === 'ident' && tokens[m].value === 'type') {
                m++;
                continue;
              }
              if (tokens[m].kind === 'ident') {
                const importedName = tokens[m].value;
                let localName = importedName;
                if (
                  m + 2 < closeBrace &&
                  tokens[m + 1].kind === 'ident' &&
                  tokens[m + 1].value === 'as' &&
                  tokens[m + 2].kind === 'ident'
                ) {
                  localName = tokens[m + 2].value;
                  m += 3;
                } else {
                  m++;
                }
                if (isChildProcess) {
                  const sink = CHILD_PROCESS_SINKS.get(importedName);
                  if (sink) {
                    const isAliased = localName !== importedName;
                    setInCurrentScope(localName, {
                      kind: 'sink',
                      target: sink,
                      depth: isAliased ? 1 : 0,
                      chain: isAliased ? [localName, sink] : [sink],
                    });
                  } else {
                    setInCurrentScope(localName, null);
                  }
                } else {
                  setInCurrentScope(localName, null);
                }
                continue;
              }
              m++;
            }
          }
        }
        i = fromIdx + 1;
        continue;
      }
      continue;
    }

    // -------------------------------------------------------------------------
    // 6. Variable declarations: `const/let/var ...`
    // -------------------------------------------------------------------------
    if (tok.kind === 'ident' && DECL_KEYWORDS.has(tok.value) && !isInObjectLiteral()) {
      let cur = i + 1;
      // Handle one or more comma-separated declarators
      while (cur < tokens.length) {
        const lhsTok = tokens[cur];
        if (!lhsTok) break;

        // 6a. Object destructuring: `const { exec, execSync: run } = require('child_process')` or `= cp`
        if (lhsTok.kind === 'punct' && lhsTok.value === '{') {
          const closeBrace = findMatchingClose(tokens, cur, '{', '}');
          if (closeBrace === -1) break;
          let eqIdx = closeBrace + 1;
          // Skip optional TS type annotation `: { ... }`
          if (tokens[eqIdx]?.kind === 'punct' && tokens[eqIdx].value === ':') {
            eqIdx = skipReturnTypeAnnotation(tokens, eqIdx);
          }
          if (tokens[eqIdx]?.kind === 'punct' && tokens[eqIdx].value === '=') {
            handledDeclEqIndices.add(eqIdx);
            const rhsStart = eqIdx + 1;
            const rhsEnd = findRhsEnd(tokens, rhsStart);
            const rhsBinding =
              rhsEnd - rhsStart === 1 && tokens[rhsStart].kind === 'ident'
                ? (lookupBinding(tokens[rhsStart].value) ?? null)
                : resolveRhsBinding(tokens, rhsStart, rhsEnd, '<destructured>', lookupBinding);

            // Walk destructured properties
            let m = cur + 1;
            while (m < closeBrace) {
              if (tokens[m].kind === 'punct' && (tokens[m].value === ',' || tokens[m].value === '...')) {
                m++;
                continue;
              }
              if (tokens[m].kind === 'ident' || tokens[m].kind === 'string') {
                const propName = tokens[m].value;
                let localName = tokens[m].kind === 'ident' ? propName : '';
                const itemEnd = findTopLevelComma(tokens, m, closeBrace - 1);
                if (m + 2 < itemEnd && tokens[m + 1].kind === 'punct' && tokens[m + 1].value === ':') {
                  if (tokens[m + 2].kind === 'ident') {
                    localName = tokens[m + 2].value;
                  } else {
                    // Nested destructuring: shadow all bound names
                    const nested = extractBoundIdentifiers(tokens, m + 2, itemEnd - 1);
                    for (const n of nested) setInCurrentScope(n, null);
                    m = itemEnd + 1;
                    continue;
                  }
                }
                if (localName) {
                  if (rhsBinding && rhsBinding.kind === 'namespace' && rhsBinding.module === 'child_process') {
                    const sink = CHILD_PROCESS_SINKS.get(propName);
                    if (sink) {
                      const isRenamed = localName !== propName;
                      const nextDepth = rhsBinding.depth + (isRenamed ? 1 : rhsBinding.depth === 0 ? 0 : 1);
                      if (nextDepth <= MAX_ALIAS_DEPTH) {
                        setInCurrentScope(localName, {
                          kind: 'sink',
                          target: sink,
                          depth: nextDepth,
                          chain: nextDepth === 0 ? [sink] : [localName, sink],
                        });
                      } else {
                        setInCurrentScope(localName, null);
                      }
                    } else {
                      setInCurrentScope(localName, null);
                    }
                  } else {
                    // Also handle `const { eval: e } = globalThis;`
                    const rhsCount = rhsEnd - rhsStart;
                    if (
                      rhsCount === 1 &&
                      tokens[rhsStart].kind === 'ident' &&
                      GLOBAL_OBJECT_NAMES.has(tokens[rhsStart].value)
                    ) {
                      const directSink = DIRECT_SINKS.get(propName);
                      if (directSink) {
                        setInCurrentScope(localName, {
                          kind: 'sink',
                          target: directSink,
                          depth: 1,
                          chain: [localName, `${tokens[rhsStart].value}.${propName}`],
                        });
                      } else {
                        setInCurrentScope(localName, null);
                      }
                    } else {
                      setInCurrentScope(localName, null);
                    }
                  }
                }
                m = itemEnd + 1;
                continue;
              }
              m++;
            }

            if (tokens[rhsEnd]?.kind === 'punct' && tokens[rhsEnd].value === ',') {
              cur = rhsEnd + 1;
              continue;
            }
          } else {
            // Destructuring without `=` (e.g. `for (const { a } of list)`)
            const bound = extractBoundIdentifiers(tokens, cur + 1, closeBrace - 1);
            for (const b of bound) setInCurrentScope(b, null);
          }
          break;
        }

        // 6b. Array destructuring: `const [a, b] = ...` -> shadow all bound names
        if (lhsTok.kind === 'punct' && lhsTok.value === '[') {
          const closeBr = findMatchingClose(tokens, cur, '[', ']');
          if (closeBr === -1) break;
          const bound = extractBoundIdentifiers(tokens, cur + 1, closeBr - 1);
          for (const b of bound) setInCurrentScope(b, null);
          break;
        }

        // 6c. Simple identifier declarator: `const fn = eval` / `let fn;`
        if (lhsTok.kind === 'ident') {
          const lhsName = lhsTok.value;
          let eqIdx = cur + 1;
          if (tokens[eqIdx]?.kind === 'punct' && tokens[eqIdx].value === ':') {
            eqIdx = skipReturnTypeAnnotation(tokens, eqIdx);
          }
          if (tokens[eqIdx]?.kind === 'punct' && tokens[eqIdx].value === '=') {
            handledDeclEqIndices.add(eqIdx);
            const rhsStart = eqIdx + 1;
            const rhsEnd = findRhsEnd(tokens, rhsStart);
            const resolved = resolveRhsBinding(tokens, rhsStart, rhsEnd, lhsName, lookupBinding);
            setInCurrentScope(lhsName, resolved);

            if (tokens[rhsEnd]?.kind === 'punct' && tokens[rhsEnd].value === ',') {
              cur = rhsEnd + 1;
              continue;
            }
          } else {
            // Uninitialized declaration: `let fn;` -> shadows any outer alias
            setInCurrentScope(lhsName, null);
            if (tokens[eqIdx]?.kind === 'punct' && tokens[eqIdx].value === ',') {
              cur = eqIdx + 1;
              continue;
            }
          }
        }
        break;
      }
      continue;
    }

    // -------------------------------------------------------------------------
    // 7. Reassignment: `fn = safe` or `fn = eval` (outside object literals)
    // -------------------------------------------------------------------------
    if (
      tok.kind === 'ident' &&
      !isInObjectLiteral() &&
      !(prev && prev.kind === 'ident' && DECL_KEYWORDS.has(prev.value)) &&
      (!prev || prev.kind !== 'punct' || (prev.value !== '.' && prev.value !== '?.' && prev.value !== ':')) &&
      next &&
      next.kind === 'punct' &&
      ASSIGNMENT_PUNCT.has(next.value) &&
      !handledDeclEqIndices.has(i + 1)
    ) {
      const lhsName = tok.value;
      if (next.value === '=') {
        const rhsStart = i + 2;
        const rhsEnd = findRhsEnd(tokens, rhsStart);
        const resolved = resolveRhsBinding(tokens, rhsStart, rhsEnd, lhsName, lookupBinding);
        invalidateOrUpdateAssignment(lhsName, resolved);
      } else {
        // Compound assignment (`+=`, etc.) invalidates any function alias
        invalidateOrUpdateAssignment(lhsName, null);
      }
      continue;
    }

    // -------------------------------------------------------------------------
    // 8. Call site detection: `alias(...)`, `new alias(...)`, or `nsAlias.exec(...)`
    // -------------------------------------------------------------------------
    if (tok.kind === 'ident' && (!prev || prev.kind !== 'punct' || (prev.value !== '.' && prev.value !== '?.'))) {
      // Skip non-call keywords / declarations
      if (prev && prev.kind === 'ident' && NON_CALL_PRECEDING_KEYWORDS.has(prev.value)) {
        continue;
      }

      // 8a. Direct call to alias identifier: `fn(...)` or `fn?.(...)`
      const isDirectCall =
        (next && next.kind === 'punct' && next.value === '(') ||
        (next &&
          next.kind === 'punct' &&
          next.value === '?.' &&
          tokens[i + 2]?.kind === 'punct' &&
          tokens[i + 2].value === '(');

      if (isDirectCall) {
        const openParenIdx = next.value === '(' ? i + 1 : i + 2;
        // Guard: ignore method/function declarations `fn(...) {`
        const closeParenIdx = findMatchingClose(tokens, openParenIdx, '(', ')');
        const afterParen = closeParenIdx !== -1 ? skipReturnTypeAnnotation(tokens, closeParenIdx + 1) : -1;
        const isMethodDecl =
          afterParen !== -1 &&
          tokens[afterParen]?.kind === 'punct' &&
          tokens[afterParen].value === '{';

        if (!isMethodDecl) {
          const binding = lookupBinding(tok.value);
          if (
            binding &&
            binding.kind === 'sink' &&
            binding.depth >= 1 &&
            binding.depth <= MAX_ALIAS_DEPTH
          ) {
            emitFinding(tok.value, binding.target, binding.depth, binding.chain, tok.line);
          }
        }
        continue;
      }

      // 8b. Member call on an ALIASED `child_process` namespace (`const sh = cp; sh.exec(...)`)
      const isMemberCall =
        next &&
        next.kind === 'punct' &&
        (next.value === '.' || next.value === '?.') &&
        tokens[i + 2]?.kind === 'ident' &&
        tokens[i + 3]?.kind === 'punct' &&
        tokens[i + 3].value === '(';

      if (isMemberCall) {
        const propName = tokens[i + 2].value;
        const sink = CHILD_PROCESS_SINKS.get(propName);
        if (sink) {
          const binding = lookupBinding(tok.value);
          if (
            binding &&
            binding.kind === 'namespace' &&
            binding.module === 'child_process' &&
            binding.depth >= 1 &&
            binding.depth <= MAX_ALIAS_DEPTH
          ) {
            emitFinding(
              `${tok.value}.${propName}`,
              sink,
              binding.depth,
              [...binding.chain, propName],
              tok.line
            );
          }
        }
      }
    }
  }

  return results;
}
