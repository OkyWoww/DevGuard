export * from './spanMap.ts';
import type { WorkspaceContext, WorkspaceFileAccessor } from './workspaceResolver.ts';

export type DevGuardRuleId =
  | 'DG001' | 'DG001-ALIAS-01'
  | 'DG002' | 'DG003' | 'DG004'
  | 'DG004-DYN-01' | 'DG004-DYN-02'
  | 'DG004-REG-01' | 'DG004-REG-UNREACHABLE'
  | 'DG004-WS-NEW' | 'DG004-WS-UNPARSED'
  | 'DG005' | 'DG005-ALIAS-01'
  | 'DG006' | 'DG007' | 'DG008';

export type AllowlistRuleId = 'DG004' | 'DG004-DYN-01' | 'DG004-DYN-02' | 'DG004-REG-01' | 'DG006';

export type LexicalRegionKind = 'code' | 'string' | 'template' | 'comment' | 'regex';

export interface LexicalRegion {
  start: number;
  end: number;
  kind: LexicalRegionKind;
}

export interface InlineFinding {
  ruleId: DevGuardRuleId;
  line: number;
  endLine?: number;
  severity: 'error' | 'warning';
  scoring?: boolean;
  message: string;
  suggestion?: string;
}

export interface ParsedSuppression {
  ruleId: DevGuardRuleId;
  targetLine: number;
  commentLine: number;
  reason: string;
  kind: 'inSource' | 'external';
  filePath?: string;
  severity?: 'error' | 'warning';
  message?: string;
}

export interface AuditAnalyzeOptions {
  filePath?: string;
  declaredDependencies?: ReadonlySet<string> | readonly string[];
  builtinModules?: readonly string[];
  subpathImports?: Record<string, unknown>;
  externalAllowlist?: ReadonlyArray<{ rule: AllowlistRuleId; reason: string }>;
  workspaceContext?: WorkspaceContext;
  workspaceFileAccessor?: WorkspaceFileAccessor;
  workspacesMode?: 'auto' | 'off';
}

export interface LineFinding {
  line: number;
  endLine?: number;
  extraLines?: number[];
  category: 'security' | 'correctness' | 'maintainability';
  penalty: number;
  shortReason: string;
  detailedReason: string;
  isCritical?: boolean;
}

export interface ExtractedStringLiteral {
  value: string;
  quote: string;
  line: number;
  endLine: number;
  startOffset: number;
  endOffset: number;
  hasInterpolation: boolean;
}

const REGEX_PRECEDING_CHARS = new Set([
  '(', '[', '{', ',', ';', '=', ':', '?', '!', '&', '|', '^', '~', '+', '-', '*', '%', '<', '>',
]);
const REGEX_PRECEDING_KEYWORDS = new Set([
  'return', 'typeof', 'void', 'delete', 'await', 'throw', 'case', 'in', 'of', 'instanceof', 'new', 'else', 'do', 'yield', 'export', 'default', 'as', 'satisfies',
]);
const CONTROL_PAREN_KEYWORDS = new Set(['if', 'while', 'for', 'with']);
export const CRITICAL_FLOW_IDENTIFIERS = [
  'payment', 'balance', 'wallet', 'ledger', 'transfer', 'charge',
  'refund', 'deduct', 'invoice', 'auth', 'token', 'jwt', 'password',
  'execute', 'query', 'transaction', 'writeFileSync',
] as const;

const SUPPRESSION_COMMENT_RE = /\bdevguard-ignore\s+(DG\d{3}(?:-DYN-0[12]|-REG-01|-EV-01)?)\s*:\s*([^\r\n]+)/i;
const VALID_DG_RULE_RE = /^(?:DG00[1-8]|DG004-DYN-0[12]|DG004-REG-01|DG00[58]-EV-01)$/;
export const MEANINGFUL_SUPPRESSION_REASON_RE = /[A-Za-z]{2,}\s+[A-Za-z]{2,}/;

/** Validates that a suppression justification has >= 8 chars and at least two alphabetic words. */
export function isValidSuppressionReason(reason: unknown): reason is string {
  if (typeof reason !== 'string') return false;
  const trimmed = reason.trim();
  return trimmed.length >= 8 && MEANINGFUL_SUPPRESSION_REASON_RE.test(trimmed);
}

function parseSuppressionFromComment(
  commentBody: string,
  commentLine: number,
  isTrailing: boolean,
  suppressions: ParsedSuppression[],
  pending: Array<{ ruleId: DevGuardRuleId; commentLine: number; reason: string }>
): void {
  const cleaned = commentBody.replace(/\*\/\s*$/, '').trim();
  const match = cleaned.match(SUPPRESSION_COMMENT_RE);
  if (!match?.[1] || !match[2]) return;
  const ruleUpper = match[1].toUpperCase();
  if (!VALID_DG_RULE_RE.test(ruleUpper)) return;
  const reason = match[2].replace(/\*\/\s*$/, '').trim();
  if (!isValidSuppressionReason(reason)) return;

  const ruleId = (
    ruleUpper === 'DG005-EV-01' ? 'DG005' : ruleUpper === 'DG008-EV-01' ? 'DG008' : ruleUpper
  ) as DevGuardRuleId;
  if (isTrailing) {
    suppressions.push({ ruleId, targetLine: commentLine, commentLine, reason, kind: 'inSource' });
  } else {
    pending.push({ ruleId, commentLine, reason });
  }
}

function flushPendingSuppressions(
  targetLine: number,
  suppressions: ParsedSuppression[],
  pending: Array<{ ruleId: DevGuardRuleId; commentLine: number; reason: string }>
): void {
  while (pending.length > 0) {
    const item = pending.shift()!;
    suppressions.push({ ...item, targetLine, kind: 'inSource' });
  }
}

function skipSingleOrDoubleQuotedLiteral(
  rawCode: string,
  out: string[],
  startIdx: number,
  startLine: number
): { nextIdx: number; endLine: number; literal: ExtractedStringLiteral } {
  const quote = rawCode[startIdx];
  let line = startLine;
  if (out[startIdx] !== '\n') out[startIdx] = ' ';
  let i = startIdx + 1;
  let closed = false;

  while (i < rawCode.length) {
    const ch = rawCode[i];
    if (ch === '\\' && i + 1 < rawCode.length) {
      if (out[i] !== '\n') out[i] = ' ';
      i++;
      if (rawCode[i] === '\n') line++;
      else if (out[i] !== '\n') out[i] = ' ';
      i++;
      continue;
    }
    if (ch === quote) {
      if (out[i] !== '\n') out[i] = ' ';
      closed = true;
      break;
    }
    if (ch === '\n') {
      // Stop BEFORE '\n' so the outer loop advances line count and resets line state cleanly
      break;
    }
    if (out[i] !== '\n') out[i] = ' ';
    i++;
  }

  const endOffset = closed ? i + 1 : i;
  const nextIdx = closed ? i : i - 1;
  return {
    nextIdx,
    endLine: line,
    literal: {
      value: rawCode.slice(startIdx + 1, closed ? endOffset - 1 : endOffset),
      quote,
      line: startLine,
      endLine: line,
      startOffset: startIdx,
      endOffset,
      hasInterpolation: false,
    },
  };
}

function skipRegexLiteral(
  rawCode: string,
  out: string[],
  startIdx: number
): { nextIdx: number; endOffset: number } {
  if (out[startIdx] !== '\n') out[startIdx] = ' ';
  let i = startIdx + 1;
  let inClass = false;
  let closed = false;

  while (i < rawCode.length && rawCode[i] !== '\n') {
    const ch = rawCode[i];
    if (out[i] !== '\n') out[i] = ' ';
    if (ch === '\\' && i + 1 < rawCode.length && rawCode[i + 1] !== '\n') {
      i++;
      if (out[i] !== '\n') out[i] = ' ';
    } else if (ch === '[' && !inClass) {
      inClass = true;
    } else if (ch === ']' && inClass) {
      inClass = false;
    } else if (ch === '/' && !inClass) {
      closed = true;
      while (i + 1 < rawCode.length && /[a-z]/i.test(rawCode[i + 1])) {
        i++;
        if (out[i] !== '\n') out[i] = ' ';
      }
      break;
    }
    i++;
  }

  if (closed) {
    return { nextIdx: i, endOffset: Math.min(rawCode.length, i + 1) };
  }
  // Unclosed regex hit '\n' or EOF: stop BEFORE '\n' so the outer loop handles '\n' cleanly
  return { nextIdx: i - 1, endOffset: i };
}

type TemplateStackFrame =
  | { kind: 'template' }
  | {
      kind: 'expr';
      braceDepth: number;
      canPrecedeRegex: boolean;
      currentWord: string;
      lastWord: string;
      prevPunct: string;
      parenIsControl: boolean[];
    };

/**
 * Iteratively masks a template literal (including arbitrarily deep nested `${...}`
 * expressions containing objects, strings, comments, regexes, and nested templates)
 * without recursion, guaranteeing O(N) time and zero call-stack overflow.
 */
function skipTemplateLiteral(
  rawCode: string,
  out: string[],
  startIdx: number,
  startLine: number
): { nextIdx: number; endLine: number; literal: ExtractedStringLiteral } {
  let line = startLine;
  let hasInterpolation = false;
  if (out[startIdx] !== '\n') out[startIdx] = ' ';
  let i = startIdx + 1;
  let closed = false;
  const stack: TemplateStackFrame[] = [{ kind: 'template' }];

  while (i < rawCode.length && stack.length > 0) {
    const top = stack[stack.length - 1];
    const ch = rawCode[i];

    if (top.kind === 'template') {
      if (ch === '\\' && i + 1 < rawCode.length) {
        if (out[i] !== '\n') out[i] = ' ';
        i++;
        if (rawCode[i] === '\n') line++;
        else if (out[i] !== '\n') out[i] = ' ';
        i++;
        continue;
      }
      if (ch === '$' && rawCode[i + 1] === '{') {
        hasInterpolation = true;
        out[i] = ' ';
        out[i + 1] = ' ';
        i += 2;
        stack.push({
          kind: 'expr',
          braceDepth: 1,
          canPrecedeRegex: true,
          currentWord: '',
          lastWord: '',
          prevPunct: '{',
          parenIsControl: [],
        });
        continue;
      }
      if (ch === '`') {
        out[i] = ' ';
        stack.pop();
        if (stack.length === 0) {
          closed = true;
          break;
        }
        const parent = stack[stack.length - 1];
        if (parent.kind === 'expr') {
          parent.canPrecedeRegex = false;
          parent.currentWord = '';
          parent.lastWord = '';
          parent.prevPunct = '';
        }
        i++;
        continue;
      }
      if (ch === '\n') line++;
      else out[i] = ' ';
      i++;
      continue;
    }

    // Inside `${ ... }` expression frame
    const next = rawCode[i + 1];
    if (ch === '\n') {
      line++;
      if (top.currentWord) {
        top.lastWord = top.currentWord;
        top.canPrecedeRegex = REGEX_PRECEDING_KEYWORDS.has(top.lastWord);
        top.currentWord = '';
      }
      i++;
      continue;
    }

    if (ch === '/' && next === '/') {
      if (top.currentWord) {
        top.lastWord = top.currentWord;
        top.canPrecedeRegex = REGEX_PRECEDING_KEYWORDS.has(top.lastWord);
        top.currentWord = '';
      }
      while (i < rawCode.length && rawCode[i] !== '\n') {
        out[i] = ' ';
        i++;
      }
      continue;
    }

    if (ch === '/' && next === '*') {
      if (top.currentWord) {
        top.lastWord = top.currentWord;
        top.canPrecedeRegex = REGEX_PRECEDING_KEYWORDS.has(top.lastWord);
        top.currentWord = '';
      }
      out[i] = ' ';
      out[i + 1] = ' ';
      i += 2;
      while (i < rawCode.length) {
        if (rawCode[i] === '*' && rawCode[i + 1] === '/') {
          out[i] = ' ';
          out[i + 1] = ' ';
          i += 2;
          break;
        }
        if (rawCode[i] === '\n') line++;
        else out[i] = ' ';
        i++;
      }
      continue;
    }

    if (ch === '\'' || ch === '"') {
      const innerStr = skipSingleOrDoubleQuotedLiteral(rawCode, out, i, line);
      line = innerStr.endLine;
      i = innerStr.nextIdx + 1;
      top.canPrecedeRegex = false;
      top.currentWord = '';
      top.lastWord = '';
      top.prevPunct = '';
      continue;
    }

    if (ch === '`') {
      out[i] = ' ';
      i++;
      stack.push({ kind: 'template' });
      continue;
    }

    if (ch === '/') {
      const canStartRegex = top.currentWord
        ? REGEX_PRECEDING_KEYWORDS.has(top.currentWord)
        : top.canPrecedeRegex;
      if (canStartRegex) {
        const rx = skipRegexLiteral(rawCode, out, i);
        i = rx.nextIdx + 1;
        top.canPrecedeRegex = false;
        top.currentWord = '';
        top.lastWord = '';
        top.prevPunct = '';
        continue;
      }
    }

    out[i] = ' ';
    if (ch === '{') {
      top.braceDepth++;
      top.currentWord = '';
      top.lastWord = '';
      top.canPrecedeRegex = true;
      top.prevPunct = '{';
    } else if (ch === '}') {
      top.braceDepth--;
      if (top.braceDepth === 0) {
        stack.pop();
      } else {
        top.currentWord = '';
        top.lastWord = '';
        top.canPrecedeRegex = false;
        top.prevPunct = '}';
      }
    } else if (/[A-Za-z0-9_$]/.test(ch)) {
      top.currentWord += ch;
      top.prevPunct = '';
    } else if (/\s/.test(ch)) {
      if (top.currentWord) {
        top.lastWord = top.currentWord;
        top.canPrecedeRegex = REGEX_PRECEDING_KEYWORDS.has(top.lastWord);
        top.currentWord = '';
      }
    } else {
      if (top.currentWord) {
        top.lastWord = top.currentWord;
        top.currentWord = '';
      }
      if (ch === '(') {
        top.parenIsControl.push(CONTROL_PAREN_KEYWORDS.has(top.lastWord));
        top.canPrecedeRegex = true;
        top.prevPunct = '(';
      } else if (ch === ')') {
        top.canPrecedeRegex = top.parenIsControl.pop() ?? false;
        top.prevPunct = ')';
      } else if (
        (ch === '+' && top.prevPunct === '+' && rawCode[i - 1] === '+') ||
        (ch === '-' && top.prevPunct === '-' && rawCode[i - 1] === '-')
      ) {
        top.canPrecedeRegex = false;
        top.prevPunct = ch + ch;
      } else {
        top.canPrecedeRegex = REGEX_PRECEDING_CHARS.has(ch);
        top.prevPunct = ch;
      }
      top.lastWord = '';
    }
    i++;
  }

  const endOffset = closed ? i + 1 : i;
  const nextIdx = closed ? i : i - 1;
  return {
    nextIdx,
    endLine: line,
    literal: {
      value: rawCode.slice(startIdx + 1, closed ? endOffset - 1 : endOffset),
      quote: '`',
      line: startLine,
      endLine: line,
      startOffset: startIdx,
      endOffset,
      hasInterpolation,
    },
  };
}

const CLOSING_JSX_TAG_RE = /<\/([A-Za-z_$][\w$.:-]*)?\s*>/g;

/**
 * Collects JSX closing tag names ("" for fragments `</>`) in a single O(N) pass so
 * JSX text tracking only activates for elements that actually have a closing tag,
 * preventing false activation on TypeScript angle-bracket casts or generics.
 */
function collectClosingJsxTags(rawCode: string): Set<string> {
  const tags = new Set<string>();
  CLOSING_JSX_TAG_RE.lastIndex = 0;
  let match: RegExpExecArray | null = CLOSING_JSX_TAG_RE.exec(rawCode);
  while (match !== null) {
    tags.add(match[1] ?? '');
    match = CLOSING_JSX_TAG_RE.exec(rawCode);
  }
  return tags;
}

function matchJsxOpeningTagName(rawCode: string, ltIdx: number): { tagName: string; nameEnd: number } | null {
  if (rawCode[ltIdx] !== '<') return null;
  if (rawCode[ltIdx + 1] === '>') {
    return { tagName: '', nameEnd: ltIdx + 1 };
  }
  const first = rawCode[ltIdx + 1];
  if (!first || !/[A-Za-z_$]/.test(first)) return null;
  let j = ltIdx + 2;
  while (j < rawCode.length && /[\w$.:-]/.test(rawCode[j])) {
    j++;
  }
  const next = rawCode[j];
  if (next === '>' || next === '/' || (next !== undefined && /\s/.test(next))) {
    return { tagName: rawCode.slice(ltIdx + 1, j), nameEnd: j };
  }
  return null;
}

function matchJsxClosingTag(rawCode: string, ltIdx: number): { tagName: string; closeEnd: number } | null {
  if (rawCode[ltIdx] !== '<' || rawCode[ltIdx + 1] !== '/') return null;
  let j = ltIdx + 2;
  const nameStart = j;
  if (j < rawCode.length && /[A-Za-z_$]/.test(rawCode[j])) {
    j++;
    while (j < rawCode.length && /[\w$.:-]/.test(rawCode[j])) {
      j++;
    }
  }
  const tagName = rawCode.slice(nameStart, j);
  while (j < rawCode.length && (rawCode[j] === ' ' || rawCode[j] === '\t')) {
    j++;
  }
  if (rawCode[j] === '>') {
    return { tagName, closeEnd: j };
  }
  return null;
}

type JsxFrame =
  | { kind: 'jsxTag'; tagName: string }
  | { kind: 'jsxText'; tagName: string }
  | { kind: 'jsxExpr'; braceDepth: number };

/** Returns true if and only if [start, end) falls strictly inside a single 'code' region. */
export function isRangeStrictlyInCodeRegion(
  regions: ReadonlyArray<LexicalRegion>,
  start: number,
  end: number
): boolean {
  if (typeof start !== 'number' || typeof end !== 'number') return false;
  if (!Number.isFinite(start) || !Number.isFinite(end)) return false;
  if (start < 0 || end <= start || regions.length === 0) return false;

  let low = 0;
  let high = regions.length - 1;
  while (low <= high) {
    const mid = (low + high) >> 1;
    const reg = regions[mid];
    if (start >= reg.start && start < reg.end) {
      return reg.kind === 'code' && end <= reg.end;
    }
    if (start < reg.start) {
      high = mid - 1;
    } else {
      low = mid + 1;
    }
  }
  return false;
}

/** Masks comments, regexes, and literals while extracting in-comment suppressions and region classification. */
export function analyzeLexicalStructure(
  rawCode: string,
  allowHashComments: boolean = false
): {
  maskedCode: string;
  stringLiterals: ExtractedStringLiteral[];
  suppressions: ParsedSuppression[];
  regions: LexicalRegion[];
} {
  if (typeof rawCode !== 'string') throw new TypeError('rawCode must be a string');
  if (rawCode.length === 0) {
    return { maskedCode: '', stringLiterals: [], suppressions: [], regions: [] };
  }

  const out = rawCode.split('');
  const stringLiterals: ExtractedStringLiteral[] = [];
  const suppressions: ParsedSuppression[] = [];
  const pending: Array<{ ruleId: DevGuardRuleId; commentLine: number; reason: string }> = [];
  const regions: LexicalRegion[] = [];
  let lastRegionEnd = 0;

  const pushRegion = (start: number, end: number, kind: LexicalRegionKind) => {
    if (start >= end) return;
    if (regions.length > 0 && regions[regions.length - 1].kind === kind && regions[regions.length - 1].end === start) {
      regions[regions.length - 1].end = end;
    } else {
      regions.push({ start, end, kind });
    }
  };

  const recordConstruct = (start: number, end: number, kind: LexicalRegionKind) => {
    if (start > lastRegionEnd) {
      pushRegion(lastRegionEnd, start, 'code');
    }
    pushRegion(start, end, kind);
    lastRegionEnd = end;
  };

  let line = 1;
  let lineHadCode = false;
  let canPrecedeRegex = true;
  let currentWord = '';
  let lastWord = '';
  let prevPunct = '';
  const parenIsControl: boolean[] = [];
  const closingJsxTags = allowHashComments ? new Set<string>() : collectClosingJsxTags(rawCode);
  const jsxStack: JsxFrame[] = [];

  try {
    for (let i = 0; i < rawCode.length; i++) {
      const ch = rawCode[i];
      const next = rawCode[i + 1];
      const jsxTop = jsxStack.length > 0 ? jsxStack[jsxStack.length - 1] : undefined;

      // Inside JSX text children: apostrophes/quotes/slashes are literal UI text, not JS tokens
      if (jsxTop && jsxTop.kind === 'jsxText') {
        if (ch === '\n') {
          line++;
          lineHadCode = false;
          continue;
        }
        if (ch === '{') {
          flushPendingSuppressions(line, suppressions, pending);
          lineHadCode = true;
          jsxStack.push({ kind: 'jsxExpr', braceDepth: 1 });
          canPrecedeRegex = true;
          currentWord = '';
          lastWord = '';
          prevPunct = '{';
          continue;
        }
        if (ch === '<') {
          const closing = matchJsxClosingTag(rawCode, i);
          if (closing) {
            flushPendingSuppressions(line, suppressions, pending);
            lineHadCode = true;
            // Pop matching JSX text frame (or top frame on mismatched tag)
            for (let s = jsxStack.length - 1; s >= 0; s--) {
              const frame = jsxStack[s];
              if (frame.kind === 'jsxText' && frame.tagName === closing.tagName) {
                jsxStack.length = s;
                break;
              }
            }
            i = closing.closeEnd;
            canPrecedeRegex = false;
            currentWord = '';
            lastWord = '';
            prevPunct = '>';
            continue;
          }
          const opening = matchJsxOpeningTagName(rawCode, i);
          if (opening && closingJsxTags.has(opening.tagName)) {
            flushPendingSuppressions(line, suppressions, pending);
            lineHadCode = true;
            jsxStack.push({ kind: 'jsxTag', tagName: opening.tagName });
            i = opening.nameEnd - 1;
            canPrecedeRegex = false;
            currentWord = '';
            lastWord = '';
            prevPunct = '';
            continue;
          }
        }
        if (!/\s/.test(ch)) {
          flushPendingSuppressions(line, suppressions, pending);
          lineHadCode = true;
        }
        continue;
      }

      if (ch === '\n') {
        line++;
        lineHadCode = false;
        if (currentWord) {
          lastWord = currentWord;
          canPrecedeRegex = REGEX_PRECEDING_KEYWORDS.has(lastWord);
          currentWord = '';
        }
        continue;
      }

      // Inside JSX opening tag header `<Tag attr="..." onClick={...}>`
      if (jsxTop && jsxTop.kind === 'jsxTag') {
        if (ch === '/' && next === '>') {
          jsxStack.pop();
          i++;
          canPrecedeRegex = false;
          currentWord = '';
          lastWord = '';
          prevPunct = '>';
          continue;
        }
        if (ch === '>') {
          jsxStack[jsxStack.length - 1] = { kind: 'jsxText', tagName: jsxTop.tagName };
          canPrecedeRegex = false;
          currentWord = '';
          lastWord = '';
          prevPunct = '>';
          continue;
        }
        if (ch === '{') {
          flushPendingSuppressions(line, suppressions, pending);
          lineHadCode = true;
          jsxStack.push({ kind: 'jsxExpr', braceDepth: 1 });
          canPrecedeRegex = true;
          currentWord = '';
          lastWord = '';
          prevPunct = '{';
          continue;
        }
      }

      // Track brace depth for `{ ... }` expressions embedded inside JSX
      if (jsxTop && jsxTop.kind === 'jsxExpr') {
        if (ch === '{') {
          jsxTop.braceDepth++;
          flushPendingSuppressions(line, suppressions, pending);
          lineHadCode = true;
          canPrecedeRegex = true;
          currentWord = '';
          lastWord = '';
          prevPunct = '{';
          continue;
        }
        if (ch === '}') {
          jsxTop.braceDepth--;
          flushPendingSuppressions(line, suppressions, pending);
          lineHadCode = true;
          if (jsxTop.braceDepth === 0) {
            jsxStack.pop();
          }
          canPrecedeRegex = false;
          currentWord = '';
          lastWord = '';
          prevPunct = '}';
          continue;
        }
      }

      if ((ch === '/' && next === '/') || ((allowHashComments || (i === 0 && next === '!')) && ch === '#')) {
        if (currentWord) {
          lastWord = currentWord;
          canPrecedeRegex = REGEX_PRECEDING_KEYWORDS.has(lastWord);
          currentWord = '';
        }
        const commentStart = i;
        const cStart = i + (ch === '#' ? 1 : 2);
        const cLine = line;
        while (i < rawCode.length && rawCode[i] !== '\n') out[i++] = ' ';
        recordConstruct(commentStart, i, 'comment');
        parseSuppressionFromComment(rawCode.slice(cStart, i), cLine, lineHadCode, suppressions, pending);
        // Leave '\n' for the main loop by stepping back 1
        i--;
      } else if (!allowHashComments && ch === '/' && next === '*') {
        if (currentWord) {
          lastWord = currentWord;
          canPrecedeRegex = REGEX_PRECEDING_KEYWORDS.has(lastWord);
          currentWord = '';
        }
        const commentStart = i;
        const cStart = i + 2;
        const cLine = line;
        const wasTrailing = lineHadCode;
        let sawNewline = false;
        let closedBlock = false;
        out[i] = ' ';
        out[i + 1] = ' ';
        for (i += 2; i < rawCode.length; i++) {
          if (rawCode[i] === '*' && rawCode[i + 1] === '/') {
            out[i] = ' ';
            out[++i] = ' ';
            closedBlock = true;
            break;
          }
          if (rawCode[i] === '\n') {
            line++;
            sawNewline = true;
          } else {
            out[i] = ' ';
          }
        }
        const commentEnd = closedBlock ? i + 1 : rawCode.length;
        const bodyEnd = closedBlock ? i - 1 : rawCode.length;
        recordConstruct(commentStart, commentEnd, 'comment');
        parseSuppressionFromComment(rawCode.slice(cStart, bodyEnd), cLine, wasTrailing, suppressions, pending);
        if (sawNewline) {
          lineHadCode = false;
        }
      } else if (!allowHashComments && ch === '<') {
        flushPendingSuppressions(line, suppressions, pending);
        lineHadCode = true;
        // Closing JSX tag `</Tag>` or `</>` must never trigger regex on `/`
        const closing = matchJsxClosingTag(rawCode, i);
        if (closing) {
          i = closing.closeEnd;
          canPrecedeRegex = false;
          currentWord = '';
          lastWord = '';
          prevPunct = '>';
          continue;
        }
        // Opening JSX tag in expression position when a matching closing tag exists in file
        const canStartExpr = currentWord ? REGEX_PRECEDING_KEYWORDS.has(currentWord) : canPrecedeRegex;
        if (canStartExpr) {
          const opening = matchJsxOpeningTagName(rawCode, i);
          if (opening && closingJsxTags.has(opening.tagName)) {
            jsxStack.push({ kind: 'jsxTag', tagName: opening.tagName });
            i = opening.nameEnd - 1;
            canPrecedeRegex = false;
            currentWord = '';
            lastWord = '';
            prevPunct = '';
            continue;
          }
        }
        if (currentWord) {
          lastWord = currentWord;
          currentWord = '';
        }
        canPrecedeRegex = true;
        prevPunct = '<';
        lastWord = '';
      } else if (
        !allowHashComments &&
        ch === '/' &&
        (currentWord ? REGEX_PRECEDING_KEYWORDS.has(currentWord) : canPrecedeRegex)
      ) {
        flushPendingSuppressions(line, suppressions, pending);
        lineHadCode = true;
        const regexStart = i;
        const rx = skipRegexLiteral(rawCode, out, i);
        recordConstruct(regexStart, rx.endOffset, 'regex');
        i = rx.nextIdx;
        canPrecedeRegex = false;
        currentWord = '';
        lastWord = '';
        prevPunct = '';
      } else if (ch === '\'' || ch === '"') {
        flushPendingSuppressions(line, suppressions, pending);
        lineHadCode = true;
        const quoteStart = i;
        const res = skipSingleOrDoubleQuotedLiteral(rawCode, out, i, line);
        stringLiterals.push(res.literal);
        recordConstruct(quoteStart, res.literal.endOffset, 'string');
        i = res.nextIdx;
        line = res.endLine;
        canPrecedeRegex = false;
        currentWord = '';
        lastWord = '';
        prevPunct = '';
      } else if (ch === '`') {
        flushPendingSuppressions(line, suppressions, pending);
        lineHadCode = true;
        const quoteStart = i;
        const res = skipTemplateLiteral(rawCode, out, i, line);
        stringLiterals.push(res.literal);
        recordConstruct(quoteStart, res.literal.endOffset, 'template');
        i = res.nextIdx;
        line = res.endLine;
        canPrecedeRegex = false;
        currentWord = '';
        lastWord = '';
        prevPunct = '';
      } else if (/[A-Za-z0-9_$]/.test(ch)) {
        flushPendingSuppressions(line, suppressions, pending);
        lineHadCode = true;
        currentWord += ch;
        prevPunct = '';
      } else {
        if (currentWord) {
          lastWord = currentWord;
          canPrecedeRegex = REGEX_PRECEDING_KEYWORDS.has(lastWord);
          currentWord = '';
        }
        if (!/\s/.test(ch)) {
          flushPendingSuppressions(line, suppressions, pending);
          lineHadCode = true;
          if (ch === '(') {
            parenIsControl.push(CONTROL_PAREN_KEYWORDS.has(lastWord));
            canPrecedeRegex = true;
            prevPunct = '(';
          } else if (ch === ')') {
            canPrecedeRegex = parenIsControl.pop() ?? false;
            prevPunct = ')';
          } else if (
            (ch === '+' && prevPunct === '+' && rawCode[i - 1] === '+') ||
            (ch === '-' && prevPunct === '-' && rawCode[i - 1] === '-')
          ) {
            canPrecedeRegex = false;
            prevPunct = ch + ch;
          } else {
            canPrecedeRegex = REGEX_PRECEDING_CHARS.has(ch);
            prevPunct = ch;
          }
          lastWord = '';
        }
      }
    }
    if (lastRegionEnd < rawCode.length) {
      pushRegion(lastRegionEnd, rawCode.length, 'code');
    }
  } catch (err) {
    const safeReason = err instanceof Error ? err.message : String(err);
    void safeReason;
    return {
      maskedCode: rawCode,
      stringLiterals: [],
      suppressions: [],
      regions: rawCode.length > 0 ? [{ start: 0, end: rawCode.length, kind: 'code' }] : [],
    };
  }
  return { maskedCode: out.join(''), stringLiterals, suppressions, regions };
}

export function calculateShannonEntropy(input: string): number {
  if (typeof input !== 'string' || !input) return 0;
  const freq = new Map<string, number>();
  for (let i = 0; i < input.length; i++) freq.set(input[i], (freq.get(input[i]) ?? 0) + 1);
  let entropy = 0;
  for (const count of freq.values()) {
    const p = count / input.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

/** Optimal String Alignment (Damerau-Levenshtein) distance treating adjacent swaps as 1 edit. */
export function damerauLevenshtein(a: string, b: string): number {
  const m = a.length;
  const n = b.length;
  const dp: number[][] = Array.from({ length: m + 1 }, () => new Array<number>(n + 1).fill(0));
  for (let i = 0; i <= m; i++) dp[i][0] = i;
  for (let j = 0; j <= n; j++) dp[0][j] = j;
  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      let val = Math.min(dp[i - 1][j] + 1, dp[i][j - 1] + 1, dp[i - 1][j - 1] + cost);
      if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) {
        val = Math.min(val, dp[i - 2][j - 2] + 1);
      }
      dp[i][j] = val;
    }
  }
  return dp[m][n];
}

export function isCommentOrEmptyLine(line: string): boolean {
  const t = line.trim();
  return !t || t.startsWith('//') || t.startsWith('#') || t.startsWith('/*') || t.startsWith('*') || t.startsWith('"""') || t.startsWith("'''");
}

export const MAX_GLOB_PATTERN_LENGTH = 512;

function normalizePosixGlobInput(raw: string): string {
  let norm = raw.trim().replace(/\\/g, '/');
  while (norm.startsWith('./')) {
    norm = norm.slice(2);
  }
  return norm;
}

function matchSegmentGlob(patSeg: string, targetSeg: string): boolean {
  let p = 0;
  let t = 0;
  let starP = -1;
  let starT = 0;

  while (t < targetSeg.length) {
    const pch = patSeg[p];
    if (p < patSeg.length && (pch === '?' || pch === targetSeg[t])) {
      p++;
      t++;
    } else if (p < patSeg.length && pch === '*') {
      while (p < patSeg.length && patSeg[p] === '*') {
        p++;
      }
      starP = p - 1;
      starT = t;
    } else if (starP !== -1) {
      p = starP + 1;
      starT++;
      t = starT;
    } else {
      return false;
    }
  }

  while (p < patSeg.length && patSeg[p] === '*') {
    p++;
  }
  return p === patSeg.length;
}

/**
 * Matches a POSIX repo-relative file path against a glob pattern (`?`, `*`, `**`)
 * in guaranteed linear O(|pattern| * |targetPath|) time without `new RegExp`.
 */
export function matchLinearGlob(pattern: string, targetPath: string): boolean {
  if (typeof pattern !== 'string' || typeof targetPath !== 'string') return false;
  const normPattern = normalizePosixGlobInput(pattern);
  const normTarget = normalizePosixGlobInput(targetPath);
  if (!normPattern || !normTarget || normPattern.length > MAX_GLOB_PATTERN_LENGTH) {
    return false;
  }

  const pSegs = normPattern.split('/');
  const tSegs = normTarget.split('/');

  let prev = new Array<boolean>(tSegs.length + 1).fill(false);
  prev[0] = true;

  for (let i = 0; i < pSegs.length; i++) {
    const patSeg = pSegs[i];
    const next = new Array<boolean>(tSegs.length + 1).fill(false);
    if (patSeg === '**') {
      next[0] = prev[0];
      for (let j = 1; j <= tSegs.length; j++) {
        next[j] = prev[j] || next[j - 1];
      }
    } else {
      for (let j = 1; j <= tSegs.length; j++) {
        if (prev[j - 1] && matchSegmentGlob(patSeg, tSegs[j - 1])) {
          next[j] = true;
        }
      }
    }
    prev = next;
  }

  return prev[tSegs.length];
}
