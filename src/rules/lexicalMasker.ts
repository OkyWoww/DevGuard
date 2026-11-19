export * from './spanMap.ts';
export type DevGuardRuleId =
  | 'DG001' | 'DG002' | 'DG003' | 'DG004'
  | 'DG004-DYN-01' | 'DG004-DYN-02'
  | 'DG005' | 'DG006' | 'DG007' | 'DG008';

export type AllowlistRuleId = 'DG004' | 'DG004-DYN-01' | 'DG004-DYN-02' | 'DG006';

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
  '', '\n', '(', '[', '{', ',', ';', '=', ':', '?', '!', '&', '|', '^', '~', '+', '-', '*', '%', '<', '>',
]);
const REGEX_PRECEDING_KEYWORDS = new Set([
  'return', 'typeof', 'void', 'delete', 'await', 'throw', 'case', 'in', 'of', 'instanceof', 'new', 'else', 'do', 'yield', 'export', 'default',
]);
export const CRITICAL_FLOW_IDENTIFIERS = [
  'payment', 'balance', 'wallet', 'ledger', 'transfer', 'charge',
  'refund', 'deduct', 'invoice', 'auth', 'token', 'jwt', 'password',
  'execute', 'query', 'transaction', 'writeFileSync',
] as const;

const SUPPRESSION_COMMENT_RE = /\bdevguard-ignore\s+(DG\d{3}(?:-DYN-0[12]|-EV-01)?)\s*:\s*([^\r\n]+)/i;
const VALID_DG_RULE_RE = /^(?:DG00[1-8]|DG004-DYN-0[12]|DG00[58]-EV-01)$/;
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

function skipQuotedLiteral(
  rawCode: string,
  out: string[],
  startIdx: number,
  startLine: number
): { nextIdx: number; endLine: number; literal: ExtractedStringLiteral } {
  const quote = rawCode[startIdx];
  let line = startLine;
  let hasInterpolation = false;
  if (out[startIdx] !== '\n') out[startIdx] = ' ';
  let i = startIdx + 1;
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
    if (quote === '`' && ch === '$' && rawCode[i + 1] === '{') hasInterpolation = true;
    if (ch === quote) {
      if (out[i] !== '\n') out[i] = ' ';
      break;
    }
    if (ch === '\n') {
      if (quote !== '`') break;
      line++;
    } else if (out[i] !== '\n') out[i] = ' ';
    i++;
  }
  const endOffset = Math.min(rawCode.length, i + 1);
  return {
    nextIdx: i,
    endLine: line,
    literal: {
      value: rawCode.slice(startIdx + 1, rawCode[endOffset - 1] === quote ? endOffset - 1 : endOffset),
      quote,
      line: startLine,
      endLine: line,
      startOffset: startIdx,
      endOffset,
      hasInterpolation,
    },
  };
}

function skipRegexLiteral(rawCode: string, out: string[], startIdx: number): number {
  if (out[startIdx] !== '\n') out[startIdx] = ' ';
  let i = startIdx + 1;
  let inClass = false;
  while (i < rawCode.length && rawCode[i] !== '\n') {
    const ch = rawCode[i];
    if (out[i] !== '\n') out[i] = ' ';
    if (ch === '\\' && i + 1 < rawCode.length && rawCode[i + 1] !== '\n') {
      i++;
      if (out[i] !== '\n') out[i] = ' ';
    } else if (ch === '[' && !inClass) inClass = true;
    else if (ch === ']' && inClass) inClass = false;
    else if (ch === '/' && !inClass) {
      while (i + 1 < rawCode.length && /[a-z]/i.test(rawCode[i + 1])) {
        i++;
        if (out[i] !== '\n') out[i] = ' ';
      }
      break;
    }
    i++;
  }
  return i;
}

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
  let prevNonWs = '';
  let currentWord = '';
  let lastWord = '';

  try {
    for (let i = 0; i < rawCode.length; i++) {
      const ch = rawCode[i];
      const next = rawCode[i + 1];
      if (ch === '\n') {
        line++;
        lineHadCode = false;
        lastWord = currentWord || lastWord;
        currentWord = '';
        prevNonWs = '\n';
      } else if ((ch === '/' && next === '/') || ((allowHashComments || (i === 0 && next === '!')) && ch === '#')) {
        const commentStart = i;
        const cStart = i + (ch === '#' ? 1 : 2);
        const cLine = line;
        while (i < rawCode.length && rawCode[i] !== '\n') out[i++] = ' ';
        recordConstruct(commentStart, i, 'comment');
        parseSuppressionFromComment(rawCode.slice(cStart, i), cLine, lineHadCode, suppressions, pending);
        if (rawCode[i] === '\n') { line++; lineHadCode = false; prevNonWs = '\n'; }
        currentWord = '';
      } else if (!allowHashComments && ch === '/' && next === '*') {
        const commentStart = i;
        const cStart = i + 2;
        const cLine = line;
        const wasTrailing = lineHadCode;
        out[i] = ' ';
        out[i + 1] = ' ';
        for (i += 2; i < rawCode.length; i++) {
          if (rawCode[i] === '*' && rawCode[i + 1] === '/') { out[i] = ' '; out[++i] = ' '; break; }
          if (rawCode[i] === '\n') line++; else out[i] = ' ';
        }
        const commentEnd = Math.min(rawCode.length, i + 1);
        recordConstruct(commentStart, commentEnd, 'comment');
        parseSuppressionFromComment(rawCode.slice(cStart, i - 1), cLine, wasTrailing, suppressions, pending);
        currentWord = '';
      } else if (!allowHashComments && ch === '/' && (REGEX_PRECEDING_KEYWORDS.has(currentWord || lastWord) || (!currentWord && REGEX_PRECEDING_CHARS.has(prevNonWs)))) {
        flushPendingSuppressions(line, suppressions, pending);
        lineHadCode = true;
        const regexStart = i;
        i = skipRegexLiteral(rawCode, out, i);
        const regexEnd = Math.min(rawCode.length, i + 1);
        recordConstruct(regexStart, regexEnd, 'regex');
        prevNonWs = ')';
        currentWord = '';
        lastWord = '';
      } else if (ch === '\'' || ch === '"' || ch === '`') {
        flushPendingSuppressions(line, suppressions, pending);
        lineHadCode = true;
        const quoteStart = i;
        const kind: LexicalRegionKind = ch === '`' ? 'template' : 'string';
        const res = skipQuotedLiteral(rawCode, out, i, line);
        stringLiterals.push(res.literal);
        recordConstruct(quoteStart, res.literal.endOffset, kind);
        i = res.nextIdx;
        line = res.endLine;
        prevNonWs = res.literal.quote;
        currentWord = '';
        lastWord = '';
      } else if (/[A-Za-z0-9_$]/.test(ch)) {
        flushPendingSuppressions(line, suppressions, pending);
        lineHadCode = true;
        currentWord += ch;
        prevNonWs = ch;
      } else {
        if (currentWord) { lastWord = currentWord; currentWord = ''; }
        if (!/\s/.test(ch)) {
          flushPendingSuppressions(line, suppressions, pending);
          lineHadCode = true;
          prevNonWs = ch;
          lastWord = '';
        }
      }
    }
    if (lastRegionEnd < rawCode.length) {
      pushRegion(lastRegionEnd, rawCode.length, 'code');
    }
  } catch {
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
