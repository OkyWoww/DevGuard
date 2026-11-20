import type { ExtractedStringLiteral, LexicalRegion } from './lexicalMasker.ts';
import { analyzeLexicalStructure, isRangeStrictlyInCodeRegion } from './lexicalMasker.ts';

export const MAX_FOLD_DEPTH = 4;
export const MAX_FOLD_OPERANDS = 64;
export const MAX_FOLDED_LENGTH = 4096;
export const MAX_FOLD_EDITS = 2000;
export const MAX_BACKSCAN = 256;

const ASCII_IDENT_RE = /^[A-Za-z_$][\w$]*$/;

const FOLD04_REJECTED_KEYWORDS = new Set([
  'return', 'typeof', 'in', 'of', 'instanceof', 'new', 'delete', 'void',
  'throw', 'case', 'do', 'else', 'yield', 'await', 'extends',
  'if', 'while', 'for', 'with', 'switch', 'catch',
  'class', 'function', 'var', 'let', 'const', 'import', 'export', 'default',
  'try', 'finally', 'debugger',
]);

const CONTROL_KEYWORDS = new Set([
  'if', 'while', 'for', 'with', 'switch', 'catch',
]);

function isSafeLiteral(rawText: string, value: string): boolean {
  if (rawText.includes('\\') || rawText.includes('\n') || rawText.includes('\r')) {
    return false;
  }
  if (value.includes('\\') || value.includes('\n') || value.includes('\r')) {
    return false;
  }
  return true;
}

function findRegionIndexForStart(regions: ReadonlyArray<LexicalRegion>, start: number): number {
  let lo = 0;
  let hi = regions.length - 1;
  while (lo <= hi) {
    const mid = (lo + hi) >>> 1;
    const r = regions[mid];
    if (r.end <= start) {
      lo = mid + 1;
    } else if (r.start > start) {
      hi = mid - 1;
    } else {
      return mid;
    }
  }
  return lo;
}

function overlapsCommentOrRegex(
  start: number,
  end: number,
  regions: ReadonlyArray<LexicalRegion>
): boolean {
  if (regions.length === 0 || end <= start) return false;
  let i = findRegionIndexForStart(regions, start);
  while (i < regions.length && regions[i].start < end) {
    const r = regions[i];
    if ((r.kind === 'comment' || r.kind === 'regex') && Math.max(start, r.start) < Math.min(end, r.end)) {
      return true;
    }
    i++;
  }
  return false;
}

function isInTemplateRegion(
  start: number,
  end: number,
  regions: ReadonlyArray<LexicalRegion>
): boolean {
  if (regions.length === 0) return false;
  const idx = findRegionIndexForStart(regions, start);
  if (idx >= regions.length) return false;
  const r = regions[idx];
  return r.kind === 'template' && start >= r.start && end <= r.end;
}

function findLiteralsInRange(
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
    if (lit.endOffset <= rangeEnd) matches.push(lit);
  }
  return matches;
}

export interface SpanMapSeg {
  vStart: number;
  vEnd: number;
  oStart: number;
  oEnd: number;
  kind: 'copy' | 'fold';
}

export type SpanMap = SpanMapSeg[];

export interface FoldTextEdit {
  start: number; // inclusive offset in source string before pass
  end: number;   // exclusive offset in source string before pass (start < end)
  replacement: string; // non-empty replacement string in virtual view
}

export interface VirtualViewResult {
  virtualCode: string;
  spanMap: SpanMap;
  editsApplied: number;
  limitExceeded: boolean;
}

/** Creates a 1-segment identity SpanMap spanning [0, length) with kind 'copy'. */
export function createIdentitySpanMap(length: number): SpanMap {
  if (length <= 0) return [];
  return [{ vStart: 0, vEnd: length, oStart: 0, oEnd: length, kind: 'copy' }];
}

/**
 * Applies a list of non-overlapping text edits onto source and constructs the corresponding SpanMap.
 * Invalid edits (negative bounds, end > source.length, start >= end, empty replacement, overlap,
 * or edits outside 'code' regions) fail-open and are skipped.
 */
export function applyTextEditsWithSpanMap(
  source: string,
  edits: ReadonlyArray<FoldTextEdit>,
  codeRegions?: ReadonlyArray<LexicalRegion>
): { virtualText: string; spanMap: SpanMap; appliedCount: number } {
  if (typeof source !== 'string') throw new TypeError('source must be a string');
  if (source.length === 0) {
    return { virtualText: '', spanMap: [], appliedCount: 0 };
  }

  // Filter valid edits and sort by start ascending
  const validEdits = edits
    .filter((e) => {
      if (!e || typeof e.start !== 'number' || typeof e.end !== 'number' || typeof e.replacement !== 'string') {
        return false;
      }
      if (!Number.isFinite(e.start) || !Number.isFinite(e.end)) {
        return false;
      }
      if (e.start < 0 || e.end > source.length || e.start >= e.end || e.replacement.length === 0) {
        return false;
      }
      if (codeRegions && !isRangeStrictlyInCodeRegion(codeRegions, e.start, e.end)) {
        return false;
      }
      return true;
    })
    .sort((a, b) => a.start - b.start || a.end - b.end);

  // Filter non-overlapping edits fail-open
  const nonOverlapping: FoldTextEdit[] = [];
  let prevEnd = -1;
  for (const edit of validEdits) {
    if (edit.start >= prevEnd) {
      nonOverlapping.push(edit);
      prevEnd = edit.end;
    }
  }

  if (nonOverlapping.length === 0) {
    return {
      virtualText: source,
      spanMap: createIdentitySpanMap(source.length),
      appliedCount: 0,
    };
  }

  const parts: string[] = [];
  const spanMap: SpanMapSeg[] = [];
  let currentO = 0;
  let currentV = 0;

  for (const edit of nonOverlapping) {
    if (edit.start > currentO) {
      const copyLen = edit.start - currentO;
      parts.push(source.slice(currentO, edit.start));
      spanMap.push({
        vStart: currentV,
        vEnd: currentV + copyLen,
        oStart: currentO,
        oEnd: edit.start,
        kind: 'copy',
      });
      currentV += copyLen;
      currentO = edit.start;
    }

    parts.push(edit.replacement);
    const repLen = edit.replacement.length;
    spanMap.push({
      vStart: currentV,
      vEnd: currentV + repLen,
      oStart: edit.start,
      oEnd: edit.end,
      kind: 'fold',
    });
    currentV += repLen;
    currentO = edit.end;
  }

  if (currentO < source.length) {
    const tailLen = source.length - currentO;
    parts.push(source.slice(currentO));
    spanMap.push({
      vStart: currentV,
      vEnd: currentV + tailLen,
      oStart: currentO,
      oEnd: source.length,
      kind: 'copy',
    });
  }

  return {
    virtualText: parts.join(''),
    spanMap,
    appliedCount: nonOverlapping.length,
  };
}

/**
 * Composes two consecutive SpanMaps: prevMap (O -> V1) and nextMap (V1 -> V2),
 * producing a single SpanMap that directly maps O -> V2.
 */
export function composeSpanMaps(
  prevMap: ReadonlyArray<SpanMapSeg>,
  nextMap: ReadonlyArray<SpanMapSeg>
): SpanMap {
  if (nextMap.length === 0) return [];
  if (prevMap.length === 0) return [];

  const rawSegments: SpanMapSeg[] = [];

  for (const segNext of nextMap) {
    const v1Start = segNext.oStart;
    const v1End = segNext.oEnd;

    // Binary search first prevMap segment whose vEnd > v1Start
    let lo = 0;
    let hi = prevMap.length;
    while (lo < hi) {
      const mid = (lo + hi) >>> 1;
      if (prevMap[mid].vEnd <= v1Start) lo = mid + 1;
      else hi = mid;
    }

    const overlapping: SpanMapSeg[] = [];
    for (let k = lo; k < prevMap.length && prevMap[k].vStart < v1End; k++) {
      overlapping.push(prevMap[k]);
    }

    if (overlapping.length === 0) {
      continue;
    }

    if (segNext.kind === 'fold') {
      // The entire virtual span in V2 is a fold. Map to bounding box of all touched original ranges.
      let minO = Infinity;
      let maxO = -Infinity;
      for (const p of overlapping) {
        const s = Math.max(v1Start, p.vStart);
        const e = Math.min(v1End, p.vEnd);
        if (p.kind === 'copy') {
          const oFrom = p.oStart + (s - p.vStart);
          const oTo = p.oStart + (e - p.vStart);
          minO = Math.min(minO, oFrom);
          maxO = Math.max(maxO, oTo);
        } else {
          minO = Math.min(minO, p.oStart);
          maxO = Math.max(maxO, p.oEnd);
        }
      }
      rawSegments.push({
        vStart: segNext.vStart,
        vEnd: segNext.vEnd,
        oStart: minO,
        oEnd: maxO,
        kind: 'fold',
      });
    } else {
      // segNext.kind === 'copy'
      for (const p of overlapping) {
        const s = Math.max(v1Start, p.vStart);
        const e = Math.min(v1End, p.vEnd);
        const v2Start = segNext.vStart + (s - v1Start);
        const v2End = segNext.vStart + (e - v1Start);

        if (p.kind === 'copy') {
          const oStart = p.oStart + (s - p.vStart);
          const oEnd = p.oStart + (e - p.vStart);
          rawSegments.push({
            vStart: v2Start,
            vEnd: v2End,
            oStart,
            oEnd,
            kind: 'copy',
          });
        } else {
          // Touching a fold from pass 1: becomes fold in composed map
          rawSegments.push({
            vStart: v2Start,
            vEnd: v2End,
            oStart: p.oStart,
            oEnd: p.oEnd,
            kind: 'fold',
          });
        }
      }
    }
  }

  // Coalesce adjacent segments
  const result: SpanMapSeg[] = [];
  for (const seg of rawSegments) {
    if (result.length === 0) {
      result.push({ ...seg });
      continue;
    }
    const last = result[result.length - 1];
    if (
      last.kind === 'copy' &&
      seg.kind === 'copy' &&
      last.vEnd === seg.vStart &&
      last.oEnd === seg.oStart
    ) {
      last.vEnd = seg.vEnd;
      last.oEnd = seg.oEnd;
    } else if (
      last.kind === 'fold' &&
      seg.kind === 'fold' &&
      last.vEnd === seg.vStart &&
      last.oStart === seg.oStart &&
      last.oEnd === seg.oEnd
    ) {
      last.vEnd = seg.vEnd;
    } else {
      result.push({ ...seg });
    }
  }

  return result;
}

/**
 * Maps a virtual span [vStart, vEnd] back to original source offsets [oStart, oEnd]
 * using binary search. If a fold segment is touched, its full original span is returned.
 */
export function toOrigSpan(
  spanMap: ReadonlyArray<SpanMapSeg>,
  vStart: number,
  vEnd?: number
): { oStart: number; oEnd: number } {
  if (spanMap.length === 0) return { oStart: 0, oEnd: 0 };
  const maxV = spanMap[spanMap.length - 1].vEnd;
  const targetEnd = vEnd !== undefined ? vEnd : vStart;

  const boundedStart = Math.max(0, Math.min(vStart, maxV));
  const boundedEnd = Math.max(boundedStart, Math.min(targetEnd, maxV));

  const findSeg = (pos: number): SpanMapSeg => {
    let low = 0;
    let high = spanMap.length - 1;
    while (low <= high) {
      const mid = (low + high) >> 1;
      const seg = spanMap[mid];
      if (pos >= seg.vStart && (pos < seg.vEnd || (pos === maxV && mid === spanMap.length - 1))) {
        return seg;
      }
      if (pos < seg.vStart) {
        high = mid - 1;
      } else {
        low = mid + 1;
      }
    }
    return spanMap[Math.min(spanMap.length - 1, Math.max(0, low))];
  };

  if (boundedStart === boundedEnd) {
    const seg = findSeg(boundedStart);
    if (seg.kind === 'copy') {
      const o = seg.oStart + (boundedStart - seg.vStart);
      return { oStart: o, oEnd: o };
    }
    return { oStart: seg.oStart, oEnd: seg.oEnd };
  }

  const startSeg = findSeg(boundedStart);
  let oStart: number;
  if (startSeg.kind === 'copy') {
    oStart = startSeg.oStart + (boundedStart - startSeg.vStart);
  } else {
    oStart = startSeg.oStart;
  }

  const endSeg = findSeg(boundedEnd > boundedStart ? boundedEnd - 1 : boundedStart);
  let oEnd: number;
  if (endSeg.kind === 'copy') {
    oEnd = endSeg.oStart + (boundedEnd - endSeg.vStart);
  } else {
    oEnd = endSeg.oEnd;
  }

  return {
    oStart: Math.min(oStart, oEnd),
    oEnd: Math.max(oStart, oEnd),
  };
}

/**
 * Maps a virtual span [vStart, vEnd] to original line and column numbers (1-based)
 * computed directly on originalSource.
 */
export function toOrigLineAndCol(
  originalSource: string,
  spanMap: ReadonlyArray<SpanMapSeg>,
  vStart: number,
  vEnd?: number
): { oStart: number; oEnd: number; line: number; col: number; endLine: number; endCol: number } {
  const { oStart, oEnd } = toOrigSpan(spanMap, vStart, vEnd);

  let line = 1;
  let lineStart = 0;
  for (let i = 0; i < oStart && i < originalSource.length; i++) {
    if (originalSource[i] === '\n') {
      line++;
      lineStart = i + 1;
    }
  }
  const col = oStart - lineStart + 1;

  let endLine = line;
  let endLineStart = lineStart;
  for (let i = oStart; i < oEnd && i < originalSource.length; i++) {
    if (originalSource[i] === '\n') {
      endLine++;
      endLineStart = i + 1;
    }
  }
  const endCol = oEnd - endLineStart + 1;

  return { oStart, oEnd, line, col, endLine, endCol };
}

/**
 * Validates the 4 core SpanMap invariants specified in SPEC.md §5.3.
 */
export function verifySpanMapInvariants(
  originalSource: string,
  virtualText: string,
  spanMap: ReadonlyArray<SpanMapSeg>
): { valid: boolean; error?: string } {
  if (virtualText.length === 0) {
    if (spanMap.length !== 0) {
      return { valid: false, error: 'Empty virtual text must have empty spanMap' };
    }
    return { valid: true };
  }

  if (spanMap.length === 0) {
    return { valid: false, error: 'Non-empty virtual text has empty spanMap' };
  }

  if (spanMap[0].vStart !== 0) {
    return { valid: false, error: `spanMap does not start at 0: got ${spanMap[0].vStart}` };
  }

  if (spanMap[spanMap.length - 1].vEnd !== virtualText.length) {
    return {
      valid: false,
      error: `spanMap does not cover virtualText length ${virtualText.length}: ends at ${spanMap[spanMap.length - 1].vEnd}`,
    };
  }

  for (let k = 0; k < spanMap.length; k++) {
    const seg = spanMap[k];
    if (seg.vStart >= seg.vEnd) {
      return { valid: false, error: `Segment ${k} has vStart >= vEnd: [${seg.vStart}, ${seg.vEnd}]` };
    }
    if (seg.oStart >= seg.oEnd) {
      return { valid: false, error: `Segment ${k} has oStart >= oEnd: [${seg.oStart}, ${seg.oEnd}]` };
    }
    if (seg.oStart < 0 || seg.oEnd > originalSource.length) {
      return {
        valid: false,
        error: `Segment ${k} oRange [${seg.oStart}, ${seg.oEnd}] out of bounds of originalSource length ${originalSource.length}`,
      };
    }
    if (k > 0 && seg.vStart !== spanMap[k - 1].vEnd) {
      return {
        valid: false,
        error: `Gap or overlap between segment ${k - 1} end ${spanMap[k - 1].vEnd} and segment ${k} start ${seg.vStart}`,
      };
    }
    if (seg.kind === 'copy') {
      if (seg.vEnd - seg.vStart !== seg.oEnd - seg.oStart) {
        return {
          valid: false,
          error: `Copy segment ${k} has mismatched lengths: vLen ${seg.vEnd - seg.vStart} !== oLen ${seg.oEnd - seg.oStart}`,
        };
      }
      for (let i = seg.vStart; i < seg.vEnd; i++) {
        const mapped = toOrigSpan(spanMap, i, i + 1);
        if (virtualText[i] !== originalSource[mapped.oStart]) {
          return {
            valid: false,
            error: `Copy segment character mismatch at vIdx ${i} ('${virtualText[i]}' !== '${originalSource[mapped.oStart]}')`,
          };
        }
      }
    }
  }

  // Monotonicity check across sampled points
  const checkPoints: number[] = [0];
  for (const seg of spanMap) {
    checkPoints.push(seg.vStart, Math.floor((seg.vStart + seg.vEnd) / 2), seg.vEnd);
  }
  checkPoints.sort((a, b) => a - b);
  for (let idx = 1; idx < checkPoints.length; idx++) {
    const p1 = checkPoints[idx - 1];
    const p2 = checkPoints[idx];
    const m1 = toOrigSpan(spanMap, p1);
    const m2 = toOrigSpan(spanMap, p2);
    if (m1.oStart > m2.oStart || m1.oEnd > m2.oEnd) {
      return {
        valid: false,
        error: `Monotonicity violation between ${p1} (oStart=${m1.oStart}, oEnd=${m1.oEnd}) and ${p2} (oStart=${m2.oStart}, oEnd=${m2.oEnd})`,
      };
    }
  }

  return { valid: true };
}

function collectFold03Edits(
  source: string,
  _maskedCode: string,
  stringLiterals: ReadonlyArray<ExtractedStringLiteral>,
  regions: ReadonlyArray<LexicalRegion>
): { edits: FoldTextEdit[]; limitFlag: boolean } {
  if (stringLiterals.length === 0 || !source.includes('`')) return { edits: [], limitFlag: false };
  const edits: FoldTextEdit[] = [];
  let limitFlag = false;

  for (const lit of stringLiterals) {
    if (lit.quote !== '`') continue;
    if (lit.hasInterpolation) continue;

    const raw = source.slice(lit.startOffset, lit.endOffset);
    if (!isSafeLiteral(raw, lit.value)) continue;
    if (overlapsCommentOrRegex(lit.startOffset, lit.endOffset, regions)) continue;

    // Check region kind: must be template region
    if (!isInTemplateRegion(lit.startOffset, lit.endOffset, regions)) continue;

    // Guard: not a tagged template (token before ` cannot be identifier, ), ], or literal quote)
    let prevIdx = lit.startOffset - 1;
    while (prevIdx >= 0 && /\s/.test(source[prevIdx])) prevIdx--;
    if (prevIdx >= 0) {
      const prevCh = source[prevIdx];
      if (
        /[A-Za-z0-9_$]/.test(prevCh) ||
        prevCh === ')' ||
        prevCh === ']' ||
        prevCh === "'" ||
        prevCh === '"' ||
        prevCh === '`'
      ) {
        continue;
      }
    }

    const val = lit.value;
    if (val.length > MAX_FOLDED_LENGTH) {
      limitFlag = true;
      continue;
    }

    let chosenQuote = '"';
    if (val.includes('"')) {
      if (val.includes("'")) {
        continue; // Contains both " and ', cannot fold without escape
      }
      chosenQuote = "'";
    }

    edits.push({
      start: lit.startOffset,
      end: lit.endOffset,
      replacement: chosenQuote + val + chosenQuote,
    });
  }

  return { edits, limitFlag };
}

function collectFold01Edits(
  source: string,
  maskedCode: string,
  stringLiterals: ReadonlyArray<ExtractedStringLiteral>,
  regions: ReadonlyArray<LexicalRegion>
): { edits: FoldTextEdit[]; limitFlag: boolean } {
  if (stringLiterals.length < 2 || !maskedCode.includes('+')) return { edits: [], limitFlag: false };
  const edits: FoldTextEdit[] = [];
  let limitFlag = false;

  const safeLiterals = stringLiterals.filter((lit) => {
    if (lit.quote !== "'" && lit.quote !== '"') return false;
    const raw = source.slice(lit.startOffset, lit.endOffset);
    if (!isSafeLiteral(raw, lit.value)) return false;
    if (overlapsCommentOrRegex(lit.startOffset, lit.endOffset, regions)) return false;
    return true;
  });

  const chains: ExtractedStringLiteral[][] = [];
  let i = 0;
  while (i < safeLiterals.length) {
    const currentChain: ExtractedStringLiteral[] = [safeLiterals[i]];
    let j = i + 1;
    while (j < safeLiterals.length) {
      const prev = currentChain[currentChain.length - 1];
      const next = safeLiterals[j];
      const gap = source.slice(prev.endOffset, next.startOffset);
      if (/^\s*\+\s*$/.test(gap)) {
        const plusIdx = prev.endOffset + gap.indexOf('+');
        if (!overlapsCommentOrRegex(plusIdx, plusIdx + 1, regions)) {
          currentChain.push(next);
          j++;
          continue;
        }
      }
      break;
    }
    if (currentChain.length >= 2) {
      chains.push(currentChain);
      i = j;
    } else {
      i++;
    }
  }

  for (const chain of chains) {
    if (chain.length > MAX_FOLD_OPERANDS) {
      limitFlag = true;
      continue;
    }

    const combined = chain.map((l) => l.value).join('');
    if (combined.length > MAX_FOLDED_LENGTH) {
      limitFlag = true;
      continue;
    }

    const L1 = chain[0];
    const Ln = chain[chain.length - 1];

    // Guard Token Before L1
    let idx = L1.startOffset - 1;
    while (idx >= 0 && /\s/.test(maskedCode[idx])) idx--;
    if (idx >= 0) {
      if (/[A-Za-z0-9_$]/.test(maskedCode[idx])) {
        let wStart = idx;
        while (wStart > 0 && /[A-Za-z0-9_$]/.test(maskedCode[wStart - 1])) wStart--;
        const word = maskedCode.slice(wStart, idx + 1);
        if (word !== 'return') {
          continue;
        }
      } else if (maskedCode[idx] === '+') {
        if (idx > 0 && maskedCode[idx - 1] === '+') continue;
        let pIdx = idx - 1;
        while (pIdx >= 0 && /\s/.test(maskedCode[pIdx])) pIdx--;
        if (pIdx < 0) continue; // Unary +
        const prevCh = maskedCode[pIdx];
        if (prevCh === ']') {
          // Binary +
        } else if (prevCh === ')') {
          let depth = 1;
          let matchP = -1;
          const maxB = Math.max(0, pIdx - MAX_BACKSCAN);
          for (let b = pIdx - 1; b >= maxB; b--) {
            if (maskedCode[b] === ')') depth++;
            else if (maskedCode[b] === '(') {
              depth--;
              if (depth === 0) { matchP = b; break; }
            }
          }
          if (matchP === -1) {
            limitFlag = true;
            continue;
          }
          let bp = matchP - 1;
          while (bp >= 0 && /\s/.test(maskedCode[bp])) bp--;
          if (bp >= 0 && /[A-Za-z0-9_$]/.test(maskedCode[bp])) {
            let cpStart = bp;
            while (cpStart > 0 && /[A-Za-z0-9_$]/.test(maskedCode[cpStart - 1])) cpStart--;
            const cpWord = maskedCode.slice(cpStart, bp + 1);
            if (CONTROL_KEYWORDS.has(cpWord)) {
              continue; // Unary + after control header
            }
          }
        } else if (prevCh === "'" || prevCh === '"' || prevCh === '`') {
          // Binary + after literal
        } else if (/[A-Za-z0-9_$]/.test(prevCh)) {
          let pwStart = pIdx;
          while (pwStart > 0 && /[A-Za-z0-9_$]/.test(maskedCode[pwStart - 1])) pwStart--;
          const pwWord = maskedCode.slice(pwStart, pIdx + 1);
          if (FOLD04_REJECTED_KEYWORDS.has(pwWord)) {
            continue; // Unary + after keyword
          }
        } else {
          continue; // Unary + after operator/delimiter
        }
      } else {
        const ch = maskedCode[idx];
        if (ch === '-' || ch === '*' || ch === '/' || ch === '%' || ch === '!' || ch === '~') {
          continue;
        }
        if (ch === '.') {
          if (idx >= 2 && maskedCode[idx - 1] === '.' && maskedCode[idx - 2] === '.') {
            // Spread ...
          } else {
            continue;
          }
        } else if (ch === '?') {
          if (idx > 0 && maskedCode[idx - 1] === '.') continue;
        } else if (ch === '(' || ch === '[' || ch === '{' || ch === ',' || ch === ';' || ch === ':') {
          // Allowed delimiter
        } else if (ch === '=' || ch === '<' || ch === '>' || ch === '&' || ch === '|' || ch === '^') {
          // Allowed lower precedence operator
        } else {
          continue;
        }
      }
    }

    // Guard Token After Ln
    let afterIdx = Ln.endOffset;
    while (afterIdx < maskedCode.length && /\s/.test(maskedCode[afterIdx])) afterIdx++;
    if (afterIdx < maskedCode.length) {
      const nextChar = maskedCode[afterIdx];
      if (
        nextChar === '.' ||
        (nextChar === '?' && maskedCode[afterIdx + 1] === '.') ||
        nextChar === '[' ||
        nextChar === '(' ||
        nextChar === '`' ||
        nextChar === '*' ||
        nextChar === '/' ||
        nextChar === '%'
      ) {
        continue;
      }
    }

    const quote = L1.quote;
    if (combined.includes(quote)) continue;

    edits.push({
      start: L1.startOffset,
      end: Ln.endOffset,
      replacement: quote + combined + quote,
    });
  }

  return { edits, limitFlag };
}

function collectFold02Edits(
  source: string,
  maskedCode: string,
  stringLiterals: ReadonlyArray<ExtractedStringLiteral>,
  regions: ReadonlyArray<LexicalRegion>
): { edits: FoldTextEdit[]; limitFlag: boolean } {
  if (stringLiterals.length === 0 || !maskedCode.includes('[') || !maskedCode.includes('join')) {
    return { edits: [], limitFlag: false };
  }
  const edits: FoldTextEdit[] = [];
  let limitFlag = false;

  let pos = 0;
  while (pos < source.length) {
    const openBracketIdx = source.indexOf('[', pos);
    if (openBracketIdx === -1) break;
    pos = openBracketIdx + 1;

    if (overlapsCommentOrRegex(openBracketIdx, openBracketIdx + 1, regions)) continue;

    // Guard Posisi [: token before [ cannot be identifier non-keyword, ), ], or ?.
    let idx = openBracketIdx - 1;
    while (idx >= 0 && /\s/.test(maskedCode[idx])) idx--;
    if (idx >= 0) {
      const prevCh = maskedCode[idx];
      if (prevCh === ')' || prevCh === ']') continue;
      if (prevCh === '.' && idx > 0 && maskedCode[idx - 1] === '?') continue;
      if (/[A-Za-z0-9_$]/.test(prevCh)) {
        let wStart = idx;
        while (wStart > 0 && /[A-Za-z0-9_$]/.test(maskedCode[wStart - 1])) wStart--;
        const word = maskedCode.slice(wStart, idx + 1);
        if (!FOLD04_REJECTED_KEYWORDS.has(word)) {
          continue;
        }
      }
    }

    const closeBracketIdx = source.indexOf(']', openBracketIdx + 1);
    if (closeBracketIdx === -1 || overlapsCommentOrRegex(closeBracketIdx, closeBracketIdx + 1, regions)) continue;

    const innerText = source.slice(openBracketIdx + 1, closeBracketIdx);
    if (innerText.includes('[') || innerText.includes('{') || innerText.includes('(')) continue;

    const lits = findLiteralsInRange(stringLiterals, openBracketIdx + 1, closeBracketIdx);
    if (lits.length === 0) continue;
    if (lits.length > MAX_FOLD_OPERANDS) {
      limitFlag = true;
      continue;
    }

    const allSafe = lits.every(
      (l) =>
        (l.quote === "'" || l.quote === '"') &&
        isSafeLiteral(source.slice(l.startOffset, l.endOffset), l.value)
    );
    if (!allSafe) continue;

    if (source.slice(openBracketIdx + 1, lits[0].startOffset).trim() !== '') continue;
    let validCommas = true;
    for (let k = 0; k < lits.length - 1; k++) {
      const gap = source.slice(lits[k].endOffset, lits[k + 1].startOffset);
      if (!/^\s*,\s*$/.test(gap)) {
        validCommas = false;
        break;
      }
    }
    if (!validCommas) continue;
    if (source.slice(lits[lits.length - 1].endOffset, closeBracketIdx).trim() !== '') continue;

    // After ]: must be followed by .join(
    let afterIdx = closeBracketIdx + 1;
    while (afterIdx < maskedCode.length && /\s/.test(maskedCode[afterIdx])) afterIdx++;
    if (maskedCode[afterIdx] !== '.') continue;
    afterIdx++;
    while (afterIdx < maskedCode.length && /\s/.test(maskedCode[afterIdx])) afterIdx++;
    if (maskedCode.slice(afterIdx, afterIdx + 4) !== 'join') continue;
    afterIdx += 4;
    while (afterIdx < maskedCode.length && /\s/.test(maskedCode[afterIdx])) afterIdx++;
    if (maskedCode[afterIdx] !== '(') continue;
    const openParenIdx = afterIdx;

    const closeParenIdx = maskedCode.indexOf(')', openParenIdx + 1);
    if (closeParenIdx === -1) continue;

    const arg = source.slice(openParenIdx + 1, closeParenIdx).trim();
    let separator = ',';
    if (arg !== '') {
      const argLits = findLiteralsInRange(stringLiterals, openParenIdx + 1, closeParenIdx);
      if (argLits.length !== 1) continue;
      const argLit = argLits[0];
      if (source.slice(argLit.startOffset, argLit.endOffset) !== arg) continue;
      if (!isSafeLiteral(arg, argLit.value)) continue;
      separator = argLit.value;
    }

    const joined = lits.map((l) => l.value).join(separator);
    if (joined.length > MAX_FOLDED_LENGTH) {
      limitFlag = true;
      continue;
    }
    const quote = lits[0].quote;
    if (joined.includes(quote)) continue;

    edits.push({
      start: openBracketIdx,
      end: closeParenIdx + 1,
      replacement: quote + joined + quote,
    });
  }

  return { edits, limitFlag };
}

function collectFold04Edits(
  source: string,
  maskedCode: string,
  stringLiterals: ReadonlyArray<ExtractedStringLiteral>,
  regions: ReadonlyArray<LexicalRegion>
): { edits: FoldTextEdit[]; limitFlag: boolean } {
  if (stringLiterals.length === 0 || !maskedCode.includes('[')) return { edits: [], limitFlag: false };
  const edits: FoldTextEdit[] = [];
  let limitFlag = false;

  let pos = 0;
  while (pos < source.length) {
    const openBracketIdx = source.indexOf('[', pos);
    if (openBracketIdx === -1) break;
    pos = openBracketIdx + 1;

    if (overlapsCommentOrRegex(openBracketIdx, openBracketIdx + 1, regions)) continue;

    let idx = openBracketIdx - 1;
    while (idx >= 0 && /\s/.test(maskedCode[idx])) idx--;
    if (idx < 0) continue;

    let hasOptChain = false;
    let optChainStart = -1;
    let tokenEnd = idx;

    if (idx > 0 && maskedCode[idx] === '.' && maskedCode[idx - 1] === '?') {
      hasOptChain = true;
      optChainStart = idx - 1;
      tokenEnd = idx - 2;
      while (tokenEnd >= 0 && /\s/.test(maskedCode[tokenEnd])) tokenEnd--;
      if (tokenEnd < 0) continue;
    }

    const ch = maskedCode[tokenEnd];
    if (ch === '}' || /[0-9]/.test(ch) || ch === "'" || ch === '"' || ch === '`') {
      continue;
    }

    if (ch === ']') {
      // Allowed member access
    } else if (ch === ')') {
      let depth = 1;
      let matchParen = -1;
      const maxB = Math.max(0, tokenEnd - MAX_BACKSCAN);
      for (let b = tokenEnd - 1; b >= maxB; b--) {
        if (maskedCode[b] === ')') depth++;
        else if (maskedCode[b] === '(') {
          depth--;
          if (depth === 0) {
            matchParen = b;
            break;
          }
        }
      }
      if (matchParen === -1) {
        limitFlag = true;
        continue;
      }
      let bp = matchParen - 1;
      while (bp >= 0 && /\s/.test(maskedCode[bp])) bp--;
      if (bp >= 0 && /[A-Za-z0-9_$]/.test(maskedCode[bp])) {
        let cpStart = bp;
        while (cpStart > 0 && /[A-Za-z0-9_$]/.test(maskedCode[cpStart - 1])) cpStart--;
        const cpWord = maskedCode.slice(cpStart, bp + 1);
        if (CONTROL_KEYWORDS.has(cpWord)) {
          continue;
        }
      }
    } else if (/[A-Za-z_$]/.test(ch)) {
      let idStart = tokenEnd;
      while (idStart > 0 && /[A-Za-z0-9_$]/.test(maskedCode[idStart - 1])) idStart--;
      const idWord = maskedCode.slice(idStart, tokenEnd + 1);
      if (!ASCII_IDENT_RE.test(idWord) || FOLD04_REJECTED_KEYWORDS.has(idWord)) {
        continue;
      }
    } else {
      continue;
    }

    const closeBracketIdx = source.indexOf(']', openBracketIdx + 1);
    if (closeBracketIdx === -1) continue;

    const inner = source.slice(openBracketIdx + 1, closeBracketIdx).trim();
    const innerLits = findLiteralsInRange(stringLiterals, openBracketIdx + 1, closeBracketIdx);
    if (innerLits.length !== 1) continue;
    const propLit = innerLits[0];
    if (source.slice(propLit.startOffset, propLit.endOffset) !== inner) continue;
    if (propLit.quote !== "'" && propLit.quote !== '"') continue;
    if (!isSafeLiteral(inner, propLit.value)) continue;
    if (!ASCII_IDENT_RE.test(propLit.value)) continue;

    const editStart = hasOptChain ? optChainStart : openBracketIdx;
    const rep = (hasOptChain ? '?.' : '.') + propLit.value;
    edits.push({
      start: editStart,
      end: closeBracketIdx + 1,
      replacement: rep,
    });
  }

  return { edits, limitFlag };
}

const HIGH_PRIORITY_FOLD_CONTEXT_RE =
  /\b(?:eval|exec|Function|system|import|require|fetch|catch|globalThis|window|global|self|child_process|payment|balance|wallet|ledger|transfer|charge|refund|deduct|invoice|auth|token|jwt|password|execute|query|transaction|writeFileSync|saldo|stock|credits|secret|api_key|apikey)\b|sk[_-]|pk[_-]|rk[_-]|AIza|gh[pousr]_|github_pat_|AKIA|ASIA|xox[baprs]-|eyJ|-----BEGIN/i;

export function isHighPriorityFoldEdit(
  _currentCode: string,
  maskedCode: string,
  edit: FoldTextEdit
): boolean {
  if (edit.replacement.startsWith('.') || edit.replacement.startsWith('?.')) {
    return true;
  }

  // Strictly match `[ <expr> ]` only when immediate non-whitespace tokens in maskedCode wrap [edit.start, edit.end)
  let prevIdx = edit.start - 1;
  while (prevIdx >= 0 && /[ \t\r\n]/.test(maskedCode[prevIdx])) prevIdx--;
  let nextIdx = edit.end;
  while (nextIdx < maskedCode.length && /[ \t\r\n]/.test(maskedCode[nextIdx])) nextIdx++;
  if (prevIdx >= 0 && nextIdx < maskedCode.length && maskedCode[prevIdx] === '[' && maskedCode[nextIdx] === ']') {
    return true;
  }

  const beforeStart = Math.max(0, edit.start - 64);
  const afterEnd = Math.min(maskedCode.length, edit.end + 64);
  const rawBefore = maskedCode.slice(beforeStart, edit.start);
  const rawAfter = maskedCode.slice(edit.end, afterEnd);

  // Clip context window at statement/block delimiters so adjacent statements never leak keywords
  const lastBoundaryBefore = Math.max(
    rawBefore.lastIndexOf(';'),
    rawBefore.lastIndexOf('{'),
    rawBefore.lastIndexOf('}')
  );
  const beforeMasked = lastBoundaryBefore >= 0 ? rawBefore.slice(lastBoundaryBefore + 1) : rawBefore;

  let firstBoundaryAfter = rawAfter.length;
  for (let i = 0; i < rawAfter.length; i++) {
    const ch = rawAfter[i];
    if (ch === ';' || ch === '{' || ch === '}') {
      firstBoundaryAfter = i;
      break;
    }
  }
  const afterMasked = rawAfter.slice(0, firstBoundaryAfter);

  return (
    HIGH_PRIORITY_FOLD_CONTEXT_RE.test(edit.replacement) ||
    HIGH_PRIORITY_FOLD_CONTEXT_RE.test(beforeMasked) ||
    HIGH_PRIORITY_FOLD_CONTEXT_RE.test(afterMasked)
  );
}

function selectWithHeadTailStride(items: FoldTextEdit[], budget: number): FoldTextEdit[] {
  if (items.length <= budget || budget <= 0) {
    return budget <= 0 ? [] : items;
  }
  const tailBudget = Math.min(Math.max(16, Math.floor(budget / 4)), items.length);
  const headAndMidBudget = budget - tailBudget;
  const tailStart = items.length - tailBudget;
  const selected: FoldTextEdit[] = [];

  if (headAndMidBudget > 0 && tailStart > 0) {
    const headCount = Math.min(headAndMidBudget, Math.max(1, Math.floor(headAndMidBudget / 2)));
    for (let i = 0; i < headCount; i++) {
      selected.push(items[i]);
    }
    const midBudget = headAndMidBudget - headCount;
    const midSpan = tailStart - headCount;
    if (midBudget > 0 && midSpan > 0) {
      const step = midSpan / midBudget;
      for (let k = 0; k < midBudget; k++) {
        const idx = headCount + Math.min(midSpan - 1, Math.floor(k * step));
        selected.push(items[idx]);
      }
    }
  }
  for (let i = tailStart; i < items.length; i++) {
    selected.push(items[i]);
  }
  return selected;
}

function selectPrioritizedEdits(
  currentCode: string,
  maskedCode: string,
  edits: FoldTextEdit[],
  budget: number
): FoldTextEdit[] {
  if (edits.length <= budget || budget <= 0) {
    return budget <= 0 ? [] : edits;
  }

  const highPriority: FoldTextEdit[] = [];
  const lowPriority: FoldTextEdit[] = [];

  for (const edit of edits) {
    if (isHighPriorityFoldEdit(currentCode, maskedCode, edit)) {
      highPriority.push(edit);
    } else {
      lowPriority.push(edit);
    }
  }

  const chosenHigh =
    highPriority.length <= budget
      ? highPriority
      : selectWithHeadTailStride(highPriority, budget);

  const remBudget = budget - chosenHigh.length;
  let chosenLow: FoldTextEdit[] = [];
  if (remBudget > 0 && lowPriority.length > 0) {
    if (lowPriority.length <= remBudget) {
      chosenLow = lowPriority;
    } else {
      const tailReserve = Math.min(128, Math.floor(remBudget / 2), lowPriority.length);
      const headBudget = remBudget - tailReserve;
      const tailStart = lowPriority.length - tailReserve;
      for (let i = 0; i < headBudget && i < tailStart; i++) {
        chosenLow.push(lowPriority[i]);
      }
      for (let i = tailStart; i < lowPriority.length; i++) {
        chosenLow.push(lowPriority[i]);
      }
    }
  }

  return [...chosenHigh, ...chosenLow].sort((a, b) => a.start - b.start);
}

/**
 * Builds the virtual view pipeline. In Stage 5.3b, constant folding FOLD-03/01/02/04
 * is executed iteratively up to MAX_FOLD_DEPTH passes within deterministic bounds.
 */
export function buildVirtualView(
  originalSource: string,
  options?: { isPython?: boolean; initialLex?: ReturnType<typeof analyzeLexicalStructure> }
): VirtualViewResult {
  if (typeof originalSource !== 'string') throw new TypeError('originalSource must be a string');
  if (originalSource.length === 0 || options?.isPython) {
    return {
      virtualCode: originalSource,
      spanMap: createIdentitySpanMap(originalSource.length),
      editsApplied: 0,
      limitExceeded: false,
    };
  }

  try {
    let currentCode = originalSource;
    let currentSpanMap = createIdentitySpanMap(originalSource.length);
    let totalEdits = 0;
    let limitExceeded = false;
    let currentLex = options?.initialLex ?? analyzeLexicalStructure(currentCode, false);
    if (currentLex.stringLiterals.length === 0) {
      return {
        virtualCode: originalSource,
        spanMap: currentSpanMap,
        editsApplied: 0,
        limitExceeded: false,
      };
    }

    for (let depth = 0; depth < MAX_FOLD_DEPTH; depth++) {
      let editsInPass = 0;

      const foldOps = [
        collectFold03Edits,
        collectFold01Edits,
        collectFold02Edits,
        collectFold04Edits,
      ];

      for (const foldOp of foldOps) {
        if (totalEdits >= MAX_FOLD_EDITS) {
          limitExceeded = true;
          break;
        }

        const { edits, limitFlag } = foldOp(
          currentCode,
          currentLex.maskedCode,
          currentLex.stringLiterals,
          currentLex.regions
        );
        if (limitFlag) {
          limitExceeded = true;
        }
        if (edits.length === 0) continue;

        const remainingBudget = MAX_FOLD_EDITS - totalEdits;
        let opBudget = remainingBudget;
        const hasDownstreamFoldTokens = /(?:\.join\s*\(|\[)/.test(currentCode);
        if (
          foldOp === collectFold03Edits &&
          edits.length > 1000 &&
          /(?:\+|\.join\s*\(|\[)/.test(currentCode)
        ) {
          const highPriorityCount = edits.filter((e) =>
            isHighPriorityFoldEdit(currentCode, currentLex.maskedCode, e)
          ).length;
          opBudget = Math.min(remainingBudget, Math.max(1000, highPriorityCount));
        } else if (
          foldOp !== collectFold04Edits &&
          edits.length > remainingBudget &&
          hasDownstreamFoldTokens
        ) {
          const highPriorityCount = edits.filter((e) =>
            isHighPriorityFoldEdit(currentCode, currentLex.maskedCode, e)
          ).length;
          // Reserve slots so downstream FOLD-02 / FOLD-04 passes cannot be starved by earlier spam
          const reserveForDownstream = Math.min(512, Math.floor(remainingBudget / 4));
          opBudget = Math.min(
            remainingBudget,
            Math.max(remainingBudget - reserveForDownstream, highPriorityCount)
          );
        }

        let toApply = edits;
        if (toApply.length > opBudget) {
          toApply = selectPrioritizedEdits(currentCode, currentLex.maskedCode, toApply, opBudget);
          limitExceeded = true;
        } else if (opBudget < edits.length) {
          limitExceeded = true;
        }
        if (toApply.length === 0) break;

        const applied = applyTextEditsWithSpanMap(currentCode, toApply);
        if (applied.appliedCount > 0) {
          currentCode = applied.virtualText;
          currentSpanMap = composeSpanMaps(currentSpanMap, applied.spanMap);
          totalEdits += applied.appliedCount;
          editsInPass += applied.appliedCount;
          currentLex = analyzeLexicalStructure(currentCode, false);
        }
      }

      if (editsInPass === 0 || totalEdits >= MAX_FOLD_EDITS) {
        break;
      }
    }

    return {
      virtualCode: currentCode,
      spanMap: currentSpanMap,
      editsApplied: totalEdits,
      limitExceeded,
    };
  } catch {
    return {
      virtualCode: originalSource,
      spanMap: createIdentitySpanMap(originalSource.length),
      editsApplied: 0,
      limitExceeded: false,
    };
  }
}
