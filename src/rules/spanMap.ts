import type { LexicalRegion } from './lexicalMasker.js';
import { isRangeStrictlyInCodeRegion } from './lexicalMasker.js';

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

    // Find all segments in prevMap that overlap with [v1Start, v1End)
    const overlapping = prevMap.filter(
      (p) => Math.max(v1Start, p.vStart) < Math.min(v1End, p.vEnd)
    );

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

/**
 * Builds the virtual view pipeline. In Stage 5.3a, 0 folds are active (virtualCode === originalSource, editsApplied === 0).
 */
export function buildVirtualView(
  originalSource: string,
  _options?: { isPython?: boolean }
): VirtualViewResult {
  try {
    return {
      virtualCode: originalSource,
      spanMap: createIdentitySpanMap(originalSource.length),
      editsApplied: 0,
      limitExceeded: false,
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
