import test from 'node:test';
import assert from 'node:assert/strict';
import { performance } from 'node:perf_hooks';
import {
  analyzeLexicalStructure,
  isRangeStrictlyInCodeRegion,
} from '../src/core/rules/lexicalMasker.js';

const FUZZ_SEED = 0xd37c0d39;
const FUZZ_CASE_COUNT = 1000;

/** Deterministic Mulberry32 PRNG (zero external dependencies). */
function createMulberry32(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

function buildLineTable(rawCode: string): Int32Array {
  const table = new Int32Array(rawCode.length + 1);
  let line = 1;
  for (let i = 0; i < rawCode.length; i++) {
    table[i] = line;
    if (rawCode[i] === '\n') line++;
  }
  table[rawCode.length] = line;
  return table;
}

/**
 * Verifies all mandatory Stage 9.1 property invariants on a single input:
 * 1. Length Preservation: maskedCode.length === rawCode.length
 * 2. Newline Preservation: every '\n' index matches identically
 * 3. Region Integrity: contiguous, sorted, non-overlapping, covering [0, rawCode.length]
 * 4. Masking Consistency: code regions match rawCode, non-code regions mask non-'\n' to ' '
 * 5. StringLiteral Offset & Line Accuracy
 * 6. Determinism & No-Throw
 */
function assertMaskerInvariants(
  rawCode: string,
  allowHashComments: boolean,
  label: string
): ReturnType<typeof analyzeLexicalStructure> {
  const res1 = analyzeLexicalStructure(rawCode, allowHashComments);
  const res2 = analyzeLexicalStructure(rawCode, allowHashComments);

  // Determinism
  assert.equal(res1.maskedCode, res2.maskedCode, `${label}: maskedCode must be deterministic`);
  assert.deepEqual(res1.regions, res2.regions, `${label}: regions must be deterministic`);
  assert.deepEqual(
    res1.stringLiterals,
    res2.stringLiterals,
    `${label}: stringLiterals must be deterministic`
  );
  assert.deepEqual(
    res1.suppressions,
    res2.suppressions,
    `${label}: suppressions must be deterministic`
  );

  // 1. Length Preservation
  assert.equal(
    res1.maskedCode.length,
    rawCode.length,
    `${label}: maskedCode.length (${res1.maskedCode.length}) !== rawCode.length (${rawCode.length})`
  );

  // 2. Newline Preservation
  for (let i = 0; i < rawCode.length; i++) {
    const rawIsNl = rawCode[i] === '\n';
    const maskedIsNl = res1.maskedCode[i] === '\n';
    assert.equal(
      maskedIsNl,
      rawIsNl,
      `${label}: newline mismatch at offset ${i} (raw=${JSON.stringify(rawCode[i])}, masked=${JSON.stringify(res1.maskedCode[i])})`
    );
  }

  // 3. Region Integrity
  if (rawCode.length === 0) {
    assert.equal(res1.regions.length, 0, `${label}: empty input must produce 0 regions`);
  } else {
    assert.ok(res1.regions.length > 0, `${label}: non-empty input must produce >= 1 region`);
    assert.equal(res1.regions[0].start, 0, `${label}: first region must start at 0`);
    assert.equal(
      res1.regions[res1.regions.length - 1].end,
      rawCode.length,
      `${label}: last region must end at rawCode.length`
    );

    for (let rIdx = 0; rIdx < res1.regions.length; rIdx++) {
      const reg = res1.regions[rIdx];
      assert.ok(
        reg.start >= 0 && reg.start < reg.end && reg.end <= rawCode.length,
        `${label}: invalid region bounds [${reg.start}, ${reg.end}) for length ${rawCode.length}`
      );
      if (rIdx > 0) {
        const prev = res1.regions[rIdx - 1];
        assert.equal(
          reg.start,
          prev.end,
          `${label}: region ${rIdx} start (${reg.start}) !== prev end (${prev.end})`
        );
        assert.notEqual(
          reg.kind,
          prev.kind,
          `${label}: adjacent regions ${rIdx - 1} and ${rIdx} with same kind "${reg.kind}" must coalesce`
        );
      }

      // 4. Masking Consistency
      if (reg.kind === 'code') {
        assert.equal(
          res1.maskedCode.slice(reg.start, reg.end),
          rawCode.slice(reg.start, reg.end),
          `${label}: code region [${reg.start}, ${reg.end}) must match rawCode verbatim`
        );
      } else {
        for (let k = reg.start; k < reg.end; k++) {
          if (rawCode[k] !== '\n') {
            assert.equal(
              res1.maskedCode[k],
              ' ',
              `${label}: non-code region (${reg.kind}) must mask char at ${k} to space`
            );
          }
        }
      }
    }
  }

  // 5. StringLiteral Offset & Line Accuracy (O(N) precomputed line table)
  if (res1.stringLiterals.length > 0) {
    const lineTable = buildLineTable(rawCode);
    for (let sIdx = 0; sIdx < res1.stringLiterals.length; sIdx++) {
      const lit = res1.stringLiterals[sIdx];
      assert.ok(
        lit.startOffset >= 0 && lit.startOffset < lit.endOffset && lit.endOffset <= rawCode.length,
        `${label}: stringLiteral[${sIdx}] invalid offsets [${lit.startOffset}, ${lit.endOffset})`
      );
      const expectedStartLine = lineTable[lit.startOffset];
      assert.equal(
        lit.line,
        expectedStartLine,
        `${label}: stringLiteral[${sIdx}] line ${lit.line} !== expected ${expectedStartLine} at offset ${lit.startOffset}`
      );
      assert.ok(
        lit.endLine >= lit.line,
        `${label}: stringLiteral[${sIdx}] endLine (${lit.endLine}) < line (${lit.line})`
      );
    }
  }

  return res1;
}

const FUZZ_TOKENS: ReadonlyArray<string> = [
  'const ',
  'let ',
  'return ',
  'if ',
  'else ',
  'eval(x)',
  'fn()',
  'arr[0]',
  'a',
  'b',
  'x++',
  'y--',
  ' = ',
  ' + ',
  ' / ',
  '/',
  '\\/',
  '// line comment',
  '/* block */',
  '/* multi\nline */',
  '/*',
  '*/',
  '"str"',
  '"esc\\""',
  '"unclosed',
  "'single'",
  "'esc\\''",
  "'unclosed",
  '`tpl`',
  '`outer ${',
  '}`',
  '${',
  '{',
  '}',
  '(',
  ')',
  '[',
  ']',
  ';',
  '\n',
  ' ',
  '\t',
  '/a\\/b[c/d]/gi',
  '/[a/b]/',
  '/unclosed',
  '<div>',
  '</div>',
  '<span title="a\'b">',
  '</span>',
  "don't",
  "can't",
  '<Input a={1} />',
  '{/* jsx comment */}',
  '# hash comment',
  '🚀',
  '👨‍👩‍👧‍👦',
  '\\',
  '\\n',
];

function generateFuzzCase(rng: () => number, idx: number): { code: string; allowHash: boolean } {
  const allowHash = idx % 7 === 0;
  const tokenCount = 5 + Math.floor(rng() * 45);
  const parts: string[] = [];

  for (let i = 0; i < tokenCount; i++) {
    if (rng() < 0.12) {
      // Inject hostile raw characters including quotes, slashes, braces, backticks, backslashes
      const hostileChars = '`\'"/\\${}[]()<>/*\n\r\t#🚀';
      const len = 1 + Math.floor(rng() * 6);
      let chunk = '';
      for (let c = 0; c < len; c++) {
        chunk += hostileChars[Math.floor(rng() * hostileChars.length)];
      }
      parts.push(chunk);
    } else {
      parts.push(FUZZ_TOKENS[Math.floor(rng() * FUZZ_TOKENS.length)]);
    }
  }
  return { code: parts.join(''), allowHash };
}

test('Stage 9.1 (A): Adversarial Nested Template Literals', () => {
  const cases: Array<{ name: string; code: string; innerTextMustBeMasked?: string }> = [
    {
      name: '3-level nested template literal',
      code: 'const s = `a ${`b ${x + `c`}`} d`; const sentinel = eval(y);',
      innerTextMustBeMasked: 'b ${x',
    },
    {
      name: '2-level nested template literal',
      code: 'const s = `a ${`b ${x}`} d`; const sentinel = eval(y);',
      innerTextMustBeMasked: ' d',
    },
    {
      name: 'object braces + inner string containing backtick inside ${...}',
      code: 'const s = `a ${ (() => { const o = { k: "`" }; return `${o.k}`; })() } d`; const sentinel = eval(y);',
      innerTextMustBeMasked: ' d',
    },
    {
      name: 'block and line comments containing backticks inside ${...}',
      code: 'const s = `a ${ /* ` fake */ 1 + // ` also fake\n 2 } d`; const sentinel = eval(y);',
      innerTextMustBeMasked: ' d',
    },
    {
      name: 'regex literal containing backtick inside ${...}',
      code: 'const s = `a ${ /`/g.test(x) } d`; const sentinel = eval(y);',
      innerTextMustBeMasked: ' d',
    },
    {
      name: 'escaped dollar-brace inside template literal',
      code: 'const s = `escaped \\${notInterp} end`; const sentinel = eval(y);',
      innerTextMustBeMasked: 'notInterp',
    },
  ];

  for (const tc of cases) {
    const res = assertMaskerInvariants(tc.code, false, tc.name);
    const evalIdx = tc.code.indexOf('eval(y)');
    assert.ok(evalIdx >= 0);
    assert.equal(
      isRangeStrictlyInCodeRegion(res.regions, evalIdx, evalIdx + 'eval(y)'.length),
      true,
      `${tc.name}: eval(y) after nested template must remain strictly in code region`
    );
    assert.ok(
      res.maskedCode.includes('eval(y)'),
      `${tc.name}: eval(y) must remain visible in maskedCode`
    );
    if (tc.innerTextMustBeMasked) {
      const innerIdx = tc.code.indexOf(tc.innerTextMustBeMasked);
      assert.ok(innerIdx >= 0);
      assert.equal(
        isRangeStrictlyInCodeRegion(res.regions, innerIdx, innerIdx + tc.innerTextMustBeMasked.length),
        false,
        `${tc.name}: "${tc.innerTextMustBeMasked}" inside nested template must NOT leak into code region`
      );
    }
  }
});

test('Stage 9.1 (B): Adversarial Regex Literal vs Division Operator', () => {
  // 1. Real regex literals with escaped slashes & char classes containing slashes
  const regexCases = [
    'const r = /a\\/b[c/d]e/gi; const sentinel = eval(x);',
    'return /abc\\/def/m; const sentinel = eval(x);',
    'return/*comment*//foo\'bar/g; const sentinel = eval(x);',
    'if (/x\\/y/.test(y)) { eval(x); }',
  ];
  for (const code of regexCases) {
    const res = assertMaskerInvariants(code, false, `regex:${code}`);
    const evalIdx = code.indexOf('eval(x)');
    assert.equal(
      isRangeStrictlyInCodeRegion(res.regions, evalIdx, evalIdx + 7),
      true,
      `eval(x) must stay in code region for: ${code}`
    );
    assert.ok(
      res.regions.some((r) => r.kind === 'regex'),
      `Expected a regex region for: ${code}`
    );
  }

  // 2. Division operators must stay strictly in code region (NOT misclassified as regex)
  const divisionCases = [
    { name: 'chained identifier division', code: 'const d = a / b / c;', target: 'a / b / c' },
    { name: 'bracket index division', code: 'const d = arr[0] / 2 / 1;', target: 'arr[0] / 2 / 1' },
    { name: 'call expression division', code: 'const d = fn() / 2 / 1;', target: 'fn() / 2 / 1' },
    { name: 'postfix increment division', code: 'const d = x++ / 2 / 1;', target: 'x++ / 2 / 1' },
    { name: 'postfix decrement division', code: 'const d = y-- / 2 / 1;', target: 'y-- / 2 / 1' },
    {
      name: 'multiline division after identifier',
      code: 'const ratio = totalAmount\n  / count / 2;\nconst sentinel = eval(x);',
      target: '/ count / 2',
    },
    {
      name: 'multiline division after call',
      code: 'const ratio = getTotal()\n  / getCount() / 2;',
      target: '/ getCount() / 2',
    },
  ];
  for (const tc of divisionCases) {
    const res = assertMaskerInvariants(tc.code, false, tc.name);
    const idx = tc.code.indexOf(tc.target);
    assert.ok(idx >= 0);
    assert.equal(
      isRangeStrictlyInCodeRegion(res.regions, idx, idx + tc.target.length),
      true,
      `${tc.name}: division "${tc.target}" must stay strictly in code region (not regex)`
    );
  }

  // 3. Unclosed regex at EOL must not corrupt line numbers of following literals
  const unclosedRegex = 'const r = /unclosed\nconst nextStr = "line-two";';
  const unclosedRes = assertMaskerInvariants(unclosedRegex, false, 'unclosed regex EOL');
  const nextLit = unclosedRes.stringLiterals.find((l) => l.value === 'line-two');
  assert.ok(nextLit, 'Expected string literal on line 2 after unclosed regex');
  assert.equal(nextLit.line, 2, 'Line counter must advance past \\n after unclosed regex');
});

test('Stage 9.1 (C): Adversarial Comments Mid-Assignment & Malformed EOF', () => {
  const midAssign = 'const /* c */ fn = /* d */ eval;';
  const midRes = assertMaskerInvariants(midAssign, false, 'mid-assignment comments');
  assert.equal(
    midRes.regions.filter((r) => r.kind === 'comment').length,
    2,
    'Expected 2 distinct comment regions'
  );
  for (const tok of ['const', 'fn', '=', 'eval']) {
    const idx = midAssign.indexOf(tok);
    assert.equal(
      isRangeStrictlyInCodeRegion(midRes.regions, idx, idx + tok.length),
      true,
      `Token "${tok}" must remain strictly in code region`
    );
  }

  // Line comment at EOF without trailing newline
  const eofLineComment = 'const a = 1; // comment at eof without newline';
  const eofLineRes = assertMaskerInvariants(eofLineComment, false, 'eof line comment');
  const lastReg1 = eofLineRes.regions[eofLineRes.regions.length - 1];
  assert.equal(lastReg1.kind, 'comment');
  assert.equal(lastReg1.end, eofLineComment.length);

  // Unclosed block comment at EOF
  const eofBlockComment = 'const a = 1; /* unclosed block comment to eof';
  const eofBlockRes = assertMaskerInvariants(eofBlockComment, false, 'eof unclosed block comment');
  const lastReg2 = eofBlockRes.regions[eofBlockRes.regions.length - 1];
  assert.equal(lastReg2.kind, 'comment');
  assert.equal(lastReg2.end, eofBlockComment.length);

  // Multi-line block comment followed by trailing suppression on next line
  const multiLineComment = 'const a = 1; /* line 1\nline 2 */ const b = eval(x); // devguard-ignore DG001: intentional test suppression';
  const multiRes = assertMaskerInvariants(multiLineComment, false, 'multiline block comment + suppression');
  assert.equal(multiRes.suppressions.length, 1);
  assert.equal(multiRes.suppressions[0].targetLine, 2);
});

test('Stage 9.1 (D): Adversarial JSX / TSX Edge Cases', () => {
  const jsxCases: Array<{ name: string; code: string; sentinel: string }> = [
    {
      name: 'closing JSX tag must not start regex literal',
      code: 'const el = <div>ok</div>; const sentinel = eval(x);',
      sentinel: 'eval(x)',
    },
    {
      name: 'multiple closing JSX tags on single line',
      code: 'const a = <div>x</div>; const b = <span>y</span>; const sentinel = eval(x);',
      sentinel: 'eval(x)',
    },
    {
      name: 'JSX text apostrophe must not swallow following code',
      code: "const el = <div>don't worry</div>;\nconst sentinel = eval(x);",
      sentinel: 'eval(x)',
    },
    {
      name: 'JSX text apostrophe surrounding embedded expression',
      code: "const el = <p>don't {eval(x)} won't</p>;",
      sentinel: 'eval(x)',
    },
    {
      name: 'JSX comment + attribute string with apostrophe + self-closing tag',
      code: `const el = <Input label="can't" {/* jsx comment */} onClick={() => eval(x)} />;`,
      sentinel: 'eval(x)',
    },
    {
      name: 'TypeScript generics and comparisons must not break masking',
      code: 'const ok = a < b && c > d; const arr: Array<string> = ["x"]; const sentinel = eval(x);',
      sentinel: 'eval(x)',
    },
  ];

  for (const tc of jsxCases) {
    const res = assertMaskerInvariants(tc.code, false, tc.name);
    const idx = tc.code.indexOf(tc.sentinel);
    assert.ok(idx >= 0);
    assert.equal(
      isRangeStrictlyInCodeRegion(res.regions, idx, idx + tc.sentinel.length),
      true,
      `${tc.name}: "${tc.sentinel}" must stay strictly in code region`
    );
    assert.ok(
      res.maskedCode.includes(tc.sentinel),
      `${tc.name}: "${tc.sentinel}" must stay visible in maskedCode`
    );
  }
});

test('Stage 9.1 (E): Malformed, Extreme, Unicode, Deep Nesting & Anti-Hang Stress', () => {
  // Unclosed quotes before newline must preserve line numbers
  const unclosedQuote = 'const a = "unclosed\nconst b = "line-two";';
  const unclosedQuoteRes = assertMaskerInvariants(unclosedQuote, false, 'unclosed quote EOL');
  const lineTwoLit = unclosedQuoteRes.stringLiterals.find((l) => l.value === 'line-two');
  assert.ok(lineTwoLit, 'Expected literal on line 2 after unclosed quote');
  assert.equal(lineTwoLit.line, 2, 'Line counter must advance past \\n after unclosed quote');

  // Extreme malformed fragments
  const malformedInputs = [
    '',
    '\\',
    'const s = "abc\\',
    "const s = 'abc\\",
    'const t = `abc\\',
    'const r = /abc\\',
    'const t = `unclosed ${`nested ${',
    '/* unclosed',
    '//',
    '🚀'.repeat(100),
    'const e = "🚀👨‍👩‍👧‍👦"; // 🌏\nconst x = `✨ ${"🔥"}`;',
  ];
  for (const input of malformedInputs) {
    assertMaskerInvariants(input, false, `malformed:${JSON.stringify(input.slice(0, 30))}`);
    assertMaskerInvariants(input, true, `malformed-py:${JSON.stringify(input.slice(0, 30))}`);
  }

  // Deeply nested template literals (depth 300) — must be iterative (no stack overflow) & fast
  const depth = 300;
  const deepTemplate =
    'const deep = ' + '`a${'.repeat(depth) + '1' + '}`'.repeat(depth) + '; const sentinel = eval(x);';
  const tDeepStart = performance.now();
  const deepRes = assertMaskerInvariants(deepTemplate, false, 'deep nested template (300)');
  const deepMs = performance.now() - tDeepStart;
  assert.ok(deepMs < 250, `Deep nested template (depth ${depth}) took too long: ${deepMs.toFixed(2)}ms`);
  const evalIdx = deepTemplate.indexOf('eval(x)');
  assert.equal(
    isRangeStrictlyInCodeRegion(deepRes.regions, evalIdx, evalIdx + 7),
    true,
    'eval(x) after 300-level nested template must remain in code region'
  );

  // Large 200 KiB adversarial input — linear time check
  const largeAdversarial =
    'const r = /a\\/b[c/d]/gi; const el = <div>don\'t</div>; const t = `a ${`b`} c`;\n'.repeat(2600);
  const tLargeStart = performance.now();
  analyzeLexicalStructure(largeAdversarial, false);
  const largeMaskerMs = performance.now() - tLargeStart;
  assertMaskerInvariants(largeAdversarial, false, 'large 200 KiB adversarial');
  assert.ok(
    largeMaskerMs < 250,
    `Large 200 KiB adversarial input must finish linearly (<250ms), got ${largeMaskerMs.toFixed(2)}ms`
  );
});

test(`Stage 9.1 (F): Deterministic Seeded Property Fuzz Suite (${FUZZ_CASE_COUNT} cases, seed=0x${FUZZ_SEED.toString(16)})`, () => {
  const rng = createMulberry32(FUZZ_SEED);
  const suiteStart = performance.now();
  let maxCaseMs = 0;

  for (let i = 0; i < FUZZ_CASE_COUNT; i++) {
    const { code, allowHash } = generateFuzzCase(rng, i);
    const caseStart = performance.now();
    assertMaskerInvariants(code, allowHash, `fuzz#${i}(hash=${allowHash})`);
    const elapsed = performance.now() - caseStart;
    if (elapsed > maxCaseMs) maxCaseMs = elapsed;
    assert.ok(
      elapsed < 100,
      `fuzz#${i} exceeded 100ms anti-hang budget (${elapsed.toFixed(2)}ms)`
    );
  }

  const totalMs = performance.now() - suiteStart;
  console.log(
    `[Stage 9.1 Fuzz] ${FUZZ_CASE_COUNT} cases (seed=0x${FUZZ_SEED.toString(16)}) verified in ${totalMs.toFixed(1)} ms (max single case: ${maxCaseMs.toFixed(2)} ms)`
  );
  assert.ok(totalMs < 10_000, `Full fuzz suite took too long: ${totalMs.toFixed(1)}ms`);
});
