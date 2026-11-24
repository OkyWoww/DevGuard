import assert from 'node:assert/strict';
import {
  MAX_ALIAS_DEPTH,
  analyzeCodeDeterministically,
  analyzeIntraProceduralAliases,
  analyzeLexicalStructure,
  detectAliasedExecutionSinks,
} from '../src/core/analyzer.ts';
import { buildSarifReportString } from '../src/core/sarif.ts';
import { explainDevGuardRule } from '../src/adapters/mcp/rulesCatalog.ts';
import { CORPUS_CASES } from './corpus/cases.ts';

function runAlias(code: string) {
  const lex = analyzeLexicalStructure(code, false);
  return detectAliasedExecutionSinks(lex.maskedCode, lex.stringLiterals);
}

function runAliasFull(code: string) {
  const lex = analyzeLexicalStructure(code, false);
  return analyzeIntraProceduralAliases(lex.maskedCode, lex.stringLiterals);
}

let passed = 0;
function test(name: string, fn: () => void): void {
  fn();
  passed++;
  console.log(`  [PASS] ${name}`);
}

console.log('Running Stage 9.2 Intra-Procedural Alias Tracking Test Suite...');

// ---------------------------------------------------------------------------
// 1. True Positives (Depth 1 & Depth 2)
// ---------------------------------------------------------------------------
test('TP-1: Depth 1 alias to eval', () => {
  const res = runAlias(`
    function run(input: string) {
      const fn = eval;
      return fn(input);
    }
  `);
  assert.equal(res.length, 1);
  assert.equal(res[0].target, 'eval');
  assert.equal(res[0].depth, 1);
  assert.equal(res[0].aliasName, 'fn');
  assert.equal(res[0].line, 4);
});

test('TP-2: Depth 2 chained alias to eval', () => {
  const res = runAlias(`
    function run(input: string) {
      const a = eval;
      const b = a;
      return b(input);
    }
  `);
  assert.equal(res.length, 1);
  assert.equal(res[0].target, 'eval');
  assert.equal(res[0].depth, 2);
  assert.deepEqual(res[0].chain, ['b', 'a', 'eval']);
});

test('TP-3: Depth 1 alias to Function constructor', () => {
  const res = runAlias(`
    const F = Function;
    const compiled = new F('return 42');
  `);
  assert.equal(res.length, 1);
  assert.equal(res[0].target, 'Function');
  assert.equal(res[0].depth, 1);
});

test('TP-4: Global object member and bracket aliases (globalThis.eval, window["eval"])', () => {
  const res1 = runAlias(`
    const e = globalThis.eval;
    e('1 + 1');
  `);
  assert.equal(res1.length, 1);
  assert.equal(res1[0].target, 'eval');

  const res2 = runAlias(`
    const e = window['eval'];
    e('1 + 1');
  `);
  assert.equal(res2.length, 1);
  assert.equal(res2[0].target, 'eval');
});

test('TP-5: child_process require + property alias and namespace alias', () => {
  const res1 = runAlias(`
    const cp = require('child_process');
    const run = cp.exec;
    run('ls -la');
  `);
  assert.equal(res1.length, 1);
  assert.equal(res1[0].target, 'child_process.exec');
  assert.equal(res1[0].depth, 1);

  const res2 = runAlias(`
    const cp = require('node:child_process');
    const sh = cp;
    sh.execSync('whoami');
  `);
  assert.equal(res2.length, 1);
  assert.equal(res2[0].target, 'child_process.execSync');
  assert.equal(res2[0].depth, 1);
});

test('TP-6: ESM named alias and namespace destructuring from node:child_process', () => {
  const res1 = runAlias(`
    import { exec as runCmd } from 'node:child_process';
    runCmd('echo hi');
  `);
  assert.equal(res1.length, 1);
  assert.equal(res1[0].target, 'child_process.exec');
  assert.equal(res1[0].depth, 1);

  const res2 = runAlias(`
    import * as cp from 'child_process';
    const { execSync: runSync } = cp;
    runSync('echo hi');
  `);
  assert.equal(res2.length, 1);
  assert.equal(res2[0].target, 'child_process.execSync');
  assert.equal(res2[0].depth, 1);
});

test('TP-7: Comment in the middle of assignment (Stage 9.1 lexicalMasker synergy)', () => {
  const res = runAlias(`
    const /* c1 */ fn = /* c2 */ eval;
    fn('1 + 1');
  `);
  assert.equal(res.length, 1);
  assert.equal(res[0].target, 'eval');
  assert.equal(res[0].depth, 1);
});

test('TP-8: Constant-folded bracket alias via Pass-V in analyzeCodeDeterministically', () => {
  const report = analyzeCodeDeterministically(
    `const e = globalThis['ev' + 'al'];\ne('1 + 1');`,
    { filePath: 'src/demo.ts' }
  );
  const aliasFindings = (report.inlineFindings ?? []).filter((f) => f.ruleId === 'DG001-ALIAS-01');
  assert.equal(aliasFindings.length, 1);
  assert.equal(aliasFindings[0].scoring, false);
  assert.equal(aliasFindings[0].severity, 'warning');
});

// ---------------------------------------------------------------------------
// 2. Depth Cap Enforcement (MAX_ALIAS_DEPTH = 2)
// ---------------------------------------------------------------------------
test('DEPTH-1: Max alias depth is strictly 2 (depth 3 is NOT flagged)', () => {
  assert.equal(MAX_ALIAS_DEPTH, 2);
  const res = runAlias(`
    const a = eval;
    const b = a;
    const c = b;
    c('1 + 1');
  `);
  assert.equal(res.length, 0);
});

test('DEPTH-2: Chained child_process namespace exceeding depth 2 is NOT flagged', () => {
  const res = runAlias(`
    const cp = require('child_process');
    const sh1 = cp;
    const sh2 = sh1;
    const e = sh2.exec;
    e('ls');
  `);
  assert.equal(res.length, 0);
});

// ---------------------------------------------------------------------------
// 3. Guardrail #1: Anti-Survivorship Bias (RegExp.exec & generic .exec)
// ---------------------------------------------------------------------------
test('GUARDRAIL-1a: RegExp.exec alias is NEVER flagged', () => {
  const res = runAlias(`
    const re = /foo(\\d+)/g;
    const run = re.exec;
    run('foo123');
    const run2 = /bar/.exec;
    run2('bar');
  `);
  assert.equal(res.length, 0);
});

test('GUARDRAIL-1b: Generic object .exec or .eval property is NEVER flagged', () => {
  const res = runAlias(`
    const run = something.exec;
    run('query');
    const { exec: dbExec } = dbClient;
    dbExec('SELECT 1');
    const customEval = mathEngine.eval;
    customEval('2 + 2');
  `);
  assert.equal(res.length, 0);
});

test('GUARDRAIL-1c: Non-child_process import named exec is NEVER flagged', () => {
  const res = runAlias(`
    import { exec as runQuery } from './db-helper';
    runQuery('SELECT 1');
  `);
  assert.equal(res.length, 0);
});

// ---------------------------------------------------------------------------
// 4. Guardrail #2: Scope Boundaries, Object Literals & Parameter Shadowing
// ---------------------------------------------------------------------------
test('GUARDRAIL-2a: Function parameter shadows outer alias', () => {
  const res = runAlias(`
    const fn = eval;
    function run(fn) {
      return fn('safe');
    }
  `);
  assert.equal(res.length, 0);
});

test('GUARDRAIL-2b: TypeScript typed & destructured parameters shadow outer alias', () => {
  const res = runAlias(`
    const fn = eval;
    function runTyped(fn: (s: string) => void): void {
      fn('safe');
    }
    function runDestructured({ fn }: { fn: (s: string) => void }) {
      fn('safe');
    }
  `);
  assert.equal(res.length, 0);
});

test('GUARDRAIL-2c: Arrow function parameters (block, expr, single-param) shadow outer alias', () => {
  const res = runAlias(`
    const fn = eval;
    const a = (fn) => { return fn('safe'); };
    const b = (fn) => fn('safe');
    const c = fn => fn('safe');
  `);
  assert.equal(res.length, 0);
});

test('GUARDRAIL-2d: Object literal { fn: safe } does NOT confuse scope tracking', () => {
  const res = runAlias(`
    const fn = eval;
    const cfg = { fn: safe };
    cfg.fn('safe');
    const svc = {
      run(fn: (x: string) => void) {
        fn('safe');
      }
    };
  `);
  assert.equal(res.length, 0);
});

test('GUARDRAIL-2e: Intra-procedural isolation across sibling functions and blocks', () => {
  const res = runAlias(`
    function a() {
      const fn = eval;
    }
    function b() {
      fn('safe');
    }
    function c() {
      {
        const inner = eval;
      }
      inner('safe');
    }
  `);
  assert.equal(res.length, 0);
});

test('GUARDRAIL-2f: Catch parameter, reassignment, and member call invalidation', () => {
  const res = runAlias(`
    let fn = eval;
    try {
      doWork();
    } catch (fn) {
      fn('safe');
    }
    obj.fn('safe');
    fn = safeHandler;
    fn('safe');
  `);
  assert.equal(res.length, 0);
});

test('GUARDRAIL-2g: Local shadowing of global Function prevents false alias', () => {
  const res = runAlias(`
    function testShadow(Function: (x: string) => void) {
      const f = Function;
      f('safe');
    }
  `);
  assert.equal(res.length, 0);
});

test('GUARDRAIL-2h: TypeScript type annotation before = is NOT misbound as alias', () => {
  const res = runAlias(`
    const fn: MyType | OtherType = eval;
    MyType('safe');
    OtherType('safe');
  `);
  assert.equal(res.length, 0);
});

// ---------------------------------------------------------------------------
// 5. Guardrail #3: Non-Scoring Contract, SARIF, & MCP Catalog Integration
// ---------------------------------------------------------------------------
test('GUARDRAIL-3a: DG001-ALIAS-01 is strictly non-scoring (zero score impact)', () => {
  const baselineCode = `
    export function processValue(input: unknown): string {
      if (typeof input !== 'string') {
        throw new Error('Invalid input');
      }
      const helper = (v: string) => v.trim();
      return helper(input);
    }
  `;
  const aliasedCode = `
    export function processValue(input: unknown): string {
      if (typeof input !== 'string') {
        throw new Error('Invalid input');
      }
      const helper = eval;
      return String(helper(input));
    }
  `;
  const baseReport = analyzeCodeDeterministically(baselineCode, { filePath: 'src/safe.ts' });
  const aliasReport = analyzeCodeDeterministically(aliasedCode, { filePath: 'src/alias.ts' });

  const aliasFindings = (aliasReport.inlineFindings ?? []).filter((f) => f.ruleId === 'DG001-ALIAS-01');
  assert.equal(aliasFindings.length, 1);
  assert.equal(aliasFindings[0].severity, 'warning');
  assert.equal(aliasFindings[0].scoring, false);

  // Zero score deduction compared to baseline
  assert.equal(aliasReport.skor.security, baseReport.skor.security);
  assert.equal(aliasReport.skor.correctness, baseReport.skor.correctness);
  assert.equal(aliasReport.skor.maintainability, baseReport.skor.maintainability);
  assert.equal(aliasReport.skor.totalScore, baseReport.skor.totalScore);
});

test('GUARDRAIL-3b: DG001-ALIAS-01 is registered in MCP rulesCatalog and SARIF output', () => {
  const explained = explainDevGuardRule('DG001-ALIAS-01');
  assert.equal(explained.found, true);
  if (explained.found) {
    assert.equal(explained.rule.ruleId, 'DG001-ALIAS-01');
    assert.equal(explained.rule.defaultSeverity, 'warning');
    assert.ok(explained.rule.remediation.length > 20);
  }

  const report = analyzeCodeDeterministically(
    `const run = eval;\nrun('1 + 1');`,
    { filePath: 'src/alias-sarif.ts' }
  );
  const { sarifJson } = buildSarifReportString([
    {
      filePath: 'src/alias-sarif.ts',
      security: report.skor.security,
      correctness: report.skor.correctness,
      maintainability: report.skor.maintainability,
      overall: report.skor.totalScore,
      passed: true,
      fatalFlaws: [],
      defenseInDepth: [],
      inlineFindings: report.inlineFindings,
    },
  ]);

  const sarif = JSON.parse(sarifJson) as {
    runs: Array<{
      tool: { driver: { rules: Array<{ id: string }> } };
      results: Array<{ ruleId: string; level: string; properties?: { scoring?: boolean } }>;
    }>;
  };
  const ruleIds = sarif.runs[0].tool.driver.rules.map((r) => r.id);
  assert.ok(ruleIds.includes('DG001-ALIAS-01'), 'SARIF driver.rules must register DG001-ALIAS-01');

  const aliasSarifResults = sarif.runs[0].results.filter((r) => r.ruleId === 'DG001-ALIAS-01');
  assert.equal(aliasSarifResults.length, 1);
  assert.equal(aliasSarifResults[0].level, 'warning');
  assert.equal(aliasSarifResults[0].properties?.scoring, false);
});

// ---------------------------------------------------------------------------
// 6. Stage 9.3: A9-1 Targets (DG001-EV-03 & DG005-ALIAS-01 p.catch(() => {}))
// ---------------------------------------------------------------------------
test('A9-1a: DG001-EV-03 parenthesized TS cast + split-string fold detected via DG001-ALIAS-01', () => {
  const ev03 = CORPUS_CASES.find((c) => c.id === 'DG001-EV-03');
  assert.ok(ev03, 'DG001-EV-03 must exist in corpus');
  const report = analyzeCodeDeterministically(ev03.code, { filePath: ev03.filePath });
  const aliasFindings = (report.inlineFindings ?? []).filter((f) => f.ruleId === 'DG001-ALIAS-01');
  assert.equal(aliasFindings.length, 1);
  assert.equal(aliasFindings[0].severity, 'warning');
  assert.equal(aliasFindings[0].scoring, false);
});

test('A9-1b: Critical-flow Promise alias p.catch(() => {}) detected via DG005-ALIAS-01 (depth 1 & 2)', () => {
  const res1 = runAlias(`
    export function runOrder(orderId: string) {
      const p = charge(orderId);
      p.catch(() => {});
    }
  `);
  assert.equal(res1.length, 1);
  assert.equal(res1[0].ruleId, 'DG005-ALIAS-01');
  assert.equal(res1[0].target, 'critical_promise.catch');
  assert.equal(res1[0].depth, 1);

  const res2 = runAlias(`
    export function runOrderChained(orderId: string) {
      const p = billing.chargePayment(orderId);
      const p2 = p;
      p2.catch(() => undefined);
    }
  `);
  assert.equal(res2.length, 1);
  assert.equal(res2[0].ruleId, 'DG005-ALIAS-01');
  assert.equal(res2[0].depth, 2);

  const res3 = runAlias(`
    export function runFnCatch(id: string) {
      const p = processInvoice(id);
      p.catch(function() {});
    }
  `);
  assert.equal(res3.length, 1);
  assert.equal(res3[0].ruleId, 'DG005-ALIAS-01');
});

// ---------------------------------------------------------------------------
// 7. Stage 9.3: A9-2 >= 5 TN Cases for DG005-ALIAS-01 (Anti-FP Guardrail)
// ---------------------------------------------------------------------------
test('A9-2-TN-1: Non-critical Promise alias with empty .catch() is NOT flagged', () => {
  const res = runAlias(`
    const p = loadUiTheme();
    p.catch(() => {});
  `);
  assert.equal(res.length, 0);
});

test('A9-2-TN-2: Critical Promise alias with real error handler .catch(err => log(err)) or .catch(handleErr) is NOT flagged', () => {
  const res = runAlias(`
    const p1 = chargePayment(orderId);
    p1.catch((err) => logError(err));
    const p2 = transferFunds(a, b);
    p2.catch(handleError);
    const p3 = verifyAuth(token);
    p3.catch((err) => { logger.error(err); throw err; });
  `);
  assert.equal(res.length, 0);
});

test('A9-2-TN-3: Parameter shadowing invalidates outer critical-flow Promise alias', () => {
  const res = runAlias(`
    const p = chargePayment(orderId);
    function ignoreShadowed(p: Promise<void>) {
      p.catch(() => {});
    }
  `);
  assert.equal(res.length, 0);
});

test('A9-2-TN-4: Reassignment invalidates critical-flow Promise alias and records bailout', () => {
  const full = runAliasFull(`
    let p = chargePayment(orderId);
    p = Promise.resolve();
    p.catch(() => {});
  `);
  assert.equal(full.findings.length, 0);
  assert.ok(full.bailouts.some((b) => b.reason === 'reassigned_binding' && b.identifier === 'p'));
});

test('A9-2-TN-5: Awaited result, cleanup method, and sibling function isolation are NOT flagged', () => {
  const res = runAlias(`
    async function run() {
      const settled = await chargePayment(orderId);
      settled.catch(() => {});
      const c = fs.close(fd);
      c.catch(() => {});
    }
    function other() {
      const p = chargePayment(orderId);
    }
    function sibling() {
      p.catch(() => {});
    }
  `);
  assert.equal(res.length, 0);
});

// ---------------------------------------------------------------------------
// 8. Stage 9.3: SPOF #2 (Nested Generics & Malformed Unbalanced `<`)
// ---------------------------------------------------------------------------
test('SPOF-2: Nested generics and malformed unbalanced angle brackets in parenthesized TS cast do not hang', () => {
  const t0 = performance.now();
  const res1 = runAlias(`
    const fn = (globalThis as Record<string, Record<string, (x: Map<string, number>) => unknown>>)['eval'];
    fn('1 + 1');
  `);
  assert.equal(res1.length, 1);
  assert.equal(res1[0].target, 'eval');

  // Malformed unbalanced `<` inside parenthesized cast
  const malformed = `const fn = (globalThis as Record<string, Map<a, b, Map<c, d)['eval'];\nfn('x');`;
  runAlias(malformed);
  const elapsedMs = performance.now() - t0;
  assert.ok(elapsedMs < 50, `Expected linear-time <50ms, took ${elapsedMs.toFixed(2)}ms`);
});

// ---------------------------------------------------------------------------
// 9. Stage 9.3: INV-7 Bail-Out Reporting & Anti-Spam Guarantee
// ---------------------------------------------------------------------------
test('INV-7a: Bail-outs fire ONLY on tracked sink/namespace/promise intersections (zero spam)', () => {
  // Ordinary code: reassignment, nested destructuring, array destructuring, returning values
  const ordinary = runAliasFull(`
    let count = 0;
    count = 1;
    const { a: { b }, ...rest } = config;
    const [first, second] = items;
    function getToken() {
      const token = createToken();
      return token;
    }
  `);
  assert.equal(ordinary.findings.length, 0);
  assert.equal(ordinary.bailouts.length, 0, `Expected 0 bailouts on ordinary code, got: ${JSON.stringify(ordinary.bailouts)}`);

  // Tracked sink bail-outs
  const tracked = runAliasFull(`
    const cp = require('child_process');
    const { nested: { exec } } = cp;
    const [arrFn] = [eval];
    const a = eval;
    const b = a;
    const c = b;
    function escapeFn() {
      const f = eval;
      runExternal(f);
      return f;
    }
  `);
  const reasons = new Set(tracked.bailouts.map((b) => b.reason));
  assert.ok(reasons.has('complex_destructuring'), 'Expected complex_destructuring bailout');
  assert.ok(reasons.has('depth_exceeded'), 'Expected depth_exceeded bailout');
  assert.ok(reasons.has('cross_function_alias'), 'Expected cross_function_alias bailout');
});

test('INV-7b: DG005-ALIAS-01 MCP catalog + SARIF non-scoring & non-fatal bailout notification', () => {
  const explained = explainDevGuardRule('DG005-ALIAS-01');
  assert.equal(explained.found, true);
  if (explained.found) {
    assert.equal(explained.rule.defaultSeverity, 'warning');
    assert.ok(explained.rule.remediation.length > 20);
  }

  const report = analyzeCodeDeterministically(
    `const p = chargePayment(id);\np.catch(() => {});\nlet fn = eval;\nfn = safe;`,
    { filePath: 'src/billing/aliased.ts' }
  );
  assert.ok((report.aliasBailouts ?? []).length >= 1);

  const { sarifJson } = buildSarifReportString([
    {
      filePath: 'src/billing/aliased.ts',
      security: report.skor.security,
      correctness: report.skor.correctness,
      maintainability: report.skor.maintainability,
      overall: report.skor.totalScore,
      passed: true,
      fatalFlaws: [],
      defenseInDepth: [],
      inlineFindings: report.inlineFindings,
      aliasBailouts: report.aliasBailouts,
    },
  ]);
  const sarif = JSON.parse(sarifJson) as {
    runs: Array<{
      tool: { driver: { rules: Array<{ id: string }> } };
      invocations: Array<{
        executionSuccessful: boolean;
        toolExecutionNotifications: Array<{ level: string; descriptor?: { id: string } }>;
      }>;
      results: Array<{ ruleId: string; level: string; properties?: { scoring?: boolean } }>;
    }>;
  };
  assert.ok(sarif.runs[0].tool.driver.rules.some((r) => r.id === 'DG005-ALIAS-01'));
  assert.equal(sarif.runs[0].invocations[0].executionSuccessful, true, 'Alias bailout must remain non-fatal');
  assert.ok(
    sarif.runs[0].invocations[0].toolExecutionNotifications.some(
      (n) => n.level === 'note' && n.descriptor?.id === 'alias_bailout_reassigned_binding'
    )
  );
  const dg005Alias = sarif.runs[0].results.filter((r) => r.ruleId === 'DG005-ALIAS-01');
  assert.equal(dg005Alias.length, 1);
  assert.equal(dg005Alias[0].properties?.scoring, false);
});

// ---------------------------------------------------------------------------
// 10. Stage 9.3: A9-4 Golden SARIF Identity on Corpus Without Alias
// ---------------------------------------------------------------------------
test('A9-4: Non-alias corpus produces 0 alias findings, 0 bailouts, and byte-for-byte identical SARIF', () => {
  const nonAliasCases = CORPUS_CASES.filter((c) => c.id !== 'DG001-EV-03');
  const summariesWithAlias = [];
  const summariesBaseline = [];

  for (const c of nonAliasCases) {
    const report = analyzeCodeDeterministically(c.code, {
      filePath: c.filePath,
      declaredDependencies: c.declaredDependencies,
    });
    const aliasInline = (report.inlineFindings ?? []).filter(
      (f) => f.ruleId === 'DG001-ALIAS-01' || f.ruleId === 'DG005-ALIAS-01'
    );
    assert.equal(
      aliasInline.length,
      0,
      `A9-4 violation: unexpected alias finding on non-alias corpus case ${c.id}: ${JSON.stringify(aliasInline)}`
    );
    assert.equal(
      report.aliasBailouts?.length ?? 0,
      0,
      `A9-4 violation: unexpected alias bailout on non-alias corpus case ${c.id}: ${JSON.stringify(report.aliasBailouts)}`
    );

    const baseSummary = {
      filePath: c.filePath,
      security: report.skor.security,
      correctness: report.skor.correctness,
      maintainability: report.skor.maintainability,
      overall: report.skor.totalScore,
      passed: report.skor.totalScore >= 85,
      fatalFlaws: [],
      defenseInDepth: [],
      inlineFindings: report.inlineFindings,
    };
    summariesBaseline.push(baseSummary);
    summariesWithAlias.push({
      ...baseSummary,
      aliasBailouts: report.aliasBailouts,
    });
  }

  const goldenBaseline = buildSarifReportString(summariesBaseline).sarifJson;
  const actualWithAlias = buildSarifReportString(summariesWithAlias).sarifJson;
  assert.equal(actualWithAlias, goldenBaseline, 'A9-4 violation: SARIF output diverged on non-alias corpus');
});

console.log(`PASS: All ${passed} Stage 9.2 + 9.3 alias tracking tests passed.`);
