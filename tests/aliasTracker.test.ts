import assert from 'node:assert/strict';
import {
  MAX_ALIAS_DEPTH,
  analyzeCodeDeterministically,
  analyzeLexicalStructure,
  detectAliasedExecutionSinks,
} from '../src/core/analyzer.ts';
import { buildSarifReportString } from '../src/core/sarif.ts';
import { explainDevGuardRule } from '../src/adapters/mcp/rulesCatalog.ts';

function runAlias(code: string) {
  const lex = analyzeLexicalStructure(code, false);
  return detectAliasedExecutionSinks(lex.maskedCode, lex.stringLiterals);
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

console.log(`PASS: All ${passed} Stage 9.2 alias tracking tests passed.`);
