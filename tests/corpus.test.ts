import test from 'node:test';
import assert from 'node:assert/strict';

import { analyzeCodeDeterministically } from '../src/devguardAnalyzer.js';
import { CORPUS_CASES, type CorpusCase } from './corpus/cases.js';

type RuleId = CorpusCase['rule'];

const RULES: readonly RuleId[] = [
  'DG001',
  'DG004',
  'DG004-DYN-01',
  'DG004-DYN-02',
  'DG005',
  'DG006',
  'DG007',
  'DG008',
];

function isRuleFlagged(c: CorpusCase): boolean {
  const report = analyzeCodeDeterministically(c.code, {
    filePath: c.filePath,
    declaredDependencies: c.declaredDependencies,
  });

  const inline = report.inlineFindings ?? [];
  if (c.rule === 'DG001') {
    const hasNonDg001InlineError = inline.some((f) => f.ruleId !== 'DG001' && f.severity === 'error');
    return (
      inline.some((f) => f.ruleId === 'DG001') ||
      (!hasNonDg001InlineError &&
        !report.isHardened &&
        (report.skor.security < 80 || report.skor.totalScore < 85 || report.temuanUtama.line !== '-'))
    );
  }

  return inline.some((f) => f.ruleId === c.rule);
}

test('Corpus Benchmark: evaluates DG001, DG004-DG008 with honest baseline accounting', () => {
  const stats = new Map<
    RuleId,
    { tpHit: number; tpTotal: number; tnFp: number; tnTotal: number; evHit: number; evTotal: number; knownMiss: number; knownFP: number }
  >();

  for (const r of RULES) {
    stats.set(r, { tpHit: 0, tpTotal: 0, tnFp: 0, tnTotal: 0, evHit: 0, evTotal: 0, knownMiss: 0, knownFP: 0 });
  }

  for (const c of CORPUS_CASES) {
    const bucket = stats.get(c.rule)!;
    const flagged = isRuleFlagged(c);

    if (c.label === 'TP') {
      bucket.tpTotal++;
      if (flagged) bucket.tpHit++;
    } else if (c.label === 'TN') {
      bucket.tnTotal++;
      if (flagged) bucket.tnFp++;
    } else {
      bucket.evTotal++;
      if (flagged) bucket.evHit++;
    }

    if (c.status === 'knownMiss') bucket.knownMiss++;
    if (c.status === 'knownFP') bucket.knownFP++;

    if (c.status === 'expected') {
      if (c.label === 'TN') {
        assert.equal(flagged, false, `Unexpected false positive on ${c.id} (${c.note})`);
      } else {
        assert.equal(flagged, true, `Expected ${c.rule} to flag ${c.id} (${c.note})`);
      }
    } else if (c.status === 'knownMiss') {
      assert.equal(flagged, false, `Case ${c.id} now passes: promote status to 'expected'`);
    } else if (c.status === 'knownFP') {
      assert.equal(flagged, true, `Case ${c.id} no longer false-positives: promote status to 'expected'`);
    }
  }

  console.log('\n| Rule | TP (hit/total) | TN (FP/total) | EVASION (hit/total) | knownMiss | knownFP |');
  console.log('| :--- | :---: | :---: | :---: | :---: | :---: |');
  for (const r of RULES) {
    const s = stats.get(r)!;
    console.log(
      `| ${r} | ${s.tpHit}/${s.tpTotal} | ${s.tnFp}/${s.tnTotal} | ${s.evHit}/${s.evTotal} | ${s.knownMiss} | ${s.knownFP} |`
    );
  }
});
