import { execFileSync } from 'node:child_process';
import { analyzeCodeDeterministically } from '../src/devguardAnalyzer.js';
import { CORPUS_CASES, type CorpusCase } from '../tests/corpus/cases.js';

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

function getCommitShortSha(): string {
  try {
    return execFileSync('git', ['rev-parse', '--short', 'HEAD'], {
      encoding: 'utf-8',
      stdio: ['ignore', 'pipe', 'ignore'],
    }).trim();
  } catch {
    return 'unknown';
  }
}

function main(): void {
  const commitSha = getCommitShortSha();
  const isoDate = new Date().toISOString().slice(0, 10);

  const totalCases = CORPUS_CASES.length;
  const tpCount = CORPUS_CASES.filter((c) => c.label === 'TP').length;
  const tnCount = CORPUS_CASES.filter((c) => c.label === 'TN').length;
  const evasionCount = CORPUS_CASES.filter((c) => c.label === 'EVASION').length;

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
  }

  console.log(`- **Commit Short SHA:** \`${commitSha}\``);
  console.log(`- **Date:** \`${isoDate}\``);
  console.log(`- **Total Cases:** \`n = ${totalCases}\` (\`TP = ${tpCount}\`, \`TN = ${tnCount}\`, \`EVASION = ${evasionCount}\`)`);
  console.log('');
  console.log('| Rule | TP (hit/total) | TN (FP/total) | EVASION (hit/total) | knownMiss | knownFP |');
  console.log('| :--- | :---: | :---: | :---: | :---: | :---: |');
  for (const r of RULES) {
    const s = stats.get(r)!;
    console.log(
      `| ${r} | ${s.tpHit}/${s.tpTotal} | ${s.tnFp}/${s.tnTotal} | ${s.evHit}/${s.evTotal} | ${s.knownMiss} | ${s.knownFP} |`
    );
  }

  console.log('');
  console.log('#### Documented `knownMiss` & `knownFP` Corpus Cases');
  const exceptions = CORPUS_CASES.filter((c) => c.status === 'knownMiss' || c.status === 'knownFP');
  if (exceptions.length === 0) {
    console.log('- None');
  } else {
    for (const c of exceptions) {
      console.log(`- **\`${c.id}\`** (\`${c.rule}\`, \`${c.status}\`): ${c.note}`);
    }
  }
}

main();
