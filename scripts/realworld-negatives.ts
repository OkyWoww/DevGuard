import * as fs from 'node:fs';
import { builtinModules } from 'node:module';
import * as path from 'node:path';
import process from 'node:process';

import { analyzeCodeDeterministically, type DevGuardRuleId } from '../src/devguardAnalyzer.js';

interface SampleHit {
  ruleId: DevGuardRuleId;
  location: string;
  message: string;
}

const IGNORED_DIRS = new Set(['node_modules', '.git', 'dist', '.test-dist', 'build', 'coverage', 'out']);
const MAX_SAMPLES = 10;

function collectTargetFiles(roots: string[]): string[] {
  const collected: string[] = [];

  const walk = (entryPath: string): void => {
    if (!fs.existsSync(entryPath)) return;
    const stat = fs.statSync(entryPath);
    if (stat.isFile()) {
      if (/\.(?:ts|js)$/.test(entryPath) && !entryPath.endsWith('.d.ts')) {
        collected.push(entryPath);
      }
      return;
    }
    if (!stat.isDirectory()) return;

    const entries = fs.readdirSync(entryPath, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name));
    for (const item of entries) {
      if (IGNORED_DIRS.has(item.name)) continue;
      walk(path.join(entryPath, item.name));
    }
  };

  for (const root of roots) {
    walk(path.resolve(root));
  }

  return collected;
}

function findNearestDependencies(filePath: string): Set<string> | undefined {
  let dir = path.dirname(path.resolve(filePath));
  while (true) {
    const pkgPath = path.join(dir, 'package.json');
    if (fs.existsSync(pkgPath)) {
      try {
        const parsed = JSON.parse(fs.readFileSync(pkgPath, 'utf-8')) as {
          dependencies?: Record<string, unknown>;
          devDependencies?: Record<string, unknown>;
          peerDependencies?: Record<string, unknown>;
        };
        return new Set([
          ...Object.keys(parsed.dependencies || {}),
          ...Object.keys(parsed.devDependencies || {}),
          ...Object.keys(parsed.peerDependencies || {}),
        ]);
      } catch {
        return undefined;
      }
    }
    const parent = path.dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  return undefined;
}

function main(): void {
  const dirs = process.argv.slice(2).filter((arg) => !arg.startsWith('--'));
  if (dirs.length === 0) {
    console.error('Usage: npx tsx scripts/realworld-negatives.ts <dir1> [dir2 ...]');
    process.exit(1);
  }

  const files = collectTargetFiles(dirs);
  const counts: Record<DevGuardRuleId, number> = {
    DG001: 0,
    'DG001-ALIAS-01': 0,
    DG002: 0,
    DG003: 0,
    DG004: 0,
    'DG004-DYN-01': 0,
    'DG004-DYN-02': 0,
    'DG004-WS-NEW': 0,
    'DG004-WS-UNPARSED': 0,
    DG005: 0,
    'DG005-ALIAS-01': 0,
    DG006: 0,
    DG007: 0,
    DG008: 0,
  };
  const samples: SampleHit[] = [];

  for (const filePath of files) {
    const code = fs.readFileSync(filePath, 'utf-8');
    const report = analyzeCodeDeterministically(code, {
      filePath,
      declaredDependencies: findNearestDependencies(filePath),
      builtinModules,
    });

    const relPosix = path.relative(process.cwd(), filePath).replace(/\\/g, '/');
    const inline = report.inlineFindings ?? [];

    for (const f of inline) {
      counts[f.ruleId] = (counts[f.ruleId] ?? 0) + 1;
      if (samples.length < MAX_SAMPLES) {
        samples.push({
          ruleId: f.ruleId,
          location: `${relPosix}:${f.line}`,
          message: f.message,
        });
      }
    }

    const hasInlineErrors = inline.some((f) => f.severity === 'error');
    if (!hasInlineErrors && !report.isHardened && report.temuanUtama.line !== '-') {
      counts.DG001++;
      if (samples.length < MAX_SAMPLES) {
        samples.push({
          ruleId: 'DG001',
          location: `${relPosix}:${report.temuanUtama.line}`,
          message: report.temuanUtama.description,
        });
      }
    }
  }

  const dateStamp = new Date().toISOString().slice(0, 10);
  const outDir = path.resolve(process.cwd(), 'docs', 'benchmarks');
  fs.mkdirSync(outDir, { recursive: true });
  const outPath = path.join(outDir, `realworld-${dateStamp}.md`);

  const lines: string[] = [
    `# Real-World Negatives Benchmark (${dateStamp})`,
    '',
    `- Scanned roots: ${dirs.map((d) => `\`${d}\``).join(', ')}`,
    `- Files analyzed: ${files.length}`,
    '',
    '## Raw Finding Counts per Rule',
    '',
    '| Rule | Raw Findings |',
    '| :--- | :---: |',
  ];

  (Object.keys(counts) as DevGuardRuleId[]).forEach((ruleId) => {
    lines.push(`| ${ruleId} | ${counts[ruleId]} |`);
  });

  lines.push('', '## Sample Locations (up to 10)', '');
  if (samples.length === 0) {
    lines.push('No findings detected.');
  } else {
    samples.forEach((s, i) => {
      lines.push(`${i + 1}. \`${s.location}\` [${s.ruleId}] (triage: unreviewed) — ${s.message}`);
    });
  }

  fs.writeFileSync(outPath, `${lines.join('\n')}\n`, 'utf-8');
  console.log(`Wrote benchmark report to ${outPath} (${files.length} files scanned)`);
}

main();
