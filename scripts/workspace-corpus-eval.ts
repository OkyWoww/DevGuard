import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import { builtinModules } from 'node:module';
import * as os from 'node:os';
import * as path from 'node:path';
import { performance } from 'node:perf_hooks';
import process from 'node:process';

import {
  classifyInScopeFiles,
  createFsWorkspaceFileAccessor,
  discoverInScopeFiles,
} from '../src/cli.js';
import {
  analyzeCodeDeterministically,
  buildWorkspaceContext,
} from '../src/devguardAnalyzer.js';

interface PinnedCorpusRepo {
  name: string;
  url: string;
  sha: string;
  v130BaselineFp: number;
}

const PINNED_REPOS: PinnedCorpusRepo[] = [
  {
    name: 'nestjs/nest',
    url: 'https://github.com/nestjs/nest.git',
    sha: 'bbbfaf1',
    v130BaselineFp: 481,
  },
  {
    name: 'vitejs/vite',
    url: 'https://github.com/vitejs/vite.git',
    sha: 'ef295d5',
    v130BaselineFp: 48,
  },
  {
    name: 'tj/commander.js',
    url: 'https://github.com/tj/commander.js.git',
    sha: 'a5a7dc0',
    v130BaselineFp: 39,
  },
];

interface Dg004Hit {
  file: string;
  line: number;
  message: string;
}

interface ModeEvalResult {
  dg004Count: number;
  wallClockMs: number;
  hits: Dg004Hit[];
  wsPackagesCount: number;
  wsSources: string[];
  wsUnparsedCount: number;
  wsUnparsedDetails: string[];
  undeclaredWsImports: number;
}

function runGit(args: string[], cwd: string): void {
  const res = spawnSync('git', args, { cwd, encoding: 'utf-8' });
  if (res.status !== 0) {
    throw new Error(`git ${args.join(' ')} failed (${res.status}): ${res.stderr || res.stdout}`);
  }
}

function clonePinnedRepo(repo: PinnedCorpusRepo, baseTempDir: string): string {
  const safeName = repo.name.replace(/[^a-zA-Z0-9_-]/g, '_');
  const repoDir = path.join(baseTempDir, safeName);
  runGit(['clone', '--filter=blob:none', '--no-checkout', repo.url, repoDir], baseTempDir);
  runGit(['checkout', repo.sha], repoDir);
  return repoDir;
}

function evaluateRepoMode(
  repoDir: string,
  analyzedFiles: string[],
  mode: 'off' | 'auto'
): ModeEvalResult {
  const t0 = performance.now();
  const accessor = createFsWorkspaceFileAccessor(repoDir);
  const wsContext = buildWorkspaceContext(accessor, { mode });
  const hits: Dg004Hit[] = [];

  for (const filePath of analyzedFiles) {
    const absPath = path.isAbsolute(filePath) ? filePath : path.resolve(repoDir, filePath);
    const code = fs.readFileSync(absPath, 'utf-8');
    const relPosix = path.relative(repoDir, absPath).replace(/\\/g, '/');

    const report = analyzeCodeDeterministically(code, {
      filePath: absPath,
      builtinModules,
      workspaceContext: wsContext,
      workspaceFileAccessor: accessor,
      workspacesMode: mode,
    });

    for (const f of report.inlineFindings ?? []) {
      if (f.ruleId === 'DG004') {
        hits.push({
          file: relPosix,
          line: f.line,
          message: f.message,
        });
      }
    }
  }

  const wallClockMs = performance.now() - t0;
  const unparsedDiagnostics = wsContext.diagnostics.filter((d) => d.ruleId === 'DG004-WS-UNPARSED');
  return {
    dg004Count: hits.length,
    wallClockMs,
    hits,
    wsPackagesCount: wsContext.packagesByName.size,
    wsSources: wsContext.detectedSources,
    wsUnparsedCount: unparsedDiagnostics.length,
    wsUnparsedDetails: unparsedDiagnostics.map((d) => `${d.sourceFile} (${d.reason ?? 'unknown'}): ${d.message}`),
    undeclaredWsImports: wsContext.undeclaredWorkspaceImportsCount,
  };
}

function main(): void {
  const keepTemp = process.argv.includes('--keep-temp');
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'devguard-stage6-corpus-'));
  console.log(`=== DevGuard Stage 6.1.d External Corpus Evaluation (A6-1, A6-7) ===`);
  console.log(`Temp workspace: ${tempRoot}\n`);

  const rows: Array<{
    repo: PinnedCorpusRepo;
    analyzedCount: number;
    skippedCount: number;
    before: ModeEvalResult;
    after: ModeEvalResult;
  }> = [];

  try {
    for (const repo of PINNED_REPOS) {
      console.log(`Fetching ${repo.name} @ ${repo.sha}...`);
      const repoDir = clonePinnedRepo(repo, tempRoot);
      const discovered = discoverInScopeFiles('all', repoDir);
      const classified = classifyInScopeFiles(discovered, { cwd: repoDir, sourceMode: 'all' });
      const analyzedFiles = classified.analyzed.map((e) => e.filePath);

      const before = evaluateRepoMode(repoDir, analyzedFiles, 'off');
      const after = evaluateRepoMode(repoDir, analyzedFiles, 'auto');

      rows.push({
        repo,
        analyzedCount: analyzedFiles.length,
        skippedCount: classified.skipped.length,
        before,
        after,
      });
    }

    console.log('\n### Before vs After DG004 External Corpus Table (A6-1, A6-7)\n');
    console.log('| Repository | Commit SHA | Analyzed / Skipped | v1.3.0 P0-4 Baseline | Before (`mode: off`) DG004 | After (`mode: auto`) DG004 | Delta | Workspaces Detected (Sources) | Unparsed Notices | Time Before (ms) | Time After (ms) |');
    console.log('| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :--- | :---: | :---: | :---: |');
    for (const r of rows) {
      const delta = r.after.dg004Count - r.before.dg004Count;
      const srcLabel = r.after.wsSources.length > 0 ? r.after.wsSources.join(', ') : 'none';
      console.log(
        `| \`${r.repo.name}\` | \`${r.repo.sha}\` | ${r.analyzedCount} / ${r.skippedCount} | ${r.repo.v130BaselineFp} | ${r.before.dg004Count} | ${r.after.dg004Count} | ${delta} | ${r.after.wsPackagesCount} (${srcLabel}) | ${r.after.wsUnparsedCount} | ${r.before.wallClockMs.toFixed(1)} | ${r.after.wallClockMs.toFixed(1)} |`
      );
    }

    for (const r of rows) {
      console.log(`\n#### Remaining DG004 Hits in \`${r.repo.name}\` @ \`${r.repo.sha}\` (mode: auto): ${r.after.dg004Count}`);
      if (r.after.wsUnparsedDetails.length > 0) {
        console.log(`Unparsed Workspace Diagnostics (${r.after.wsUnparsedDetails.length}):`);
        r.after.wsUnparsedDetails.forEach((d) => console.log(`- ${d}`));
      }
      if (r.after.hits.length === 0) {
        console.log('None (0 DG004 findings).');
      } else {
        r.after.hits.forEach((h, idx) => {
          console.log(`${idx + 1}. \`${h.file}:${h.line}\` — ${h.message}`);
        });
      }
    }
  } finally {
    if (!keepTemp) {
      fs.rmSync(tempRoot, { recursive: true, force: true });
    }
  }
}

main();
