import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import { builtinModules } from 'node:module';
import * as os from 'node:os';
import * as path from 'node:path';
import { performance } from 'node:perf_hooks';
import process from 'node:process';

import {
  analyzeCodeDeterministically,
  type AliasBailoutReason,
} from '../src/core/analyzer.ts';

interface PinnedCorpusRepo {
  name: string;
  url: string;
  sha: string;
}

const PINNED_REPOS: readonly PinnedCorpusRepo[] = [
  { name: 'nestjs/nest', url: 'https://github.com/nestjs/nest.git', sha: 'bbbfaf1' },
  { name: 'vitejs/vite', url: 'https://github.com/vitejs/vite.git', sha: 'ef295d5' },
  { name: 'tj/commander.js', url: 'https://github.com/tj/commander.js.git', sha: 'a5a7dc0' },
];

const IGNORED_DIRS = new Set([
  'node_modules',
  '.git',
  'dist',
  '.test-dist',
  'build',
  'coverage',
  'out',
  'fixtures',
  '__fixtures__',
]);

interface AliasHit {
  repo: string;
  file: string;
  line: number;
  ruleId: 'DG001-ALIAS-01' | 'DG005-ALIAS-01';
  message: string;
}

interface RepoEvalSummary {
  name: string;
  filesScanned: number;
  wallClockMs: number;
  dg001AliasCount: number;
  dg005AliasCount: number;
  bailoutsByReason: Record<AliasBailoutReason, number>;
  hits: AliasHit[];
}

function collectJsTsFiles(rootDir: string): string[] {
  const results: string[] = [];
  const walk = (entry: string): void => {
    if (!fs.existsSync(entry)) return;
    let stat: fs.Stats;
    try {
      stat = fs.lstatSync(entry);
    } catch {
      return;
    }
    if (stat.isSymbolicLink()) return;
    if (stat.isFile()) {
      if (/\.(?:ts|tsx|js|jsx|mjs|cjs|mts|cts)$/.test(entry) && !entry.endsWith('.d.ts')) {
        if (stat.size <= 1024 * 1024) {
          results.push(entry);
        }
      }
      return;
    }
    if (!stat.isDirectory()) return;
    const entries = fs
      .readdirSync(entry, { withFileTypes: true })
      .sort((a, b) => a.name.localeCompare(b.name));
    for (const item of entries) {
      if (IGNORED_DIRS.has(item.name)) continue;
      walk(path.join(entry, item.name));
    }
  };
  walk(path.resolve(rootDir));
  return results;
}

function evaluateDirectory(name: string, rootDir: string): RepoEvalSummary {
  const t0 = performance.now();
  const files = collectJsTsFiles(rootDir);
  const hits: AliasHit[] = [];
  let dg001AliasCount = 0;
  let dg005AliasCount = 0;
  const bailoutsByReason: Record<AliasBailoutReason, number> = {
    reassigned_binding: 0,
    complex_destructuring: 0,
    cross_function_alias: 0,
    depth_exceeded: 0,
  };

  for (const absPath of files) {
    const code = fs.readFileSync(absPath, 'utf-8');
    const relPosix = path.relative(rootDir, absPath).replace(/\\/g, '/');
    const ft0 = performance.now();
    const report = analyzeCodeDeterministically(code, {
      filePath: absPath,
      builtinModules,
      workspacesMode: 'off',
    });
    const ftMs = performance.now() - ft0;
    if (ftMs > 500) {
      console.error(`[alias-corpus-eval] SLOW FILE (${ftMs.toFixed(1)} ms): ${name}/${relPosix}`);
    }

    for (const f of report.inlineFindings ?? []) {
      if (f.ruleId === 'DG001-ALIAS-01' || f.ruleId === 'DG005-ALIAS-01') {
        if (f.ruleId === 'DG001-ALIAS-01') dg001AliasCount++;
        else dg005AliasCount++;
        hits.push({
          repo: name,
          file: relPosix,
          line: f.line,
          ruleId: f.ruleId,
          message: f.message,
        });
      }
    }

    for (const b of report.aliasBailouts ?? []) {
      bailoutsByReason[b.reason] = (bailoutsByReason[b.reason] ?? 0) + 1;
    }
  }

  return {
    name,
    filesScanned: files.length,
    wallClockMs: performance.now() - t0,
    dg001AliasCount,
    dg005AliasCount,
    bailoutsByReason,
    hits,
  };
}

async function resolveFullSha(repo: PinnedCorpusRepo): Promise<string | null> {
  if (/^[0-9a-f]{40}$/i.test(repo.sha)) return repo.sha;
  try {
    const res = await fetch(`https://api.github.com/repos/${repo.name}/commits/${repo.sha}`, {
      headers: { Accept: 'application/vnd.github.sha', 'User-Agent': 'DevGuard-Corpus-Eval' },
      signal: AbortSignal.timeout(10000),
    });
    if (!res.ok) return null;
    const text = (await res.text()).trim();
    return /^[0-9a-f]{40}$/i.test(text) ? text : null;
  } catch {
    return null;
  }
}

async function clonePinnedRepo(repo: PinnedCorpusRepo, baseTempDir: string): Promise<string> {
  const safeName = repo.name.replace(/[^a-zA-Z0-9_-]/g, '_');
  const repoDir = path.join(baseTempDir, safeName);
  const runGit = (args: string[], cwd: string) => {
    const res = spawnSync('git', args, { cwd, encoding: 'utf-8' });
    if (res.status !== 0) {
      throw new Error(`git ${args.join(' ')} failed (${res.status}): ${res.stderr || res.stdout}`);
    }
  };
  const fullSha = await resolveFullSha(repo);
  if (fullSha) {
    fs.mkdirSync(repoDir, { recursive: true });
    runGit(['init', '-q'], repoDir);
    runGit(['remote', 'add', 'origin', repo.url], repoDir);
    runGit(['fetch', '--depth', '1', 'origin', fullSha], repoDir);
    runGit(['checkout', '-q', 'FETCH_HEAD'], repoDir);
    return repoDir;
  }
  runGit(['clone', '--filter=blob:none', '--no-checkout', repo.url, repoDir], baseTempDir);
  runGit(['checkout', '-q', repo.sha], repoDir);
  return repoDir;
}

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  const useExternal = args.includes('--external');
  const customDirs = args.filter((a) => !a.startsWith('--'));
  const summaries: RepoEvalSummary[] = [];

  if (useExternal) {
    const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'devguard-alias-corpus-'));
    try {
      for (const repo of PINNED_REPOS) {
        console.error(`[alias-corpus-eval] Cloning ${repo.name}@${repo.sha}...`);
        const repoDir = await clonePinnedRepo(repo, tempRoot);
        console.error(`[alias-corpus-eval] Cloned ${repo.name}@${repo.sha}; scanning...`);
        summaries.push(evaluateDirectory(`${repo.name}@${repo.sha}`, repoDir));
      }
    } finally {
      fs.rmSync(tempRoot, { recursive: true, force: true });
    }
  } else {
    const targets = customDirs.length > 0 ? customDirs : ['src'];
    for (const dir of targets) {
      summaries.push(evaluateDirectory(dir, path.resolve(dir)));
    }
  }

  console.log('# Stage 9.3 Alias Tracking Corpus Evaluation (A9-3)');
  console.log('');
  console.log('| Target | Files | DG001-ALIAS-01 | DG005-ALIAS-01 | Bailouts (reassign/destr/cross-fn/depth) | Time (ms) |');
  console.log('| :--- | :---: | :---: | :---: | :---: | :---: |');
  for (const s of summaries) {
    const b = s.bailoutsByReason;
    const bailSummary = `${b.reassigned_binding}/${b.complex_destructuring}/${b.cross_function_alias}/${b.depth_exceeded}`;
    console.log(
      `| ${s.name} | ${s.filesScanned} | ${s.dg001AliasCount} | ${s.dg005AliasCount} | ${bailSummary} | ${s.wallClockMs.toFixed(1)} |`
    );
  }

  const allHits = summaries.flatMap((s) => s.hits);
  console.log('');
  console.log(`## Detailed Findings for Triage (Total: ${allHits.length})`);
  if (allHits.length === 0) {
    console.log('- None (0 findings — 0% raw hit rate on scanned clean targets).');
  } else {
    allHits.forEach((h, idx) => {
      console.log(`${idx + 1}. \`${h.repo} :: ${h.file}:${h.line}\` [${h.ruleId}] (triage: unreviewed) — ${h.message}`);
    });
  }
}

void main().catch((err) => {
  console.error(err);
  process.exit(1);
});
