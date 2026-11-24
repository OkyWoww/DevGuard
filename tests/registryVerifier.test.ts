import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import test from 'node:test';

import {
  encodeNpmPackagePath,
  isValidNpmPackageName,
  verifyPackageListAgainstNpm,
  type RegistryFetchFn,
} from '../src/core/rules/registryVerifier.ts';
import { parseCliArgs } from '../src/adapters/cli/args.ts';
import { runCli, runCliAsync } from '../src/adapters/cli/index.ts';
import { explainDevGuardRule } from '../src/adapters/mcp/rulesCatalog.ts';
import { createMcpSession } from '../src/adapters/mcp/protocol.ts';

const FIXED_NOW_MS = Date.parse('2026-11-24T12:00:00.000Z');
const DAY_MS = 86_400_000;

function isoDaysAgo(days: number): string {
  return new Date(FIXED_NOW_MS - days * DAY_MS).toISOString();
}

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

function makeCleanSafeTsSource(importLines: string[]): string {
  return [
    ...importLines,
    'export function computeSafeTotal(amount: number): number {',
    '  if (typeof amount !== "number" || !Number.isFinite(amount) || amount < 0) {',
    '    throw new TypeError("Invalid non-negative number");',
    '  }',
    '  try {',
    '    return amount + 1;',
    '  } catch (err) {',
    '    throw err;',
    '  }',
    '}',
  ].join('\n');
}

test('REG-1: Package name validation & scoped URL encoding block traversal and SSRF vectors', () => {
  assert.equal(isValidNpmPackageName('express'), true);
  assert.equal(isValidNpmPackageName('lodash.isequal'), true);
  assert.equal(isValidNpmPackageName('@google/genai'), true);
  assert.equal(isValidNpmPackageName('@types/node'), true);

  assert.equal(isValidNpmPackageName(''), false);
  assert.equal(isValidNpmPackageName(' express '), false);
  assert.equal(isValidNpmPackageName('../evil-pkg'), false);
  assert.equal(isValidNpmPackageName('@scope/../evil'), false);
  assert.equal(isValidNpmPackageName('pkg?token=secret'), false);
  assert.equal(isValidNpmPackageName('pkg#fragment'), false);
  assert.equal(isValidNpmPackageName('pkg%2f..'), false);
  assert.equal(isValidNpmPackageName('https://evil.example/pkg'), false);
  assert.equal(isValidNpmPackageName('a'.repeat(215)), false);

  assert.equal(encodeNpmPackagePath('express'), 'express');
  assert.equal(encodeNpmPackagePath('@google/genai'), '@google%2fgenai');
});

test('REG-2 (TP Suite): Detects 404, newly registered (<30d + postinstall), scoped slopsquat, 0.0.1-security, unpublished, npm: alias, and Pass-V folded imports', async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'devguard-reg-tp-'));
  try {
    fs.writeFileSync(
      path.join(tmpDir, 'package.json'),
      JSON.stringify(
        {
          name: 'demo-app',
          version: '1.0.0',
          dependencies: {
            'hallucinated-jwt-guard': '^1.0.0',
            'fresh-slop-helper': '^0.1.0',
            '@ai-slop/pay-sdk': '^1.0.0',
            'tombstoned-pkg': '^1.0.0',
            'vanished-pkg': '^1.0.0',
            'safe-looking-alias': 'npm:real-young-squat@^1.0.0',
            'slopsquat-folded': '^1.0.0',
          },
        },
        null,
        2
      ),
      'utf-8'
    );

    fs.mkdirSync(path.join(tmpDir, 'src'), { recursive: true });
    fs.writeFileSync(
      path.join(tmpDir, 'src', 'app.ts'),
      makeCleanSafeTsSource([
        "import guard from 'hallucinated-jwt-guard';",
        "import fresh from 'fresh-slop-helper';",
        "import sdk from '@ai-slop/pay-sdk/client';",
        "import tomb from 'tombstoned-pkg';",
        "import vanished from 'vanished-pkg';",
        "import aliased from 'safe-looking-alias';",
        "const folded = require('slopsquat-' + 'folded');",
        'void [guard, fresh, sdk, tomb, vanished, aliased, folded];',
      ]),
      'utf-8'
    );

    const requestedUrls: string[] = [];
    const mockFetch: RegistryFetchFn = async (url) => {
      requestedUrls.push(url);
      if (url.endsWith('/hallucinated-jwt-guard')) {
        return jsonResponse({ error: 'Not found' }, 404);
      }
      if (url.endsWith('/fresh-slop-helper')) {
        return jsonResponse({
          name: 'fresh-slop-helper',
          time: { created: isoDaysAgo(3) },
          'dist-tags': { latest: '0.1.0' },
          versions: {
            '0.1.0': {
              scripts: { postinstall: 'node setup.js' },
            },
          },
        });
      }
      if (url.endsWith('/@ai-slop%2fpay-sdk')) {
        return jsonResponse({
          name: '@ai-slop/pay-sdk',
          time: { created: isoDaysAgo(7) },
          'dist-tags': { latest: '1.0.0' },
          versions: { '1.0.0': {} },
        });
      }
      if (url.endsWith('/tombstoned-pkg')) {
        return jsonResponse({
          name: 'tombstoned-pkg',
          time: { created: isoDaysAgo(400) },
          'dist-tags': { latest: '0.0.1-security' },
          versions: { '0.0.1-security': {} },
        });
      }
      if (url.endsWith('/vanished-pkg')) {
        return jsonResponse({
          name: 'vanished-pkg',
          time: { created: isoDaysAgo(500), unpublished: { time: isoDaysAgo(2) } },
          versions: {},
        });
      }
      if (url.endsWith('/real-young-squat')) {
        return jsonResponse({
          name: 'real-young-squat',
          time: { created: isoDaysAgo(1) },
          'dist-tags': { latest: '1.0.0' },
          versions: { '1.0.0': {} },
        });
      }
      if (url.endsWith('/slopsquat-folded')) {
        return jsonResponse({ error: 'Not found' }, 404);
      }
      throw new Error(`Unexpected URL in mockFetch: ${url}`);
    };

    let stdout = '';
    let stderr = '';
    const exitCode = await runCliAsync(['check', 'src/app.ts', '--verify-registry', '--format', 'json'], {
      cwd: tmpDir,
      stdout: (s) => {
        stdout += s;
      },
      stderr: (s) => {
        stderr += s;
      },
      fetchImpl: mockFetch,
      registryOptions: { nowMs: FIXED_NOW_MS },
    });

    // Non-scoring INV-8: exit code MUST stay 0 on otherwise clean file!
    assert.equal(exitCode, 0, `Expected non-scoring exit 0, stderr: ${stderr}`);
    assert.ok(!requestedUrls.some((u) => u.includes('safe-looking-alias')), 'Must unwrap npm: alias target');
    assert.equal(requestedUrls.length, 7);

    const parsed = JSON.parse(stdout) as {
      passed: boolean;
      overallScore: number;
      files: Array<{
        filePath: string;
        inlineFindings?: Array<{
          ruleId: string;
          line: number;
          severity: string;
          scoring?: boolean;
          message: string;
        }>;
      }>;
    };

    assert.equal(parsed.passed, true);
    assert.ok(parsed.overallScore >= 85);
    const regFindings = (parsed.files[0].inlineFindings ?? []).filter((f) => f.ruleId === 'DG004-REG-01');
    assert.equal(regFindings.length, 7);
    for (const f of regFindings) {
      assert.equal(f.severity, 'warning');
      assert.equal(f.scoring, false);
    }

    // Proportional heads-up narrative check (not alarmist accusation)
    const freshMsg = regFindings.find((f) => f.line === 2)?.message ?? '';
    assert.ok(freshMsg.includes('published recently on npm (3 day(s) ago, 1 version(s), defines postinstall lifecycle script)'));
    assert.ok(freshMsg.includes('verify publisher identity'));
    assert.equal(regFindings.find((f) => f.line === 1)?.message.includes('HTTP 404'), true);
    assert.equal(regFindings.find((f) => f.line === 3)?.line, 3);
    assert.equal(regFindings.find((f) => f.line === 4)?.message.includes('0.0.1-security'), true);
    assert.equal(regFindings.find((f) => f.line === 5)?.message.includes('unpublished'), true);
    assert.equal(regFindings.find((f) => f.line === 6)?.message.includes('real-young-squat'), true);
    assert.equal(regFindings.find((f) => f.line === 7)?.line, 7);
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('REG-3 (INV-8 TN Suite >=6 Cases): Excludes established packages, scoped packages, workspace:*, file:, link:, git+, builtins, tsconfig/#subpath, and benign deprecations', async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'devguard-reg-tn-'));
  try {
    fs.writeFileSync(
      path.join(tmpDir, 'pnpm-workspace.yaml'),
      'packages:\n  - "packages/*"\n',
      'utf-8'
    );
    fs.writeFileSync(
      path.join(tmpDir, 'tsconfig.json'),
      JSON.stringify({
        compilerOptions: {
          baseUrl: '.',
          paths: {
            '@internal/*': ['src/internal/*'],
          },
        },
      }),
      'utf-8'
    );
    fs.writeFileSync(
      path.join(tmpDir, 'package.json'),
      JSON.stringify(
        {
          name: 'acme-monorepo-root',
          private: true,
          imports: {
            '#local/*': './src/local/*.ts',
          },
          dependencies: {
            express: '^4.21.0',
            '@prisma/client': '^5.0.0',
            'legacy-deprecated-lib': '^2.0.0',
            '@acme/shared': 'workspace:*',
            'local-file-pkg': 'file:./vendor/local-file-pkg',
            'local-link-pkg': 'link:./vendor/local-link-pkg',
            'git-dep-pkg': 'git+https://github.com/example/repo.git',
            'tarball-pkg': 'https://example.com/pkg-1.0.0.tgz',
          },
        },
        null,
        2
      ),
      'utf-8'
    );

    fs.mkdirSync(path.join(tmpDir, 'packages', 'shared'), { recursive: true });
    fs.writeFileSync(
      path.join(tmpDir, 'packages', 'shared', 'package.json'),
      JSON.stringify({ name: '@acme/shared', version: '1.0.0' }),
      'utf-8'
    );

    fs.mkdirSync(path.join(tmpDir, 'src', 'internal'), { recursive: true });
    fs.mkdirSync(path.join(tmpDir, 'src', 'local'), { recursive: true });
    fs.writeFileSync(path.join(tmpDir, 'src', 'internal', 'util.ts'), 'export const u = 1;\n', 'utf-8');
    fs.writeFileSync(path.join(tmpDir, 'src', 'local', 'cfg.ts'), 'export const c = 2;\n', 'utf-8');

    fs.writeFileSync(
      path.join(tmpDir, 'src', 'service.ts'),
      makeCleanSafeTsSource([
        "import * as fs from 'node:fs';", // TN-1: prefixed Node builtin
        "import path from 'path';", // TN-2: bare Node builtin
        "import express from 'express';", // TN-3: established unscoped package (>30d)
        "import { PrismaClient } from '@prisma/client/edge';", // TN-4: established scoped subpath package (>30d)
        "import legacy from 'legacy-deprecated-lib';", // TN-5: benign deprecation on established package
        "import { shared } from '@acme/shared';", // TN-6: workspace internal package / workspace:*
        "import filePkg from 'local-file-pkg';", // TN-7: file: protocol
        "import linkPkg from 'local-link-pkg';", // TN-8: link: protocol
        "import gitPkg from 'git-dep-pkg';", // TN-9: git+ protocol
        "import { u } from '@internal/util';", // TN-10: tsconfig paths alias
        "import { c } from '#local/cfg';", // TN-11: package.json #subpath import
        'void [fs, path, express, PrismaClient, legacy, shared, filePkg, linkPkg, gitPkg, u, c];',
      ]),
      'utf-8'
    );

    const queriedPackages: string[] = [];
    const mockFetch: RegistryFetchFn = async (url) => {
      queriedPackages.push(url);
      if (url.endsWith('/express')) {
        return jsonResponse({
          name: 'express',
          time: { created: '2010-12-29T19:38:25.450Z' },
          'dist-tags': { latest: '4.21.2' },
          versions: { '4.21.2': {} },
        });
      }
      if (url.endsWith('/@prisma%2fclient')) {
        return jsonResponse({
          name: '@prisma/client',
          time: { created: '2020-03-31T10:00:00.000Z' },
          'dist-tags': { latest: '5.20.0' },
          versions: { '5.20.0': {} },
        });
      }
      if (url.endsWith('/legacy-deprecated-lib')) {
        return jsonResponse({
          name: 'legacy-deprecated-lib',
          time: { created: isoDaysAgo(800) },
          'dist-tags': { latest: '2.0.0' },
          versions: {
            '2.0.0': {
              deprecated: 'Package renamed; please migrate to modern-lib v3.',
            },
          },
        });
      }
      throw new Error(`Unexpected registry fetch for excluded dependency: ${url}`);
    };

    let stdout = '';
    const code = await runCliAsync(['check', 'src/service.ts', '--verify-registry', '--format', 'json'], {
      cwd: tmpDir,
      stdout: (s) => {
        stdout += s;
      },
      fetchImpl: mockFetch,
      registryOptions: { nowMs: FIXED_NOW_MS },
    });

    assert.equal(code, 0);
    // ONLY the 3 real external npm packages were queried; 0 calls for workspace/file/link/git/builtins/tsconfig/#subpath!
    assert.equal(queriedPackages.length, 3);
    const parsed = JSON.parse(stdout) as {
      passed: boolean;
      workspaceDiagnostics: unknown[];
      files: Array<{ inlineFindings?: Array<{ ruleId: string }> }>;
    };
    assert.equal(parsed.passed, true);
    assert.equal(parsed.workspaceDiagnostics.length, 0);
    const regHits = (parsed.files[0].inlineFindings ?? []).filter((f) => f.ruleId.startsWith('DG004-REG'));
    assert.equal(regHits.length, 0);
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('REG-4 (INV-6 Allowlist & Inline Suppression Guard): .devguard.json suppresses DG004-REG-01 while inline comment is rejected', async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'devguard-reg-sup-'));
  try {
    fs.writeFileSync(
      path.join(tmpDir, 'package.json'),
      JSON.stringify({
        name: 'sup-test',
        dependencies: {
          'private-artifactory-pkg': '^1.0.0',
          'inline-bypass-pkg': '^1.0.0',
        },
      }),
      'utf-8'
    );
    fs.writeFileSync(
      path.join(tmpDir, '.devguard.json'),
      JSON.stringify({
        ignoreRulesByPath: {
          'src/allowed.ts': [
            {
              rule: 'DG004-REG-01',
              reason: 'Hosted on internal Artifactory registry mirror',
            },
          ],
        },
      }),
      'utf-8'
    );
    fs.mkdirSync(path.join(tmpDir, 'src'), { recursive: true });
    fs.writeFileSync(
      path.join(tmpDir, 'src', 'allowed.ts'),
      makeCleanSafeTsSource(["import priv from 'private-artifactory-pkg';", 'void priv;']),
      'utf-8'
    );
    fs.writeFileSync(
      path.join(tmpDir, 'src', 'bypass.ts'),
      makeCleanSafeTsSource([
        '// devguard-ignore DG004-REG-01: developer tries inline suppression',
        "import bypass from 'inline-bypass-pkg';",
        'void bypass;',
      ]),
      'utf-8'
    );

    const mockFetch: RegistryFetchFn = async () => jsonResponse({ error: 'Not found' }, 404);

    let sarifOut = '';
    const exitCode = await runCliAsync(['check', 'src', '--verify-registry', '--format', 'sarif'], {
      cwd: tmpDir,
      stdout: (s) => {
        sarifOut += s;
      },
      fetchImpl: mockFetch,
      registryOptions: { nowMs: FIXED_NOW_MS },
    });

    assert.equal(exitCode, 0);
    const sarif = JSON.parse(sarifOut) as {
      runs: Array<{
        results: Array<{
          ruleId: string;
          message: { text: string };
          suppressions?: Array<{ kind: string; justification: string }>;
          properties?: { scoring?: boolean };
        }>;
      }>;
    };
    const regResults = sarif.runs[0].results.filter((r) => r.ruleId === 'DG004-REG-01');
    assert.equal(regResults.length, 2);

    const suppressedItem = regResults.find((r) => Array.isArray(r.suppressions) && r.suppressions.length > 0);
    assert.ok(suppressedItem, 'Expected external .devguard.json suppression in SARIF');
    assert.equal(suppressedItem.suppressions?.[0].kind, 'external');
    assert.equal(suppressedItem.properties?.scoring, false);

    const unsuppressedItem = regResults.find((r) => !r.suppressions);
    assert.ok(unsuppressedItem, 'Expected inline suppression attempt to remain active');
    assert.ok(
      unsuppressedItem.message.text.includes('[Suppression ignored: DG004-REG-01 cannot be suppressed inline]')
    );
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('REG-5 (INV-7 Fail-Safe, Dual Timeouts, Bounded Concurrency, Stream Cap, & Non-Blocking Exit 0)', async () => {
  // 5a. Concurrency cap (maxInFlight <= 4 when concurrency: 4 across 16 packages) + deterministic ordering
  const manyPkgs = Array.from({ length: 16 }, (_, idx) => `pkg-${String(idx).padStart(2, '0')}`);
  let inFlight = 0;
  let maxObservedInFlight = 0;

  const concOutcomes = await verifyPackageListAgainstNpm(manyPkgs, {
    concurrency: 4,
    nowMs: FIXED_NOW_MS,
    fetchImpl: async (url) => {
      inFlight++;
      if (inFlight > maxObservedInFlight) {
        maxObservedInFlight = inFlight;
      }
      await new Promise((resolve) => setTimeout(resolve, 12));
      inFlight--;
      return jsonResponse({
        name: url.split('/').pop(),
        time: { created: isoDaysAgo(120) },
        versions: { '1.0.0': {} },
      });
    },
  });

  assert.equal(inFlight, 0);
  assert.ok(maxObservedInFlight <= 4, `Expected maxInFlight <= 4, got ${maxObservedInFlight}`);
  assert.equal(concOutcomes.size, 16);

  // 5b. Per-request timeout, 429, 503, 401 private registry, network reject, malformed JSON, & oversized stream
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'devguard-reg-resilience-'));
  try {
    fs.writeFileSync(
      path.join(tmpDir, 'package.json'),
      JSON.stringify({
        name: 'resilience-app',
        dependencies: {
          'pkg-timeout': '^1.0.0',
          'pkg-429': '^1.0.0',
          'pkg-503': '^1.0.0',
          'pkg-401': '^1.0.0',
          'pkg-neterr': '^1.0.0',
          'pkg-badjson': '^1.0.0',
          'pkg-oversized': '^1.0.0',
        },
      }),
      'utf-8'
    );
    fs.mkdirSync(path.join(tmpDir, 'src'), { recursive: true });
    fs.writeFileSync(
      path.join(tmpDir, 'src', 'index.ts'),
      makeCleanSafeTsSource([
        "import a from 'pkg-timeout';",
        "import b from 'pkg-429';",
        "import c from 'pkg-503';",
        "import d from 'pkg-401';",
        "import e from 'pkg-neterr';",
        "import f from 'pkg-badjson';",
        "import g from 'pkg-oversized';",
        'void [a, b, c, d, e, f, g];',
      ]),
      'utf-8'
    );

    const mockFailures: RegistryFetchFn = async (url, init) => {
      if (url.endsWith('/pkg-timeout')) {
        return await new Promise<Response>((_resolve, reject) => {
          const sig = init?.signal;
          if (sig?.aborted) {
            const err = new Error('Aborted');
            err.name = 'AbortError';
            reject(err);
            return;
          }
          sig?.addEventListener(
            'abort',
            () => {
              const err = new Error('Aborted');
              err.name = 'AbortError';
              reject(err);
            },
            { once: true }
          );
        });
      }
      if (url.endsWith('/pkg-429')) {
        return new Response('Too Many Requests', { status: 429 });
      }
      if (url.endsWith('/pkg-503')) {
        return new Response('Service Unavailable', { status: 503 });
      }
      if (url.endsWith('/pkg-401')) {
        return new Response('Unauthorized', { status: 401 });
      }
      if (url.endsWith('/pkg-neterr')) {
        throw new TypeError('fetch failed: ENOTFOUND registry.npmjs.org');
      }
      if (url.endsWith('/pkg-badjson')) {
        return new Response('{corrupt-json', { status: 200 });
      }
      if (url.endsWith('/pkg-oversized')) {
        const hugePayload = new Uint8Array(8_192).fill(65);
        return new Response(hugePayload, { status: 200 });
      }
      throw new Error(`Unexpected URL: ${url}`);
    };

    let sarifText = '';
    const code = await runCliAsync(['check', 'src/index.ts', '--verify-registry', '--format', 'sarif'], {
      cwd: tmpDir,
      stdout: (s) => {
        sarifText += s;
      },
      fetchImpl: mockFailures,
      registryOptions: {
        nowMs: FIXED_NOW_MS,
        perRequestTimeoutMs: 40,
        totalTimeoutMs: 5_000,
        maxResponseBytes: 2_048,
      },
    });

    // Non-blocking guarantee: clean code exits 0 even when every registry request fails!
    assert.equal(code, 0);
    const sarif = JSON.parse(sarifText) as {
      runs: Array<{
        invocations: Array<{ executionSuccessful: boolean }>;
        results: Array<{ ruleId: string; properties?: { scoring?: boolean; reason?: string }; message: { text: string } }>;
      }>;
    };
    assert.equal(sarif.runs[0].invocations[0].executionSuccessful, true);

    const unreachable = sarif.runs[0].results.filter((r) => r.ruleId === 'DG004-REG-UNREACHABLE');
    assert.equal(unreachable.length, 7);
    const reasons = new Set(unreachable.map((u) => u.properties?.reason));
    assert.deepEqual(
      reasons,
      new Set(['timeout', 'rate_limited', 'http_error', 'network_error', 'invalid_response', 'response_too_large'])
    );
    assert.ok(
      unreachable.some((u) => u.message.text.includes('without .npmrc credentials')),
      '401/403 notice must mention public registry / .npmrc privacy'
    );
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }

  // 5c. Total run wall-clock budget (run_timeout)
  const budgetOutcomes = await verifyPackageListAgainstNpm(['slow-a', 'slow-b', 'slow-c'], {
    concurrency: 1,
    perRequestTimeoutMs: 2_000,
    totalTimeoutMs: 35,
    fetchImpl: async (_url, init) =>
      await new Promise<Response>((_resolve, reject) => {
        init?.signal?.addEventListener(
          'abort',
          () => {
            const err = new Error('Run budget aborted');
            err.name = 'AbortError';
            reject(err);
          },
          { once: true }
        );
      }),
  });
  assert.equal(budgetOutcomes.get('slow-a')?.kind, 'unreachable');
  assert.equal(
    (budgetOutcomes.get('slow-b') as { reason?: string })?.reason,
    'run_timeout'
  );
});

test('REG-6 (INV-2, INV-5, SPOF #1, & §8.3 MCP Offline Guarantee): Default OFF parity, sync runCli guard, and MCP isolation', async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'devguard-reg-parity-'));
  try {
    fs.writeFileSync(
      path.join(tmpDir, 'package.json'),
      JSON.stringify({ name: 'parity-app', dependencies: { 'unverified-pkg': '^1.0.0' } }),
      'utf-8'
    );
    const file = path.join(tmpDir, 'clean.ts');
    fs.writeFileSync(
      file,
      makeCleanSafeTsSource(["import u from 'unverified-pkg';", 'void u;']),
      'utf-8'
    );

    let fetchCount = 0;
    const forbiddenFetch: RegistryFetchFn = async () => {
      fetchCount++;
      throw new Error('fetch must NEVER be called when --verify-registry is omitted');
    };

    for (const fmt of ['text', 'json', 'sarif'] as const) {
      let syncOut = '';
      let asyncOut = '';
      const syncCode = runCli(['check', 'clean.ts', '--format', fmt], {
        cwd: tmpDir,
        stdout: (s) => {
          syncOut += s;
        },
        fetchImpl: forbiddenFetch,
      });
      const asyncCode = await runCliAsync(['check', 'clean.ts', '--format', fmt], {
        cwd: tmpDir,
        stdout: (s) => {
          asyncOut += s;
        },
        fetchImpl: forbiddenFetch,
      });
      assert.equal(syncCode, 0);
      assert.equal(asyncCode, 0);
      assert.equal(asyncOut, syncOut, `Byte-for-byte parity failed for format=${fmt}`);
    }
    assert.equal(fetchCount, 0);

    // SPOF #1: Calling synchronous runCli() with --verify-registry fails closed with exit 2
    let syncErr = '';
    const syncRegCode = runCli(['check', 'clean.ts', '--verify-registry'], {
      cwd: tmpDir,
      stderr: (s) => {
        syncErr += s;
      },
    });
    assert.equal(syncRegCode, 2);
    assert.ok(syncErr.includes('runCliAsync'));

    // CLI flag validation: --verify-registry=true rejected, mcp --verify-registry rejected
    const badInline = parseCliArgs(['check', '--verify-registry=true']);
    assert.equal(badInline.kind, 'error');
    const badMcp = parseCliArgs(['mcp', '--verify-registry']);
    assert.equal(badMcp.kind, 'error');

    // MCP rulesCatalog explains DG004-REG-01 & DG004-REG-UNREACHABLE offline, while MCP session rejects unknown args
    const explainedReg = explainDevGuardRule('DG004-REG-01');
    assert.equal(explainedReg.found, true);
    const explainedUnreach = explainDevGuardRule('DG004-REG-UNREACHABLE');
    assert.equal(explainedUnreach.found, true);

    const session = createMcpSession(tmpDir);
    const initRes = session.handleRawLine(
      JSON.stringify({
        jsonrpc: '2.0',
        id: 1,
        method: 'initialize',
        params: { protocolVersion: '2025-11-25' },
      })
    );
    assert.ok(initRes && !initRes.error);

    const mcpCallRes = session.handleRawLine(
      JSON.stringify({
        jsonrpc: '2.0',
        id: 2,
        method: 'tools/call',
        params: {
          name: 'devguard_check_files',
          arguments: { paths: ['clean.ts'], verify_registry: true },
        },
      })
    );
    const mcpPayload = mcpCallRes?.result as { isError?: boolean; content: Array<{ text: string }> };
    assert.equal(mcpPayload.isError, true);
    assert.ok(mcpPayload.content[0].text.includes('Unknown argument(s): verify_registry'));
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('REG-7: Directory scan checks unimported manifest dependencies while explicit single-file scan only checks file imports', async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'devguard-reg-manifest-scope-'));
  try {
    fs.writeFileSync(
      path.join(tmpDir, 'package.json'),
      JSON.stringify({
        name: 'manifest-scope-app',
        dependencies: {
          'unimported-hallucinated-pkg': '^1.0.0',
          '@local/ws': 'workspace:*',
        },
      }),
      'utf-8'
    );
    fs.mkdirSync(path.join(tmpDir, 'src'), { recursive: true });
    fs.writeFileSync(
      path.join(tmpDir, 'src', 'clean.ts'),
      makeCleanSafeTsSource([]),
      'utf-8'
    );

    let singleFileFetchCalls = 0;
    const singleCode = await runCliAsync(['check', 'src/clean.ts', '--verify-registry', '--format', 'json'], {
      cwd: tmpDir,
      stdout: () => {},
      fetchImpl: async () => {
        singleFileFetchCalls++;
        return jsonResponse({}, 404);
      },
    });
    assert.equal(singleCode, 0);
    assert.equal(singleFileFetchCalls, 0, 'Explicit single-file check with 0 imports must make 0 fetch calls');

    let dirFetchUrls: string[] = [];
    let dirOut = '';
    const dirCode = await runCliAsync(['check', '--verify-registry', '--format', 'json'], {
      cwd: tmpDir,
      stdout: (s) => {
        dirOut += s;
      },
      fetchImpl: async (url) => {
        dirFetchUrls.push(url);
        return jsonResponse({ error: 'Not found' }, 404);
      },
      registryOptions: { nowMs: FIXED_NOW_MS },
    });
    assert.equal(dirCode, 0);
    assert.deepEqual(dirFetchUrls, ['https://registry.npmjs.org/unimported-hallucinated-pkg']);
    const parsedDir = JSON.parse(dirOut) as {
      passed: boolean;
      workspaceDiagnostics: Array<{ ruleId: string; sourceFile: string; scoring: boolean }>;
    };
    assert.equal(parsedDir.passed, true);
    assert.equal(parsedDir.workspaceDiagnostics.length, 1);
    assert.equal(parsedDir.workspaceDiagnostics[0].ruleId, 'DG004-REG-01');
    assert.equal(parsedDir.workspaceDiagnostics[0].sourceFile, 'package.json');
    assert.equal(parsedDir.workspaceDiagnostics[0].scoring, false);
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});
