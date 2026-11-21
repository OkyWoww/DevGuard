import { execFileSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { resolveGitRepoRoot } from './git.ts';

export const HOOK_BEGIN_MARKER = '# BEGIN DEVGUARD HOOK';
export const HOOK_END_MARKER = '# END DEVGUARD HOOK';

const HOOK_SNIPPET = [
  HOOK_BEGIN_MARKER,
  'if command -v devguard >/dev/null 2>&1; then',
  '  devguard check --staged',
  'elif [ -f "./dist/cli.js" ]; then',
  '  node ./dist/cli.js check --staged',
  'else',
  '  npx --no-install devguard check --staged',
  'fi',
  HOOK_END_MARKER,
].join('\n');

export type InstallHookStatus = 'created' | 'appended' | 'already-installed';

export type InstallHookResult =
  | { ok: true; hookPath: string; status: InstallHookStatus }
  | { ok: false; error: string };

function isSafeShellShebang(firstLine: string): boolean {
  const trimmed = firstLine.trim();
  if (!trimmed.startsWith('#!')) {
    return true;
  }
  return /^#!\s*(?:\/usr\/bin\/env\s+(?:-S\s+)?(?:sh|bash|dash|zsh)\b|\/(?:usr\/)?bin\/(?:sh|bash|dash|zsh)\b)/.test(
    trimmed
  );
}

function resolveHooksDirectory(repoRoot: string): { ok: true; hooksDir: string } | { ok: false; error: string } {
  try {
    const rawHooksPath = execFileSync('git', ['rev-parse', '--git-path', 'hooks'], {
      cwd: repoRoot,
      encoding: 'utf-8',
      stdio: ['ignore', 'pipe', 'pipe'],
      timeout: 10000,
    }).trim();
    if (!rawHooksPath) {
      return { ok: false, error: 'Git returned an empty hooks directory path.' };
    }
    const resolved = path.isAbsolute(rawHooksPath)
      ? rawHooksPath
      : path.resolve(repoRoot, rawHooksPath);
    return { ok: true, hooksDir: resolved };
  } catch (err) {
    return {
      ok: false,
      error: `Failed to resolve Git hooks directory: ${err instanceof Error ? err.message : String(err)}`,
    };
  }
}

function tryChmodExecutable(filePath: string): void {
  try {
    fs.chmodSync(filePath, 0o755);
  } catch {
    // On platforms without POSIX chmod bits, best-effort executable bit update
    return;
  }
}

/**
 * Installs a DevGuard pre-commit hook idempotently and non-destructively.
 * Refuses fail-closed if outside a Git repo, if the existing hook is non-shell/binary,
 * or if marker blocks are corrupted.
 */
export function installPreCommitHook(cwd: string): InstallHookResult {
  const rootRes = resolveGitRepoRoot(cwd);
  if (!rootRes.ok) {
    return { ok: false, error: rootRes.error };
  }

  const hooksDirRes = resolveHooksDirectory(rootRes.repoRoot);
  if (!hooksDirRes.ok) {
    return { ok: false, error: hooksDirRes.error };
  }

  const hookPath = path.join(hooksDirRes.hooksDir, 'pre-commit');
  fs.mkdirSync(hooksDirRes.hooksDir, { recursive: true });

  if (!fs.existsSync(hookPath)) {
    const content = `#!/bin/sh\nset -e\n\n${HOOK_SNIPPET}\n`;
    fs.writeFileSync(hookPath, content, { encoding: 'utf-8', mode: 0o755 });
    tryChmodExecutable(hookPath);
    return { ok: true, hookPath, status: 'created' };
  }

  let rawBuf: Buffer;
  try {
    rawBuf = fs.readFileSync(hookPath);
  } catch (err) {
    return {
      ok: false,
      error: `Unable to read existing pre-commit hook at "${hookPath}": ${err instanceof Error ? err.message : String(err)}`,
    };
  }

  if (rawBuf.includes(0)) {
    return {
      ok: false,
      error: `Refusing to modify binary pre-commit hook at "${hookPath}".`,
    };
  }

  const existing = rawBuf.toString('utf-8');
  const firstLine = existing.split(/\r?\n/, 1)[0] ?? '';
  if (!isSafeShellShebang(firstLine)) {
    return {
      ok: false,
      error: `Refusing to modify non-shell pre-commit hook ("${firstLine.trim()}") at "${hookPath}".`,
    };
  }

  const beginIdx = existing.indexOf(HOOK_BEGIN_MARKER);
  const endIdx = existing.indexOf(HOOK_END_MARKER);

  if ((beginIdx !== -1) !== (endIdx !== -1) || (beginIdx !== -1 && endIdx < beginIdx)) {
    return {
      ok: false,
      error: `Refusing to modify pre-commit hook at "${hookPath}": corrupted or unmatched DevGuard hook markers.`,
    };
  }

  if (beginIdx !== -1 && endIdx !== -1) {
    const afterEnd = endIdx + HOOK_END_MARKER.length;
    const updated = existing.slice(0, beginIdx) + HOOK_SNIPPET + existing.slice(afterEnd);
    if (updated !== existing) {
      fs.writeFileSync(hookPath, updated, { encoding: 'utf-8', mode: 0o755 });
    }
    tryChmodExecutable(hookPath);
    return { ok: true, hookPath, status: 'already-installed' };
  }

  const separator = existing.endsWith('\n') ? '\n' : '\n\n';
  const appended = `${existing}${separator}${HOOK_SNIPPET}\n`;
  fs.writeFileSync(hookPath, appended, { encoding: 'utf-8', mode: 0o755 });
  tryChmodExecutable(hookPath);
  return { ok: true, hookPath, status: 'appended' };
}
