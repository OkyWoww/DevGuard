import { execFileSync } from 'node:child_process';

export type GitResolveResult =
  | { ok: true; files: string[]; repoRoot: string }
  | { ok: false; error: string };

const MAX_GIT_REF_LENGTH = 256;

/**
 * Validates a Git ref string before passing it to `execFileSync('git', ...)`.
 * Rejects leading dashes (preventing option/argument injection), whitespace,
 * control characters, and overly long refs.
 */
export function validateGitRef(ref: string): { ok: true; ref: string } | { ok: false; error: string } {
  if (typeof ref !== 'string' || ref.trim().length === 0) {
    return { ok: false, error: 'Git ref must be a non-empty string.' };
  }
  if (ref.length > MAX_GIT_REF_LENGTH) {
    return { ok: false, error: `Git ref exceeds maximum length (${MAX_GIT_REF_LENGTH}).` };
  }
  if (ref.startsWith('-')) {
    return { ok: false, error: `Rejected unsafe Git ref starting with "-": "${ref}"` };
  }
  if (/[\s\x00-\x1f\x7f]/.test(ref)) {
    return { ok: false, error: `Rejected unsafe Git ref containing whitespace or control characters: "${ref}"` };
  }
  return { ok: true, ref };
}

function runGitSafely(
  args: readonly string[],
  cwd: string
): { ok: true; stdout: string } | { ok: false; stderr: string } {
  try {
    const stdout = execFileSync('git', [...args], {
      cwd,
      encoding: 'utf-8',
      stdio: ['ignore', 'pipe', 'pipe'],
      timeout: 15000,
    });
    return { ok: true, stdout };
  } catch (err) {
    const errObj = err as { stderr?: string | Buffer; message?: string };
    const stderrText =
      typeof errObj?.stderr === 'string'
        ? errObj.stderr.trim()
        : Buffer.isBuffer(errObj?.stderr)
        ? errObj.stderr.toString('utf-8').trim()
        : errObj?.message || 'Git execution failed';
    return { ok: false, stderr: stderrText };
  }
}

export function resolveGitRepoRoot(cwd: string): { ok: true; repoRoot: string } | { ok: false; error: string } {
  const res = runGitSafely(['rev-parse', '--show-toplevel'], cwd);
  if (!res.ok || res.stdout.trim().length === 0) {
    return {
      ok: false,
      error: `Not inside a Git repository (${cwd}): ${res.ok ? 'empty toplevel' : res.stderr}`,
    };
  }
  return { ok: true, repoRoot: res.stdout.trim() };
}

function parseGitFileList(stdout: string): string[] {
  return stdout
    .split(/\r?\n/)
    .map((line) => line.trim().replace(/\\/g, '/'))
    .filter((line) => line.length > 0);
}

/**
 * Resolves staged files via `git diff --cached --name-only --diff-filter=ACMR --`.
 * Fails closed if `cwd` is not a Git repository.
 */
export function getStagedFiles(cwd: string): GitResolveResult {
  const rootRes = resolveGitRepoRoot(cwd);
  if (!rootRes.ok) {
    return { ok: false, error: rootRes.error };
  }

  const diffRes = runGitSafely(
    ['diff', '--cached', '--name-only', '--diff-filter=ACMR', '--'],
    rootRes.repoRoot
  );
  if (!diffRes.ok) {
    return { ok: false, error: `Failed to list staged files: ${diffRes.stderr}` };
  }

  return {
    ok: true,
    files: parseGitFileList(diffRes.stdout),
    repoRoot: rootRes.repoRoot,
  };
}

/**
 * Resolves files changed since `ref` via `git diff --name-only --diff-filter=ACMR <ref> --`.
 * Validates `ref` first and uses `execFileSync` with `--` separator to prevent argument injection.
 */
export function getChangedFilesSince(ref: string, cwd: string): GitResolveResult {
  const refCheck = validateGitRef(ref);
  if (!refCheck.ok) {
    return { ok: false, error: refCheck.error };
  }

  const rootRes = resolveGitRepoRoot(cwd);
  if (!rootRes.ok) {
    return { ok: false, error: rootRes.error };
  }

  const verifyRes = runGitSafely(['rev-parse', '--verify', refCheck.ref], rootRes.repoRoot);
  if (!verifyRes.ok) {
    return {
      ok: false,
      error: `Unknown or invalid Git ref "${refCheck.ref}": ${verifyRes.stderr}`,
    };
  }

  const diffRes = runGitSafely(
    ['diff', '--name-only', '--diff-filter=ACMR', refCheck.ref, '--'],
    rootRes.repoRoot
  );
  if (!diffRes.ok) {
    return {
      ok: false,
      error: `Failed to diff against "${refCheck.ref}": ${diffRes.stderr}`,
    };
  }

  return {
    ok: true,
    files: parseGitFileList(diffRes.stdout),
    repoRoot: rootRes.repoRoot,
  };
}
