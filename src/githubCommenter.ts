import * as fs from 'node:fs';
import * as path from 'node:path';
import {
  redactSecretsPreservingLayout,
  type InlineFinding,
  type ParsedSuppression,
} from './devguardAnalyzer.js';

export interface PrEnvironmentInfo {
  isPullRequest: boolean;
  isFork: boolean;
  prNumber?: number;
}

export function detectPrEnvironment(eventPayload: unknown): PrEnvironmentInfo {
  if (!eventPayload || typeof eventPayload !== 'object') {
    return { isPullRequest: false, isFork: false };
  }
  const payload = eventPayload as {
    pull_request?: {
      number?: number;
      head?: { repo?: { full_name?: string } | null } | null;
    } | null;
    repository?: { full_name?: string } | null;
  };

  const pr = payload.pull_request;
  if (!pr || typeof pr !== 'object') {
    return { isPullRequest: false, isFork: false };
  }

  const headFullName = pr.head?.repo?.full_name;
  const baseFullName = payload.repository?.full_name;
  const isFork = !headFullName || !baseFullName || headFullName !== baseFullName;

  return {
    isPullRequest: true,
    isFork,
    prNumber: typeof pr.number === 'number' ? pr.number : undefined,
  };
}

export function formatLayer2StatusLabel(status?: string, mode?: 'HYBRID' | 'OFFLINE_AST'): string {
  if (status) {
    if (status.startsWith('Layer 2 (Gemini):')) return status;
    if (status === 'Verified' || status === 'Executed: Redacted') return 'Layer 2 (Gemini): Verified';
    if (status === 'Skipped: Offline') return 'Layer 2 (Gemini): Skipped [Offline]';
    if (status === 'Skipped: No API Key' || status.startsWith('Skipped: Offline')) {
      return 'Layer 2 (Gemini): Skipped [No API Key]';
    }
    if (status === 'Skipped: Fork PR') return 'Layer 2 (Gemini): Skipped [Fork PR]';
    if (status === 'Skipped: Quota/Error Fallback' || status === 'Skipped: Gemini API Error Fallback') {
      return 'Layer 2 (Gemini): Skipped [Quota/Error Fallback]';
    }
    if (status === 'Skipped: Redaction Abort') return 'Layer 2 (Gemini): Skipped [Redaction Abort]';
    if (status.startsWith('Skipped [')) return `Layer 2 (Gemini): ${status}`;
    if (status.startsWith('Skipped: ')) {
      return `Layer 2 (Gemini): Skipped [${status.slice('Skipped: '.length)}]`;
    }
  }
  return mode === 'HYBRID' ? 'Layer 2 (Gemini): Verified' : 'Layer 2 (Gemini): Skipped [No API Key]';
}

export type SkippedReason =
  | 'unsupported_language'
  | 'file_too_large'
  | 'parse_error'
  | 'internal_error';

export interface SkippedFileReportItem {
  filePath: string;
  reason: SkippedReason;
}

export interface PrCoverageSummary {
  analyzedCount: number;
  skippedFiles: SkippedFileReportItem[];
  ignoredNonCodeCount: number;
  ignoredDeletedCount?: number;
  overallScore?: number | null;
  failOnUnanalyzable?: boolean;
  maxSkippedDisplay?: number;
}

export const MAX_PR_SKIPPED_FILES_DISPLAY = 20;

/** Formats canonical human-readable skipped reason text per DevGuard v1.3.0 spec. */
export function formatSkippedReasonText(reason: SkippedReason): string {
  switch (reason) {
    case 'unsupported_language':
      return 'Skipped: Unsupported language';
    case 'file_too_large':
      return 'Skipped: File too large (> 1 MiB)';
    case 'parse_error':
      return 'Skipped: Parse error';
    case 'internal_error':
      return 'Skipped: Internal error';
  }
}

export interface FileAuditSummary {
  filePath: string;
  security: number;
  correctness: number;
  maintainability: number;
  overall: number;
  passed: boolean;
  fatalFlaws: string[];
  defenseInDepth: string[];
  inlineFindings?: InlineFinding[];
  suppressions?: ParsedSuppression[];
  invalidAllowlistEntries?: string[];
  allowlistModifiedInPr?: boolean;
  layer2Status?: string;
}

export const COMMENT_SIGNATURE = '<!-- devguard-adversarial-audit-sticky-comment -->';

interface PrContext {
  token: string;
  repo: string;
  prNumber: number;
  apiBase: string;
  headers: Record<string, string>;
}

function escapeTableCell(value: string): string {
  return value.replace(/\|/g, '\\|').replace(/`/g, '\\`').replace(/[\r\n]+/g, ' ');
}

/** Sanitizes PR comment markdown text: redacts secrets, blocks external image pixels, and neutralizes @mentions. */
export function sanitizeMarkdownText(value: string): string {
  const redacted = redactSecretsPreservingLayout(value);
  const noExternalImages = redacted.replace(
    /!\[([^\]]*)\]\(\s*https?:\/\/[^)]+\)/gi,
    (_full, alt: string) => `[blocked-external-image: ${alt}]`
  );
  return noExternalImages.replace(/(^|[^A-Za-z0-9_])@([A-Za-z0-9_][A-Za-z0-9_-]*)/g, '$1@\u200B$2');
}

function normalizePosixRepoPath(filePath: string): string {
  const relPath = path.isAbsolute(filePath) ? path.relative(process.cwd(), filePath) : filePath;
  return relPath.replace(/\\/g, '/').replace(/^\.\//, '');
}

function resolvePrContext(): PrContext | null {
  const token = process.env.GITHUB_TOKEN;
  const repo = process.env.GITHUB_REPOSITORY;
  const eventPath = process.env.GITHUB_EVENT_PATH;

  if (!token || !repo || !eventPath || !fs.existsSync(eventPath)) {
    return null;
  }

  let envInfo: PrEnvironmentInfo = { isPullRequest: false, isFork: false };
  try {
    const eventData = JSON.parse(fs.readFileSync(eventPath, 'utf-8')) as unknown;
    envInfo = detectPrEnvironment(eventData);
  } catch (err) {
    console.warn('⚠️ Gagal membaca payload event GitHub:', err);
    return null;
  }

  if (!envInfo.isPullRequest || !envInfo.prNumber) {
    return null;
  }
  const prNumber = envInfo.prNumber;

  const apiBase = (process.env.GITHUB_API_URL || 'https://api.github.com').replace(/\/+$/, '');
  const headers: Record<string, string> = {
    Authorization: `Bearer ${token}`,
    Accept: 'application/vnd.github+json',
    'Content-Type': 'application/json',
    'X-GitHub-Api-Version': '2022-11-28',
    'User-Agent': 'DevGuard-Action-Bot',
  };

  return { token, repo, prNumber, apiBase, headers };
}

/** Builds the sticky PR comment Markdown body with score, coverage block, and detailed findings. */
export function buildPullRequestCommentMarkdown(
  summaries: FileAuditSummary[],
  minScore: number,
  mode: 'HYBRID' | 'OFFLINE_AST',
  coverage?: PrCoverageSummary
): string {
  const analyzedCount = coverage ? coverage.analyzedCount : summaries.length;
  const skippedFiles = coverage?.skippedFiles ?? [];
  const skippedCount = skippedFiles.length;
  const codeFilesCount = analyzedCount + skippedCount;
  const ignoredNonCodeCount = coverage?.ignoredNonCodeCount ?? 0;
  const ignoredDeletedCount = coverage?.ignoredDeletedCount ?? 0;

  const overallScore: number | null =
    analyzedCount === 0
      ? null
      : coverage?.overallScore !== undefined
        ? coverage.overallScore
        : summaries.length > 0
          ? Math.round(summaries.reduce((acc, s) => acc + s.overall, 0) / summaries.length)
          : null;

  const analyzedPassed = summaries.every((summary) => summary.passed);
  const unanalyzableFailed = Boolean(coverage?.failOnUnanalyzable && skippedCount > 0);
  const allPassed = analyzedPassed && !unanalyzableFailed;

  const badgeStatus = allPassed ? '✅ PASSED (READY TO MERGE)' : '🚫 REJECTED (SECURITY GATE FAILED)';
  const engineLabel = mode === 'HYBRID'
    ? 'Hybrid Dual-Layer (Single-Pass Lexical & Heuristic Engine + Gemini 3.8 Flash)'
    : '100% Offline Single-Pass Lexical & Heuristic Engine';

  const headerStatuses = Array.from(
    new Set(summaries.map((s) => formatLayer2StatusLabel(s.layer2Status, mode)))
  );
  const headerLayer2Status =
    headerStatuses.length > 0 ? headerStatuses.join(' / ') : formatLayer2StatusLabel(undefined, mode);

  const scoreDisplay = overallScore === null ? 'N/A' : `${overallScore}/100`;
  const scoreHeadline = `DevGuard v1.3.0 — Score: ${scoreDisplay}  (analyzed ${analyzedCount} of ${codeFilesCount} code files · ${skippedCount} skipped)`;

  const maxDisplay = Math.max(1, coverage?.maxSkippedDisplay ?? MAX_PR_SKIPPED_FILES_DISPLAY);
  const skippedLines = skippedFiles
    .slice(0, maxDisplay)
    .map(
      (item) =>
        `    - ${sanitizeMarkdownText(normalizePosixRepoPath(item.filePath).replace(/[\r\n]+/g, ' '))} — ${formatSkippedReasonText(item.reason)}`
    );
  if (skippedFiles.length > maxDisplay) {
    skippedLines.push(`    - +${skippedFiles.length - maxDisplay} more`);
  }

  const coverageLines: string[] = [
    'Coverage',
    `- Analyzed: ${analyzedCount}`,
    `- Skipped: ${skippedCount}`,
    ...skippedLines,
    `- Ignored (non-code): ${ignoredNonCodeCount}`,
  ];
  if (ignoredDeletedCount > 0) {
    coverageLines.push(`- Ignored (deleted): ${ignoredDeletedCount}`);
  }
  const coverageBlock = coverageLines.join('\n');

  const tableRows = summaries.map((summary) => {
    const icon = summary.passed ? '🟢' : '🔴';
    const fileL2 = formatLayer2StatusLabel(summary.layer2Status, mode);
    return `| ${icon} \`${escapeTableCell(summary.filePath)}\` | **${summary.overall}/100** | ${summary.security} | ${summary.correctness} | ${summary.maintainability} | \`${escapeTableCell(fileL2)}\` |`;
  }).join('\n');

  let detailsSection = '';
  for (const summary of summaries) {
    if (summary.fatalFlaws.length > 0 || summary.defenseInDepth.length > 0) {
      detailsSection += `\n#### 🔍 Detail Audit: \`${summary.filePath.replace(/`/g, '\\`').replace(/[\r\n]+/g, ' ')}\`\n`;
      if (summary.fatalFlaws.length > 0) {
        detailsSection += '**💣 Celah Keamanan / Logika Terdeteksi:**\n';
        summary.fatalFlaws.forEach((flaw) => {
          detailsSection += `- ❌ ${sanitizeMarkdownText(flaw)}\n`;
        });
      }
      if (summary.defenseInDepth.length > 0) {
        detailsSection += '\n**🛡️ Catatan Defense-in-Depth (Alasan Skor Tidak 100/100):**\n';
        summary.defenseInDepth.forEach((note) => {
          detailsSection += `- ⚠️ ${sanitizeMarkdownText(note)}\n`;
        });
      }
    }
  }

  const allSuppressions = summaries.flatMap((summary) =>
    (summary.suppressions || []).map((s) => ({
      ...s,
      filePath: s.filePath || summary.filePath,
    }))
  );
  const allInvalidEntries = Array.from(
    new Set(summaries.flatMap((summary) => summary.invalidAllowlistEntries || []))
  );
  const allowlistChanged = summaries.some((summary) => summary.allowlistModifiedInPr === true);

  let suppressionSection = '';
  if (allowlistChanged) {
    suppressionSection += '\n> ⚠️ allowlist config (.devguard.json) changed in this PR; changes apply only after merge\n';
  }
  if (allSuppressions.length > 0) {
    const supRows = allSuppressions
      .map(
        (s) =>
          `| \`${escapeTableCell(normalizePosixRepoPath(s.filePath))}\` | ${s.targetLine} | \`${s.ruleId}\` | \`${s.kind}\` | ${escapeTableCell(sanitizeMarkdownText(s.reason))} |`
      )
      .join('\n');
    suppressionSection += `\n### 🙈 Active Suppressions\n| File | Line | Rule | Kind | Reason |\n| :--- | :---: | :---: | :---: | :--- |\n${supRows}\n`;
  }
  if (allInvalidEntries.length > 0) {
    suppressionSection += '\n### ⚠️ Rejected `.devguard.json` Allowlist Entries\n';
    allInvalidEntries.forEach((entry) => {
      suppressionSection += `- ❌ ${escapeTableCell(sanitizeMarkdownText(entry))}\n`;
    });
  }

  return `${COMMENT_SIGNATURE}
## 🛡️ DevGuard Adversarial Security Gatekeeper

${scoreHeadline}

| Status Gerbang | Ambang Batas Skor | Mode Mesin | Status Analisis |
| :--- | :--- | :--- | :--- |
| **${badgeStatus}** | \`${minScore}/100\` | \`${engineLabel}\` | **${headerLayer2Status}** |

${coverageBlock}

### 📊 Skor Evaluasi Berkas
| Berkas | Skor Akhir | Security | Correctness | Maintainability | Layer 2 |
| :--- | :---: | :---: | :---: | :---: | :--- |
${tableRows || '| Tidak ada berkas yang diaudit | — | — | — | — | — |'}
${suppressionSection}${detailsSection}

---
*Diinspeksi secara otomatis oleh [DevGuard Zero-Leniency Auditor](https://github.com/marketplace/actions/devguard-adversarial-code-auditor).*`;
}

export async function postPullRequestComment(
  summaries: FileAuditSummary[],
  minScore: number,
  mode: 'HYBRID' | 'OFFLINE_AST',
  coverage?: PrCoverageSummary
): Promise<void> {
  const ctx = resolvePrContext();
  if (!ctx) {
    console.log('ℹ️  Bukan konteks Pull Request GitHub atau GITHUB_TOKEN tidak tersedia. Melewati Auto-PR Comment.');
    return;
  }

  const { repo, prNumber, apiBase, headers } = ctx;
  const markdownBody = buildPullRequestCommentMarkdown(summaries, minScore, mode, coverage);

  const commentsUrl = `${apiBase}/repos/${repo}/issues/${prNumber}/comments`;

  try {
    // Read every comments page so an older sticky comment is not missed on busy PRs.
    let botComment: { id: number; body?: string } | undefined;
    for (let page = 1; page <= 10; page++) {
      const listResp = await fetch(`${commentsUrl}?per_page=100&page=${page}`, {
        headers,
        signal: AbortSignal.timeout(15_000),
      });
      if (listResp.status === 403) {
        console.warn('⚠️ GitHub PR Comments API mengembalikan HTTP 403 (token read-only / fork PR); sticky comment dilewati secara aman.');
        return;
      }
      if (!listResp.ok) {
        console.warn(`⚠️ Gagal membaca komentar PR (HTTP ${listResp.status}); komentar laporan tidak dibuat untuk menghindari duplikasi.`);
        return;
      }

      const existingComments = await listResp.json() as Array<{ id: number; body?: string }>;
      botComment = existingComments.find((comment) => comment.body?.includes(COMMENT_SIGNATURE));
      if (botComment || existingComments.length < 100) break;
    }

    if (botComment) {
      const updateUrl = `${apiBase}/repos/${repo}/issues/comments/${botComment.id}`;
      const updateResp = await fetch(updateUrl, {
        method: 'PATCH',
        headers,
        body: JSON.stringify({ body: markdownBody }),
        signal: AbortSignal.timeout(15_000),
      });
      if (updateResp.status === 403) {
        console.warn('⚠️ GitHub PR Comments API mengembalikan HTTP 403 saat PATCH (token read-only / fork PR); dilewati secara fail-open.');
      } else if (updateResp.ok) {
        console.log(`💬 Berhasil memperbarui komentar laporan DevGuard pada PR #${prNumber}.`);
      } else {
        console.warn(`⚠️ Gagal memperbarui komentar PR (HTTP ${updateResp.status}).`);
      }
      return;
    }

    const createResp = await fetch(commentsUrl, {
      method: 'POST',
      headers,
      body: JSON.stringify({ body: markdownBody }),
      signal: AbortSignal.timeout(15_000),
    });

    if (createResp.status === 403) {
      console.warn('⚠️ GitHub PR Comments API mengembalikan HTTP 403 saat POST (token read-only / fork PR); dilewati secara fail-open.');
    } else if (createResp.ok) {
      console.log(`💬 Berhasil mengirim komentar laporan DevGuard ke PR #${prNumber}.`);
    } else {
      console.warn(`⚠️ Gagal mengirim komentar PR (HTTP ${createResp.status}): Pastikan workflow memiliki izin 'pull-requests: write'.`);
    }
  } catch (error) {
    console.warn('⚠️ Terjadi kesalahan jaringan saat menghubungi GitHub API:', error);
    return;
  }
}

export async function postInlineReviewComments(summaries: FileAuditSummary[]): Promise<void> {
  const pending: Array<{ path: string; line: number; body: string; ruleId: string }> = [];

  for (const summary of summaries) {
    if (!summary.inlineFindings || summary.inlineFindings.length === 0) continue;
    const normalizedPath = normalizePosixRepoPath(summary.filePath);

    for (const finding of summary.inlineFindings) {
      const targetLine = Math.max(1, finding.line);
      const safeMessage = sanitizeMarkdownText(finding.message);
      let body = `🛡️ **[DevGuard ${finding.ruleId}]** (${finding.severity.toUpperCase()}): ${safeMessage}`;
      if (finding.suggestion) {
        body += `\n\n\`\`\`suggestion\n${redactSecretsPreservingLayout(finding.suggestion)}\n\`\`\``;
      }
      pending.push({ path: normalizedPath, line: targetLine, body, ruleId: finding.ruleId });
    }
  }

  if (pending.length === 0) return;

  const ctx = resolvePrContext();
  if (!ctx) return;

  const { repo, prNumber, apiBase, headers } = ctx;
  const reviewCommentsUrl = `${apiBase}/repos/${repo}/pulls/${prNumber}/comments`;

  try {
    // Deduplicate against existing inline PR review comments matching path, line, and [DevGuard DGxxx] / [DGxxx]
    const existingKeys = new Set<string>();
    for (let page = 1; page <= 10; page++) {
      const listResp = await fetch(`${reviewCommentsUrl}?per_page=100&page=${page}`, {
        headers,
        signal: AbortSignal.timeout(15_000),
      });
      if (listResp.status === 403) {
        console.warn('⚠️ GitHub PR Review API mengembalikan HTTP 403 (token read-only / fork PR); inline review dilewati secara fail-open.');
        return;
      }
      if (!listResp.ok) {
        console.warn(`⚠️ Gagal membaca komentar review PR (HTTP ${listResp.status}); melewati inline review untuk menghindari spam.`);
        return;
      }

      const existing = await listResp.json() as Array<{
        path?: string;
        line?: number | null;
        original_line?: number | null;
        body?: string;
      }>;

      for (const item of existing) {
        const commentLine = item.line ?? item.original_line;
        if (!item.path || !commentLine || !item.body) continue;
        const ruleMatch = item.body.match(/\[(?:DevGuard\s+)?(DG\d{3})\]/);
        if (ruleMatch?.[1]) {
          existingKeys.add(`${item.path}:${commentLine}:${ruleMatch[1]}`);
        }
      }

      if (existing.length < 100) break;
    }

    const dedupedComments = pending
      .filter((item) => !existingKeys.has(`${item.path}:${item.line}:${item.ruleId}`))
      .map(({ path: filePath, line, body }) => ({
        path: filePath,
        line,
        side: 'RIGHT' as const,
        body,
      }));

    if (dedupedComments.length === 0) {
      console.log(`ℹ️  Seluruh ${pending.length} temuan inline PR #${prNumber} sudah terpasang sebelumnya.`);
      return;
    }

    const createReviewUrl = `${apiBase}/repos/${repo}/pulls/${prNumber}/reviews`;
    const reviewResp = await fetch(createReviewUrl, {
      method: 'POST',
      headers,
      body: JSON.stringify({
        event: 'COMMENT',
        comments: dedupedComments,
      }),
      signal: AbortSignal.timeout(15_000),
    });

    if (reviewResp.status === 403) {
      console.warn('⚠️ GitHub PR Review API mengembalikan HTTP 403 (token read-only / fork PR); inline review dilewati secara fail-open.');
      return;
    }

    if (reviewResp.status === 422) {
      console.warn(`⚠️ GitHub PR Review API mengembalikan HTTP 422 (baris di luar diff hunk); inline comment dilewati secara aman.`);
      return;
    }

    if (reviewResp.ok) {
      console.log(`📌 Berhasil menyematkan ${dedupedComments.length} inline PR review comment pada PR #${prNumber}.`);
    } else {
      console.warn(`⚠️ Gagal mengirim inline PR review comment (HTTP ${reviewResp.status}); melanjutkan pipeline secara fail-open.`);
    }
  } catch (error) {
    console.warn('⚠️ Terjadi kesalahan jaringan saat mengirim inline PR review comment:', error);
    return;
  }
}
