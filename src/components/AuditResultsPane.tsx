import React from 'react';
import {
  AlertCircle,
  AlertTriangle,
  CheckCircle2,
  Info,
  RefreshCw,
  RotateCcw,
  ShieldAlert,
} from 'lucide-react';
import type {
  AuditErrorInfo,
  AuditFinding,
  AuditNotice,
  AuditReport,
  AuditRunState,
  AuditVerdict,
  FindingSeverity,
  WorkbenchLocale,
} from '../types/workbench';

export interface AuditResultsPaneProps {
  runState: AuditRunState;
  report: AuditReport | null;
  error: AuditErrorInfo | null;
  selectedFindingId: string | null;
  onSelectFinding: (finding: AuditFinding) => void;
  onSelectNoticeLine: (notice: AuditNotice) => void;
  onRetry: () => void;
  locale?: WorkbenchLocale;
}

const COPY: Record<
  WorkbenchLocale,
  {
    paneTitle: string;
    idleTitle: string;
    idleBody: string;
    runningTitle: string;
    runningBody: string;
    retryButton: string;
    overallLabel: string;
    securityLabel: string;
    correctnessLabel: string;
    maintainabilityLabel: string;
    blockingHeading: string;
    blockingEmpty: string;
    advisoryHeading: string;
    noticesHeading: string;
    noticesBadge: string;
    noticesEmpty: string;
    jumpHint: string;
  }
> = {
  en: {
    paneTitle: 'Findings & Diagnostics',
    idleTitle: 'Ready for Single-File Audit',
    idleBody:
      'Press Run Audit or Ctrl/Cmd + Enter to evaluate the active editor buffer against deterministic DevGuard rules (DG001-DG008).',
    runningTitle: 'Evaluating Source Buffer',
    runningBody: 'Running lexical masking, rule checks, and score aggregation...',
    retryButton: 'Retry',
    overallLabel: 'Overall',
    securityLabel: 'Security',
    correctnessLabel: 'Correctness',
    maintainabilityLabel: 'Maintainability',
    blockingHeading: 'Blocking Findings',
    blockingEmpty: 'No blocking findings detected in this buffer.',
    advisoryHeading: 'Advisory Findings',
    noticesHeading: 'Non-Scoring Notices',
    noticesBadge: 'NON-SCORING',
    noticesEmpty: 'No workspace or dynamic-import notices emitted.',
    jumpHint: 'Focus line',
  },
  id: {
    paneTitle: 'Temuan & Diagnostik',
    idleTitle: 'Siap Menjalankan Audit Single-File',
    idleBody:
      'Tekan Jalankan Audit atau Ctrl/Cmd + Enter untuk mengevaluasi kode aktif terhadap aturan deterministik DevGuard (DG001-DG008).',
    runningTitle: 'Mengevaluasi Kode Sumber',
    runningBody: 'Menjalankan lexical masking, pemeriksaan aturan, dan kalkulasi skor...',
    retryButton: 'Coba Lagi',
    overallLabel: 'Total',
    securityLabel: 'Security',
    correctnessLabel: 'Correctness',
    maintainabilityLabel: 'Maintainability',
    blockingHeading: 'Temuan Blocking',
    blockingEmpty: 'Tidak ada temuan blocking pada berkas ini.',
    advisoryHeading: 'Temuan Tambahan',
    noticesHeading: 'Non-Scoring Notices',
    noticesBadge: 'NON-SCORING',
    noticesEmpty: 'Tidak ada notice workspace atau dynamic-import.',
    jumpHint: 'Fokus baris',
  },
};

function verdictBadgeClasses(verdict: AuditVerdict): string {
  switch (verdict) {
    case 'PASS':
      return 'border-emerald-500/40 bg-emerald-500/10 text-emerald-300';
    case 'REVIEW':
      return 'border-amber-500/40 bg-amber-500/10 text-amber-300';
    case 'FAIL':
      return 'border-rose-500/40 bg-rose-500/10 text-rose-300';
  }
}

function scoreValueClasses(score: number): string {
  if (score >= 85) return 'text-emerald-400';
  if (score >= 70) return 'text-amber-400';
  return 'text-rose-400';
}

function severityBadgeClasses(severity: FindingSeverity): string {
  switch (severity) {
    case 'error':
      return 'border-rose-500/40 bg-rose-500/10 text-rose-300';
    case 'warning':
      return 'border-amber-500/40 bg-amber-500/10 text-amber-300';
    case 'info':
      return 'border-slate-700 bg-slate-800/80 text-slate-300';
  }
}

export const AuditResultsPane: React.FC<AuditResultsPaneProps> = ({
  runState,
  report,
  error,
  selectedFindingId,
  onSelectFinding,
  onSelectNoticeLine,
  onRetry,
  locale = 'en',
}) => {
  const copy = COPY[locale];

  const renderBody = () => {
    if (runState === 'running') {
      return (
        <div className="flex flex-1 flex-col items-center justify-center px-6 py-16 text-center">
          <RefreshCw className="mb-3 h-6 w-6 animate-spin text-emerald-400" aria-hidden="true" />
          <h2 className="text-sm font-semibold text-slate-100">{copy.runningTitle}</h2>
          <p className="mt-1 max-w-sm text-xs text-slate-400">{copy.runningBody}</p>
        </div>
      );
    }

    if (runState === 'error' && error) {
      return (
        <div className="flex flex-1 flex-col justify-center p-5">
          <div
            role="alert"
            className="rounded-lg border border-rose-500/40 bg-rose-950/20 p-4"
          >
            <div className="flex items-start justify-between gap-3">
              <div className="flex items-start gap-2.5">
                <AlertCircle className="mt-0.5 h-4 w-4 shrink-0 text-rose-400" aria-hidden="true" />
                <div>
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-xs font-semibold text-rose-300">
                      {error.code}
                    </span>
                  </div>
                  <p className="mt-1 text-xs leading-relaxed text-slate-200">{error.message}</p>
                </div>
              </div>
              {error.retryable && (
                <button
                  type="button"
                  onClick={onRetry}
                  className="inline-flex shrink-0 items-center gap-1.5 rounded-md border border-slate-700 bg-slate-900 px-3 py-1.5 text-xs font-medium text-slate-100 transition-colors hover:border-slate-600 hover:bg-slate-800 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-emerald-400"
                >
                  <RotateCcw className="h-3.5 w-3.5" aria-hidden="true" />
                  <span>{copy.retryButton}</span>
                </button>
              )}
            </div>
          </div>
        </div>
      );
    }

    if (runState === 'idle' || !report) {
      return (
        <div className="flex flex-1 flex-col items-center justify-center px-6 py-16 text-center">
          <CheckCircle2 className="mb-3 h-6 w-6 text-slate-600" aria-hidden="true" />
          <h2 className="text-sm font-semibold text-slate-200">{copy.idleTitle}</h2>
          <p className="mt-1.5 max-w-md text-xs leading-relaxed text-slate-400">
            {copy.idleBody}
          </p>
        </div>
      );
    }

    const blockingFindings = report.findings.filter((item) => item.blocking);
    const advisoryFindings = report.findings.filter((item) => !item.blocking);

    return (
      <div className="flex flex-1 flex-col gap-4 overflow-y-auto p-4">
        {/* Summary Strip */}
        <div className="rounded-md border border-slate-800 bg-[#0A0E17] p-3.5">
          <div className="mb-3 flex items-center justify-between gap-2">
            <div className="flex items-center gap-2">
              <span
                className={`rounded border px-2 py-0.5 font-mono text-xs font-semibold ${verdictBadgeClasses(
                  report.verdict
                )}`}
              >
                {report.verdict}
              </span>
              {typeof report.durationMs === 'number' && (
                <span className="font-mono text-[11px] text-slate-500">
                  {report.durationMs} ms
                </span>
              )}
            </div>
            <span className="font-mono text-[11px] text-slate-400">
              {blockingFindings.length} blocking · {report.notices.length} notices
            </span>
          </div>

          <div className="grid grid-cols-2 gap-2.5 sm:grid-cols-4">
            {[
              { label: copy.overallLabel, value: report.scores.overall },
              { label: copy.securityLabel, value: report.scores.security },
              { label: copy.correctnessLabel, value: report.scores.correctness },
              { label: copy.maintainabilityLabel, value: report.scores.maintainability },
            ].map((metric) => (
              <div
                key={metric.label}
                className="rounded border border-slate-800 bg-[#0D1117] px-3 py-2"
              >
                <div className="text-[11px] text-slate-400">{metric.label}</div>
                <div
                  className={`mt-0.5 font-mono text-xl font-semibold tabular-nums ${scoreValueClasses(
                    metric.value
                  )}`}
                >
                  {metric.value}
                  <span className="text-xs font-normal text-slate-500">/100</span>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Blocking Findings */}
        <div className="space-y-2">
          <div className="flex items-center justify-between">
            <h3 className="flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wider text-slate-200">
              <ShieldAlert className="h-3.5 w-3.5 text-rose-400" aria-hidden="true" />
              <span>{copy.blockingHeading}</span>
            </h3>
            <span className="font-mono text-[11px] text-slate-400">
              {blockingFindings.length}
            </span>
          </div>

          {blockingFindings.length === 0 ? (
            <div className="rounded-md border border-slate-800 bg-[#0A0E17] px-3 py-2.5 text-xs text-slate-400">
              {copy.blockingEmpty}
            </div>
          ) : (
            <ul className="space-y-1.5">
              {blockingFindings.map((finding, index) => {
                const selectionKey = `${finding.id}-${finding.line}-${index}`;
                const isSelected =
                  selectedFindingId === finding.id || selectedFindingId === selectionKey;
                const locationText =
                  typeof finding.column === 'number'
                    ? `L${finding.line}:${finding.column}`
                    : `L${finding.line}`;

                return (
                  <li key={selectionKey}>
                    <button
                      type="button"
                      onClick={() => onSelectFinding(finding)}
                      title={`${copy.jumpHint} ${finding.line}`}
                      className={`w-full rounded-md border px-3 py-2.5 text-left transition-colors focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-emerald-400 ${
                        isSelected
                          ? 'border-emerald-500/60 bg-slate-900'
                          : 'border-slate-800 bg-[#0A0E17] hover:border-slate-700 hover:bg-slate-900/70'
                      }`}
                    >
                      <div className="flex flex-wrap items-center justify-between gap-2">
                        <div className="flex items-center gap-2">
                          <span className="font-mono text-xs font-semibold text-slate-100">
                            {finding.id}
                          </span>
                          <span
                            className={`rounded border px-1.5 py-0.5 font-mono text-[10px] uppercase ${severityBadgeClasses(
                              finding.severity
                            )}`}
                          >
                            {finding.severity}
                          </span>
                          <span className="text-xs font-medium text-slate-300">
                            {finding.ruleTitle}
                          </span>
                        </div>
                        <span className="font-mono text-[11px] text-emerald-400">
                          {locationText}
                        </span>
                      </div>
                      <p className="mt-1.5 text-xs leading-relaxed text-slate-300">
                        {finding.message}
                      </p>
                    </button>
                  </li>
                );
              })}
            </ul>
          )}
        </div>

        {/* Advisory / Non-Blocking Findings (if any) */}
        {advisoryFindings.length > 0 && (
          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <h3 className="flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wider text-slate-300">
                <AlertTriangle className="h-3.5 w-3.5 text-amber-400" aria-hidden="true" />
                <span>{copy.advisoryHeading}</span>
              </h3>
              <span className="font-mono text-[11px] text-slate-400">
                {advisoryFindings.length}
              </span>
            </div>
            <ul className="space-y-1.5">
              {advisoryFindings.map((finding, index) => (
                <li key={`${finding.id}-adv-${finding.line}-${index}`}>
                  <button
                    type="button"
                    onClick={() => onSelectFinding(finding)}
                    className="w-full rounded-md border border-slate-800 bg-[#0A0E17] px-3 py-2 text-left transition-colors hover:border-slate-700 hover:bg-slate-900/70 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-emerald-400"
                  >
                    <div className="flex items-center justify-between gap-2">
                      <div className="flex items-center gap-2">
                        <span className="font-mono text-xs font-semibold text-slate-200">
                          {finding.id}
                        </span>
                        <span
                          className={`rounded border px-1.5 py-0.5 font-mono text-[10px] uppercase ${severityBadgeClasses(
                            finding.severity
                          )}`}
                        >
                          {finding.severity}
                        </span>
                        <span className="text-xs text-slate-400">{finding.ruleTitle}</span>
                      </div>
                      <span className="font-mono text-[11px] text-slate-400">
                        L{finding.line}
                      </span>
                    </div>
                    <p className="mt-1 text-xs leading-relaxed text-slate-400">
                      {finding.message}
                    </p>
                  </button>
                </li>
              ))}
            </ul>
          </div>
        )}

        {/* Non-Scoring Notices Section (Strictly Separated) */}
        <div className="space-y-2 border-t border-slate-800 pt-3">
          <div className="flex items-center justify-between">
            <h3 className="flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wider text-slate-300">
              <Info className="h-3.5 w-3.5 text-slate-400" aria-hidden="true" />
              <span>{copy.noticesHeading}</span>
            </h3>
            <span className="rounded border border-slate-700 bg-slate-900 px-1.5 py-0.5 font-mono text-[10px] text-slate-400">
              {copy.noticesBadge}
            </span>
          </div>

          {report.notices.length === 0 ? (
            <div className="rounded-md border border-slate-800/80 bg-[#0A0E17]/60 px-3 py-2 text-xs text-slate-500">
              {copy.noticesEmpty}
            </div>
          ) : (
            <ul className="space-y-1.5">
              {report.notices.map((notice, index) => {
                const key = `${notice.code}-${notice.line ?? 'none'}-${index}`;
                const content = (
                  <>
                    <div className="flex items-center justify-between gap-2">
                      <span className="font-mono text-xs font-semibold text-amber-300">
                        {notice.code}
                      </span>
                      {typeof notice.line === 'number' && (
                        <span className="font-mono text-[11px] text-slate-400">
                          L{notice.line}
                        </span>
                      )}
                    </div>
                    <p className="mt-1 text-xs leading-relaxed text-slate-400">
                      {notice.message}
                    </p>
                  </>
                );

                return (
                  <li key={key}>
                    {typeof notice.line === 'number' ? (
                      <button
                        type="button"
                        onClick={() => onSelectNoticeLine(notice)}
                        className="w-full rounded-md border border-slate-800 bg-[#0A0E17] px-3 py-2 text-left transition-colors hover:border-slate-700 hover:bg-slate-900/70 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-emerald-400"
                      >
                        {content}
                      </button>
                    ) : (
                      <div className="rounded-md border border-slate-800 bg-[#0A0E17] px-3 py-2">
                        {content}
                      </div>
                    )}
                  </li>
                );
              })}
            </ul>
          )}
        </div>
      </div>
    );
  };

  return (
    <section
      aria-label={copy.paneTitle}
      className="flex min-h-[540px] flex-col rounded-lg border border-slate-800 bg-[#0D1117]"
    >
      <div className="flex items-center justify-between border-b border-slate-800 px-3.5 py-2.5">
        <h2 className="text-xs font-semibold uppercase tracking-wider text-slate-200">
          {copy.paneTitle}
        </h2>
        <span className="font-mono text-[11px] text-slate-500">SARIF v2.1.0</span>
      </div>
      {renderBody()}
    </section>
  );
};
