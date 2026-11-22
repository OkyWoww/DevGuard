import React, { useEffect, useRef, useState } from 'react';
import {
  AlertCircle,
  AlertTriangle,
  Check,
  CheckCircle2,
  ChevronDown,
  ChevronRight,
  Copy,
  Info,
  Play,
  RefreshCw,
  RotateCcw,
  ShieldAlert,
  Wrench,
} from 'lucide-react';
import {
  getLocalizedRuleTitle,
  localizeFindingMessage,
  localizeNoticeMessage,
  localizeRemediationSummary,
} from '../i18n';
import type {
  AuditEngineSource,
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
  selectedFindingKey: string | null;
  engineSource?: AuditEngineSource | null;
  onSelectFinding: (finding: AuditFinding) => void;
  onSelectNoticeLine: (notice: AuditNotice) => void;
  onApplyRemediation?: (remediationCode: string, reAudit: boolean) => void;
  onRetry: () => void;
  locale?: WorkbenchLocale;
}

const COPY_FEEDBACK_MS = 1500;

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
    remediationHeading: string;
    remediationBadge: string;
    applyFixBtn: string;
    applyAndReauditBtn: string;
    copyCodeBtn: string;
    copiedBtn: string;
    previewPatchShow: string;
    previewPatchHide: string;
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
    remediationHeading: 'Hardened Remediation Patch',
    remediationBadge: 'PATCH READY',
    applyFixBtn: 'Apply Fix to Editor',
    applyAndReauditBtn: 'Apply Fix & Re-Audit',
    copyCodeBtn: 'Copy Code',
    copiedBtn: 'Copied',
    previewPatchShow: 'Preview Patch',
    previewPatchHide: 'Hide Patch',
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
    remediationHeading: 'Patch Remediasi Hardened',
    remediationBadge: 'PATCH SIAP',
    applyFixBtn: 'Terapkan ke Editor',
    applyAndReauditBtn: 'Terapkan & Audit Ulang',
    copyCodeBtn: 'Salin Kode',
    copiedBtn: 'Disalin',
    previewPatchShow: 'Lihat Kode Patch',
    previewPatchHide: 'Sembunyikan Patch',
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
  selectedFindingKey,
  engineSource,
  onSelectFinding,
  onSelectNoticeLine,
  onApplyRemediation,
  onRetry,
  locale = 'en',
}) => {
  const copy = COPY[locale];
  const resolvedEngineSource = engineSource ?? report?.engineSource ?? null;
  const [showPatchPreview, setShowPatchPreview] = useState<boolean>(false);
  const [copiedPatch, setCopiedPatch] = useState<boolean>(false);
  const copyTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => {
    setShowPatchPreview(false);
    setCopiedPatch(false);
  }, [report]);

  useEffect(() => {
    return () => {
      if (copyTimerRef.current !== null) {
        clearTimeout(copyTimerRef.current);
        copyTimerRef.current = null;
      }
    };
  }, []);

  const handleCopyRemediation = async (patchCode: string) => {
    if (!patchCode) return;
    try {
      await navigator.clipboard.writeText(patchCode);
      if (copyTimerRef.current !== null) {
        clearTimeout(copyTimerRef.current);
      }
      setCopiedPatch(true);
      copyTimerRef.current = setTimeout(() => {
        setCopiedPatch(false);
        copyTimerRef.current = null;
      }, COPY_FEEDBACK_MS);
    } catch {
      setCopiedPatch(false);
    }
  };

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
    const remediation =
      report.verdict !== 'PASS' &&
      report.remediation &&
      report.remediation.code.trim().length > 0
        ? report.remediation
        : null;

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

        {/* Hardened Remediation Card (Below Summary Strip, Above Blocking Findings) */}
        {remediation && onApplyRemediation && (
          <div className="rounded-md border border-slate-700 bg-[#0A0E17] p-3.5">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div className="flex items-center gap-2">
                <Wrench className="h-3.5 w-3.5 text-emerald-400" aria-hidden="true" />
                <h3 className="text-xs font-semibold text-slate-100">
                  {copy.remediationHeading}
                </h3>
                <span className="rounded border border-emerald-500/40 bg-emerald-950/30 px-1.5 py-0.5 font-mono text-[10px] text-emerald-300">
                  {copy.remediationBadge}
                </span>
              </div>
              <span className="rounded border border-slate-800 bg-slate-900 px-1.5 py-0.5 font-mono text-[10px] text-slate-400">
                {remediation.language || 'code'}
              </span>
            </div>

            {remediation.summary && (
              <p className="mt-2 font-mono text-[11px] leading-relaxed text-slate-300">
                {localizeRemediationSummary(remediation.summary, locale)}
              </p>
            )}

            <div className="mt-3 flex flex-wrap items-center gap-2">
              <button
                type="button"
                onClick={() => onApplyRemediation(remediation.code, true)}
                className="inline-flex h-8 items-center gap-1.5 rounded-md bg-emerald-600 px-3 text-xs font-semibold text-white transition-colors hover:bg-emerald-500 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-emerald-400"
              >
                <Play className="h-3 w-3 fill-current" aria-hidden="true" />
                <span>{copy.applyAndReauditBtn}</span>
              </button>

              <button
                type="button"
                onClick={() => onApplyRemediation(remediation.code, false)}
                className="inline-flex h-8 items-center gap-1.5 rounded-md border border-slate-700 bg-slate-900 px-3 text-xs font-medium text-slate-200 transition-colors hover:border-slate-600 hover:bg-slate-800 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-emerald-400"
              >
                <span>{copy.applyFixBtn}</span>
              </button>

              <button
                type="button"
                onClick={() => void handleCopyRemediation(remediation.code)}
                className={`inline-flex h-8 items-center gap-1.5 rounded-md border px-2.5 font-mono text-[11px] font-medium transition-colors focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-emerald-400 ${
                  copiedPatch
                    ? 'border-emerald-500/50 bg-emerald-950/40 text-emerald-300'
                    : 'border-slate-700 bg-slate-900 text-slate-300 hover:border-slate-600 hover:bg-slate-800'
                }`}
              >
                {copiedPatch ? (
                  <Check className="h-3 w-3 text-emerald-400" aria-hidden="true" />
                ) : (
                  <Copy className="h-3 w-3 text-slate-400" aria-hidden="true" />
                )}
                <span>{copiedPatch ? copy.copiedBtn : copy.copyCodeBtn}</span>
              </button>

              <button
                type="button"
                aria-expanded={showPatchPreview}
                onClick={() => setShowPatchPreview((prev) => !prev)}
                className="ml-auto inline-flex h-8 items-center gap-1 rounded-md border border-slate-800 bg-[#0D1117] px-2.5 font-mono text-[11px] text-slate-400 transition-colors hover:border-slate-700 hover:text-slate-200 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-emerald-400"
              >
                {showPatchPreview ? (
                  <ChevronDown className="h-3.5 w-3.5" aria-hidden="true" />
                ) : (
                  <ChevronRight className="h-3.5 w-3.5" aria-hidden="true" />
                )}
                <span>
                  {showPatchPreview ? copy.previewPatchHide : copy.previewPatchShow}
                </span>
              </button>
            </div>

            {showPatchPreview && (
              <pre className="mt-3 max-h-60 overflow-auto rounded border border-slate-800 bg-[#06090F] p-3 font-mono text-[11px] leading-relaxed text-slate-200">
                {remediation.code}
              </pre>
            )}
          </div>
        )}

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
                const findingKey = `${finding.id}:${finding.line}`;
                const isSelected = selectedFindingKey === findingKey;
                const locationText =
                  typeof finding.column === 'number'
                    ? `L${finding.line}:${finding.column}`
                    : `L${finding.line}`;

                return (
                  <li key={`${findingKey}:${index}`}>
                    <button
                      type="button"
                      aria-pressed={isSelected}
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
                            {getLocalizedRuleTitle(finding.id, locale)}
                          </span>
                        </div>
                        <span className="font-mono text-[11px] text-emerald-400">
                          {locationText}
                        </span>
                      </div>
                      <p className="mt-1.5 text-xs leading-relaxed text-slate-300">
                        {localizeFindingMessage(finding.id, finding.message, finding.line, locale)}
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
              {advisoryFindings.map((finding, index) => {
                const findingKey = `${finding.id}:${finding.line}`;
                const isSelected = selectedFindingKey === findingKey;
                return (
                  <li key={`${findingKey}:adv:${index}`}>
                    <button
                      type="button"
                      aria-pressed={isSelected}
                      onClick={() => onSelectFinding(finding)}
                      className={`w-full rounded-md border px-3 py-2 text-left transition-colors focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-emerald-400 ${
                        isSelected
                          ? 'border-emerald-500/60 bg-slate-900'
                          : 'border-slate-800 bg-[#0A0E17] hover:border-slate-700 hover:bg-slate-900/70'
                      }`}
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
                          <span className="text-xs text-slate-400">
                            {getLocalizedRuleTitle(finding.id, locale)}
                          </span>
                        </div>
                        <span className="font-mono text-[11px] text-slate-400">
                          L{finding.line}
                        </span>
                      </div>
                      <p className="mt-1 text-xs leading-relaxed text-slate-400">
                        {localizeFindingMessage(finding.id, finding.message, finding.line, locale)}
                      </p>
                    </button>
                  </li>
                );
              })}
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
                      {localizeNoticeMessage(notice.code, notice.message, locale)}
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
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-800 px-3.5 py-2.5">
        <h2 className="text-xs font-semibold uppercase tracking-wider text-slate-200">
          {copy.paneTitle}
        </h2>
        <div className="flex items-center gap-2 font-mono text-[11px]">
          {resolvedEngineSource && (
            <span
              className={`rounded border px-1.5 py-0.5 text-[10px] ${
                resolvedEngineSource === 'live'
                  ? 'border-emerald-500/40 bg-emerald-950/30 text-emerald-300'
                  : 'border-slate-700 bg-slate-900 text-slate-300'
              }`}
            >
              {resolvedEngineSource === 'live' ? 'Engine: Live' : 'Engine: Local Offline'}
            </span>
          )}
          <span className="text-slate-500">SARIF v2.1.0</span>
        </div>
      </div>
      {renderBody()}
    </section>
  );
};
