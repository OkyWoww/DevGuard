import React, { useCallback, useMemo, useState } from 'react';
import {
  analyzeCodeDeterministically,
  type InlineFinding,
  type ParsedDevGuardReport,
} from './devguardAnalyzer';
import RAW_PRESETS from './data/presets.json';
import { getInitialLocale, persistLocale } from './i18n';
import { CommandBar } from './components/CommandBar';
import { CodeEditorPane } from './components/CodeEditorPane';
import { AuditResultsPane } from './components/AuditResultsPane';
import type {
  AuditEngineSource,
  AuditErrorInfo,
  AuditFinding,
  AuditNotice,
  AuditReport,
  AuditRunState,
  AuditVerdict,
  CodePreset,
  ExportFormat,
  WorkbenchLocale,
} from './types/workbench';

const AUDIT_TIMEOUT_MS = 10000;
const VERSION_LABEL = 'v1.5.0';

const PRESET_FILE_NAMES: Record<string, string> = {
  banking: 'src/ledger/transfer_points.py',
  jwt: 'src/auth/billing_route.ts',
  command: 'scripts/network_probe.py',
  traversal: 'src/server/download_report.js',
  ecommerce: 'src/checkout/calculate_total.js',
  custom: 'src/scratchpad.ts',
};

const RULE_TITLES: Record<string, string> = {
  DG001: 'Security or Logic Flaw',
  DG002: 'Defense-in-Depth Hardening',
  DG003: 'Score Below Threshold',
  DG004: 'Supply-Chain / Undeclared Package',
  DG005: 'Swallowed Exception',
  DG006: 'Non-Atomic State Mutation (TOCTOU)',
  DG007: 'Hardcoded Secret or Credential',
  DG008: 'Missing Timeout or Unbounded Async Loop',
};

function stripLeadingEmoji(raw: string): string {
  return raw.replace(/^[^\p{L}\p{N}]+/u, '').trim() || raw.trim();
}

function inferLanguageFromFileName(fileName: string, fallback: string): string {
  const lower = fileName.trim().toLowerCase();
  if (lower.endsWith('.ts') || lower.endsWith('.tsx')) return 'TypeScript';
  if (lower.endsWith('.js') || lower.endsWith('.jsx') || lower.endsWith('.mjs') || lower.endsWith('.cjs')) {
    return 'JavaScript';
  }
  if (lower.endsWith('.py')) return 'Python';
  return fallback;
}

function clampLine(line: number, totalLines: number): number {
  const safeTotal = Math.max(1, totalLines);
  if (!Number.isFinite(line)) return 1;
  return Math.min(Math.max(1, Math.trunc(line)), safeTotal);
}

function extractFirstLineNumber(text: string): number {
  const match = text.match(/\d+/);
  if (!match) return 1;
  const parsed = Number.parseInt(match[0], 10);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : 1;
}

function isNonScoringNoticeRule(ruleId: string, scoring?: boolean): boolean {
  return (
    scoring === false ||
    ruleId.startsWith('DG004-DYN-') ||
    ruleId.startsWith('DG004-WS-')
  );
}

function buildSarifExport(
  fileName: string,
  findings: AuditFinding[],
  notices: AuditNotice[]
): Record<string, unknown> {
  const results = [
    ...findings.map((finding) => ({
      ruleId: finding.id,
      level: finding.severity === 'info' ? 'note' : finding.severity,
      message: { text: finding.message },
      locations: [
        {
          physicalLocation: {
            artifactLocation: { uri: fileName || 'snippet.ts', uriBaseId: '%SRCROOT%' },
            region: {
              startLine: Math.max(1, finding.line),
              startColumn: finding.column ?? 1,
            },
          },
        },
      ],
    })),
    ...notices.map((notice) => ({
      ruleId: notice.code,
      level: 'warning',
      message: { text: notice.message },
      properties: { scoring: false },
      locations: [
        {
          physicalLocation: {
            artifactLocation: { uri: fileName || 'snippet.ts', uriBaseId: '%SRCROOT%' },
            region: { startLine: Math.max(1, notice.line ?? 1), startColumn: 1 },
          },
        },
      ],
    })),
  ];

  return {
    $schema:
      'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'DevGuard Adversarial Code Auditor',
            version: VERSION_LABEL.replace(/^v/, ''),
          },
        },
        results,
      },
    ],
  };
}

function normalizeParsedReport(
  parsed: ParsedDevGuardReport,
  fileName: string,
  durationMs: number,
  engineSource: AuditEngineSource
): AuditReport {
  const findings: AuditFinding[] = [];
  const notices: AuditNotice[] = [];

  const inlineList: InlineFinding[] = Array.isArray(parsed.inlineFindings)
    ? parsed.inlineFindings
    : [];

  for (const item of inlineList) {
    if (isNonScoringNoticeRule(item.ruleId, item.scoring)) {
      notices.push({
        code: item.ruleId,
        message: item.message,
        line: item.line > 0 ? item.line : undefined,
      });
    } else {
      findings.push({
        id: item.ruleId,
        ruleTitle: RULE_TITLES[item.ruleId] || item.ruleId,
        severity: item.severity,
        message: item.message,
        line: Math.max(1, item.line),
        blocking: item.severity === 'error',
      });
    }
  }

  const hasBlockingInline = findings.some((f) => f.blocking);
  if (
    !hasBlockingInline &&
    !parsed.isHardened &&
    parsed.temuanUtama?.description &&
    parsed.temuanUtama.line !== '-'
  ) {
    findings.push({
      id: 'DG001',
      ruleTitle: RULE_TITLES.DG001,
      severity: 'error',
      message: parsed.temuanUtama.description,
      line: extractFirstLineNumber(parsed.temuanUtama.line),
      blocking: true,
    });
  }

  for (const note of parsed.residualNotes || []) {
    findings.push({
      id: 'DG002',
      ruleTitle: RULE_TITLES.DG002,
      severity: 'info',
      message: note,
      line: extractFirstLineNumber(note),
      blocking: false,
    });
  }

  const hasBlocking = findings.some((f) => f.blocking);
  let verdict: AuditVerdict = 'PASS';
  if (hasBlocking || parsed.skor.totalScore < 70 || parsed.skor.security < 70) {
    verdict = 'FAIL';
  } else if (parsed.skor.totalScore < 85) {
    verdict = 'REVIEW';
  }

  return {
    verdict,
    scores: {
      overall: parsed.skor.totalScore,
      security: parsed.skor.security,
      correctness: parsed.skor.correctness,
      maintainability: parsed.skor.maintainability,
    },
    findings,
    notices,
    rawSarif: buildSarifExport(fileName, findings, notices),
    durationMs,
    engineSource,
  };
}

function triggerFileDownload(fileName: string, content: string): void {
  const blob = new Blob([content], { type: 'application/json;charset=utf-8' });
  const objectUrl = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = objectUrl;
  anchor.download = fileName;
  anchor.click();
  URL.revokeObjectURL(objectUrl);
}

export default function App() {
  const presets = useMemo<CodePreset[]>(
    () =>
      RAW_PRESETS.map((preset) => ({
        id: preset.id,
        label: stripLeadingEmoji(preset.title),
        fileName: PRESET_FILE_NAMES[preset.id] || `src/${preset.id}.ts`,
        language: preset.lang,
        code: preset.code,
      })),
    []
  );

  const initialPreset = presets[0];

  const [locale, setLocale] = useState<WorkbenchLocale>(getInitialLocale);
  const [selectedPresetId, setSelectedPresetId] = useState<string>(initialPreset.id);
  const [code, setCode] = useState<string>(initialPreset.code);
  const [fileName, setFileName] = useState<string>(initialPreset.fileName);
  const [language, setLanguage] = useState<string>(initialPreset.language);
  const [runState, setRunState] = useState<AuditRunState>('idle');
  const [report, setReport] = useState<AuditReport | null>(null);
  const [engineSource, setEngineSource] = useState<AuditEngineSource | null>(null);
  const [error, setError] = useState<AuditErrorInfo | null>(null);
  const [activeLine, setActiveLine] = useState<number | null>(null);
  const [selectedFindingKey, setSelectedFindingKey] = useState<string | null>(null);

  const totalLines = useMemo(() => Math.max(1, code.split('\n').length), [code]);

  const flaggedLines = useMemo<ReadonlySet<number>>(() => {
    if (!report) return new Set<number>();
    const linesSet = new Set<number>();
    for (const finding of report.findings) {
      if (finding.blocking && Number.isFinite(finding.line) && finding.line >= 1) {
        linesSet.add(clampLine(finding.line, totalLines));
      }
    }
    return linesSet;
  }, [report, totalLines]);

  const handleLocaleChange = useCallback((nextLocale: WorkbenchLocale) => {
    setLocale(nextLocale);
    persistLocale(nextLocale);
  }, []);

  const handleCodeChange = useCallback((nextCode: string) => {
    setCode(nextCode);
    setActiveLine(null);
    setSelectedFindingKey(null);
  }, []);

  const handleSelectPreset = useCallback(
    (presetId: string) => {
      const target = presets.find((item) => item.id === presetId);
      if (!target) return;
      setSelectedPresetId(target.id);
      setCode(target.code);
      setFileName(target.fileName);
      setLanguage(target.language);
      setRunState('idle');
      setReport(null);
      setEngineSource(null);
      setError(null);
      setActiveLine(null);
      setSelectedFindingKey(null);
    },
    [presets]
  );

  const handleFileNameChange = useCallback((nextFileName: string) => {
    setFileName(nextFileName);
    setLanguage((prev) => inferLanguageFromFileName(nextFileName, prev));
  }, []);

  const handleClearCode = useCallback(() => {
    setCode('');
    setRunState('idle');
    setReport(null);
    setEngineSource(null);
    setError(null);
    setActiveLine(null);
    setSelectedFindingKey(null);
  }, []);

  const handleRunAudit = useCallback(async () => {
    if (code.trim().length === 0) {
      setRunState('error');
      setReport(null);
      setEngineSource(null);
      setActiveLine(null);
      setSelectedFindingKey(null);
      setError({
        code: 'INVALID_INPUT',
        message:
          locale === 'id'
            ? 'Editor kode kosong. Masukkan cuplikan kode sebelum menjalankan audit.'
            : 'Code editor is empty. Provide a source snippet before running an audit.',
        retryable: false,
      });
      return;
    }

    const startedAt = performance.now();
    setRunState('running');
    setError(null);
    setActiveLine(null);
    setSelectedFindingKey(null);

    try {
      const response = await fetch('/api/devguard/review', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ code, fileName, locale }),
        signal: AbortSignal.timeout(AUDIT_TIMEOUT_MS),
      });

      if (!response.ok) {
        setRunState('error');
        setReport(null);
        setEngineSource(null);
        setError({
          code: 'HTTP_ERROR',
          message:
            locale === 'id'
              ? `Server audit mengembalikan status HTTP ${response.status}.`
              : `Audit endpoint returned HTTP ${response.status}.`,
          retryable: true,
        });
        return;
      }

      const payload = (await response.json()) as { parsedReport?: ParsedDevGuardReport };
      const hasLiveReport = Boolean(payload.parsedReport);
      const source: AuditEngineSource = hasLiveReport ? 'live' : 'offline';
      const parsed =
        payload.parsedReport ??
        analyzeCodeDeterministically(code, { filePath: fileName });
      const durationMs = Math.max(1, Math.round(performance.now() - startedAt));
      setEngineSource(source);
      setReport(normalizeParsedReport(parsed, fileName, durationMs, source));
      setRunState('success');
    } catch (caught: unknown) {
      const isTimeout =
        caught instanceof Error &&
        (caught.name === 'TimeoutError' || caught.name === 'AbortError');

      if (isTimeout) {
        setRunState('error');
        setReport(null);
        setEngineSource(null);
        setError({
          code: 'TIMEOUT',
          message:
            locale === 'id'
              ? 'Permintaan audit melebihi batas waktu 10 detik. Coba jalankan ulang.'
              : 'Audit request timed out after 10 seconds. Please retry.',
          retryable: true,
        });
        return;
      }

      // Explicit offline fallback to local deterministic analyzer when API backend is unreachable
      try {
        const localParsed = analyzeCodeDeterministically(code, { filePath: fileName });
        const durationMs = Math.max(1, Math.round(performance.now() - startedAt));
        setEngineSource('offline');
        setReport(normalizeParsedReport(localParsed, fileName, durationMs, 'offline'));
        setRunState('success');
      } catch (fallbackErr: unknown) {
        setRunState('error');
        setReport(null);
        setEngineSource(null);
        setError({
          code: 'NETWORK',
          message:
            fallbackErr instanceof Error
              ? fallbackErr.message
              : 'Unable to reach audit server or run local deterministic fallback.',
          retryable: true,
        });
      }
    }
  }, [code, fileName, locale]);

  const handleExport = useCallback(
    (format: ExportFormat) => {
      if (!report) return;
      if (format === 'sarif') {
        const sarifData =
          report.rawSarif ?? buildSarifExport(fileName, report.findings, report.notices);
        triggerFileDownload('devguard-results.sarif', JSON.stringify(sarifData, null, 2));
        return;
      }
      triggerFileDownload('devguard-report.json', JSON.stringify(report, null, 2));
    },
    [fileName, report]
  );

  const handleSelectFinding = useCallback(
    (finding: AuditFinding) => {
      const safeLine = clampLine(finding.line, totalLines);
      setSelectedFindingKey(`${finding.id}:${finding.line}`);
      setActiveLine(safeLine);
    },
    [totalLines]
  );

  const handleSelectNoticeLine = useCallback(
    (notice: AuditNotice) => {
      if (typeof notice.line === 'number' && notice.line > 0) {
        setSelectedFindingKey(null);
        setActiveLine(clampLine(notice.line, totalLines));
      }
    },
    [totalLines]
  );

  return (
    <div className="flex min-h-screen flex-col bg-[#0A0E17] font-sans text-slate-100">
      <CommandBar
        versionLabel={VERSION_LABEL}
        locale={locale}
        presets={presets}
        selectedPresetId={selectedPresetId}
        runState={runState}
        canExport={runState === 'success' && report !== null}
        onLocaleChange={handleLocaleChange}
        onSelectPreset={handleSelectPreset}
        onRunAudit={handleRunAudit}
        onExport={handleExport}
      />

      <main className="mx-auto grid w-full max-w-[1600px] flex-1 grid-cols-1 gap-4 p-4 lg:grid-cols-12 lg:p-6">
        <div className="lg:col-span-6">
          <CodeEditorPane
            code={code}
            fileName={fileName}
            language={language}
            activeLine={activeLine}
            flaggedLines={flaggedLines}
            runState={runState}
            timeoutMs={AUDIT_TIMEOUT_MS}
            onCodeChange={handleCodeChange}
            onFileNameChange={handleFileNameChange}
            onClearCode={handleClearCode}
            onRunShortcut={handleRunAudit}
            locale={locale}
          />
        </div>

        <div className="lg:col-span-6">
          <AuditResultsPane
            runState={runState}
            report={report}
            error={error}
            selectedFindingKey={selectedFindingKey}
            engineSource={engineSource}
            onSelectFinding={handleSelectFinding}
            onSelectNoticeLine={handleSelectNoticeLine}
            onRetry={handleRunAudit}
            locale={locale}
          />
        </div>
      </main>
    </div>
  );
}
