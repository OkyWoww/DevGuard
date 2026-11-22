export type WorkbenchLocale = 'en' | 'id';

export type AuditRunState = 'idle' | 'running' | 'success' | 'error';

export type AuditVerdict = 'PASS' | 'FAIL' | 'REVIEW';

export type FindingSeverity = 'error' | 'warning' | 'info';

export type ExportFormat = 'json' | 'sarif';

export type AuditEngineSource = 'live' | 'offline';

export interface CodePreset {
  id: string;
  label: string;
  fileName: string;
  language: string;
  code: string;
}

export interface ScoreBreakdown {
  overall: number;        // 0..100
  security: number;       // 0..100
  correctness: number;    // 0..100
  maintainability: number; // 0..100
}

export interface AuditFinding {
  id: string;             // e.g. 'DG001' .. 'DG008'
  ruleTitle: string;
  severity: FindingSeverity;
  message: string;
  line: number;           // 1-based line index
  column?: number;        // 1-based column index
  blocking: boolean;
}

export interface AuditNotice {
  code: string;           // e.g. 'DG004-WS-SHALLOW', 'DG004-WS-NEW', 'DG004-WS-UNPARSED', 'DG004-DYN-01'
  message: string;
  line?: number;
}

export interface AuditRemediation {
  code: string;
  language: string;
  summary: string;
}

export interface AuditReport {
  verdict: AuditVerdict;
  scores: ScoreBreakdown;
  findings: AuditFinding[];
  notices: AuditNotice[];
  remediation?: AuditRemediation;
  rawSarif?: unknown;
  durationMs?: number;
  engineSource?: AuditEngineSource;
}

export interface AuditErrorInfo {
  code: 'TIMEOUT' | 'NETWORK' | 'HTTP_ERROR' | 'INVALID_INPUT';
  message: string;
  retryable: boolean;
}
