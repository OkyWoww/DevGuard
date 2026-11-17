import * as fs from 'node:fs';
import * as path from 'node:path';
import { redactSecretsPreservingLayout } from './devguardAnalyzer.js';
import {
  formatSkippedReasonText,
  type FileAuditSummary,
  type SkippedFileReportItem,
} from './githubCommenter.js';

function normalizeSarifUri(filePath: string): string {
  const relPath = path.isAbsolute(filePath)
    ? path.relative(process.cwd(), filePath)
    : filePath;
  return relPath.replace(/\\/g, '/').replace(/^\.\//, '');
}

export interface SarifFindingLocation {
  filePath: string;
  ruleId: string;
  level: 'error' | 'warning' | 'note';
  message: string;
  startLine?: number;
}

/**
 * Mencoba mengekstrak nomor baris jika pesan error mengandung pola "Line X", "baris X", atau "[Baris X]",
 * fallback ke baris 1 jika temuan bersifat arsitektural tingkat file.
 */
function extractLineNumber(text: string): number {
  const match = text.match(/(?:line|baris)\s*[:#\s]?\s*(\d+)/i);
  if (match && match[1]) {
    const parsed = parseInt(match[1], 10);
    return parsed > 0 ? parsed : 1;
  }
  return 1;
}

function createSarifResult(
  ruleId: string,
  level: 'error' | 'warning' | 'note',
  text: string,
  uri: string,
  startLine: number,
  endLine?: number
): Record<string, unknown> {
  const safeStartLine = Math.max(1, startLine);
  const region: Record<string, number> = {
    startLine: safeStartLine,
    startColumn: 1,
  };
  if (endLine && endLine >= safeStartLine) {
    region.endLine = endLine;
  }

  return {
    ruleId,
    level,
    message: { text: redactSecretsPreservingLayout(text) },
    locations: [
      {
        physicalLocation: {
          artifactLocation: {
            uri,
            uriBaseId: '%SRCROOT%',
          },
          region,
        },
      },
    ],
  };
}

export function generateSarifReport(
  summaries: FileAuditSummary[],
  outputPath: string = 'devguard-results.sarif',
  skippedFiles: ReadonlyArray<SkippedFileReportItem> = []
): string {
  const rulesMap = new Map<string, {
    id: string;
    name: string;
    shortDescription: { text: string };
    fullDescription: { text: string };
    defaultConfiguration: { level: 'error' | 'warning' | 'note' };
    properties: { tags: string[]; 'security-severity': string };
  }>();

  // Security-severity CVSS mapping per rule (OASIS SARIF / GitHub Code Scanning):
  // DG001: 9.5, DG007: 9.0, DG006: 8.5, DG003: 8.0, DG004: 7.5, DG005: 7.0, DG008: 6.5, DG002: 5.0

  // Rule 1: Fatal Security / Logic Flaw (Blocker)
  rulesMap.set('DG001', {
    id: 'DG001',
    name: 'AdversarialSecurityOrLogicFlaw',
    shortDescription: {
      text: 'Critical security vulnerability or exploitable logic flaw detected by DevGuard.'
    },
    fullDescription: {
      text: 'DevGuard Hybrid Auditor identified a deterministic Single-Pass Lexical & Heuristic sink, TOCTOU race condition, type bypass, or critical security risk that violates the quality gate.'
    },
    defaultConfiguration: { level: 'error' },
    properties: {
      tags: ['security', 'adversarial-audit', 'external/cwe/cwe-693'],
      'security-severity': '9.5'
    }
  });

  // Rule 2: Defense-in-Depth Hardening Note (Warning/Note)
  rulesMap.set('DG002', {
    id: 'DG002',
    name: 'DefenseInDepthRecommendation',
    shortDescription: {
      text: 'Defense-in-Depth architectural hardening recommendation.'
    },
    fullDescription: {
      text: 'Zero-Leniency audit note explaining why code does not receive a 100/100 score and how to harden against secondary edge cases.'
    },
    defaultConfiguration: { level: 'warning' },
    properties: {
      tags: ['security', 'defense-in-depth', 'maintainability'],
      'security-severity': '5.0'
    }
  });

  // Rule 3: Threshold Gate Failure
  rulesMap.set('DG003', {
    id: 'DG003',
    name: 'OverallScoreBelowThreshold',
    shortDescription: {
      text: 'File overall DevGuard score fell below minimum CI threshold.'
    },
    fullDescription: {
      text: 'The combined Security, Correctness, and Maintainability score did not meet the configured minimum threshold for this repository.'
    },
    defaultConfiguration: { level: 'error' },
    properties: {
      tags: ['quality-gate', 'security'],
      'security-severity': '8.0'
    }
  });

  // Rule 4: Hallucinated & Typosquatted Packages (Slopsquatting)
  rulesMap.set('DG004', {
    id: 'DG004',
    name: 'HallucinatedOrTyposquattedPackage',
    shortDescription: {
      text: 'Hallucinated, undeclared, or typosquatted package dependency detected.'
    },
    fullDescription: {
      text: 'Detected a package import with a suspicious edit distance to a popular NPM package or absent from package.json.'
    },
    defaultConfiguration: { level: 'error' },
    properties: {
      tags: ['security', 'supply-chain', 'slopsquatting', 'external/cwe/cwe-829'],
      'security-severity': '7.5'
    }
  });

  // Rule 5: Swallowed Exceptions
  rulesMap.set('DG005', {
    id: 'DG005',
    name: 'SwallowedExceptionInFlow',
    shortDescription: {
      text: 'Empty or console-only catch block swallows runtime failures.'
    },
    fullDescription: {
      text: 'A catch block ignores exceptions or logs only without rethrowing, returning a failure state, or rolling back critical state.'
    },
    defaultConfiguration: { level: 'warning' },
    properties: {
      tags: ['security', 'reliability', 'error-handling', 'external/cwe/cwe-390'],
      'security-severity': '7.0'
    }
  });

  // Rule 6: Non-Atomic Balance / Stock Mutations (TOCTOU)
  rulesMap.set('DG006', {
    id: 'DG006',
    name: 'NonAtomicBalanceOrStockMutation',
    shortDescription: {
      text: 'Non-atomic check-then-act mutation across await boundary (TOCTOU race condition).'
    },
    fullDescription: {
      text: 'Reads and validates balance, stock, or quota state before mutating it across an asynchronous boundary without an atomic transaction or lock.'
    },
    defaultConfiguration: { level: 'error' },
    properties: {
      tags: ['security', 'concurrency', 'toctou', 'external/cwe/cwe-362'],
      'security-severity': '8.5'
    }
  });

  // Rule 7: Hardcoded AI, Payment & Cloud API Secrets
  rulesMap.set('DG007', {
    id: 'DG007',
    name: 'HardcodedSecretOrApiKey',
    shortDescription: {
      text: 'Hardcoded AI, payment, or cloud API secret detected in source code.'
    },
    fullDescription: {
      text: 'Detected a provider-prefixed API key or high-entropy credential literal assigned directly in source instead of loaded from environment variables.'
    },
    defaultConfiguration: { level: 'error' },
    properties: {
      tags: ['security', 'secrets', 'credentials', 'external/cwe/cwe-798'],
      'security-severity': '9.0'
    }
  });

  // Rule 8: Missing Fetch Timeout & Unbounded Async Loops
  rulesMap.set('DG008', {
    id: 'DG008',
    name: 'MissingTimeoutOrUnboundedAsyncLoop',
    shortDescription: {
      text: 'Missing network AbortSignal timeout or unbounded async polling loop.'
    },
    fullDescription: {
      text: 'Detected an external fetch() call lacking AbortSignal.timeout() or an unbounded loop containing await without break, return, throw, or bounded retry limits.'
    },
    defaultConfiguration: { level: 'error' },
    properties: {
      tags: ['security', 'reliability', 'resilience', 'external/cwe/cwe-400'],
      'security-severity': '6.5'
    }
  });

  const results: Array<Record<string, unknown>> = [];

  for (const summary of summaries) {
    const normalizedUri = normalizeSarifUri(summary.filePath);

    // 1. Emit inlineFindings directly when present (DG001-DG008)
    const inlineFindings = summary.inlineFindings || [];
    for (const finding of inlineFindings) {
      results.push(
        createSarifResult(
          finding.ruleId,
          finding.severity,
          finding.message,
          normalizedUri,
          finding.line,
          finding.endLine
        )
      );
    }

    // 2. Masukkan Fatal Flaws sebagai SARIF 'error' (DG001) jika belum tercakup penuh oleh inlineFindings
    const inlineErrorMessages = inlineFindings
      .filter((f) => f.severity === 'error')
      .map((f) => f.message);

    for (const flaw of summary.fatalFlaws) {
      const coveredCompletelyByInline =
        inlineErrorMessages.length > 0 &&
        inlineErrorMessages.every((msg) => flaw.includes(msg)) &&
        flaw.trim() === inlineErrorMessages.join(' ').trim();

      if (!coveredCompletelyByInline) {
        const line = extractLineNumber(flaw);
        results.push(createSarifResult('DG001', 'error', flaw, normalizedUri, line));
      }
    }

    // 3. Jika skor gagal tapi fatalFlaws & inlineFindings error kosong, catat pelanggaran threshold (DG003)
    if (
      !summary.passed &&
      Number.isFinite(summary.overall) &&
      summary.fatalFlaws.length === 0 &&
      inlineErrorMessages.length === 0
    ) {
      results.push(
        createSarifResult(
          'DG003',
          'error',
          `DevGuard overall score (${summary.overall}/100) is below the required threshold. (Security: ${summary.security}, Correctness: ${summary.correctness}, Maintainability: ${summary.maintainability})`,
          normalizedUri,
          1
        )
      );
    }

    // 4. Masukkan catatan Defense-in-Depth sebagai SARIF 'warning' (DG002)
    for (const note of summary.defenseInDepth) {
      const line = extractLineNumber(note);
      results.push(createSarifResult('DG002', 'warning', note, normalizedUri, line));
    }

    // 5. Stage 3a: Emit active suppressions with standard SARIF v2.1.0 suppressions metadata
    for (const sup of summary.suppressions || []) {
      const suppressedResult = createSarifResult(
        sup.ruleId,
        sup.severity || 'warning',
        sup.message || `Suppressed ${sup.ruleId} finding: ${sup.reason}`,
        normalizedUri,
        sup.targetLine
      );
      suppressedResult.suppressions = [
        {
          kind: sup.kind,
          justification: redactSecretsPreservingLayout(sup.reason),
        },
      ];
      results.push(suppressedResult);
    }
  }

  const hasExecutionError = skippedFiles.some(
    (item) => item.reason === 'parse_error' || item.reason === 'internal_error'
  );

  const toolExecutionNotifications = skippedFiles.map((item) => {
    const isError = item.reason === 'parse_error' || item.reason === 'internal_error';
    return {
      level: (isError ? 'error' : 'note') as 'error' | 'note',
      message: {
        text: redactSecretsPreservingLayout(formatSkippedReasonText(item.reason)),
      },
      locations: [
        {
          physicalLocation: {
            artifactLocation: {
              uri: normalizeSarifUri(item.filePath),
              uriBaseId: '%SRCROOT%',
            },
          },
        },
      ],
    };
  });

  const sarifLog = {
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'DevGuard Adversarial Code Auditor',
            informationUri: 'https://github.com/OkyWoww/DevGuard',
            version: '1.2.1',
            rules: Array.from(rulesMap.values())
          }
        },
        invocations: [
          {
            executionSuccessful: !hasExecutionError,
            toolExecutionNotifications,
          },
        ],
        results
      }
    ]
  };

  const resolvedPath = path.resolve(process.cwd(), outputPath);
  fs.writeFileSync(resolvedPath, JSON.stringify(sarifLog, null, 2), 'utf-8');
  console.log(`📄 Laporan SARIF v2.1.0 berhasil dibuat: ${resolvedPath} (${results.length} anotasi)`);

  return resolvedPath;
}
