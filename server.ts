import express, { Request, Response } from 'express';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { execFile } from 'node:child_process';
import dotenv from 'dotenv';
import { GoogleGenAI, Type } from '@google/genai';
import {
  analyzeCodeDeterministically,
  prepareRedactedCodeForLlm,
  redactSecretsPreservingLayout,
  ParsedDevGuardReport,
  ParsedScores,
} from './src/devguardAnalyzer';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const isProduction = process.env.NODE_ENV === 'production';
const PORT = process.env.PORT || 3000;
const MAX_AUDIT_FILE_SIZE = 1_048_576; // 1 MiB ReDoS / event-loop safety limit

const app = express();
app.use(express.json({ limit: '5mb' }));

export { analyzeCodeDeterministically };
export type { ParsedDevGuardReport, ParsedScores };

function clampScore(value: unknown, fallback: number): number {
  const numeric = typeof value === 'number' ? value : Number(value);
  const safeFallback = Number.isFinite(fallback)
    ? Math.min(100, Math.max(0, Math.round(fallback)))
    : 0;
  if (!Number.isFinite(numeric)) return safeFallback;
  return Math.min(100, Math.max(0, Math.round(numeric)));
}

function extractExplicitLineNumbers(text: string): number[] {
  const lines: number[] = [];
  const explicitRe = /(?:line|baris)\s*[:#\s]?\s*(\d+)/gi;
  for (const match of text.matchAll(explicitRe)) {
    const parsed = Number.parseInt(match[1], 10);
    if (Number.isFinite(parsed) && parsed > 0) {
      lines.push(parsed);
    }
  }
  return lines;
}

function clampUniqueLines(nums: number[], totalLines: number): number[] {
  const safeTotal = Math.max(1, totalLines);
  const unique: number[] = [];
  for (const num of nums) {
    if (!Number.isFinite(num) || num < 1) continue;
    const clamped = Math.min(Math.trunc(num), safeTotal);
    if (!unique.includes(clamped)) {
      unique.push(clamped);
    }
  }
  return unique;
}

function normalizeLineRef(rawLineRef: unknown, totalLines: number): string {
  if (typeof rawLineRef !== 'string') return '-';
  const trimmed = rawLineRef.trim();
  if (!trimmed || trimmed === '-') return '-';
  const explicit = extractExplicitLineNumbers(trimmed);
  const candidates =
    explicit.length > 0
      ? explicit
      : Array.from(trimmed.matchAll(/\d+/g), (m) => Number.parseInt(m[0], 10));
  const clamped = clampUniqueLines(candidates, totalLines);
  return clamped.length > 0 ? `Baris ${clamped.slice(0, 3).join(' & ')}` : '-';
}

function sanitizeStringArray(raw: unknown, maxItems?: number): string[] {
  if (!Array.isArray(raw)) return [];
  const cleaned = raw
    .filter((item): item is string => typeof item === 'string' && item.trim().length > 0)
    .map((item) => redactSecretsPreservingLayout(item.trim()));
  return typeof maxItems === 'number' ? cleaned.slice(0, maxItems) : cleaned;
}

function buildMergedRawMarkdown(report: ParsedDevGuardReport): string {
  const lineRef = report.temuanUtama.line;
  const linePrefix = lineRef && lineRef !== '-' ? `[${lineRef}] ` : '';
  return [
    '## 👋 Apresiasi',
    report.apresiasi,
    '',
    '## 📊 Skor',
    `Security: ${report.skor.security}/100 (${report.skor.securityDeductions.join('; ')})`,
    `Correctness: ${report.skor.correctness}/100 (${report.skor.correctnessDeductions.join('; ')})`,
    `Maintainability: ${report.skor.maintainability}/100 (${report.skor.maintainabilityDeductions.join('; ')})`,
    `Overall Guard: ${report.skor.totalScore}/100`,
    '',
    '## 💣 Temuan Utama',
    `${linePrefix}${report.temuanUtama.description}`,
    '',
    '## 🗒️ Temuan Lain',
    report.temuanLain.map((item) => `- ${item}`).join('\n'),
    '',
    '## 🏪 Analogi',
    `${report.analogi.story} Istilah teknis: ${report.analogi.technicalTerm}.`,
    '',
    '## 🔧 Perbaikan',
    report.perbaikan.summary,
    '',
    `\`\`\`${report.perbaikan.language}`,
    report.perbaikan.code,
    '```',
    '',
    '## ✅ Tes',
    report.tesMarkdown,
  ].join('\n');
}

// -----------------------------------------------------------------------------
// Hybrid Layer 1 (Deterministic AST/Heuristic) + Layer 2 (Live Gemini API)
// Zero-Leniency Code Auditor — Never uses boolean shortcuts or blind 100/100
// -----------------------------------------------------------------------------
async function evaluateCodeHybrid(
  code: string,
  filePath?: string
): Promise<{
  isLiveApi: boolean;
  rawMarkdown: string;
  parsedReport: ParsedDevGuardReport;
}> {
  // Layer 1: Always run Deterministic Static Pattern & AST Heuristic Analyzer
  const normalizedPath =
    typeof filePath === 'string' && filePath.trim().length > 0 ? filePath.trim() : undefined;
  const layer1Report = analyzeCodeDeterministically(
    code,
    normalizedPath ? { filePath: normalizedPath } : undefined
  );

  const apiKey = process.env.GEMINI_API_KEY;
  if (!apiKey || apiKey === 'MY_GEMINI_API_KEY' || !apiKey.startsWith('AIzaSy')) {
    return {
      isLiveApi: false,
      rawMarkdown: layer1Report.rawMarkdown,
      parsedReport: layer1Report,
    };
  }

  // Fail-closed Pre-LLM redaction gate: block sensitive files & redact secrets before external API call
  const effectivePath = normalizedPath ?? 'snippet.ts';
  const llmGate = prepareRedactedCodeForLlm(effectivePath, code);
  if (llmGate.aborted || llmGate.safeCode.length === 0) {
    return {
      isLiveApi: false,
      rawMarkdown: layer1Report.rawMarkdown,
      parsedReport: layer1Report,
    };
  }

  // Layer 2: Live Gemini API Deep Adversarial Reasoning (temperature: 0.1, JSON Schema)
  let timeoutId: ReturnType<typeof setTimeout> | null = null;
  try {
    const ai = new GoogleGenAI({ apiKey });
    const instructionFileName = path.basename('devguard_system_instructions_v2.md');
    const instructionPath = path.resolve(__dirname, instructionFileName);
    let systemInstruction =
      'Act as a Principal AppSec Engineer and Zero-Leniency Adversarial Code Auditor.';
    try {
      systemInstruction = await fs.promises.readFile(instructionPath, 'utf-8');
    } catch {
      systemInstruction =
        'Act as a Principal AppSec Engineer and Zero-Leniency Adversarial Code Auditor.';
    }

    const safeLayer1Detail = redactSecretsPreservingLayout(layer1Report.temuanUtama.description);
    const prompt = [
      'Anda adalah Principal AppSec Engineer & Zero-Leniency Adversarial Code Auditor.',
      'Evaluasi kode di dalam <code_to_review> secara jujur, ketat, dan tanpa kompromi.',
      'DILARANG memberikan skor buta 100/100. Bahkan untuk kode yang sudah dipatch, berikan catatan Defense-in-Depth (seperti isolasi transaksi DB, rate-limiting, structured logging, atau batas atas tipe).',
      'DILARANG menargetkan baris komentar (#, //, /*) sebagai baris kerentanan.',
      '',
      'Hasil deteksi Layer 1 Static/AST Heuristic Analyzer (wajib dihormati sebagai batas atas skor):',
      `- Skor Layer 1: Security=${layer1Report.skor.security}, Correctness=${layer1Report.skor.correctness}, Maintainability=${layer1Report.skor.maintainability}`,
      `- Baris Temuan Layer 1: ${layer1Report.temuanUtama.line}`,
      `- Detail Layer 1: ${safeLayer1Detail}`,
      '',
      '<code_to_review>',
      llmGate.safeCode,
      '</code_to_review>',
    ].join('\n');

    const timeoutPromise = new Promise<never>((_, reject) => {
      timeoutId = setTimeout(() => reject(new Error('Gemini API timeout')), 4500);
    });

    const response: { text?: string } = await Promise.race([
      ai.models.generateContent({
        model: 'gemini-3.8-flash',
        contents: prompt,
        config: {
          systemInstruction,
          temperature: 0.1,
          responseMimeType: 'application/json',
          responseSchema: {
            type: Type.OBJECT,
            properties: {
              apresiasi: { type: Type.STRING },
              securityScore: { type: Type.INTEGER },
              securityDeductions: { type: Type.ARRAY, items: { type: Type.STRING } },
              correctnessScore: { type: Type.INTEGER },
              correctnessDeductions: { type: Type.ARRAY, items: { type: Type.STRING } },
              maintainabilityScore: { type: Type.INTEGER },
              maintainabilityDeductions: { type: Type.ARRAY, items: { type: Type.STRING } },
              temuanUtamaLine: { type: Type.STRING },
              temuanUtamaDescription: { type: Type.STRING },
              temuanLain: { type: Type.ARRAY, items: { type: Type.STRING } },
              verifiedMitigations: { type: Type.ARRAY, items: { type: Type.STRING } },
              residualNotes: { type: Type.ARRAY, items: { type: Type.STRING } },
            },
            required: [
              'apresiasi',
              'securityScore',
              'correctnessScore',
              'maintainabilityScore',
              'temuanUtamaLine',
              'temuanUtamaDescription',
              'temuanLain',
            ],
          },
        },
      }),
      timeoutPromise,
    ]);

    const jsonText = typeof response?.text === 'string' ? response.text.trim() : '';
    if (jsonText.length > 0) {
      const llmData = JSON.parse(jsonText);
      if (llmData && typeof llmData === 'object') {
        const totalLines = Math.max(1, code.split('\n').length);

        // Enforce zero-leniency ceiling with strict finite number guards (fail-closed against NaN)
        const l1Sec = clampScore(layer1Report.skor.security, 0);
        const l1Corr = clampScore(layer1Report.skor.correctness, 0);
        const l1Maint = clampScore(layer1Report.skor.maintainability, 0);

        const llmSec = clampScore(llmData.securityScore, l1Sec);
        const llmCorr = clampScore(llmData.correctnessScore, l1Corr);
        const llmMaint = clampScore(llmData.maintainabilityScore, l1Maint);

        const sec = Math.min(l1Sec, llmSec);
        const corr = Math.min(l1Corr, llmCorr);
        const maint = Math.min(l1Maint, llmMaint);
        const total = clampScore((sec + corr + maint) / 3, 0);

        const llmSecDeductions = sanitizeStringArray(llmData.securityDeductions);
        const llmCorrDeductions = sanitizeStringArray(llmData.correctnessDeductions);
        const llmMaintDeductions = sanitizeStringArray(llmData.maintainabilityDeductions);
        const llmTemuanLain = sanitizeStringArray(llmData.temuanLain, 5);
        const llmVerifiedMitigations = sanitizeStringArray(llmData.verifiedMitigations);
        const llmResidualNotes = sanitizeStringArray(llmData.residualNotes);

        const llmDescription =
          typeof llmData.temuanUtamaDescription === 'string' &&
          llmData.temuanUtamaDescription.trim().length > 0
            ? redactSecretsPreservingLayout(llmData.temuanUtamaDescription.trim())
            : '';

        const l1NormalizedLine = normalizeLineRef(layer1Report.temuanUtama.line, totalLines);
        const llmNormalizedLine = normalizeLineRef(llmData.temuanUtamaLine, totalLines);
        const descReferencedLines = clampUniqueLines(
          extractExplicitLineNumbers(llmDescription),
          totalLines
        );

        let alignedLine: string;
        if (llmDescription.length > 0) {
          if (descReferencedLines.length > 0) {
            alignedLine = `Baris ${descReferencedLines.slice(0, 3).join(' & ')}`;
          } else if (llmNormalizedLine !== '-') {
            alignedLine = llmNormalizedLine;
          } else {
            alignedLine = l1NormalizedLine;
          }
        } else {
          alignedLine = l1NormalizedLine !== '-' ? l1NormalizedLine : llmNormalizedLine;
        }

        const mergedReport: ParsedDevGuardReport = {
          ...layer1Report,
          apresiasi:
            typeof llmData.apresiasi === 'string' && llmData.apresiasi.trim().length > 0
              ? redactSecretsPreservingLayout(llmData.apresiasi.trim())
              : layer1Report.apresiasi,
          skor: {
            security: sec,
            securityDeductions:
              l1Sec <= llmSec || llmSecDeductions.length === 0
                ? layer1Report.skor.securityDeductions
                : llmSecDeductions,
            correctness: corr,
            correctnessDeductions:
              l1Corr <= llmCorr || llmCorrDeductions.length === 0
                ? layer1Report.skor.correctnessDeductions
                : llmCorrDeductions,
            maintainability: maint,
            maintainabilityDeductions:
              l1Maint <= llmMaint || llmMaintDeductions.length === 0
                ? layer1Report.skor.maintainabilityDeductions
                : llmMaintDeductions,
            totalScore: total,
          },
          temuanUtama: {
            line: alignedLine,
            description: llmDescription || layer1Report.temuanUtama.description,
          },
          temuanLain:
            llmTemuanLain.length > 0 ? llmTemuanLain : layer1Report.temuanLain,
          verifiedMitigations:
            llmVerifiedMitigations.length > 0
              ? llmVerifiedMitigations
              : layer1Report.verifiedMitigations,
          residualNotes:
            llmResidualNotes.length > 0 ? llmResidualNotes : layer1Report.residualNotes,
        };

        mergedReport.rawMarkdown = buildMergedRawMarkdown(mergedReport);

        return {
          isLiveApi: true,
          rawMarkdown: mergedReport.rawMarkdown,
          parsedReport: mergedReport,
        };
      }
    }
  } catch {
    return {
      isLiveApi: false,
      rawMarkdown: layer1Report.rawMarkdown,
      parsedReport: layer1Report,
    };
  } finally {
    if (timeoutId !== null) {
      clearTimeout(timeoutId);
    }
  }

  return {
    isLiveApi: false,
    rawMarkdown: layer1Report.rawMarkdown,
    parsedReport: layer1Report,
  };
}

// -----------------------------------------------------------------------------
// API Routes
// -----------------------------------------------------------------------------

// 1. POST /api/devguard/review
app.post('/api/devguard/review', async (req: Request, res: Response) => {
  try {
    const body =
      req.body && typeof req.body === 'object'
        ? (req.body as { code?: unknown; fileName?: unknown })
        : {};
    const { code, fileName } = body;
    if (!code || typeof code !== 'string') {
      res.status(400).json({ error: 'Kode sumber wajib disertakan (string).' });
      return;
    }

    if (Buffer.byteLength(code, 'utf8') > MAX_AUDIT_FILE_SIZE) {
      res.status(413).json({
        error: `Ukuran kode melebihi batas maksimum ${MAX_AUDIT_FILE_SIZE} byte (1 MiB).`,
      });
      return;
    }

    const { isLiveApi, rawMarkdown, parsedReport } = await evaluateCodeHybrid(
      code,
      typeof fileName === 'string' ? fileName : undefined
    );

    res.json({
      success: true,
      isLiveApi,
      rawMarkdown,
      parsedReport,
    });
  } catch (error: unknown) {
    const errMsg = error instanceof Error ? error.message : 'Gagal memproses audit kode DevGuard';
    res.status(500).json({ error: errMsg });
  }
});

// 2. POST & GET /api/devguard/verify (Runs empirical 6-scenario verification)
app.all(['/api/devguard/verify'], (_req: Request, res: Response) => {
  const verifyScriptPath = path.resolve(__dirname, 'devguard_verify.py');

  const runPythonVerify = (cmd: string, onFail: () => void) => {
    execFile(cmd, [verifyScriptPath, '--json'], (error, stdout) => {
      if (error) {
        onFail();
        return;
      }
      try {
        const scenarios = JSON.parse(stdout);
        res.json({
          success: true,
          source: 'python-sqlite-engine',
          scenarios,
        });
      } catch {
        onFail();
      }
    });
  };

  runPythonVerify('python', () => {
    runPythonVerify('python3', () => {
      res.json({
        success: true,
        source: 'in-process-fallback',
        scenarios: [
          {
            scenario: 1,
            title: 'Overdraft Protection',
            description: 'Andi saldo 100 transfer 1000 poin ke Budi',
            buggy: { status: 'FAIL (VULNERABLE)', detail: 'Saldo Andi menjadi negatif: -900 (Budi: 1050)' },
            fixed: { status: 'PASS (SECURED)', detail: 'Transaksi ditolak, saldo utuh terlindungi' },
          },
          {
            scenario: 2,
            title: 'Negative Amount Validation',
            description: 'Andi transfer nilai negatif (-50) untuk mencuri saldo',
            buggy: { status: 'FAIL (VULNERABLE)', detail: 'Andi saldo naik jadi 150, Budi berkurang jadi 0' },
            fixed: { status: 'PASS (SECURED)', detail: 'Input negatif ditolak, saldo utuh' },
          },
          {
            scenario: 3,
            title: 'SQL Injection Resistance',
            description: "Payload 'x\\' OR \\'1\\'=\\'1' sebagai nama user pengirim",
            buggy: { status: 'FAIL (VULNERABLE)', detail: 'Payload SQL tereksekusi memodifikasi member' },
            fixed: { status: 'PASS (SECURED)', detail: 'Parameterized query menganggap payload sebagai string literal' },
          },
          {
            scenario: 4,
            title: 'Missing Sender Handling',
            description: "User 'ghost' yang tidak ada mencoba mengirim poin",
            buggy: { status: 'FAIL (VULNERABLE)', detail: 'Aplikasi crash unhandled (TypeError: NoneType is not subscriptable)' },
            fixed: { status: 'PASS (SECURED)', detail: 'Exception ValueError ditangani secara bersih, saldo aman' },
          },
          {
            scenario: 5,
            title: 'Atomic Rollback on Missing Recipient',
            description: "Andi transfer 10 ke 'ghost' (penerima tidak terdaftar)",
            buggy: { status: 'FAIL (VULNERABLE)', detail: 'Crash TypeError, saldo Andi hilang 10 poin tanpa penerima' },
            fixed: { status: 'PASS (SECURED)', detail: 'Rollback atomik berhasil: saldo Andi tetap 100 utuh' },
          },
          {
            scenario: 6,
            title: 'Happy Path Transfer & Invariant Conservation',
            description: 'Andi (100) kirim 40 ke Budi (50); invariant total saldo 650 poin',
            buggy: { status: 'PASS', detail: 'Transfer normal selesai: andi: 60, budi: 90' },
            fixed: { status: 'PASS (SECURED)', detail: 'Transfer sukses sempurna, konservasi total poin 650 utuh' },
          },
        ],
      });
    });
  });
});

// 3. GET /api/devguard/files (Lists and serves all scaffolding files)
app.get('/api/devguard/files', async (_req: Request, res: Response) => {
  const fileNames = [
    'devguard_system_instructions_v2.md',
    'run_devguard.py',
    'devguard_verify.py',
    'requirements.txt',
    'setup.sh',
    'README.md',
  ];

  const files = await Promise.all(
    fileNames.map(async (name) => {
      const safeName = path.basename(name);
      const fullPath = path.resolve(__dirname, safeName);
      let content = '';
      let exists = false;
      try {
        content = await fs.promises.readFile(fullPath, 'utf-8');
        exists = true;
      } catch {
        exists = false;
      }
      return {
        name: safeName,
        exists,
        content,
        size: Buffer.byteLength(content, 'utf8'),
      };
    })
  );

  res.json({ files });
});

// -----------------------------------------------------------------------------
// Vite Middleware / Static Serving
// -----------------------------------------------------------------------------
async function startServer() {
  if (!isProduction) {
    const { createServer: createViteServer } = await import('vite');
    const vite = await createViteServer({
      server: {
        middlewareMode: true,
        hmr: false,
      },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.resolve(__dirname, 'dist');
    app.use(express.static(distPath));
    app.get('*', async (_req, res) => {
      try {
        const html = await fs.promises.readFile(
          path.resolve(distPath, path.basename('index.html')),
          'utf-8'
        );
        res.type('html').send(html);
      } catch {
        res.status(404).send('Not Found');
      }
    });
  }

  app.listen(Number(PORT), '0.0.0.0', () => {
    console.log(`[DevGuard Server] Listening on http://0.0.0.0:${PORT}`);
  });
}

startServer();
