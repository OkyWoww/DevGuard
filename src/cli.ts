#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import dotenv from 'dotenv';
import { GoogleGenAI, Type } from '@google/genai';
import {
  analyzeCodeDeterministically,
  ParsedDevGuardReport,
} from './devguardAnalyzer.js';

dotenv.config();

interface CliAuditResult {
  mode: 'zero-api' | 'hybrid';
  isLiveApi: boolean;
  parsedReport: ParsedDevGuardReport;
}

export async function runDevGuardAudit(
  codeContent: string,
  fileName: string = 'snippet'
): Promise<CliAuditResult> {
  // Layer 1: Deterministic AST & Static Heuristic Analyzer (Instant, 100% Free, Zero-API)
  const l1Result = analyzeCodeDeterministically(codeContent);

  const apiKey = process.env.GEMINI_API_KEY;

  if (!apiKey || apiKey === 'MY_GEMINI_API_KEY' || !apiKey.startsWith('AIzaSy')) {
    console.log('\n⚡ Info: GEMINI_API_KEY tidak terdeteksi.');
    console.log('🛡️  Menjalankan DevGuard dalam mode: 100% Offline Deterministic AST Engine (Mode Zero-API).\n');
    return {
      mode: 'zero-api',
      isLiveApi: false,
      parsedReport: l1Result,
    };
  }

  console.log('\n🤖 Menjalankan DevGuard dalam mode: Hybrid Dual-Layer (AST + Gemini 3.8 Flash).');
  console.log('🔑 GEMINI_API_KEY terdeteksi: Menggunakan kuota API developer lokal...\n');

  try {
    const ai = new GoogleGenAI({ apiKey });
    const prompt = [
      'Anda adalah Principal AppSec Engineer & Zero-Leniency Adversarial Code Auditor.',
      'Evaluasi kode di dalam <code_to_review> secara jujur, ketat, dan tanpa kompromi.',
      'DILARANG memberikan skor buta 100/100.',
      '',
      `Hasil deteksi Layer 1 AST Analyzer:`,
      `- Security=${l1Result.skor.security}, Correctness=${l1Result.skor.correctness}, Maintainability=${l1Result.skor.maintainability}`,
      `- Baris Temuan: ${l1Result.temuanUtama.line}`,
      '',
      '<code_to_review>',
      codeContent,
      '</code_to_review>',
    ].join('\n');

    const timeoutPromise = new Promise<never>((_, reject) =>
      setTimeout(() => reject(new Error('Gemini API timeout')), 6000)
    );

    const response: any = await Promise.race([
      ai.models.generateContent({
        model: 'gemini-3.8-flash',
        contents: prompt,
        config: {
          temperature: 0.1,
          responseMimeType: 'application/json',
          responseSchema: {
            type: Type.OBJECT,
            properties: {
              apresiasi: { type: Type.STRING },
              skor: {
                type: Type.OBJECT,
                properties: {
                  security: { type: Type.INTEGER },
                  securityDeductions: { type: Type.ARRAY, items: { type: Type.STRING } },
                  correctness: { type: Type.INTEGER },
                  correctnessDeductions: { type: Type.ARRAY, items: { type: Type.STRING } },
                  maintainability: { type: Type.INTEGER },
                  maintainabilityDeductions: { type: Type.ARRAY, items: { type: Type.STRING } },
                },
                required: ['security', 'correctness', 'maintainability'],
              },
              temuanUtama: {
                type: Type.OBJECT,
                properties: {
                  line: { type: Type.STRING },
                  description: { type: Type.STRING },
                },
                required: ['line', 'description'],
              },
              temuanLain: { type: Type.ARRAY, items: { type: Type.STRING } },
              analogi: {
                type: Type.OBJECT,
                properties: {
                  story: { type: Type.STRING },
                  technicalTerm: { type: Type.STRING },
                },
                required: ['story', 'technicalTerm'],
              },
              perbaikanSummary: { type: Type.STRING },
            },
            required: ['apresiasi', 'skor', 'temuanUtama', 'analogi'],
          },
        },
      }),
      timeoutPromise,
    ]);

    const geminiData = JSON.parse(response.text.trim());

    // Ceilings enforced by Layer 1 zero-leniency rubric
    const reconciledSecurity = Math.min(l1Result.skor.security, geminiData.skor?.security ?? 100);
    const reconciledCorrectness = Math.min(l1Result.skor.correctness, geminiData.skor?.correctness ?? 100);
    const reconciledMaintainability = Math.min(l1Result.skor.maintainability, geminiData.skor?.maintainability ?? 100);
    const reconciledTotal = Math.round((reconciledSecurity + reconciledCorrectness + reconciledMaintainability) / 3);

    return {
      mode: 'hybrid',
      isLiveApi: true,
      parsedReport: {
        ...l1Result,
        apresiasi: geminiData.apresiasi || l1Result.apresiasi,
        skor: {
          security: reconciledSecurity,
          securityDeductions: geminiData.skor?.securityDeductions?.length
            ? geminiData.skor.securityDeductions
            : l1Result.skor.securityDeductions,
          correctness: reconciledCorrectness,
          correctnessDeductions: geminiData.skor?.correctnessDeductions?.length
            ? geminiData.skor.correctnessDeductions
            : l1Result.skor.correctnessDeductions,
          maintainability: reconciledMaintainability,
          maintainabilityDeductions: geminiData.skor?.maintainabilityDeductions?.length
            ? geminiData.skor.maintainabilityDeductions
            : l1Result.skor.maintainabilityDeductions,
          totalScore: reconciledTotal,
        },
        temuanUtama: {
          line: l1Result.temuanUtama.line !== '-' ? l1Result.temuanUtama.line : (geminiData.temuanUtama?.line || '-'),
          description: geminiData.temuanUtama?.description || l1Result.temuanUtama.description,
        },
        temuanLain: geminiData.temuanLain?.length ? geminiData.temuanLain : l1Result.temuanLain,
        analogi: {
          story: geminiData.analogi?.story || l1Result.analogi.story,
          technicalTerm: geminiData.analogi?.technicalTerm || l1Result.analogi.technicalTerm,
        },
      },
    };
  } catch (err: any) {
    console.warn(`⚠️  Gemini API tidak dapat dijangkau (${err.message}). Otomatis dialihkan ke Layer 1 AST Engine.`);
    return {
      mode: 'zero-api',
      isLiveApi: false,
      parsedReport: l1Result,
    };
  }
}

function printReport(result: CliAuditResult, targetName: string) {
  const r = result.parsedReport;
  const s = r.skor;

  console.log('======================================================================');
  console.log(`               DEVGUARD ADVERSARIAL CODE AUDIT REPORT                 `);
  console.log('======================================================================');
  console.log(`Target      : ${targetName}`);
  console.log(`Mode Engine : ${result.mode === 'hybrid' ? '🤖 Hybrid (Layer 1 AST + Layer 2 Gemini 3.8 Flash)' : '🛡️  Zero-API (100% Offline / Local AST Engine)'}`);
  console.log(`Status Kunci: ${result.isLiveApi ? 'API Key Valid' : 'Offline / Tanpa Kuota API'}`);
  console.log('----------------------------------------------------------------------');
  console.log('📊 MATRIKS SKOR ZERO-LENIENCY:');
  console.log(`   Security        : ${s.security}/100`);
  console.log(`   Correctness     : ${s.correctness}/100`);
  console.log(`   Maintainability : ${s.maintainability}/100`);
  console.log(`   Overall Guard   : ${s.totalScore}/100 [${r.isHardened ? '✓ SIAP MERGE (HARDENED)' : s.totalScore < 60 ? '✗ PERLU DITOLAK' : '⚠ PERLU REVISI'}]`);
  console.log('----------------------------------------------------------------------');
  console.log(`💣 TEMUAN UTAMA (${r.temuanUtama.line}):`);
  console.log(`   ${r.temuanUtama.description}`);
  console.log('----------------------------------------------------------------------');
  console.log('🗒️  TEMUAN LAIN & CATATAN ARSITEKTUR:');
  r.temuanLain.forEach((item, idx) => {
    console.log(`   ${idx + 1}. ${item}`);
  });
  console.log('----------------------------------------------------------------------');
  console.log(`🏪 ANALOGI DUNIA NYATA (${r.analogi.technicalTerm}):`);
  console.log(`   "${r.analogi.story}"`);
  console.log('======================================================================\n');
}

// -----------------------------------------------------------------------------
// CLI Direct Execution Entrypoint
// Usage:
//   npx tsx src/cli.ts [path/to/file]
//   npx tsx src/cli.ts --check [path/to/file]
// -----------------------------------------------------------------------------
async function main() {
  const args = process.argv.slice(2);
  let filePath = args.find((a) => !a.startsWith('--'));
  const enforceExitCode = args.includes('--check') || args.includes('--ci');

  // If no file passed, audit default junior sample
  let codeContent = '';
  let targetName = '';

  if (filePath && fs.existsSync(filePath)) {
    codeContent = fs.readFileSync(filePath, 'utf-8');
    targetName = path.basename(filePath);
  } else {
    // Default fallback snippet (Banking Ledger)
    targetName = 'banking_sample.py (Default)';
    codeContent = `# Modul transfer poin member (oleh: Junior Backend Dev)
def kirim_poin(db, user_pengirim, user_penerima, jumlah):
    q1 = "SELECT poin FROM members WHERE username = '" + user_pengirim + "'"
    saldo = db.execute(q1).fetchone()[0]
    if saldo > 0:
        saldo_baru = saldo - jumlah
        db.execute("UPDATE members SET poin = " + str(saldo_baru) + " WHERE username = '" + user_pengirim + "'")
        q2 = "SELECT poin FROM members WHERE username = '" + user_penerima + "'"
        saldo_penerima = db.execute(q2).fetchone()[0]
        db.execute("UPDATE members SET poin = " + str(saldo_penerima + jumlah) + " WHERE username = '" + user_penerima + "'")
        return "Berhasil transfer!"
    return "Gagal!"
`;
  }

  const result = await runDevGuardAudit(codeContent, targetName);
  printReport(result, targetName);

  if (enforceExitCode) {
    if (!result.parsedReport.isHardened && result.parsedReport.skor.totalScore < 80) {
      console.error('❌ CI Check Gagal: Skor di bawah batas minimum (80/100). Perbaiki celah sebelum merge.');
      process.exit(1);
    } else {
      console.log('✅ CI Check Lolos: Kode memenuhi standar keamanan.');
      process.exit(0);
    }
  }
}

// Check if run directly via CLI
const isMain = process.argv[1] && (
  process.argv[1].endsWith('cli.ts') ||
  process.argv[1].endsWith('cli.js') ||
  process.argv[1].includes('cli')
);

if (isMain) {
  main().catch((err) => {
    console.error('Fatal CLI Error:', err);
    process.exit(1);
  });
}
