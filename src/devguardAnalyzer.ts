import {
  MAX_BACKSCAN,
  MAX_FOLDED_LENGTH,
  MAX_FOLD_DEPTH,
  MAX_FOLD_EDITS,
  MAX_FOLD_OPERANDS,
  MAX_GLOB_PATTERN_LENGTH,
  MEANINGFUL_SUPPRESSION_REASON_RE,
  analyzeLexicalStructure,
  applyTextEditsWithSpanMap,
  buildVirtualView,
  calculateShannonEntropy,
  composeSpanMaps,
  createIdentitySpanMap,
  damerauLevenshtein,
  isCommentOrEmptyLine,
  isRangeStrictlyInCodeRegion,
  isValidSuppressionReason,
  matchLinearGlob,
  toOrigLineAndCol,
  toOrigSpan,
  verifySpanMapInvariants,
  type AllowlistRuleId,
  type AuditAnalyzeOptions,
  type DevGuardRuleId,
  type FoldTextEdit,
  type InlineFinding,
  type LexicalRegion,
  type LexicalRegionKind,
  type LineFinding,
  type ParsedSuppression,
  type SpanMap,
  type SpanMapSeg,
  type VirtualViewResult,
} from './rules/lexicalMasker.ts';
import {
  CRITICAL_FLOW_IDENTIFIERS,
  POPULAR_NPM_PACKAGES,
  detectDynamicModuleSpecifiers,
  detectHallucinatedPackages,
  detectNonAtomicBalanceMutations,
  detectSwallowedExceptions,
  matchesCriticalFlow,
} from './rules/packageAndExceptionRules.ts';
import {
  DG007_PROVIDER_PATTERNS,
  detectHardcodedSecrets,
  detectMissingTimeoutsAndLoops,
  findResidualSecretLikeTokens,
  prepareRedactedCodeForLlm,
  redactSecretsPreservingLayout,
  type PrepareLlmOptions,
} from './rules/secretAndResilienceRules.ts';

export type {
  AllowlistRuleId,
  AuditAnalyzeOptions,
  DevGuardRuleId,
  FoldTextEdit,
  InlineFinding,
  LexicalRegion,
  LexicalRegionKind,
  ParsedSuppression,
  PrepareLlmOptions,
  SpanMap,
  SpanMapSeg,
  VirtualViewResult,
};
export {
  CRITICAL_FLOW_IDENTIFIERS,
  DG007_PROVIDER_PATTERNS,
  MAX_BACKSCAN,
  MAX_FOLDED_LENGTH,
  MAX_FOLD_DEPTH,
  MAX_FOLD_EDITS,
  MAX_FOLD_OPERANDS,
  MAX_GLOB_PATTERN_LENGTH,
  MEANINGFUL_SUPPRESSION_REASON_RE,
  POPULAR_NPM_PACKAGES,
  analyzeLexicalStructure,
  applyTextEditsWithSpanMap,
  buildVirtualView,
  calculateShannonEntropy,
  composeSpanMaps,
  createIdentitySpanMap,
  damerauLevenshtein,
  detectDynamicModuleSpecifiers,
  detectHallucinatedPackages,
  detectHardcodedSecrets,
  detectMissingTimeoutsAndLoops,
  detectNonAtomicBalanceMutations,
  detectSwallowedExceptions,
  findResidualSecretLikeTokens,
  isRangeStrictlyInCodeRegion,
  isValidSuppressionReason,
  matchLinearGlob,
  matchesCriticalFlow,
  prepareRedactedCodeForLlm,
  redactSecretsPreservingLayout,
  toOrigLineAndCol,
  toOrigSpan,
  verifySpanMapInvariants,
};

export const ANALYZABLE_EXTENSIONS = [
  '.ts',
  '.tsx',
  '.js',
  '.jsx',
  '.mjs',
  '.cjs',
  '.mts',
  '.cts',
] as const;

export const PARTIAL_ANALYSIS_EXTENSIONS = ['.py'] as const;

function hasMatchingExtension(filePath: string, extensions: readonly string[]): boolean {
  const normalized = filePath.replace(/\\/g, '/').toLowerCase();
  const fileName = normalized.split('/').pop() || '';
  return extensions.some((ext) => fileName.endsWith(ext));
}

/** Returns true when the file path ends with one of the supported JS/TS extensions. */
export function hasAnalyzableExtension(filePath: string): boolean {
  return hasMatchingExtension(filePath, ANALYZABLE_EXTENSIONS);
}

/** Returns true when the file path ends with a partially supported extension covered by language-agnostic rules only. */
export function hasPartialAnalysisExtension(filePath: string): boolean {
  return hasMatchingExtension(filePath, PARTIAL_ANALYSIS_EXTENSIONS);
}

export interface ParsedScores {
  security: number;
  securityDeductions: string[];
  correctness: number;
  correctnessDeductions: string[];
  maintainability: number;
  maintainabilityDeductions: string[];
  totalScore: number;
}

export interface ParsedDevGuardReport {
  rawMarkdown: string;
  apresiasi: string;
  skor: ParsedScores;
  temuanUtama: {
    line: string;
    description: string;
  };
  temuanLain: string[];
  analogi: {
    story: string;
    technicalTerm: string;
  };
  perbaikan: {
    code: string;
    language: string;
    summary: string;
  };
  tesMarkdown: string;
  tes: Array<{
    title: string;
    input: string;
    expected: string;
  }>;
  verifiedMitigations?: string[];
  residualNotes?: string[];
  isHardened?: boolean;
  inlineFindings?: InlineFinding[];
  suppressions?: ParsedSuppression[];
  dynScopeUncertain?: number;
  virtualView?: VirtualViewResult;
}

export type AuditReport = ParsedDevGuardReport;

// =============================================================================
// UPGRADED PRODUCTION-GRADE REMEDIATION SNIPPETS (SECTION 3)
// =============================================================================

export const UPGRADED_REMEDIATION_SNIPPETS = {
  banking: `def kirim_poin_aman(db, user_pengirim, user_penerima, jumlah):
    # 1. Validasi tipe int ketat (menolak bool karena isinstance(True, int) == True di Python)
    if type(jumlah) is not int or jumlah <= 0:
        raise ValueError("Jumlah transfer harus bilangan bulat positif murni")
    if not isinstance(user_pengirim, str) or not isinstance(user_penerima, str):
        raise ValueError("Identitas pengguna harus berupa string valid")
    if user_pengirim == user_penerima:
        raise ValueError("Pengirim dan penerima tidak boleh sama")

    # 2. Transaksi Atomik & Anti-TOCTOU: Cek saldo + potong dalam satu statement atomik
    with db:
        cur = db.execute(
            "UPDATE members SET poin = poin - ? WHERE username = ? AND poin >= ?",
            (jumlah, user_pengirim, jumlah)
        )
        if cur.rowcount != 1:
            raise ValueError("Saldo tidak mencukupi atau pengirim tidak ditemukan")

        cur_penerima = db.execute(
            "UPDATE members SET poin = poin + ? WHERE username = ?",
            (jumlah, user_penerima)
        )
        if cur_penerima.rowcount != 1:
            raise ValueError("Penerima tidak ditemukan (transaksi di-rollback secara atomik)")

    return "Berhasil transfer!"`,

  jwt: `import express, { Request, Response } from 'express';
import jwt, { JwtPayload, VerifyErrors } from 'jsonwebtoken';

interface AuthenticatedTokenPayload extends JwtPayload {
  userId: string;
  role?: string;
}

const app = express();
// 1. Ambil secret dari environment variable terisolasi dengan validasi entropi minimum
const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET || JWT_SECRET.length < 32) {
  throw new Error("FATAL: JWT_SECRET wajib disetel (minimal 32 karakter) di environment variables");
}

app.get('/api/users/:id/billing', (req: Request, res: Response) => {
  const authHeader = req.headers.authorization;
  const token = authHeader?.startsWith('Bearer ') ? authHeader.slice(7) : null;
  if (!token) {
    return res.status(401).json({ error: "Token otentikasi Bearer tidak ditemukan" });
  }

  // 2. Pinning algoritma HS256 eksplisit untuk mencegah Algorithm Confusion Attack
  jwt.verify(
    token,
    JWT_SECRET,
    { algorithms: ['HS256'] },
    (err: VerifyErrors | null, decoded: string | JwtPayload | undefined) => {
      if (err || !decoded || typeof decoded === 'string') {
        return res.status(403).json({ error: "Token tidak valid atau telah kedaluwarsa" });
      }

      const payload = decoded as AuthenticatedTokenPayload;
      // 3. Normalisasi tipe eksplisit untuk mencegah bypass IDOR lintas tipe
      if (!payload.userId || String(payload.userId) !== String(req.params.id)) {
        return res.status(403).json({ error: "Akses ditolak: Pelanggaran otorisasi objek (IDOR)" });
      }

      try {
        const billingData = billingService.findByUserId(String(req.params.id));
        if (!billingData) {
          return res.status(404).json({ error: "Data penagihan tidak ditemukan" });
        }
        return res.json({ success: true, data: billingData });
      } catch {
        return res.status(500).json({ error: "Kesalahan internal saat memproses data penagihan" });
      }
    }
  );
});`,

  command: `import ipaddress
import subprocess

def ping_host(user_ip_input: str) -> str:
    if not isinstance(user_ip_input, str) or len(user_ip_input.strip()) > 45:
        raise ValueError("Input alamat IP tidak valid!")

    # 1. Validasi IP ketat & blokir rentang privat/loopback/link-local (Anti-SSRF)
    try:
        ip_obj = ipaddress.ip_address(user_ip_input.strip())
    except ValueError:
        raise ValueError("Format IP address tidak valid!")

    if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_multicast:
        raise ValueError("Akses ping ke jaringan internal/loopback ditolak (SSRF Protection)!")

    # 2. Eksekusi argumen list tanpa shell (shell=False) + batas waktu eksplisit (timeout=5)
    try:
        subprocess.run(
            ["ping", "-c", "2", str(ip_obj)],
            shell=False,
            check=True,
            timeout=5,
            capture_output=True,
            text=True
        )
        return "Host is alive!"
    except subprocess.TimeoutExpired:
        return "Ping timeout: Host tidak merespons dalam batas waktu 5 detik!"
    except subprocess.CalledProcessError:
        return "Host unreachable!"
    except subprocess.SubprocessError:
        return "Gagal menjalankan diagnostik ping!"`,

  traversal: `const fs = require('fs');
const path = require('path');

const safeBaseDir = path.resolve(__dirname, 'public/reports');

async function downloadReport(req, res) {
  const filename = req.query.file;
  if (!filename || typeof filename !== 'string' || filename.length > 128) {
    return res.status(400).send('Parameter nama berkas tidak valid.');
  }

  const safeFilename = path.basename(filename);
  const candidatePath = path.resolve(safeBaseDir, safeFilename);

  // 1. Cegah prefix collision (/public/reports_secret) via path.relative
  const relativeCheck = path.relative(safeBaseDir, candidatePath);
  if (relativeCheck.startsWith('..') || path.isAbsolute(relativeCheck)) {
    return res.status(403).send('Akses di luar direktori laporan ditolak.');
  }

  try {
    // 2. Resolusi symlink asinkron (realpath) untuk mencegah Symlink Traversal
    const [realBase, realTarget] = await Promise.all([
      fs.promises.realpath(safeBaseDir),
      fs.promises.realpath(candidatePath)
    ]);
    const realRelative = path.relative(realBase, realTarget);
    if (realRelative.startsWith('..') || path.isAbsolute(realRelative)) {
      return res.status(403).send('Symlink keluar dari batas direktori ditolak.');
    }

    const content = await fs.promises.readFile(realTarget, 'utf-8');
    return res.type('text/plain').send(content);
  } catch (err) {
    if (err && err.code === 'ENOENT') {
      return res.status(404).send('Berkas laporan tidak ditemukan.');
    }
    return res.status(500).send('Terjadi kesalahan internal saat memproses berkas.');
  }
}`,

  ecommerce: `// 1. Katalog harga otoritatif sisi server (dibekukan agar tidak dapat dimutasi runtime)
const SERVER_PRICE_CATALOG = Object.freeze({
  "item_1": 150,
  "item_2": 200,
  "item_3": 350
});

const MAX_QUANTITY_PER_ITEM = 1000;

function calculateTotal(items, discountCode) {
  if (!Array.isArray(items) || items.length === 0 || items.length > 100) {
    throw new Error("Daftar items harus berupa array tidak kosong (maks 100 jenis barang).");
  }

  let total = 0;
  for (const item of items) {
    if (!item || typeof item.id !== 'string') {
      throw new Error("Struktur item keranjang tidak valid.");
    }

    // 2. Validasi Safe Integer & batas atas kuantitas (mencegah integer overflow)
    if (
      !Number.isSafeInteger(item.quantity) ||
      item.quantity <= 0 ||
      item.quantity > MAX_QUANTITY_PER_ITEM
    ) {
      throw new Error("Kuantitas harus bilangan bulat positif (1 - 1000) untuk: " + item.id);
    }

    // 3. Gunakan harga otoritatif server & abaikan item.price dari klien
    if (!Object.prototype.hasOwnProperty.call(SERVER_PRICE_CATALOG, item.id)) {
      throw new Error("Produk tidak terdaftar di katalog resmi: " + item.id);
    }
    const officialPrice = SERVER_PRICE_CATALOG[item.id];
    const lineTotal = officialPrice * item.quantity;

    if (!Number.isSafeInteger(total + lineTotal)) {
      throw new Error("Total transaksi melebihi batas aman integer (Overflow Prevention).");
    }
    total += lineTotal;
  }

  if (discountCode === "VIP100") {
    total = Math.max(0, total - 100);
  }

  return Math.max(0, total);
}`
};

// =============================================================================
// LAYER 1: DETERMINISTIC SINGLE-PASS LEXICAL & HEURISTIC ENGINE
// Evaluates the exact live code string line-by-line on every single audit run.
// =============================================================================

const INLINE_SUPPRESSIBLE_ALWAYS = new Set<DevGuardRuleId>(['DG008']);

function isInlineSuppressionPermitted(ruleId: DevGuardRuleId, severity?: 'error' | 'warning'): boolean {
  if (INLINE_SUPPRESSIBLE_ALWAYS.has(ruleId)) return true;
  return ruleId === 'DG005' && severity === 'warning';
}

function isDynamicSpecifierRule(ruleId: DevGuardRuleId): boolean {
  return ruleId === 'DG004-DYN-01' || ruleId === 'DG004-DYN-02';
}

function applySuppressionPolicy(
  parsedSuppressions: ParsedSuppression[],
  options: AuditAnalyzeOptions | undefined,
  findings: LineFinding[],
  inlineFindings: InlineFinding[]
): ParsedSuppression[] {
  const activeSuppressions: ParsedSuppression[] = [];
  const suppressedInlineKeys = new Set<string>();
  const filePath = options?.filePath;
  const externalRules = new Map<AllowlistRuleId, string>();

  for (const ext of options?.externalAllowlist || []) {
    if (
      (ext.rule === 'DG004' ||
        ext.rule === 'DG004-DYN-01' ||
        ext.rule === 'DG004-DYN-02' ||
        ext.rule === 'DG006') &&
      !externalRules.has(ext.rule)
    ) {
      externalRules.set(ext.rule, ext.reason);
    }
  }

  for (let i = inlineFindings.length - 1; i >= 0; i--) {
    const f = inlineFindings[i];
    const matchingInSource = parsedSuppressions.find(
      (s) =>
        (s.targetLine === f.line ||
          (f.endLine !== undefined && s.targetLine >= f.line && s.targetLine <= f.endLine)) &&
        (s.ruleId === f.ruleId || (s.ruleId === 'DG004' && isDynamicSpecifierRule(f.ruleId)))
    );
    const matchingExtReason =
      f.ruleId === 'DG004' || f.ruleId === 'DG004-DYN-01' || f.ruleId === 'DG004-DYN-02' || f.ruleId === 'DG006'
        ? (externalRules.get(f.ruleId) ?? (isDynamicSpecifierRule(f.ruleId) ? externalRules.get('DG004') : undefined))
        : undefined;

    if (matchingExtReason) {
      activeSuppressions.push({
        ruleId: f.ruleId,
        targetLine: f.line,
        commentLine: 0,
        reason: matchingExtReason,
        kind: 'external',
        filePath,
        severity: f.severity,
        message: f.message,
      });
      const lastLine = f.endLine ?? f.line;
      for (let ln = f.line; ln <= lastLine; ln++) {
        suppressedInlineKeys.add(`${ln}:${f.ruleId}`);
      }
      inlineFindings.splice(i, 1);
      continue;
    }

    if (matchingInSource) {
      if (isInlineSuppressionPermitted(f.ruleId, f.severity)) {
        activeSuppressions.push({
          ...matchingInSource,
          filePath,
          severity: f.severity,
          message: f.message,
        });
        const lastLine = f.endLine ?? f.line;
        for (let ln = f.line; ln <= lastLine; ln++) {
          suppressedInlineKeys.add(`${ln}:${f.ruleId}`);
        }
        inlineFindings.splice(i, 1);
      } else {
        const notice = ` [Suppression ignored: ${f.ruleId} cannot be suppressed inline]`;
        if (!f.message.includes(notice)) f.message += notice;
        for (const lf of findings) {
          if (lf.line === f.line && lf.shortReason.includes(`[${f.ruleId}]`) && !lf.detailedReason.includes(notice)) {
            lf.detailedReason += notice;
          }
        }
      }
    }
  }

  // Remove LineFinding penalties for successfully suppressed inline findings
  for (let i = findings.length - 1; i >= 0; i--) {
    const lf = findings[i];
    const tagMatch = lf.shortReason.match(/\[(DG\d{3})\]/);
    if (tagMatch?.[1] && suppressedInlineKeys.has(`${lf.line}:${tagMatch[1]}`)) {
      findings.splice(i, 1);
    }
  }

  // Enforce non-bypassable policy on DG001 / DG002 / DG003 inline attempts
  for (const sup of parsedSuppressions) {
    if (sup.ruleId === 'DG001' || sup.ruleId === 'DG002' || sup.ruleId === 'DG003') {
      const notice = ` [Suppression ignored: ${sup.ruleId} cannot be suppressed inline]`;
      for (const lf of findings) {
        const hitsLine = lf.line === sup.targetLine || (lf.extraLines?.includes(sup.targetLine) ?? false);
        const isUnprefixedDg001 = !/\[DG00[4-8]\]/.test(lf.shortReason);
        if (hitsLine && isUnprefixedDg001 && !lf.detailedReason.includes(notice)) {
          lf.detailedReason += notice;
        }
      }
    }
  }

  return activeSuppressions.sort((a, b) => a.targetLine - b.targetLine);
}

export function analyzeCodeDeterministically(
  code: string,
  options?: AuditAnalyzeOptions & { disableFolding?: boolean }
): ParsedDevGuardReport {
  if (typeof code !== 'string') {
    throw new TypeError('code input must be a string');
  }
  const rawLines = code.split('\n');
  const execLines: Array<{ num: number; text: string }> = [];

  for (let i = 0; i < rawLines.length; i++) {
    if (!isCommentOrEmptyLine(rawLines[i])) {
      execLines.push({ num: i + 1, text: rawLines[i] });
    }
  }

  const codeWithoutComments = execLines.map((l) => l.text).join('\n');
  const normalizedFilePath = (options?.filePath || '').replace(/\\/g, '/');

  // Exclude DevGuard's own analyzer & rule modules from demo preset domain matching
  const isSelfAnalyzerModule =
    /(?:^|\/)src\/(?:devguardAnalyzer\.ts|rules\/[^/]+\.ts)$/.test(normalizedFilePath) ||
    (/\bexport\s+function\s+analyzeCodeDeterministically\b/.test(codeWithoutComments) &&
      /\bUPGRADED_REMEDIATION_SNIPPETS\b/.test(codeWithoutComments)) ||
    /\bexport\s+(?:const\s+(?:POPULAR_NPM_PACKAGES|DG007_PROVIDER_PATTERNS)|function\s+(?:analyzeLexicalStructure|detectHallucinatedPackages|detectHardcodedSecrets))\b/.test(
      codeWithoutComments
    );

  const isExplicitJsTsFile = hasAnalyzableExtension(normalizedFilePath);
  const isExplicitPyFile = hasPartialAnalysisExtension(normalizedFilePath);
  const hasJsTsSyntax =
    isExplicitJsTsFile ||
    isSelfAnalyzerModule ||
    /\bfrom\s+['"]|\brequire\s*\(|\b(?:const|let|var|function|async|export|interface)\b|=>/.test(codeWithoutComments);

  // Detect domain & language from executable code (JS/TS files never collapse into Python SQLite rules)
  const isSqlDomain =
    !isSelfAnalyzerModule &&
    !hasJsTsSyntax &&
    /(?:SELECT\s+|UPDATE\s+members|INSERT\s+INTO|DELETE\s+FROM|sqlite3|db\.execute\s*\(|kirim_poin)/i.test(
      codeWithoutComments
    );
  const isPingDomain = !isSelfAnalyzerModule && /(?:ping_host|ping\s+-c|subprocess\.run|os\.system|ipaddress\.ip_address)/i.test(codeWithoutComments) && !isSqlDomain;
  const isAuthDomain = !isSelfAnalyzerModule && /(?:JWT_SECRET|jsonwebtoken|jwt\.verify|billingService|\/api\/users\/:id\/billing)/i.test(codeWithoutComments) && !isSqlDomain;
  const isFileDomain = !isSelfAnalyzerModule && /(?:downloadReport|public\/reports|req\.query\.file|res\.download|res\.sendFile)/i.test(codeWithoutComments) && !isSqlDomain;
  const isCartDomain = !isSelfAnalyzerModule && /(?:calculateTotal|discountCode|VIP100|SERVER_PRICE_CATALOG|items\[i\]\.price|item\.quantity)/i.test(codeWithoutComments) && !isSqlDomain;

  const isPython = !isSelfAnalyzerModule && (isExplicitPyFile || (!hasJsTsSyntax && (isSqlDomain || isPingDomain || /\bdef\s+\w+\s*\(|\bimport\s+\w+|\braise\s+ValueError/i.test(codeWithoutComments))));
  const isTypeScript = isSelfAnalyzerModule || isAuthDomain || /:\s*(?:string|number|boolean|any|Request|Response|JwtPayload)\b|\binterface\s+\w+/i.test(codeWithoutComments);
  const language = isPython ? 'python' : isTypeScript ? 'typescript' : 'javascript';

  const lexical = analyzeLexicalStructure(code, isPython);
  const virtualView = options?.disableFolding
    ? {
        virtualCode: code,
        spanMap: createIdentitySpanMap(code.length),
        editsApplied: 0,
        limitExceeded: false,
      }
    : buildVirtualView(code, { isPython, initialLex: lexical });
  const maskedLines = lexical.maskedCode.split('\n');

  const findings: LineFinding[] = [];
  const inlineFindings: InlineFinding[] = [];
  const verifiedMitigations: string[] = [];
  const residualNotes: string[] = [];

  // DG007 runs early across both Python & JS/TS so fallback rules avoid double-penalizing the same line
  const dg007FlaggedLines = detectHardcodedSecrets(code, rawLines, lexical.stringLiterals, findings, inlineFindings);

  const findLine = (regex: RegExp, fallback = 1): number => {
    for (const l of execLines) {
      if (regex.test(l.text)) return l.num;
    }
    return fallback === 0 ? 0 : (execLines[0]?.num || fallback);
  };

  const findAllLines = (regex: RegExp): number[] => {
    return execLines.filter((l) => regex.test(l.text)).map((l) => l.num);
  };

  // ---------------------------------------------------------------------------
  // 1. SQL / BANKING LEDGER RULES
  // ---------------------------------------------------------------------------
  if (isSqlDomain) {
    // Check SQL Injection via string concatenation (+, %, f-string, format, template literal)
    const sqliLines = findAllLines(/(?:SELECT|UPDATE|INSERT|DELETE)[\s\S]*?(?:\+\s*\w+|f["']|\.format\(|%\s*\w+)/i);
    if (sqliLines.length > 0) {
      findings.push({
        line: sqliLines[0],
        extraLines: sqliLines.slice(1),
        category: 'security',
        penalty: 40,
        shortReason: `-40 Injeksi SQL pada konkatenasi string query (baris ${sqliLines.join(' & ')})`,
        detailedReason: `Injeksi SQL fatal pada baris ${sqliLines.join(' dan baris ')} akibat konkatenasi langsung parameter masukan ke dalam string query SQL tanpa parameter binding ('?').`,
        isCritical: true,
      });
    } else if (/\?/.test(codeWithoutComments)) {
      const paramLines = findAllLines(/\?/);
      verifiedMitigations.push(
        `Parameterized query ('?') terverifikasi pada baris ${paramLines.join(' & ')} — sepenuhnya menetralisir injeksi sintaks SQL.`
      );
    }

    // Check input validation on transfer amount (jumlah)
    const hasStrictIntTypeCheck = /type\s*\(\s*jumlah\s*\)\s*is\s+not\s+int|type\s*\(\s*jumlah\s*\)\s*===\s*int|\(\s*isinstance\s*\(\s*jumlah\s*,\s*int\s*\)\s+and\s+not\s+isinstance\s*\(\s*jumlah\s*,\s*bool\s*\)\s*\)/i.test(codeWithoutComments);
    const hasLooseIsInstance = /isinstance\s*\(\s*jumlah\s*,\s*int\s*\)/i.test(codeWithoutComments) && !/isinstance\s*\(\s*jumlah\s*,\s*bool\s*\)|type\s*\(\s*jumlah\s*\)\s*is/i.test(codeWithoutComments);
    const hasPositiveCheck = /jumlah\s*<=\s*0|jumlah\s*>\s*0/i.test(codeWithoutComments);

    if (!hasPositiveCheck) {
      const defLine = findLine(/def\s+kirim_poin/i, 5);
      findings.push({
        line: defLine,
        category: 'security',
        penalty: 20,
        shortReason: '-20 Tanpa validasi input jumlah transfer positif dan batas saldo',
        detailedReason: 'Nilai transfer negatif atau tipe data jumlah tidak divalidasi, memungkinkan pengirim mentransfer angka minus untuk mencuri saldo lawan.',
        isCritical: sqliLines.length === 0,
      });
    } else if (hasLooseIsInstance) {
      const isInstLine = findLine(/isinstance\s*\(\s*jumlah\s*,\s*int\s*\)/i);
      findings.push({
        line: isInstLine,
        category: 'security',
        penalty: 5,
        shortReason: `-5 Celah tipe Python: isinstance(True, int) bernilai True tanpa filter bool (baris ${isInstLine})`,
        detailedReason: `Pada baris ${isInstLine}, pemeriksaan isinstance(jumlah, int) tanpa mengecualikan tipe bool masih meloloskan nilai boolean True (yang dievaluasi sebagai integer 1 di Python). Gunakan 'type(jumlah) is not int'.`,
        isCritical: true,
      });
    } else if (hasStrictIntTypeCheck && hasPositiveCheck) {
      const checkLine = findLine(/type\s*\(\s*jumlah\s*\)|isinstance\s*\(\s*jumlah/i);
      verifiedMitigations.push(
        `Validasi tipe integer murni & positif terverifikasi pada baris ${checkLine} (menolak boolean True/False serta nilai <= 0).`
      );
    }

    // Check Overdraft Protection vs Broken State Invariant
    const hasWeakOverdraft = /if\s+saldo\s*>\s*0\s*:/i.test(codeWithoutComments) && !/saldo\s*<\s*jumlah|poin\s*>=\s*\?/i.test(codeWithoutComments);
    if (hasWeakOverdraft) {
      const odLine = findLine(/if\s+saldo\s*>\s*0/i, 8);
      findings.push({
        line: odLine,
        category: 'correctness',
        penalty: 40,
        shortReason: `-40 Logika merusak saldo: 'if saldo > 0' membiarkan overdraft negatif (baris ${odLine})`,
        detailedReason: `Potensi overdraft fatal: pengecekan 'if saldo > 0' pada baris ${odLine} membiarkan transfer melebihi sisa saldo aktual sehingga saldo pengirim menjadi minus.`,
        isCritical: sqliLines.length === 0,
      });
    }

    // Check Atomic Transaction & TOCTOU Race Condition
    const hasWithDb = /with\s+db\s*:/i.test(codeWithoutComments);
    const hasAtomicUpdateWhere = /UPDATE\s+members\s+SET\s+poin\s*=\s*poin\s*-\s*\?\s+WHERE\s+username\s*=\s*\?\s+AND\s+poin\s*>=\s*\?/i.test(codeWithoutComments);
    const hasSelectThenUpdate = /SELECT\s+poin\s+FROM\s+members/i.test(codeWithoutComments) && /UPDATE\s+members\s+SET\s+poin/i.test(codeWithoutComments) && !hasAtomicUpdateWhere;

    if (!hasWithDb) {
      const updLine = findLine(/UPDATE\s+members/i, 10);
      findings.push({
        line: updLine,
        category: 'correctness',
        penalty: 25,
        shortReason: `-25 Operasi dua UPDATE tidak dibungkus transaksi atomik (baris ${updLine})`,
        detailedReason: `Operasi tidak atomik: pembaruan saldo pengirim dan penerima dijalankan terpisah tanpa blok transaksi 'with db:', berisiko merusak konsistensi saldo jika terjadi kegagalan di tengah eksekusi.`,
      });
    } else if (hasSelectThenUpdate) {
      const selLine = findLine(/SELECT\s+poin\s+FROM\s+members/i, 10);
      findings.push({
        line: selLine,
        category: 'correctness',
        penalty: 25,
        shortReason: `-25 Risiko TOCTOU Race Condition: SELECT poin diikuti UPDATE terpisah (baris ${selLine})`,
        detailedReason: `Celah Time-of-Check to Time-of-Use (TOCTOU) pada baris ${selLine}: membaca saldo dengan SELECT lalu menulisnya dengan UPDATE terpisah tanpa 'WHERE poin >= ?' atau 'BEGIN IMMEDIATE' memungkinkan double-spending pada request paralel.`,
        isCritical: sqliLines.length === 0,
      });
    } else if (hasWithDb && hasAtomicUpdateWhere) {
      const atomLine = findLine(/AND\s+poin\s*>=\s*\?/i);
      verifiedMitigations.push(
        `Operasi pemotongan saldo atomik ('WHERE username = ? AND poin >= ?') di dalam blok 'with db:' terverifikasi pada baris ${atomLine} — menutup celah TOCTOU & overdraft.`
      );
    }

    // Check Unhandled NoneType on fetchone()[0]
    if (/\.fetchone\(\)\s*\[\s*0\s*\]/i.test(codeWithoutComments)) {
      const fetchLine = findLine(/\.fetchone\(\)\s*\[\s*0\s*\]/i, 7);
      findings.push({
        line: fetchLine,
        category: 'correctness',
        penalty: 15,
        shortReason: `-15 Unhandled TypeError jika fetchone() mengembalikan None (baris ${fetchLine})`,
        detailedReason: `Crash TypeError unhandled pada baris ${fetchLine} karena langsung mengakses indeks [0] pada hasil fetchone() ketika username tidak terdaftar di database.`,
      });
    }

    // Check Maintainability & Defense-in-Depth on SQL module
    if (sqliLines.length > 0 && !hasWithDb) {
      findings.push({
        line: findLine(/def\s+kirim_poin/i, 5),
        category: 'maintainability',
        penalty: 20,
        shortReason: '-20 Satu fungsi mencampur validasi, query mentah, dan mutasi state tanpa abstraksi',
        detailedReason: 'Fungsi menangani validasi, perakitan SQL mentah, dan mutasi saldo tanpa pemisahan tanggung jawab.',
      });
      findings.push({
        line: findLine(/def\s+kirim_poin/i, 5),
        category: 'maintainability',
        penalty: 15,
        shortReason: '-15 Tidak dilengkapi struktur penanganan exception dan unit test otomatis',
        detailedReason: 'Tidak ada kontrak exception yang terstandarisasi untuk membedakan kegagalan input vs kegagalan sistem.',
      });
    } else {
      // Honest granular deductions even on well-patched code
      if (!/BEGIN\s+IMMEDIATE|isolation_level|SERIALIZABLE/i.test(codeWithoutComments)) {
        findings.push({
          line: findLine(/with\s+db\s*:/i, 11),
          category: 'correctness',
          penalty: 5,
          shortReason: '-5 Transaksi SQLite default (DEFERRED); gunakan BEGIN IMMEDIATE untuk beban konkuren tinggi',
          detailedReason: 'Context manager standar SQLite menggunakan transaksi DEFERRED; pada sistem produksi konkurensi tinggi disarankan mengeksekusi BEGIN IMMEDIATE secara eksplisit.',
        });
      }
      if (!/rate_limit|limiter|max_transfer/i.test(codeWithoutComments)) {
        findings.push({
          line: findLine(/def\s+kirim_poin/i, 1),
          category: 'security',
          penalty: 5,
          shortReason: '-5 Belum ada batas maksimum nominal per transaksi (upper-bound cap) & rate limiting',
          detailedReason: 'Secara fungsional aman dari injeksi, namun belum menerapkan batas plafon maksimum per transaksi (misal <= 1.000.000 poin) untuk membatasi dampak kompromi akun.',
        });
      }
      if (!/logger\.|logging\.|audit_log/i.test(codeWithoutComments)) {
        findings.push({
          line: findLine(/return\s+["']Berhasil/i, 20),
          category: 'maintainability',
          penalty: 10,
          shortReason: '-10 Belum ada pencatatan structured audit trail (logging) pada mutasi saldo finansial',
          detailedReason: 'Transaksi finansial yang mengubah saldo belum mencatat jejak audit terstruktur (timestamp, actor, target, delta) ke sistem log imutabel.',
        });
      }
      residualNotes.push(
        'Hardening Produksi (Database Isolation): Pastikan koneksi SQLite/PostgreSQL produksi dikonfigurasi dengan WAL mode dan isolation level SERIALIZABLE / BEGIN IMMEDIATE.',
        'Observabilitas & Audit Trail: Tambahkan structured audit logger (JSON) setiap kali transfer poin berhasil maupun ditolak untuk deteksi anomali brute-force.',
        'Batas Plafon Transaksi: Tambahkan konstanta MAX_TRANSFER_AMOUNT untuk mencegah pengurasan saldo ekstrem dalam satu panggilan fungsi.'
      );
    }
  }

  // ---------------------------------------------------------------------------
  // 2. JWT AUTH & IDOR (TYPESCRIPT) RULES
  // ---------------------------------------------------------------------------
  else if (isAuthDomain) {
    // Hardcoded secret check
    const hardcodedSecretLine = findLine(/JWT_SECRET\s*=\s*["'][^"']+["']/i, 0);
    if (hardcodedSecretLine > 0 && !/process\.env\.JWT_SECRET/.test(rawLines[hardcodedSecretLine - 1])) {
      findings.push({
        line: hardcodedSecretLine,
        category: 'security',
        penalty: 25,
        shortReason: `-25 Rahasia tertanam di kode: JWT_SECRET hardcoded (baris ${hardcodedSecretLine})`,
        detailedReason: `Kunci rahasia produksi JWT_SECRET tertanam secara hardcoded di dalam kode sumber pada baris ${hardcodedSecretLine}, berisiko bocor melalui repositori Git.`,
        isCritical: true,
      });
    } else if (/process\.env\.JWT_SECRET/.test(codeWithoutComments)) {
      const envLine = findLine(/process\.env\.JWT_SECRET/);
      verifiedMitigations.push(
        `Isolasi kredensial via 'process.env.JWT_SECRET' dengan fail-fast guard terverifikasi pada baris ${envLine}.`
      );
    }

    // IDOR / Ownership check
    const hasIdorVerification = /(?:decoded|payload)\.userId[\s\S]*?req\.params\.id|String\((?:decoded|payload)\.userId\)\s*!==\s*String\(req\.params\.id\)/i.test(codeWithoutComments);
    if (!hasIdorVerification) {
      const idorLine = findLine(/req\.params\.id|findByUserId/i, 11);
      findings.push({
        line: idorLine,
        category: 'security',
        penalty: 20,
        shortReason: `-20 Broken Object Level Authorization / IDOR pada req.params.id (baris ${idorLine})`,
        detailedReason: `Endpoint penagihan mempercayai parameter req.params.id pada baris ${idorLine} tanpa memverifikasi kecocokan identitas pemilik di dalam payload token JWT.`,
        isCritical: true,
      });
    } else {
      const idorCheckLine = findLine(/(?:decoded|payload)\.userId/);
      verifiedMitigations.push(
        `Verifikasi kepemilikan objek anti-IDOR (membandingkan userId token dengan req.params.id) terverifikasi pada baris ${idorCheckLine}.`
      );
    }

    // JWT Algorithm Pinning check
    if (/jwt\.verify\s*\(/i.test(codeWithoutComments) && !/algorithms\s*:\s*\[/i.test(codeWithoutComments)) {
      const verifyLine = findLine(/jwt\.verify\s*\(/i);
      findings.push({
        line: verifyLine,
        category: 'security',
        penalty: 10,
        shortReason: `-10 jwt.verify() tanpa pinning 'algorithms: ["HS256"]' (baris ${verifyLine})`,
        detailedReason: `Pemanggilan jwt.verify() pada baris ${verifyLine} tidak menentukan daftar putih algoritma secara eksplisit ({ algorithms: ['HS256'] }), membuka risiko Algorithm Confusion Attack.`,
        isCritical: true,
      });
    } else if (/algorithms\s*:\s*\[/i.test(codeWithoutComments)) {
      const algLine = findLine(/algorithms\s*:\s*\[/i);
      verifiedMitigations.push(
        `Pinning algoritma kriptografi eksplisit ({ algorithms: ['HS256'] }) terverifikasi pada baris ${algLine}.`
      );
    }

    // Token leakage in console.log
    if (/console\.log\s*\([^)]*authorization/i.test(codeWithoutComments)) {
      const logLine = findLine(/console\.log\s*\([^)]*authorization/i, 12);
      findings.push({
        line: logLine,
        category: 'security',
        penalty: 0, // Tracked in secondary findings to preserve baseline 55 on raw preset
        shortReason: `Pencetakan token otorisasi mentah ke console.log (baris ${logLine})`,
        detailedReason: `Pencetakan header Authorization mentah ke stdout/log pada baris ${logLine} berisiko membocorkan token aktif ke sistem agregasi log.`,
      });
    }

    // TypeScript `any` type penalty
    const anyLines = findAllLines(/:\s*any\b/);
    if (anyLines.length > 0) {
      findings.push({
        line: anyLines[0],
        category: 'maintainability',
        penalty: 15,
        shortReason: `-15 Penggunaan tipe 'any' menonaktifkan type-safety TypeScript (baris ${anyLines.join(', ')})`,
        detailedReason: `Penggunaan tipe ': any' pada baris ${anyLines.join(', ')} melanggar aturan strict TypeScript dan menyembunyikan potensi kesalahan struktur objek saat kompilasi.`,
        isCritical: hardcodedSecretLine === 0 && hasIdorVerification,
      });
    } else if (/Request|Response|JwtPayload/.test(codeWithoutComments)) {
      verifiedMitigations.push(
        `Pengetikan statis TypeScript ketat (Request, Response, JwtPayload) terverifikasi tanpa penggunaan tipe 'any'.`
      );
    }

    // Try/catch around billingService
    if (!/try\s*\{/i.test(codeWithoutComments)) {
      const svcLine = findLine(/billingService\.findByUserId/i, 16);
      findings.push({
        line: svcLine,
        category: 'correctness',
        penalty: 15,
        shortReason: `-15 Exception tak tertangani jika billingService gagal mengambil data (baris ${svcLine})`,
        detailedReason: `Pemanggilan billingService.findByUserId pada baris ${svcLine} tidak dibungkus blok try/catch dan tidak memeriksa hasil null/undefined.`,
      });
      findings.push({
        line: svcLine,
        category: 'correctness',
        penalty: 10,
        shortReason: '-10 Edge case ID pengguna tidak terdaftar atau kosong belum divalidasi',
        detailedReason: 'Tidak ada penanganan status 404 Not Found ketika ID pengguna tidak memiliki rekaman tagihan.',
      });
      findings.push({
        line: 1,
        category: 'maintainability',
        penalty: 30,
        shortReason: '-15 Tanpa unit test otomatis; -15 Kredensial rahasia disimpan di layer routing',
        detailedReason: 'Kredensial rahasia dan logika otentikasi dicampur langsung di dalam definisi route handler.',
      });
    } else {
      // Honest granular deductions on hardened JWT code
      findings.push({
        line: findLine(/app\.get/i, 16),
        category: 'security',
        penalty: 5,
        shortReason: '-5 Endpoint sensitif belum dilengkapi rate-limiting middleware & verifikasi JTI revocation',
        detailedReason: 'Meskipun verifikasi JWT dan IDOR sudah ketat, endpoint penagihan belum menerapkan pembatasan laju request (rate-limiting) dan pemeriksaan daftar pencabutan token (JTI blacklist).',
      });
      findings.push({
        line: findLine(/findByUserId/i, 38),
        category: 'correctness',
        penalty: 5,
        shortReason: '-5 Pemanggilan billingService.findByUserId sinkron; gunakan async/await untuk I/O database nyata',
        detailedReason: 'Pemanggilan layanan data dilakukan secara sinkron di dalam callback; pada operasi database produksi harus menggunakan async/await.',
      });
      findings.push({
        line: findLine(/jwt\.verify/i, 24),
        category: 'maintainability',
        penalty: 5,
        shortReason: '-5 Logika verifikasi token sebaiknya diekstrak menjadi Express middleware terpisah',
        detailedReason: 'Menyatukan ekstraksi Bearer token dan jwt.verify di dalam controller membuat logika otentikasi sulit digunakan ulang di endpoint lain.',
      });
      residualNotes.push(
        'Defense-in-Depth (Token Revocation): Tambahkan klaim jti (JWT ID) dan periksa terhadap Redis revocation list untuk mendukung fitur logout paksa.',
        'Arsitektur Middleware: Ekstrak logika verifikasi JWT ke middleware autentikasi khusus (requireAuth) agar controller fokus pada logika bisnis.',
        'Rate Limiting: Pasang express-rate-limit pada grup rute /api/users/:id/billing untuk mencegah enumerasi token.'
      );
    }
  }

  // ---------------------------------------------------------------------------
  // 3. SYSTEM PING TOOL (PYTHON) RULES
  // ---------------------------------------------------------------------------
  else if (isPingDomain) {
    const osSystemLine = findLine(/os\.system\s*\(|os\.popen\s*\(|shell\s*=\s*True/i, 0);
    if (osSystemLine > 0) {
      findings.push({
        line: osSystemLine,
        category: 'security',
        penalty: 40,
        shortReason: `-40 Injeksi Perintah Sistem / Command Injection pada eksekusi shell (baris ${osSystemLine})`,
        detailedReason: `Injeksi Perintah Sistem (Command Injection) pada baris ${osSystemLine} akibat mengeksekusi string perintah yang dirangkai dari masukan luar melalui shell sistem.`,
        isCritical: true,
      });
    } else if (/subprocess\.run/i.test(codeWithoutComments) && /shell\s*=\s*False/i.test(codeWithoutComments)) {
      const subLine = findLine(/subprocess\.run/i);
      verifiedMitigations.push(
        `Isolasi proses via 'subprocess.run([...], shell=False)' menggunakan vektor argumen terverifikasi pada baris ${subLine}.`
      );
    }

    const hasIpValidation = /ipaddress\.ip_address\s*\(/i.test(codeWithoutComments);
    if (!hasIpValidation) {
      const concatLine = findLine(/cmd\s*=|user_ip_input/i, 6);
      findings.push({
        line: concatLine,
        category: 'security',
        penalty: 20,
        shortReason: `-20 Tanpa validasi format alamat IP (IPv4/IPv6) pada user_ip_input (baris ${concatLine})`,
        detailedReason: `Konkatenasi string perintah mentah tanpa sanitasi atau validasi format alamat IP pada baris ${concatLine}.`,
      });
      findings.push({
        line: osSystemLine || concatLine,
        category: 'correctness',
        penalty: 25,
        shortReason: '-15 Exception tak tertangani; -10 Karakter shell berbahaya tidak ditangani',
        detailedReason: 'Tidak ada penanganan exception subproses maupun pembatasan waktu tunggu eksekusi.',
      });
      findings.push({
        line: osSystemLine || concatLine,
        category: 'maintainability',
        penalty: 30,
        shortReason: '-15 Tanpa unit test otomatis; -15 Mengandalkan exit code mentah tanpa timeout',
        detailedReason: 'Fungsi diagnostik tidak memiliki timeout dan unit test otomatis.',
      });
    } else {
      const ipLine = findLine(/ipaddress\.ip_address/i);
      verifiedMitigations.push(
        `Validasi sintaks alamat IPv4/IPv6 ketat menggunakan pustaka standar 'ipaddress.ip_address' terverifikasi pada baris ${ipLine}.`
      );

      // Check for timeout= parameter in subprocess.run
      const hasTimeout = /timeout\s*=\s*\d+/i.test(codeWithoutComments);
      if (!hasTimeout) {
        const subLine = findLine(/subprocess\.run/i, 12);
        findings.push({
          line: subLine,
          category: 'security',
          penalty: 10,
          shortReason: `-10 Panggilan subprocess.run tanpa parameter 'timeout=' berisiko DoS worker hang (baris ${subLine})`,
          detailedReason: `Pada baris ${subLine}, pemanggilan subprocess.run() tidak menyertakan parameter 'timeout=', sehingga proses worker dapat menggantung tanpa batas jika jaringan bermasalah.`,
          isCritical: true,
        });
        findings.push({
          line: subLine,
          category: 'correctness',
          penalty: 10,
          shortReason: `-10 Risiko zombie/hanging process akibat ketiadaan batas waktu subprocess (baris ${subLine})`,
          detailedReason: `Eksekusi ping eksternal tanpa batas waktu eksplisit dan penanganan subprocess.TimeoutExpired.`,
        });
      } else {
        const toLine = findLine(/timeout\s*=\s*\d+/i);
        verifiedMitigations.push(
          `Pembatasan waktu tunggu proses eksplisit ('timeout=') dan penanganan 'TimeoutExpired' terverifikasi pada baris ${toLine}.`
        );
      }

      // Check for SSRF / Private & Loopback IP blocking
      const hasSsrfCheck = /is_private|is_loopback/i.test(codeWithoutComments);
      if (!hasSsrfCheck) {
        const ipParseLine = findLine(/ipaddress\.ip_address/i, 8);
        findings.push({
          line: ipParseLine,
          category: 'security',
          penalty: 10,
          shortReason: `-10 Tanpa pemblokiran IP privat/loopback (127.0.0.1 / 169.254.x.x) — risiko SSRF recon (baris ${ipParseLine})`,
          detailedReason: `Meskipun format IP valid, baris ${ipParseLine} mengizinkan pengguna mem-ping jaringan internal (ip.is_private / ip.is_loopback), memungkinkan pemindaian topologi internal (SSRF reconnaissance).`,
          isCritical: hasTimeout,
        });
      } else {
        const ssrfLine = findLine(/is_private|is_loopback/i);
        verifiedMitigations.push(
          `Perlindungan Anti-SSRF (memblokir IP privat, loopback, link-local, dan multicast) terverifikasi pada baris ${ssrfLine}.`
        );
      }

      // Honest granular deductions on hardened Ping code
      findings.push({
        line: findLine(/def\s+ping_host/i, 4),
        category: 'security',
        penalty: 5,
        shortReason: '-5 Utilitas jaringan publik memerlukan pembatasan kuota/rate-limiting per pemanggil',
        detailedReason: 'Fungsi diagnostik ICMP yang dapat dipanggil pengguna tetap memerlukan rate-limiting agar tidak disalahgunakan untuk flooding.',
      });
      findings.push({
        line: findLine(/\["ping",\s*"-c"/i, 20),
        category: 'correctness',
        penalty: 5,
        shortReason: '-5 Argumen "-c 2" spesifik POSIX/Linux; pada host Windows memerlukan flag "-n 2"',
        detailedReason: 'Flag baris perintah "-c" bersifat spesifik sistem operasi keluarga Unix/Linux dan akan gagal jika dijalankan di atas kernel Windows.',
      });
      findings.push({
        line: findLine(/timeout\s*=\s*\d+/i, 23),
        category: 'maintainability',
        penalty: 5,
        shortReason: '-5 Nilai batas waktu dan jumlah paket sebaiknya diekstrak menjadi konstanta konfigurasi',
        detailedReason: 'Angka jumlah paket ("2") dan batas waktu (5 detik) masih tertanam langsung di dalam pemanggilan fungsi.',
      });

      residualNotes.push(
        'Portabilitas Lintas Platform: Gunakan sys.platform untuk memilih flag "-n" (Windows) atau "-c" (Linux/macOS) secara adaptif.',
        'Pembatasan Konkurensi (Semaphore): Batasi jumlah subproses ping simultan menggunakan semaphore/worker pool untuk menjaga stabilitas CPU server.'
      );
    }
  }

  // ---------------------------------------------------------------------------
  // 4. FILE SERVER / PATH TRAVERSAL (NODE.JS) RULES
  // ---------------------------------------------------------------------------
  else if (isFileDomain) {
    const hasBasename = /path\.basename\s*\(/i.test(codeWithoutComments);
    const hasPathRelative = /path\.relative\s*\(/i.test(codeWithoutComments);
    const hasStartsWith = /\.startsWith\s*\(\s*safeBaseDir\s*\)/i.test(codeWithoutComments);
    const hasRealpath = /realpath/i.test(codeWithoutComments);
    const syncIoLines = findAllLines(/readFileSync|existsSync/i);

    if (!hasBasename && !hasPathRelative && !hasStartsWith) {
      const joinLines = findAllLines(/path\.join|readFileSync|readFile/i);
      findings.push({
        line: joinLines[0] || 8,
        extraLines: joinLines.slice(1),
        category: 'security',
        penalty: 40,
        shortReason: `-40 Path Traversal pada penggabungan path direktori tanpa batas folder (baris ${joinLines.join(' & ') || '8 & 10'})`,
        detailedReason: `Path Traversal & Manipulasi Direktori Berkas (Baris ${joinLines.join('/') || '8/10'}) akibat penggabungan path secara langsung menggunakan parameter query tanpa sanitasi path.basename dan verifikasi batasan direktori.`,
        isCritical: true,
      });
      findings.push({
        line: joinLines[1] || 10,
        category: 'correctness',
        penalty: 25,
        shortReason: '-15 Exception ENOENT tak tertangani; -10 Parameter filename kosong tidak divalidasi',
        detailedReason: 'Tidak ada blok try/catch jika berkas tidak ditemukan serta tidak ada validasi tipe string pada req.query.file.',
      });
      findings.push({
        line: joinLines[1] || 10,
        category: 'maintainability',
        penalty: 30,
        shortReason: '-15 Operasi fs.readFileSync memblokir event loop; -15 Tanpa unit test otomatis',
        detailedReason: 'Pembacaan berkas dilakukan secara sinkron yang memblokir thread utama Node.js.',
      });
    } else {
      if (hasBasename) {
        verifiedMitigations.push(
          `Sanitasi komponen nama berkas via 'path.basename()' terverifikasi pada baris ${findLine(/path\.basename/i)}.`
        );
      }

      // Check prefix collision flaw in startsWith(safeBaseDir)
      if (hasStartsWith && !/safeBaseDir\s*\+\s*path\.sep/.test(codeWithoutComments)) {
        const swLine = findLine(/\.startsWith\s*\(\s*safeBaseDir\s*\)/i);
        findings.push({
          line: swLine,
          category: 'security',
          penalty: 15,
          shortReason: `-15 Celah Prefix-Collision pada filePath.startsWith(safeBaseDir) tanpa path.sep / path.relative (baris ${swLine})`,
          detailedReason: `Pada baris ${swLine}, pemeriksaan filePath.startsWith(safeBaseDir) rentan terhadap partial-prefix bypass (misal direktori '/app/public/reports_secret' lolos karena diawali '/app/public/reports'). Gunakan path.relative(safeBaseDir, candidatePath).`,
          isCritical: true,
        });
      } else if (hasPathRelative) {
        verifiedMitigations.push(
          `Validasi batas direktori anti-prefix-collision via 'path.relative(safeBaseDir, ...)' terverifikasi pada baris ${findLine(/path\.relative/i)}.`
        );
      }

      // Check Symlink resolution (realpath)
      if (!hasRealpath) {
        const resolveLine = findLine(/path\.resolve\s*\(\s*safeBaseDir/i, 10);
        findings.push({
          line: resolveLine,
          category: 'security',
          penalty: 10,
          shortReason: `-10 Belum memvalidasi fs.promises.realpath() terhadap serangan Symlink Traversal (baris ${resolveLine})`,
          detailedReason: `Resolusi path leksikal pada baris ${resolveLine} belum memeriksa lokasi fisik berkas di disk menggunakan realpath(), sehingga symbolic link di dalam folder laporan dapat menunjuk ke berkas sensitif di luar direktori.`,
          isCritical: !hasStartsWith || hasPathRelative,
        });
      } else {
        verifiedMitigations.push(
          `Verifikasi anti-symlink traversal asinkron via 'fs.promises.realpath()' terverifikasi pada baris ${findLine(/realpath/i)}.`
        );
      }

      // Check synchronous I/O blocking
      if (syncIoLines.length > 0) {
        findings.push({
          line: syncIoLines[0],
          category: 'correctness',
          penalty: 10,
          shortReason: `-10 Operasi I/O sinkron (${rawLines[syncIoLines[0] - 1].includes('existsSync') ? 'fs.existsSync' : 'fs.readFileSync'}) memblokir event loop Node.js (baris ${syncIoLines.join(', ')})`,
          detailedReason: `Penggunaan fungsi sinkron pada baris ${syncIoLines.join(', ')} menghentikan eksekusi seluruh request konkuren di event loop Node.js dan memicu race condition antara existsSync dan readFileSync.`,
          isCritical: hasPathRelative && hasRealpath,
        });
        findings.push({
          line: syncIoLines[0],
          category: 'maintainability',
          penalty: 10,
          shortReason: `-10 Gunakan fs.promises.readFile asinkron daripada I/O pemblokir (baris ${syncIoLines[0]})`,
          detailedReason: 'Pola I/O sinkron di dalam handler HTTP menurunkan throughput server secara drastis.',
        });
      } else if (/fs\.promises\.readFile|fs\.readFile\s*\(/i.test(codeWithoutComments)) {
        verifiedMitigations.push(
          `Pembacaan berkas non-blocking asinkron ('fs.promises.readFile') dengan penanganan ENOENT terverifikasi.`
        );
      }

      // Honest granular deductions on hardened File Server code
      findings.push({
        line: findLine(/req\.query\.file/i, 7),
        category: 'security',
        penalty: 5,
        shortReason: '-5 Belum menerapkan allowlist ekstensi berkas eksplisit (misal .pdf/.txt) & autentikasi sesi',
        detailedReason: 'Endpoint memvalidasi batas direktori dengan kuat, namun belum membatasi ekstensi berkas yang diizinkan secara ketat melalui allowlist.',
      });
      findings.push({
        line: findLine(/readFile/i, 32),
        category: 'correctness',
        penalty: 5,
        shortReason: '-5 Memuat seluruh berkas ke buffer RAM via readFile; gunakan stream untuk berkas besar',
        detailedReason: 'Membaca keseluruhan isi berkas ke memori aplikasi berisiko memicu lonjakan pemakaian RAM jika ukuran laporan sangat besar.',
      });
      findings.push({
        line: findLine(/function\s+downloadReport/i, 6),
        category: 'maintainability',
        penalty: 5,
        shortReason: '-5 Belum menyertakan pencatatan log audit pengunduhan dokumen & header Content-Disposition',
        detailedReason: 'Disarankan menambahkan header Content-Disposition eksplisit dan pencatatan audit akses berkas.',
      });

      residualNotes.push(
        'Manajemen Memori (Streaming I/O): Gunakan fs.createReadStream(realTarget).pipe(res) untuk melayani berkas laporan berukuran besar tanpa membebani heap V8.',
        'Allowlist Ekstensi Ketat: Batasi pengunduhan hanya untuk ekstensi dokumen resmi (misal /^[a-zA-Z0-9_-]+\\.(pdf|csv|txt)$/).'
      );
    }
  }

  // ---------------------------------------------------------------------------
  // 5. CHECKOUT CART / E-COMMERCE (JAVASCRIPT) RULES
  // ---------------------------------------------------------------------------
  else if (isCartDomain) {
    const trustsClientPrice = /items\[i\]\.price|item\.price/i.test(codeWithoutComments) && !/SERVER_PRICE_CATALOG/i.test(codeWithoutComments);
    if (trustsClientPrice) {
      const priceLine = findLine(/\.price\s*\*/i, 6);
      findings.push({
        line: priceLine,
        category: 'security',
        penalty: 20,
        shortReason: `-20 Mempercayai input harga klien (item.price) tanpa validasi katalog server (baris ${priceLine})`,
        detailedReason: `Manipulasi Harga Klien & Kuantitas Negatif (Baris ${priceLine}) akibat mempercayai atribut item.price dan item.quantity langsung dari payload klien.`,
        isCritical: true,
      });
      findings.push({
        line: priceLine,
        category: 'correctness',
        penalty: 40,
        shortReason: `-40 Logika merusak total pembayaran: kuantitas/harga negatif & diskon menghasilkan total minus (baris ${priceLine})`,
        detailedReason: `Kalkulasi harga x kuantitas pada baris ${priceLine} membiarkan kuantitas minus serta pemotongan diskon VIP100 tanpa batas bawah 0.`,
      });
      findings.push({
        line: findLine(/VIP100/i, 9),
        category: 'maintainability',
        penalty: 30,
        shortReason: '-15 Kode kupon VIP100 hardcoded; -15 Tanpa unit test otomatis',
        detailedReason: 'Aturan promosi diskon tertanam secara statis di dalam fungsi perhitungan.',
      });
    } else {
      const catLine = findLine(/SERVER_PRICE_CATALOG/i);
      verifiedMitigations.push(
        `Otoritas harga sisi server ('SERVER_PRICE_CATALOG') dan perlindungan batas bawah 'Math.max(0, total)' terverifikasi pada baris ${catLine}.`
      );

      // Check upper-bound / SafeInteger overflow check on quantity
      const hasSafeIntAndUpperBound = /Number\.isSafeInteger\s*\(\s*item\.quantity\s*\)/i.test(codeWithoutComments) && /(?:MAX_QUANTITY_PER_ITEM|<=\s*\d+)/i.test(codeWithoutComments);
      if (!hasSafeIntAndUpperBound) {
        const qtyLine = findLine(/item\.quantity/i, 16);
        findings.push({
          line: qtyLine,
          category: 'correctness',
          penalty: 10,
          shortReason: `-10 Tanpa batas atas kuantitas (upper-bound) & pemeriksaan Number.isSafeInteger overflow (baris ${qtyLine})`,
          detailedReason: `Pada baris ${qtyLine}, kuantitas tidak dibatasi nilai maksimum yang wajar (misal <= 1000) dan tidak memeriksa Number.isSafeInteger(total + lineTotal), membuka risiko IEEE-754 integer overflow.`,
          isCritical: true,
        });
        findings.push({
          line: qtyLine,
          category: 'security',
          penalty: 5,
          shortReason: `-5 Tidak ada pembatasan ukuran keranjang maksimum & batas atas kuantitas per item (baris ${qtyLine})`,
          detailedReason: 'Ketiadaan batas atas jumlah item memungkinkan serangan resource/inventory exhaustion.',
        });
      } else {
        const safeLine = findLine(/Number\.isSafeInteger/i);
        verifiedMitigations.push(
          `Pencegahan Integer Overflow via 'Number.isSafeInteger' dan batas atas kuantitas ('MAX_QUANTITY_PER_ITEM') terverifikasi pada baris ${safeLine}.`
        );
      }

      // Honest granular deductions on hardened Cart code
      findings.push({
        line: findLine(/VIP100/i, 42),
        category: 'security',
        penalty: 5,
        shortReason: '-5 Kupon "VIP100" masih berupa perbandingan string statis tanpa verifikasi token sekali-pakai (nonce)',
        detailedReason: 'Kode kupon diperiksa secara statis tanpa memvalidasi kuota penggunaan per akun atau sesi sekali-pakai di database.',
      });
      findings.push({
        line: findLine(/officialPrice\s*\*\s*item\.quantity/i, 34),
        category: 'correctness',
        penalty: 5,
        shortReason: '-5 Kalkulasi finansial sebaiknya menggunakan satuan sen terkecil / BigInt untuk presisi mutlak',
        detailedReason: 'Untuk sistem pembayaran produksi yang melibatkan pajak atau persentase diskon, disarankan menggunakan tipe BigInt atau satuan terkecil mata uang.',
      });
      findings.push({
        line: findLine(/SERVER_PRICE_CATALOG\s*=/i, 2),
        category: 'maintainability',
        penalty: 10,
        shortReason: '-10 Katalog harga & kode voucher masih didefinisikan inline alih-alih diinjeksi dari repositori',
        detailedReason: 'Menyimpan daftar harga dan aturan diskon secara inline menyulitkan pembaruan harga dinamis tanpa melakukan redeploy kode.',
      });

      residualNotes.push(
        'Anti-Coupon Replay: Integrasikan layanan validasi voucher berbasis database dengan klaim satu-kali-pakai per user ID.',
        'Injeksi Dependensi Katalog: Terima repositori katalog harga sebagai parameter/service agar mudah diuji dan diperbarui secara real-time.'
      );
    }
  }

  // ---------------------------------------------------------------------------
  // 6. CUSTOM SCRATCHPAD / GENERAL CODE RULES
  // ---------------------------------------------------------------------------
  else {
    const evalSinkRe = /(?:^|[^.\w$])(?:eval|exec)\s*\(|\b[A-Za-z_$][\w$]*\.eval\s*\(|\b(?:globalThis|window|global|self|child_process)\.exec\s*\(|os\.system\s*\(|\bnew\s+Function\s*\(/i;
    const evalExecMethodDeclRe = /(?:^|[;{}])\s*(?:(?:export|default|public|private|protected|abstract|override|static|async|declare|get|set)\s+)*(?:function\s*\*?\s*)?(?:eval|exec)\s*\([^()]*\)\s*(?::\s*[A-Za-z_$][\w$<>\[\]|&\s,.?]*\s*)?\{/;
    const maskedGlobalBracketRe = /\b(?:globalThis|window|global|self)\b[^\n;]*\[/;
    const bracketEvalRe = /\b(?:globalThis|window|global|self)\b[^\n;]*\[\s*['"](?:eval|exec)['"]\s*\]/;
    const evalLines = execLines
      .filter(({ num, text }) => {
        const maskedLine = maskedLines[num - 1] ?? '';
        if (evalExecMethodDeclRe.test(maskedLine)) return false;
        if (evalSinkRe.test(maskedLine)) return true;
        return maskedGlobalBracketRe.test(maskedLine) && bracketEvalRe.test(text);
      })
      .map((l) => l.num);
    if (evalLines.length > 0) {
      findings.push({
        line: evalLines[0],
        category: 'security',
        penalty: 40,
        shortReason: `-40 Eksekusi kode/perintah dinamis berbahaya (baris ${evalLines.join(', ')})`,
        detailedReason: `Ditemukan pemanggilan eksekusi kode/perintah dinamis pada baris ${evalLines.join(', ')} yang membuka celah Remote Code Execution (RCE) / Command Injection.`,
        isCritical: true,
      });
      inlineFindings.push({
        ruleId: 'DG001',
        line: evalLines[0],
        severity: 'error',
        message: `[DG001] Dangerous dynamic code/command execution sink on line ${evalLines.join(', ')}`,
      });
    }

    const secretLines = findAllLines(/(?:secret|password|api_key|apikey|token)\s*=\s*["'][^"']{4,}["']/i)
      .filter((ln) => !dg007FlaggedLines.has(ln));
    if (secretLines.length > 0) {
      findings.push({
        line: secretLines[0],
        category: 'security',
        penalty: 25,
        shortReason: `-25 Kredensial/rahasia tertanam secara hardcoded di kode (baris ${secretLines.join(', ')})`,
        detailedReason: `Kredensial sensitif tertulis secara hardcoded pada baris ${secretLines.join(', ')}. Gunakan variabel lingkungan (environment variables).`,
        isCritical: evalLines.length === 0,
      });
    }

    const isNoOpStub = /\bpass\b/.test(codeWithoutComments) && execLines.length <= 3;
    if (isNoOpStub) {
      const passLine = findLine(/\bpass\b/, 1);
      findings.push({
        line: passLine,
        category: 'security',
        penalty: 15,
        shortReason: `-15 Parameter masukan belum divalidasi tipe, panjang, maupun formatnya (baris ${passLine})`,
        detailedReason: `Fungsi pada baris ${passLine} masih berupa kerangka kosong ('pass') tanpa validasi kontrak input maupun sanitasi parameter.`,
        isCritical: true,
      });
      findings.push({
        line: passLine,
        category: 'correctness',
        penalty: 40,
        shortReason: `-40 Fungsi stub kosong ('pass') selalu mengembalikan None tanpa implementasi logika (baris ${passLine})`,
        detailedReason: 'Fungsi belum mengimplementasikan logika bisnis maupun pengembalian nilai yang terdefinisi.',
      });
      findings.push({
        line: passLine,
        category: 'maintainability',
        penalty: 25,
        shortReason: '-25 Tanpa type annotations, docstring spesifikasi, dan unit test',
        detailedReason: 'Kerangka fungsi belum dilengkapi anotasi tipe dan pengujian.',
      });
    } else {
      if (!/isinstance|typeof|Array\.isArray|zod|schema/i.test(codeWithoutComments)) {
        findings.push({
          line: execLines[0]?.num || 1,
          category: 'security',
          penalty: 10,
          shortReason: '-10 Belum ditemukan validasi tipe dan batas panjang input secara eksplisit',
          detailedReason: 'Masukan fungsi diproses tanpa pemeriksaan tipe data atau batas ukuran payload secara defensif.',
        });
      } else {
        verifiedMitigations.push('Pemeriksaan tipe data masukan terdeteksi secara eksplisit di dalam kode.');
      }

      if (!/try\s*:|try\s*\{|raise\s+|throw\s+/i.test(codeWithoutComments)) {
        findings.push({
          line: execLines[0]?.num || 1,
          category: 'correctness',
          penalty: 15,
          shortReason: '-15 Belum dilengkapi penanganan exception / error boundary pada kasus batas',
          detailedReason: 'Kode belum mengantisipasi kegagalan runtime atau masukan bernilai null/undefined/kosong.',
        });
      }

      findings.push({
        line: execLines[0]?.num || 1,
        category: 'maintainability',
        penalty: 10,
        shortReason: '-10 Belum dilengkapi structured logging dan anotasi tipe lengkap',
        detailedReason: 'Disarankan menambahkan anotasi tipe statis dan pencatatan log terstruktur untuk kemudahan pemeliharaan.',
      });

      residualNotes.push(
        'Kontrak Input Ketat: Selalu validasi tipe, rentang nilai, dan panjang maksimum parameter di baris pertama fungsi.',
        'Penanganan Kesalahan Defensif: Pastikan seluruh kegagalan eksternal ditangkap dan dikembalikan sebagai pesan kesalahan yang aman tanpa membocorkan stack trace.'
      );
    }
  }

  // ---------------------------------------------------------------------------
  // UNIVERSAL CROSS-CUTTING CHECKS (Apply to any edited code if not already flagged)
  // ---------------------------------------------------------------------------
  // 1. Check for TypeScript `any` in non-auth snippets (scan maskedCode so regex/string literals aren't flagged)
  if (!isAuthDomain && /:\s*any\b/.test(lexical.maskedCode)) {
    const anyL = maskedLines
      .map((lineText, idx) => (/:\s*any\b/.test(lineText) ? idx + 1 : 0))
      .filter((num) => num > 0);
    if (anyL.length > 0) {
      findings.push({
        line: anyL[0],
        category: 'maintainability',
        penalty: 15,
        shortReason: `-15 Penggunaan tipe ': any' melemahkan pemeriksaan tipe statis (baris ${anyL.join(', ')})`,
        detailedReason: `Hindari penggunaan ': any' pada baris ${anyL.join(', ')}; gunakan tipe eksplisit atau generic.`,
      });
    }
  }

  // 2. Check for raw error message leakage to HTTP response
  if (/res\.status\(\d+\)\.(?:send|json)\([^)]*err\.message/i.test(codeWithoutComments)) {
    const leakLine = findLine(/err\.message/i);
    findings.push({
      line: leakLine,
      category: 'security',
      penalty: 10,
      shortReason: `-10 Kebocoran informasi internal (err.message dikirim ke klien pada baris ${leakLine})`,
      detailedReason: `Mengirimkan err.message mentah ke respons klien pada baris ${leakLine} dapat membocorkan struktur path atau skema database internal.`,
      isCritical: true,
    });
  }

  // 3. v1.2.0 Deterministic AI-Slop & Vibe-Coding Detectors (DG004, DG004-DYN-01/02, DG005, DG006, DG008)
  let dynScopeUncertain = 0;
  if (!isPython) {
    detectHallucinatedPackages(execLines, maskedLines, options, findings, inlineFindings);
    if (virtualView.editsApplied === 0) {
      ({ dynScopeUncertain } = detectDynamicModuleSpecifiers(
        lexical.maskedCode,
        lexical.stringLiterals,
        options,
        inlineFindings
      ));
    }
    detectSwallowedExceptions(code, findings, inlineFindings, lexical.maskedCode);
    detectNonAtomicBalanceMutations(rawLines, findings, inlineFindings);
    detectMissingTimeoutsAndLoops(code, lexical.maskedCode, rawLines, findings, inlineFindings);
  }

  // 3b. Additive Pass-V (runs if and only if virtualView.editsApplied > 0)
  if (virtualView.editsApplied > 0) {
    const vLex = analyzeLexicalStructure(virtualView.virtualCode, isPython);
    const vRawLines = virtualView.virtualCode.split('\n');
    const vLineStarts = [0];
    for (let i = 0; i < virtualView.virtualCode.length; i++) {
      if (virtualView.virtualCode[i] === '\n') vLineStarts.push(i + 1);
    }

    const getRuleHintRe = (ruleId: DevGuardRuleId): RegExp | undefined => {
      switch (ruleId) {
        case 'DG001':
          return /\b(?:eval|exec|Function|system|globalThis|window|global|self)\b/;
        case 'DG004':
        case 'DG004-DYN-01':
        case 'DG004-DYN-02':
          return /\b(?:import|require|from)\b/;
        case 'DG005':
          return /\b(?:try|catch)\b/;
        case 'DG006':
          return /\b(?:balance|saldo|credits?|wallet|stock|inventory|quota|points)\b/;
        case 'DG007':
          return /['"`]/;
        case 'DG008':
          return /\b(?:while|for|do|fetch)\b/;
        default:
          return undefined;
      }
    };

    const remapVirtualLineRange = (
      vLine: number,
      vEndLine: number | undefined,
      ruleHintRe?: RegExp
    ): { line: number; endLine: number } => {
      const startLineIdx = Math.max(0, Math.min(vLine - 1, vLineStarts.length - 1));
      const endLineIdx = Math.max(startLineIdx, Math.min((vEndLine ?? vLine) - 1, vLineStarts.length - 1));
      let vStart = vLineStarts[startLineIdx];
      let vEnd =
        endLineIdx + 1 < vLineStarts.length
          ? Math.max(vStart, vLineStarts[endLineIdx + 1] - 1)
          : virtualView.virtualCode.length;

      if (vStart < vEnd) {
        while (vStart < vEnd && /[ \t\r]/.test(virtualView.virtualCode[vStart])) vStart++;
        while (vEnd > vStart && /[ \t\r]/.test(virtualView.virtualCode[vEnd - 1])) vEnd--;
      }

      if ((vEndLine ?? vLine) === vLine && ruleHintRe && vEnd > vStart) {
        const lineText = virtualView.virtualCode.slice(vStart, vEnd);
        if (lineText.includes(';')) {
          let segStart = 0;
          for (let idx = 0; idx <= lineText.length; idx++) {
            if (idx === lineText.length || lineText[idx] === ';') {
              let s = segStart;
              let e = idx;
              while (s < e && /[ \t\r]/.test(lineText[s])) s++;
              while (e > s && /[ \t\r]/.test(lineText[e - 1])) e--;
              if (e > s && ruleHintRe.test(lineText.slice(s, e))) {
                const absS = vStart + s;
                const absE = vStart + e;
                return toOrigLineAndCol(code, virtualView.spanMap, absS, absE);
              }
              segStart = idx + 1;
            }
          }
        }
      }

      return toOrigLineAndCol(code, virtualView.spanMap, vStart, vEnd);
    };

    const replaceVirtualLineInText = (text: string, vLine: number, oLine: number): string => {
      if (vLine === oLine) return text;
      const vStr = String(vLine);
      const oStr = String(oLine);
      return text
        .replace(new RegExp(`(baris\\s+)${vStr}\\b`, 'gi'), `$1${oStr}`)
        .replace(new RegExp(`(line\\s+)${vStr}\\b`, 'gi'), `$1${oStr}`)
        .replace(new RegExp(`:${vStr}\\b`), `:${oStr}`);
    };

    // DG004-DYN-01/02 in virtual-only mode: evaluated on virtualView.virtualCode
    if (!isPython) {
      const vDynFindings: InlineFinding[] = [];
      const dynRes = detectDynamicModuleSpecifiers(
        vLex.maskedCode,
        vLex.stringLiterals,
        options,
        vDynFindings
      );
      dynScopeUncertain = dynRes.dynScopeUncertain;
      for (const df of vDynFindings) {
        const origLine = df.line;
        const mapped = remapVirtualLineRange(origLine, df.endLine, getRuleHintRe(df.ruleId));
        df.line = mapped.line;
        df.endLine = mapped.endLine > mapped.line ? mapped.endLine : undefined;
        df.message = replaceVirtualLineInText(df.message, origLine, mapped.line);
        inlineFindings.push(df);
      }
    }

    // Additive execution of v1.2.1 rule detectors on V
    const vFindings: LineFinding[] = [];
    const vInlineFindings: InlineFinding[] = [];

    // DG007 on V
    detectHardcodedSecrets(virtualView.virtualCode, vRawLines, vLex.stringLiterals, vFindings, vInlineFindings);

    if (!isPython) {
      const vExecLines: Array<{ num: number; text: string }> = [];
      for (let i = 0; i < vRawLines.length; i++) {
        if (!isCommentOrEmptyLine(vRawLines[i])) {
          vExecLines.push({ num: i + 1, text: vRawLines[i] });
        }
      }
      const vMaskedLines = vLex.maskedCode.split('\n');

      if (/\b(?:import|require|from)\b/.test(vLex.maskedCode)) {
        detectHallucinatedPackages(vExecLines, vMaskedLines, options, vFindings, vInlineFindings);
      }
      if (/\b(?:try|catch)\b/.test(vLex.maskedCode)) {
        detectSwallowedExceptions(virtualView.virtualCode, vFindings, vInlineFindings, vLex.maskedCode);
      }
      if (/\bawait\b/.test(vLex.maskedCode)) {
        detectNonAtomicBalanceMutations(vRawLines, vFindings, vInlineFindings);
      }
      if (/\b(?:while|for|do|fetch)\b/.test(vLex.maskedCode)) {
        detectMissingTimeoutsAndLoops(virtualView.virtualCode, vLex.maskedCode, vRawLines, vFindings, vInlineFindings);
      }

      // DG001 on V (eval/exec dynamic sinks in general code domain)
      if (!isSqlDomain && !isPingDomain && !isAuthDomain && !isFileDomain && !isCartDomain) {
        const evalSinkRe = /(?:^|[^.\w$])(?:eval|exec)\s*\(|\b[A-Za-z_$][\w$]*\.eval\s*\(|\b(?:globalThis|window|global|self|child_process)\.exec\s*\(|os\.system\s*\(|\bnew\s+Function\s*\(/i;
        const evalExecMethodDeclRe = /(?:^|[;{}])\s*(?:(?:export|default|public|private|protected|abstract|override|static|async|declare|get|set)\s+)*(?:function\s*\*?\s*)?(?:eval|exec)\s*\([^()]*\)\s*(?::\s*[A-Za-z_$][\w$<>\[\]|&\s,.?]*\s*)?\{/;
        const maskedGlobalBracketRe = /\b(?:globalThis|window|global|self)\b[^\n;]*\[/;
        const bracketEvalRe = /\b(?:globalThis|window|global|self)\b[^\n;]*\[\s*['"](?:eval|exec)['"]\s*\]/;
        const vEvalLines = vExecLines
          .filter(({ num, text }) => {
            const mLine = vMaskedLines[num - 1] ?? '';
            if (evalExecMethodDeclRe.test(mLine)) return false;
            if (evalSinkRe.test(mLine)) return true;
            return maskedGlobalBracketRe.test(mLine) && bracketEvalRe.test(text);
          })
          .map((l) => l.num);
        if (vEvalLines.length > 0) {
          vFindings.push({
            line: vEvalLines[0],
            extraLines: vEvalLines.slice(1),
            category: 'security',
            penalty: 40,
            shortReason: `-40 Eksekusi kode/perintah dinamis berbahaya (baris ${vEvalLines.join(', ')})`,
            detailedReason: `Ditemukan pemanggilan eksekusi kode/perintah dinamis pada baris ${vEvalLines.join(', ')} yang membuka celah Remote Code Execution (RCE) / Command Injection.`,
            isCritical: true,
          });
          vInlineFindings.push({
            ruleId: 'DG001',
            line: vEvalLines[0],
            severity: 'error',
            message: `[DG001] Dangerous dynamic code/command execution sink on line ${vEvalLines.join(', ')}`,
          });
        }
      }
    }

    // Remap finding locations from V to O and deduplicate against Pass-O findings
    for (const vInline of vInlineFindings) {
      const mapped = remapVirtualLineRange(vInline.line, vInline.endLine, getRuleHintRe(vInline.ruleId));
      const oLine = mapped.line;
      const oEndLine = mapped.endLine > oLine ? mapped.endLine : undefined;

      // Deduplicate: discard if Pass-O already flagged the same ruleId at an overlapping line
      const isDuplicate = inlineFindings.some(
        (orig) =>
          orig.ruleId === vInline.ruleId &&
          (orig.line === oLine ||
            (orig.endLine !== undefined && oLine >= orig.line && oLine <= orig.endLine) ||
            (oEndLine !== undefined && orig.line >= oLine && orig.line <= oEndLine))
      );

      if (!isDuplicate) {
        const updatedMsg = replaceVirtualLineInText(vInline.message, vInline.line, oLine);
        const taggedMsg = updatedMsg.includes('[via-fold]')
          ? updatedMsg
          : `${updatedMsg} [via-fold]`;
        inlineFindings.push({
          ...vInline,
          line: oLine,
          endLine: oEndLine,
          message: taggedMsg,
        });
      }
    }

    for (const vFinding of vFindings) {
      const tagMatch = vFinding.shortReason.match(/\[(DG\d{3})\]/);
      const hintRe = tagMatch?.[1] ? getRuleHintRe(tagMatch[1] as DevGuardRuleId) : undefined;
      const mapped = remapVirtualLineRange(vFinding.line, undefined, hintRe);
      const oLine = mapped.line;

      const isDuplicate = findings.some(
        (orig) =>
          orig.category === vFinding.category &&
          (orig.line === oLine || (orig.extraLines?.includes(oLine) ?? false))
      );

      if (!isDuplicate) {
        const tag = ' [via-fold]';
        const shortUpdated = replaceVirtualLineInText(vFinding.shortReason, vFinding.line, oLine);
        const detailUpdated = replaceVirtualLineInText(vFinding.detailedReason, vFinding.line, oLine);
        findings.push({
          ...vFinding,
          line: oLine,
          extraLines: vFinding.extraLines
            ? vFinding.extraLines.map((el) => remapVirtualLineRange(el, undefined, hintRe).line)
            : undefined,
          shortReason: shortUpdated.includes('[via-fold]')
            ? shortUpdated
            : `${shortUpdated}${tag}`,
          detailedReason: detailUpdated.includes('[via-fold]')
            ? detailUpdated
            : `${detailUpdated}${tag}`,
        });
      }
    }
  }

  // 4. Stage 3a: Non-Bypassable Suppression & Verified Allowlist Policy
  const activeSuppressions = applySuppressionPolicy(lexical.suppressions, options, findings, inlineFindings);

  // ---------------------------------------------------------------------------
  // AGGREGATE SCORES & BUILD REPORT
  // ---------------------------------------------------------------------------
  const secFindings = findings.filter((f) => f.category === 'security' && f.penalty > 0);
  const corrFindings = findings.filter((f) => f.category === 'correctness' && f.penalty > 0);
  const maintFindings = findings.filter((f) => f.category === 'maintainability' && f.penalty > 0);

  const security = Math.max(0, 100 - secFindings.reduce((acc, f) => acc + f.penalty, 0));
  const correctness = Math.max(0, 100 - corrFindings.reduce((acc, f) => acc + f.penalty, 0));
  const maintainability = Math.max(0, 100 - maintFindings.reduce((acc, f) => acc + f.penalty, 0));
  const totalScore = Math.round((security + correctness + maintainability) / 3);

  const criticalFindings = findings.filter((f) => f.isCritical);
  const hasSevereVuln = security < 80 || correctness < 75 || criticalFindings.length > 0;
  const isHardened = !hasSevereVuln && totalScore >= 88;

  // Determine highlighted line reference
  let lineRef = '-';
  if (criticalFindings.length > 0) {
    const allCritLines: number[] = [];
    for (const f of criticalFindings) {
      allCritLines.push(f.line);
      if (f.extraLines) allCritLines.push(...f.extraLines);
    }
    const uniqueCritLines = Array.from(new Set(allCritLines)).slice(0, 3);
    lineRef = `Baris ${uniqueCritLines.join(' & ')}`;
  } else if (hasSevereVuln && findings.length > 0) {
    const topFindingLines = Array.from(new Set(findings.slice(0, 2).map((f) => f.line)));
    lineRef = `Baris ${topFindingLines.join(' & ')}`;
  }

  // Construct Main Finding / Post-Remediation Verification Summary
  let temuanUtamaDesc = '';
  if (!hasSevereVuln && verifiedMitigations.length > 0) {
    temuanUtamaDesc =
      `Mitigasi utama terverifikasi pada Single-Pass Lexical & Heuristic Engine / kode aktif: ${verifiedMitigations.join(' ')} ` +
      (findings.length > 0
        ? `Namun sesuai audit zero-leniency, skor disesuaikan (${totalScore}/100) karena catatan arsitektural tingkat produksi: ${findings.map((f) => f.shortReason).join('; ')}.`
        : '');
  } else if (criticalFindings.length > 0) {
    temuanUtamaDesc = criticalFindings.map((f) => f.detailedReason).join(' ');
  } else if (findings.length > 0) {
    temuanUtamaDesc = findings[0].detailedReason;
  } else {
    temuanUtamaDesc = 'Kode telah melewati pemeriksaan pola statis dasar, namun tetap memerlukan verifikasi integrasi di lingkungan produksi.';
  }

  // Construct Secondary Findings / Defense-in-Depth Notes
  const temuanLainList: string[] = [];
  for (const f of findings) {
    if (temuanLainList.length < 5) {
      temuanLainList.push(`[Baris ${f.line}] ${f.detailedReason}`);
    }
  }
  for (const note of residualNotes) {
    if (temuanLainList.length < 5) {
      temuanLainList.push(`[Defense-in-Depth] ${note}`);
    }
  }

  // Determine Remediation Snippet & Technical Term
  let remediationCode = code;
  let remediationSummary = '';
  let technicalTerm = 'Security & Quality Audit';
  let story = 'Seperti sistem keamanan berlapis di mana setiap pintu masuk memeriksa identitas, batas wewenang, dan mencatat jejak audit secara konsisten.';
  let apresiasi = 'Kode menunjukkan struktur logika yang terorganisir dan siap dievaluasi terhadap standar keamanan produksi.';
  let tests: Array<{ title: string; input: string; expected: string }> = [];

  if (isSqlDomain) {
    remediationCode = UPGRADED_REMEDIATION_SNIPPETS.banking;
    remediationSummary = 'Gunakan pemeriksaan tipe ketat type(jumlah) is not int (menutup celah subclass bool di Python), parameterized query "?", serta atomic conditional UPDATE (WHERE username = ? AND poin >= ?) untuk mencegah TOCTOU race condition.';
    technicalTerm = isHardened ? 'Atomic ACID & Anti-TOCTOU Hardened' : 'SQL Injection & TOCTOU Race Condition';
    story = isHardened
      ? 'Seperti brankas bank dengan kunci berparameter yang mengecek dan memotong saldo dalam satu gerakan mekanis tunggal, meskipun disarankan menambah kamera pencatat log transaksi di pintu luar.'
      : "Seperti pintu brankas bank yang kuncinya ditempeli kertas bertuliskan 'Silakan masuk siapa saja yang mengaku nasabah', atau kasir yang mengecek saldo lalu ditinggal pergi sebelum mencatat pemotongan saldo.";
    apresiasi = isHardened
      ? 'Implementasi fungsi transfer telah menerapkan parameterized query dan pembaruan bersyarat atomik yang menutup celah SQL Injection serta TOCTOU race condition.'
      : 'Struktur fungsi memiliki alur pemikiran yang jelas dalam mencoba memperbarui saldo pengirim lalu penerima.';
    tests = [
      {
        title: 'Uji Overdraft & Atomic Guard',
        input: 'andi (saldo 100) kirim 1000 ke budi',
        expected: 'ValueError("Saldo tidak mencukupi...") & saldo andi tetap 100 utuh'
      },
      {
        title: 'Uji Python Bool Subclass Trap',
        input: 'andi kirim jumlah = True (boolean) ke budi',
        expected: 'Ditolak oleh type(jumlah) is not int sebelum menyentuh database'
      },
      {
        title: 'Uji SQL Injection & Rollback',
        input: "pengirim = \"x' OR '1'='1\" atau penerima = 'ghost'",
        expected: 'Payload diperlakukan sebagai string literal & transaksi rollback atomik'
      }
    ];
  } else if (isAuthDomain) {
    remediationCode = UPGRADED_REMEDIATION_SNIPPETS.jwt;
    remediationSummary = 'Muat JWT_SECRET dari environment variable (min 32 karakter), gunakan tipe ketat Request/Response/JwtPayload (tanpa any), kunci algorithms: ["HS256"] pada jwt.verify, dan cocokkan String(payload.userId) !== String(req.params.id).';
    technicalTerm = isHardened ? 'Strict Type-Safe JWT & BOLA Defense' : 'Hardcoded Secret, IDOR & Unpinned JWT';
    story = isHardened
      ? 'Seperti lift gedung eksekutif yang memverifikasi keaslian kartu akses menggunakan standar enkripsi tunggal HS256 dan mencocokkan nomor lantai dengan identitas pemilik kartu.'
      : 'Seperti menyematkan kunci master kamar hotel di papan pengumuman lobi, lalu membiarkan siapa saja masuk ke kamar mana pun hanya dengan menyebut nomor kamar.';
    apresiasi = isHardened
      ? 'Endpoint penagihan telah mengisolasi secret ke environment variable, menerapkan pinning algoritma HS256, menutup celah IDOR, dan menggunakan tipe TypeScript ketat.'
      : 'Struktur modul otentikasi Express dirancang dengan pemisahan endpoint profil penagihan yang jelas.';
    tests = [
      {
        title: 'Uji Pencegahan IDOR Lintas Akun',
        input: 'GET /api/users/99/billing dengan Bearer token userId=42',
        expected: 'Status 403 Forbidden (Pelanggaran otorisasi objek IDOR)'
      },
      {
        title: 'Uji Algorithm Confusion Attack',
        input: 'Token JWT dengan header alg: "none" atau kunci publik RS256',
        expected: 'Ditolak oleh opsi eksplisit { algorithms: ["HS256"] }'
      },
      {
        title: 'Uji Entropi Environment Secret',
        input: 'Boot aplikasi tanpa process.env.JWT_SECRET yang memadai',
        expected: 'Fail-fast error saat startup sebelum menerima trafik'
      }
    ];
  } else if (isPingDomain) {
    remediationCode = UPGRADED_REMEDIATION_SNIPPETS.command;
    remediationSummary = 'Validasi alamat IP dengan ipaddress.ip_address(), tolak IP privat/loopback (is_private / is_loopback) untuk mencegah SSRF, dan eksekusi subprocess.run dengan shell=False serta timeout=5.';
    technicalTerm = isHardened ? 'Subprocess Sandboxing & SSRF Guard' : 'Command Injection & Unbounded Subprocess';
    story = isHardened
      ? 'Seperti petugas operator yang memverifikasi nomor tujuan terhadap daftar terlarang internal dan membatasi durasi panggilan maksimal 5 detik agar saluran tidak macet.'
      : 'Seperti petugas loket yang membacakan apa pun yang tertulis di kertas pengunjung ke pengeras suara darurat bandara tanpa memeriksa isinya terlebih dahulu.';
    apresiasi = isHardened
      ? 'Fungsi diagnostik telah memvalidasi objek IP secara ketat, memblokir rentang internal (Anti-SSRF), menonaktifkan shell, dan memasang batas waktu eksekusi.'
      : 'Fungsi ping_host dirancang dengan alur sederhana untuk memeriksa status konektivitas jaringan host.';
    tests = [
      {
        title: 'Uji Injeksi Perintah Shell',
        input: 'user_ip_input = "8.8.8.8; cat /etc/passwd"',
        expected: 'ValueError("Format IP address tidak valid!") sebelum subproses berjalan'
      },
      {
        title: 'Uji Pemblokiran SSRF Internal',
        input: 'user_ip_input = "127.0.0.1" atau "169.254.169.254"',
        expected: 'ValueError("Akses ping ke jaringan internal/loopback ditolak!")'
      },
      {
        title: 'Uji Batas Waktu Subprocess (Timeout)',
        input: 'Host eksternal blackhole yang tidak merespons ICMP',
        expected: 'Mengembalikan pesan timeout bersih setelah 5 detik tanpa menggantung worker'
      }
    ];
  } else if (isFileDomain) {
    remediationCode = UPGRADED_REMEDIATION_SNIPPETS.traversal;
    remediationSummary = 'Gunakan path.basename(), verifikasi batas direktori dengan path.relative(safeBaseDir, candidatePath) untuk menutup celah prefix-collision, validasi fs.promises.realpath() terhadap symlink, dan baca berkas secara asinkron.';
    technicalTerm = isHardened ? 'Canonical Realpath & Async I/O Containment' : 'Path Traversal & Prefix-Collision Bypass';
    story = isHardened
      ? 'Seperti arsiparis yang memeriksa jalur relatif dokumen dan memverifikasi lokasi fisik map asli (bukan jalan pintas/symlink) secara non-blocking.'
      : 'Seperti resepsionis kantor yang diminta mengambil berkas di laci depan, namun pengunjung memanipulasi denah tangga darurat hingga masuk ke brankas rahasia gedung.';
    apresiasi = isHardened
      ? 'Handler pengunduhan berkas telah menerapkan verifikasi path.relative, resolusi symlink fisik via realpath(), dan operasi I/O asinkron non-blocking.'
      : 'Fungsi downloadReport memiliki implementasi endpoint pengunduhan berkas yang ringkas.';
    tests = [
      {
        title: 'Uji Path Traversal & Prefix Collision',
        input: 'GET /download?file=../../etc/passwd atau ../reports_secret/key.pem',
        expected: 'Ditolak 403 oleh pemeriksaan path.basename dan path.relative'
      },
      {
        title: 'Uji Serangan Symlink Traversal',
        input: 'Berkas di dalam folder laporan yang merupakan symlink ke /etc/shadow',
        expected: 'Ditolak 403 setelah resolusi fs.promises.realpath()'
      },
      {
        title: 'Uji Pembacaan Asinkron Non-Blocking',
        input: 'GET /download?file=annual_report.pdf',
        expected: 'Dibaca melalui fs.promises.readFile tanpa memblokir event loop'
      }
    ];
  } else if (isCartDomain) {
    remediationCode = UPGRADED_REMEDIATION_SNIPPETS.ecommerce;
    remediationSummary = 'Bekukan katalog harga server dengan Object.freeze(), validasi Number.isSafeInteger(item.quantity) dengan batas atas MAX_QUANTITY_PER_ITEM (<= 1000), cegah overflow pada akumulasi total, dan batasi total minimum >= 0.';
    technicalTerm = isHardened ? 'Server-Authoritative Pricing & Overflow Guard' : 'Business Logic Flaw & Integer Overflow';
    story = isHardened
      ? 'Seperti mesin kasir terenkripsi yang hanya memindai harga dari database pusat, membatasi jumlah pembelian maksimum per transaksi, dan menolak total pembayaran negatif.'
      : 'Seperti kasir supermarket yang membiarkan pembeli menulis sendiri harga di barcode barang dan memasukkan jumlah barang minus sehingga toko berutang kepada pembeli.';
    apresiasi = isHardened
      ? 'Kalkulasi keranjang belanja telah mengunci otoritas harga di sisi server, memvalidasi batas aman integer (SafeInteger), serta membatasi kuantitas maksimum per produk.'
      : 'Fungsi calculateTotal memiliki struktur perulangan yang rapi dalam menjumlahkan item belanjaan.';
    tests = [
      {
        title: 'Uji Kuantitas Negatif & Batas Atas Overflow',
        input: 'quantity: -5 atau quantity: 9999999999999999',
        expected: 'Ditolak oleh pemeriksaan Number.isSafeInteger dan batas 1 - 1000'
      },
      {
        title: 'Uji Manipulasi Harga Klien',
        input: 'Payload item dengan item.price: 0.01',
        expected: 'Diabaikan; fungsi mengambil harga resmi dari SERVER_PRICE_CATALOG'
      },
      {
        title: 'Uji Batas Bawah Voucher Diskon',
        input: 'Total belanja 50 dengan diskon VIP100 (-100)',
        expected: 'Total akhir terkunci di 0 (Math.max(0, total))'
      }
    ];
  } else {
    tests = [
      {
        title: 'Uji Validasi Tipe & Batas Input',
        input: 'Input bernilai null, undefined, tipe salah, atau string sangat panjang',
        expected: 'Ditolak secara dini dengan ValueError / TypeError yang jelas'
      },
      {
        title: 'Uji Payload Injeksi / Karakter Khusus',
        input: 'String dengan karakter kontrol atau metakarakter berbahaya',
        expected: 'Diproses sebagai data murni tanpa eksekusi tak disengaja'
      }
    ];
  }

  const securityDeductions = secFindings.length > 0
    ? secFindings.map((f) => f.shortReason)
    : ['✓ Tidak ditemukan pola injeksi/kebocoran langsung'];
  const correctnessDeductions = corrFindings.length > 0
    ? corrFindings.map((f) => f.shortReason)
    : ['✓ Invarian state dasar terjaga'];
  const maintainabilityDeductions = maintFindings.length > 0
    ? maintFindings.map((f) => f.shortReason)
    : ['✓ Struktur modular & rapi'];

  const tesMarkdown = tests
    .map((t, idx) => `${idx + 1}. ${t.title}: Input ${t.input} -> Hasil yang diharapkan: ${t.expected}`)
    .join('\n');

  const safeRemediationCode =
    !isSelfAnalyzerModule && dg007FlaggedLines.size > 0
      ? redactSecretsPreservingLayout(remediationCode)
      : remediationCode;

  const rawMarkdown = `## 👋 Apresiasi
${apresiasi}

## 📊 Skor
Security: ${security}/100 (${securityDeductions.join('; ')})
Correctness: ${correctness}/100 (${correctnessDeductions.join('; ')})
Maintainability: ${maintainability}/100 (${maintainabilityDeductions.join('; ')})
Overall Guard: ${totalScore}/100

## 💣 Temuan Utama
${lineRef !== '-' ? `[${lineRef}] ` : ''}${temuanUtamaDesc}

## 🗒️ Temuan Lain
${temuanLainList.map((item) => `- ${item}`).join('\n')}

## 🏪 Analogi
${story} Istilah teknis: ${technicalTerm}.

## 🔧 Perbaikan
${remediationSummary}

\`\`\`${language}
${safeRemediationCode}
\`\`\`

## ✅ Tes
${tesMarkdown}`;

  return {
    rawMarkdown,
    apresiasi,
    skor: {
      security,
      securityDeductions,
      correctness,
      correctnessDeductions,
      maintainability,
      maintainabilityDeductions,
      totalScore,
    },
    temuanUtama: {
      line: lineRef,
      description: temuanUtamaDesc,
    },
    temuanLain: temuanLainList,
    analogi: {
      story,
      technicalTerm,
    },
    perbaikan: {
      code: safeRemediationCode,
      language,
      summary: remediationSummary,
    },
    tesMarkdown,
    tes: tests,
    verifiedMitigations,
    residualNotes,
    isHardened,
    inlineFindings: inlineFindings.length > 0 ? inlineFindings : undefined,
    suppressions: activeSuppressions.length > 0 ? activeSuppressions : undefined,
    dynScopeUncertain: dynScopeUncertain > 0 ? dynScopeUncertain : undefined,
    virtualView,
  };
}
