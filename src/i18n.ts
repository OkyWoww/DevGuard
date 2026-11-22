export type Locale = 'en' | 'id';

export const DEFAULT_LOCALE: Locale = 'en';
const STORAGE_KEY = 'devguard_locale';

export function getInitialLocale(): Locale {
  if (typeof window === 'undefined') return DEFAULT_LOCALE;
  try {
    const saved = window.localStorage.getItem(STORAGE_KEY);
    if (saved === 'en' || saved === 'id') return saved;
  } catch {
    return DEFAULT_LOCALE;
  }
  return DEFAULT_LOCALE;
}

export function persistLocale(locale: Locale): boolean {
  if (typeof window === 'undefined') return false;
  try {
    window.localStorage.setItem(STORAGE_KEY, locale);
    return true;
  } catch {
    return false;
  }
}

export interface UiDictionary {
  header: {
    subtitle: string;
    tabAudit: string;
    tabVerify: string;
    tabPrompt: string;
    tabFiles: string;
    auditing: string;
    runAudit: string;
  };
  editor: {
    title: string;
    resetBtn: string;
    resetTitle: string;
    presetLabel: string;
    presetBadge: string;
    isolationHintPrefix: string;
    isolationHintSuffix: string;
    browserModeNoticeBeforeMono: string;
    browserModeNoticeMiddle: string;
    browserModeNoticeAfterBase: string;
    vulnBannerText: string;
    vulnBannerBtn: string;
    appliedToastText: string;
    appliedToastBtn: string;
    appliedToastBtnTitle: string;
    gutterLinePrefix: string;
    gutterFatalSuffix: string;
    gutterClickHint: string;
    placeholder: string;
    linesLabel: string;
    flaggedLinesLabel: string;
  };
  results: {
    loadingTitle: string;
    loadingSubtitle: string;
    scoreStripTitle: string;
    viewStructured: string;
    viewRaw: string;
    secFallbackTitle: string;
    secHardened: string;
    corrFallbackTitle: string;
    corrHardened: string;
    maintFallbackTitle: string;
    maintHardened: string;
    statusReady: string;
    statusReject: string;
    statusRevise: string;
    remediationBannerTitle: string;
    remediationBannerDesc: string;
    applyToEditor: string;
    applyToEditorTitle: string;
    applyAndReaudit: string;
    applyAndReauditTitle: string;
    appreciationTitle: string;
    postRemediationTitle: string;
    zeroExploitsBadge: (score: number) => string;
    verifiedMitigationsTitle: string;
    residualNotesTitle: string;
    liveRegressionTipPrefix: string;
    liveRegressionTipMiddle: string;
    liveRegressionTipSuffix: string;
    mainFindingTitle: string;
    jumpToLineTitle: string;
    otherFindingsHardened: string;
    otherFindingsDefault: string;
    analogyTitle: string;
    analogyTermLabel: string;
    patchCardTitle: string;
    copied: string;
    copyCode: string;
    copyCodeTitle: string;
    applyPatchBtn: string;
    applyPatchAndReauditBtn: string;
    testCasesTitle: string;
    testCasesSubtitle: string;
    standbyBadge: string;
    standbyTitle: string;
    standbyDesc: string;
    standbyFeature1: string;
    standbyFeature2: string;
  };
  verify: {
    title: string;
    subtitle: string;
    rerunBtn: string;
    scenarioPrefix: string;
    originalCodeLabel: string;
    hardenedCodeLabel: string;
    summaryTitle: string;
    summaryDesc: string;
    totalPointsLabel: string;
  };
  prompt: {
    copyPromptBtn: string;
    loadingPrompt: string;
    defenseTitle: string;
    defense1Title: string;
    defense1DescBefore: string;
    defense1DescAfter: string;
    defense2Title: string;
    defense2Desc: string;
    defense3Title: string;
    defense3Desc: string;
    sandboxTitle: string;
    sandboxDesc: string;
    payload1Label: string;
    payload2Label: string;
  };
  files: {
    artifactsTitle: string;
    cliQuickstartTitle: string;
    selectFileFallback: string;
    copiedExcl: string;
    copyContent: string;
    download: string;
    noFileSelected: string;
  };
}

export const UI_TEXT: Record<Locale, UiDictionary> = {
  en: {
    header: {
      subtitle: 'Adversarial Code Review Harness · Gemini Interactions API',
      tabAudit: 'Audit Studio',
      tabVerify: 'Empirical Test Harness',
      tabPrompt: 'Anti-Injection Defense',
      tabFiles: 'Scaffolding Files',
      auditing: 'Auditing...',
      runAudit: 'Run DevGuard Audit',
    },
    editor: {
      title: 'Target Code Snippet',
      resetBtn: 'Reset',
      resetTitle: 'Reset editor and audit results to clean initial state',
      presetLabel: 'Select Case Study / Scenario Preset:',
      presetBadge: 'Multi-Language & Domain',
      isolationHintPrefix: 'Pasted code is wrapped inside data isolation tags',
      isolationHintSuffix:
        'Each audit dynamically evaluates the active editor string (Zero-Leniency Hybrid Auditor).',
      browserModeNoticeBeforeMono:
        'Browser mode audits single-file snippets only; monorepo resolution (',
      browserModeNoticeMiddle: '), base-branch ',
      browserModeNoticeAfterBase: ', and PR comments run in GitHub Actions CI.',
      vulnBannerText:
        'Security/logic vulnerabilities detected! Production-grade remediation patch is ready.',
      vulnBannerBtn: 'Apply Fix & Re-Audit',
      appliedToastText:
        'Patch applied to editor. Click Re-Audit Now to run hybrid evaluation on the updated code.',
      appliedToastBtn: 'Re-Audit Now',
      appliedToastBtnTitle: 'Run a fresh audit on the current editor code',
      gutterLinePrefix: 'Line',
      gutterFatalSuffix: ' (Critical Finding)',
      gutterClickHint: ' - Click to jump',
      placeholder: 'Paste code to audit here...',
      linesLabel: 'Lines:',
      flaggedLinesLabel: 'Flagged:',
    },
    results: {
      loadingTitle:
        'Running Adversarial Code Analysis (Layer 1 Single-Pass Lexical & Heuristic Engine + Layer 2 Gemini)...',
      loadingSubtitle:
        'Checking dangerous sinks, TOCTOU race conditions, type safety, and computing zero-leniency rubric penalties.',
      scoreStripTitle: 'DevGuard Score Evaluation',
      viewStructured: 'Structured View',
      viewRaw: 'Raw Markdown',
      secFallbackTitle: 'Security Evaluation',
      secHardened: '✓ Hardened',
      corrFallbackTitle: 'Correctness Evaluation',
      corrHardened: '✓ Invariants Preserved',
      maintFallbackTitle: 'Clean Structure',
      maintHardened: '✓ Clean Structure',
      statusReady: 'Status: Merge Ready (Hardened)',
      statusReject: 'Status: Block Merge',
      statusRevise: 'Status: Needs Revision',
      remediationBannerTitle: '🛠️ Hardened Remediation Patch Ready',
      remediationBannerDesc:
        'Apply the hardened patch against TOCTOU race conditions, type safety issues, and numeric bounds:',
      applyToEditor: 'Apply to Editor',
      applyToEditorTitle: 'Apply remediation patch to the editor on the left',
      applyAndReaudit: 'Apply Fix & Re-Audit',
      applyAndReauditTitle: 'Apply patch and immediately trigger a live re-audit',
      appreciationTitle: '👋 Summary & Structural Strengths',
      postRemediationTitle: '🛡️ Post-Remediation Audit (Engineering-Grade Verification)',
      zeroExploitsBadge: (score) => `✓ 0 Critical Exploits · Honest Score ${score}/100`,
      verifiedMitigationsTitle:
        '1. Verified Code Mitigations & Single-Pass Lexical & Heuristic Engine Checks:',
      residualNotesTitle:
        '2. Residual Architectural Notes (Defense-in-Depth — Why Not a Blind 100/100):',
      liveRegressionTipPrefix: 'Live Regression Detection Active:',
      liveRegressionTipMiddle:
        'If you mutate the code in the editor (e.g., remove timeout=5, add : any, or reintroduce string concatenation +) and click',
      liveRegressionTipSuffix:
        ', the score and red gutter highlights will react immediately.',
      mainFindingTitle: '💣 Primary Finding (Critical Blocker)',
      jumpToLineTitle: 'Click to jump to this line in the code editor',
      otherFindingsHardened: 'Granular Evaluation Details & Production Considerations',
      otherFindingsDefault: 'Other Findings (Up to 5 Items)',
      analogyTitle: '🏪 Real-World Analogy',
      analogyTermLabel: 'Concept:',
      patchCardTitle: '🛠️ Hardened Reference Patch',
      copied: 'Copied',
      copyCode: 'Copy Code',
      copyCodeTitle: 'Copy remediation code to clipboard',
      applyPatchBtn: 'Apply Fix to Editor',
      applyPatchAndReauditBtn: 'Apply & Re-Audit',
      testCasesTitle: '✅ Verification Test Cases',
      testCasesSubtitle: 'Input Verification & Expected Outcomes',
      standbyBadge: 'Awaiting Audit',
      standbyTitle: 'No Audit Executed Yet',
      standbyDesc:
        "Click the 'Run DevGuard Audit' button in the top-right corner to start analyzing the code.",
      standbyFeature1: 'Deterministic mathematical scoring rubric',
      standbyFeature2: 'Critical line highlights in editor gutter',
    },
    verify: {
      title: 'Empirical Verification Test Suite (SQLite ACID)',
      subtitle:
        'Empirically proves failures in original vulnerable code vs. deterministic correctness of the DevGuard hardened patch across 6 transaction scenarios.',
      rerunBtn: 'Re-Run 6 Scenarios',
      scenarioPrefix: 'Scenario',
      originalCodeLabel: 'Original Code:',
      hardenedCodeLabel: 'Hardened Code:',
      summaryTitle: 'Empirical Proof: 6 of 6 Verification Scenarios Passed',
      summaryDesc:
        'System balance conservation holds strictly (650 total points), SQL injection payloads are neutralized, and transactions execute atomically with automatic rollback.',
      totalPointsLabel: 'Total System Points',
    },
    prompt: {
      copyPromptBtn: 'Copy Prompt',
      loadingPrompt: 'Loading system instructions...',
      defenseTitle: 'DevGuard Anti-Prompt Injection Mechanism',
      defense1Title: '1. Raw Data Isolation (Fencing Tags)',
      defense1DescBefore: 'User-submitted code is fenced inside dedicated delimiter tags',
      defense1DescAfter:
        '. The system strictly treats everything inside as untrusted raw data with zero instruction authority.',
      defense2Title: '2. Deterministic Penalty Rubric',
      defense2Desc:
        'Scores are never subjective. Every violation carries a fixed penalty (e.g., SQL Injection = -40, Balance Corruption/Race Condition = -40/-25).',
      defense3Title: '3. Strict Line-Evidence Discipline',
      defense3Desc:
        'The auditor cannot hallucinate findings and must cite concrete line numbers. Instead of claiming code was "tested", it outputs reproducible verification scenarios.',
      sandboxTitle: 'Prompt Injection Resilience Sandbox',
      sandboxDesc:
        'Inject manipulative instructions inside target code to verify DevGuard enforces penalties without flinching:',
      payload1Label: 'Test Payload 1:',
      payload2Label: 'Test Payload 2:',
    },
    files: {
      artifactsTitle: 'DevGuard Open-Source Project Artifacts',
      cliQuickstartTitle: 'CLI Quickstart Commands',
      selectFileFallback: 'Select a File',
      copiedExcl: 'Copied!',
      copyContent: 'Copy Content',
      download: 'Download',
      noFileSelected: 'No file selected.',
    },
  },
  id: {
    header: {
      subtitle: 'Adversarial Code Review Harness · Gemini Interactions API',
      tabAudit: 'Audit Studio',
      tabVerify: 'Empirical Test Harness',
      tabPrompt: 'Anti-Injection Defense',
      tabFiles: 'Scaffolding Files',
      auditing: 'Mengaudit...',
      runAudit: 'Run DevGuard Audit',
    },
    editor: {
      title: 'Target Junior Developer Snippet',
      resetBtn: 'Reset Pengujian',
      resetTitle: 'Reset seluruh pengujian ke kondisi awal (0) sebelum audit',
      presetLabel: 'Pilih Preset Studi Kasus / Skenario:',
      presetBadge: 'Multi-Bahasa & Domain',
      isolationHintPrefix: 'Kode yang ditempel dibungkus di dalam tag isolasi data',
      isolationHintSuffix:
        'Setiap klik audit mengevaluasi string kode aktif secara dinamis (Zero-Leniency Hybrid Auditor).',
      browserModeNoticeBeforeMono:
        'Mode browser hanya menguji cuplikan/berkas tunggal (single-file); resolusi monorepo (',
      browserModeNoticeMiddle: '), base-branch ',
      browserModeNoticeAfterBase: ', dan komentar PR berjalan di GitHub Actions CI.',
      vulnBannerText:
        'Celah keamanan/logika terdeteksi! Patch remediasi tingkat produksi siap diterapkan.',
      vulnBannerBtn: 'Terapkan Perbaikan & Uji Ulang',
      appliedToastText:
        'Patch diterapkan ke editor. Klik Uji Ulang Sekarang untuk menjalankan evaluasi hibrida pada kode baru.',
      appliedToastBtn: 'Uji Ulang Sekarang',
      appliedToastBtnTitle: 'Klik untuk langsung menjalankan audit ulang pada kode di editor',
      gutterLinePrefix: 'Baris',
      gutterFatalSuffix: ' (Temuan Fatal)',
      gutterClickHint: ' - Klik untuk fokus',
      placeholder: 'Tempel kode yang ingin diaudit di sini...',
      linesLabel: 'Baris:',
      flaggedLinesLabel: 'Sorotan Celah:',
    },
    results: {
      loadingTitle:
        'Menganalisis Kode Secara Adversarial (Layer 1 Single-Pass Lexical & Heuristic Engine + Layer 2 Gemini)...',
      loadingSubtitle:
        'Memeriksa sink berbahaya, kondisi balapan TOCTOU, keamanan tipe, serta menghitung penalti rubrik zero-leniency.',
      scoreStripTitle: 'Hasil Evaluasi Skor DevGuard',
      viewStructured: 'Structured View',
      viewRaw: 'Raw Markdown',
      secFallbackTitle: 'Evaluasi Keamanan',
      secHardened: '✓ Hardened',
      corrFallbackTitle: 'Evaluasi Logika',
      corrHardened: '✓ Invarian Terjaga',
      maintFallbackTitle: 'Struktur Bersih',
      maintHardened: '✓ Struktur Bersih',
      statusReady: 'Status: Siap Merge (Hardened)',
      statusReject: 'Status: Perlu Ditolak',
      statusRevise: 'Status: Perlu Revisi',
      remediationBannerTitle: '🛠️ Patch Remediasi Hardened Siap Diterapkan',
      remediationBannerDesc:
        'Terapkan patch yang telah diperkeras terhadap TOCTOU, keamanan tipe, dan batas numerik:',
      applyToEditor: 'Terapkan ke Editor',
      applyToEditorTitle: 'Terapkan perbaikan ke editor di sebelah kiri',
      applyAndReaudit: 'Terapkan Perbaikan & Uji Ulang',
      applyAndReauditTitle: 'Terapkan perbaikan dan langsung audit ulang secara dinamis',
      appreciationTitle: '👋 Apresiasi & Ringkasan Struktur',
      postRemediationTitle: '🛡️ Audit Pasca-Remediasi (Engineering-Grade Verification)',
      zeroExploitsBadge: (score) => `✓ 0 Celah Eksploitasi Kritis · Skor Jujur ${score}/100`,
      verifiedMitigationsTitle:
        '1. Mitigasi Kode & Single-Pass Lexical & Heuristic Engine Terverifikasi:',
      residualNotesTitle:
        '2. Catatan Arsitektural Residual (Defense-in-Depth — Mengapa Bukan 100/100 Buta):',
      liveRegressionTipPrefix: 'Deteksi Regresi Live Aktif:',
      liveRegressionTipMiddle:
        'Jika Anda memodifikasi kode di editor (misal menghapus timeout=5, menambahkan : any, atau mengembalikan konkatenasi +) lalu klik',
      liveRegressionTipSuffix: ', skor dan sorotan baris merah akan langsung bereaksi.',
      mainFindingTitle: '💣 Temuan Utama (Bom Waktu Fatal)',
      jumpToLineTitle: 'Klik untuk loncat ke baris ini di editor kode',
      otherFindingsHardened: 'Rincian Evaluasi Granular & Pertimbangan Produksi',
      otherFindingsDefault: 'Temuan Lain (Maksimal 5 Butir)',
      analogyTitle: '🏪 Analogi Sehari-hari',
      analogyTermLabel: 'Istilah:',
      patchCardTitle: '🛠️ Referensi Kode Perbaikan (Hardened Reference Patch)',
      copied: 'Disalin',
      copyCode: 'Salin Kode',
      copyCodeTitle: 'Salin kode perbaikan ke clipboard',
      applyPatchBtn: 'Terapkan Perbaikan ke Editor',
      applyPatchAndReauditBtn: 'Terapkan ke Editor & Uji Ulang',
      testCasesTitle: '✅ Kasus Uji Pembuktian',
      testCasesSubtitle: 'Verifikasi Input & Hasil yang Diharapkan',
      standbyBadge: 'Menunggu Audit',
      standbyTitle: 'Belum Ada Pengujian yang Dijalankan',
      standbyDesc:
        "Klik tombol 'Run DevGuard Audit' di kanan atas untuk memulai analisis kode.",
      standbyFeature1: 'Penilaian rubrik matematis baku',
      standbyFeature2: 'Sorotan baris celah di gutter editor',
    },
    verify: {
      title: 'Empirical Verification Test Suite (SQLite ACID)',
      subtitle:
        'Membuktikan secara empiris kegagalan kode junior asli vs keberhasilan mutlak kode perbaikan DevGuard pada 6 skenario transaksi.',
      rerunBtn: 'Re-Run 6 Scenarios',
      scenarioPrefix: 'Skenario',
      originalCodeLabel: 'Kode Asli:',
      hardenedCodeLabel: 'Kode Aman:',
      summaryTitle: 'Bukti Empiris: 6 dari 6 Skenario Pengujian Lolos',
      summaryDesc:
        'Konservasi saldo sistem terbukti utuh (total 650 poin), SQL injection string tidak tereksekusi, dan transaksi beroperasi secara atomik dengan rollback otomatis.',
      totalPointsLabel: 'Total Poin Sistem',
    },
    prompt: {
      copyPromptBtn: 'Salin Prompt',
      loadingPrompt: 'Memuat instruksi sistem...',
      defenseTitle: 'Mekanisme Anti-Prompt Injection DevGuard',
      defense1Title: '1. Isolasi Data Mentah (Fencing Tags)',
      defense1DescBefore: 'Kode input pengguna diapit oleh tag pembatas khusus',
      defense1DescAfter:
        '. Sistem mendeklarasikan secara absolut bahwa isi di dalam tag adalah data mentah tanpa wewenang perintah.',
      defense2Title: '2. Rubrik Pengurangan Skor Tetap',
      defense2Desc:
        'Skor tidak dinilai secara subjektif atau generik. Setiap pelanggaran memiliki penalti pasti (misal: Injeksi SQL = -40, Rusak Saldo/Race Condition = -40/-25).',
      defense3Title: '3. Aturan Kejujuran Baris Nyata',
      defense3Desc:
        'Reviewer dilarang mengarang temuan dan wajib menunjuk nomor baris yang konkret. Tidak ada klaim "sudah dites" di dalam review; sebaliknya pengguna diberikan skenario uji.',
      sandboxTitle: 'Uji Coba Ketahanan Injeksi Prompt',
      sandboxDesc:
        'Coba masukkan perintah manipulatif ke dalam kode junior untuk membuktikan DevGuard tetap memberikan penalti tanpa goyah:',
      payload1Label: 'Uji Payload 1:',
      payload2Label: 'Uji Payload 2:',
    },
    files: {
      artifactsTitle: 'DevGuard Open-Source Project Artifacts',
      cliQuickstartTitle: 'CLI Quickstart Commands',
      selectFileFallback: 'Pilih Berkas',
      copiedExcl: 'Disalin!',
      copyContent: 'Salin Isi',
      download: 'Unduh',
      noFileSelected: 'Tidak ada berkas yang dipilih.',
    },
  },
};

const RULE_TITLES_BY_LOCALE: Record<Locale, Record<string, string>> = {
  en: {
    DG001: 'Security or Logic Flaw',
    DG002: 'Defense-in-Depth Hardening',
    DG003: 'Score Below Threshold',
    DG004: 'Supply-Chain / Undeclared Package',
    'DG004-DYN-01': 'Dynamic import() Specifier',
    'DG004-DYN-02': 'Dynamic require() Specifier',
    'DG004-WS-NEW': 'New Workspace Package in PR',
    'DG004-WS-UNPARSED': 'Unparseable Workspace Config',
    'DG004-WS-SHALLOW': 'Shallow Clone Base Ref',
    DG005: 'Swallowed Exception',
    DG006: 'Non-Atomic State Mutation (TOCTOU)',
    DG007: 'Hardcoded Secret or Credential',
    DG008: 'Missing Timeout or Unbounded Async Loop',
  },
  id: {
    DG001: 'Celah Keamanan atau Logika',
    DG002: 'Penguatan Defense-in-Depth',
    DG003: 'Skor di Bawah Ambang Batas',
    DG004: 'Rantai Pasok / Paket Tidak Terdaftar',
    'DG004-DYN-01': 'Spesifier import() Dinamis',
    'DG004-DYN-02': 'Spesifier require() Dinamis',
    'DG004-WS-NEW': 'Paket Workspace Baru di PR',
    'DG004-WS-UNPARSED': 'Konfigurasi Workspace Gagal Di-parse',
    'DG004-WS-SHALLOW': 'Base Ref Shallow Clone',
    DG005: 'Pengecualian Ditelan (Swallowed Exception)',
    DG006: 'Mutasi Status Non-Atomik (TOCTOU)',
    DG007: 'Rahasia atau Kredensial Hardcoded',
    DG008: 'Tanpa Timeout atau Loop Async Tak Terbatas',
  },
};

const DEFAULT_FINDING_FALLBACK: Record<Locale, Record<string, string>> = {
  en: {
    DG001: 'Critical security vulnerability or exploitable logic flaw detected.',
    DG002: 'Defense-in-Depth architectural hardening recommendation.',
    DG003: 'Overall score fell below the required quality gate threshold.',
    DG004: 'Undeclared or potentially typosquatted package dependency detected.',
    DG005: 'Empty or log-only catch block swallows exceptions in a critical flow.',
    DG006: 'Non-atomic check-then-act state mutation across an await boundary (TOCTOU).',
    DG007: 'Hardcoded secret or API credential detected in source code.',
    DG008: 'External network call lacks AbortSignal.timeout() or async loop is unbounded.',
  },
  id: {
    DG001: 'Ditemukan celah keamanan kritis atau kesalahan logika yang dapat dieksploitasi.',
    DG002: 'Rekomendasi penguatan arsitektur Defense-in-Depth.',
    DG003: 'Skor keseluruhan berada di bawah ambang batas minimum quality gate.',
    DG004: 'Terdeteksi dependensi paket tidak terdaftar atau berpotensi typosquatting.',
    DG005: 'Blok catch kosong atau hanya logging menelan pengecualian pada alur kritis.',
    DG006: 'Mutasi status check-then-act tidak atomik melintasi batas await (TOCTOU).',
    DG007: 'Terdeteksi rahasia atau kredensial API hardcoded di dalam kode sumber.',
    DG008: 'Pemanggilan jaringan eksternal tanpa AbortSignal.timeout() atau loop async tak terbatas.',
  },
};

const INDONESIAN_HINT_RE =
  /\b(?:pada baris|baris \d+|tidak terdaftar|tertanam secara|mempercayai parameter|konkatenasi|celah|ditemukan|disarankan|gunakan|pastikan|tanpa sanitasi|blok catch|kunci rahasia|pembatasan laju|bekukan katalog|muat|tambahkan|periksa|arsitektur|ekstrak|otentikasi|pencabutan|menyatukan|pemanggilan|transaksi|pencatatan|pengunduhan|kuantitas|katalog|kerangka|masukan|saran|kebijakan)\b/i;

const ENGLISH_HINT_RE =
  /\b(?:line \d+|hardcoded|vulnerability|detected|recommendation|recommend|enforce|validate|verify|ensure|missing|swallowed|untrusted|parameterized|remediation|bypass|allowlist|defense-in-depth|token revocation|middleware architecture|rate limiting)\b/i;

export function getLocalizedRuleTitle(ruleId: string, locale: Locale): string {
  return RULE_TITLES_BY_LOCALE[locale][ruleId] ?? ruleId;
}

export function localizeFindingMessage(
  ruleId: string,
  message: string,
  line: number,
  locale: Locale
): string {
  const trimmed = message.trim();
  if (!trimmed) {
    return DEFAULT_FINDING_FALLBACK[locale][ruleId] ?? '';
  }

  const clean = trimmed
    .replace(/^\[(?:Defense-in-Depth|Baris \d+|Line \d+)\]\s*/i, '')
    .trim();

  if (locale === 'en') {
    // 1. Advisory & Defense-in-Depth findings
    if (/Token Revocation|Redis revocation|logout paksa|jti \(JWT ID\)/i.test(clean)) {
      return 'Defense-in-Depth (Token Revocation): Add a jti (JWT ID) claim and verify against a Redis revocation list to support emergency token revocation and forced logout.';
    }
    if (/Arsitektur Middleware|Middleware Architecture|requireAuth|middleware autentikasi/i.test(clean)) {
      return 'Middleware Architecture: Extract JWT verification logic into a dedicated authentication middleware (requireAuth) so the controller focuses on core business logic.';
    }
    if (/Rate Limiting.*(?:express-rate-limit|enumerasi token|billing)|express-rate-limit|enumerasi token/i.test(clean)) {
      return 'Rate Limiting: Enforce express-rate-limit on /api/users/:id/billing route group to prevent token enumeration and brute-force attempts.';
    }
    if (/Database Isolation|WAL mode|isolation level.*SERIALIZABLE|BEGIN IMMEDIATE/i.test(clean)) {
      return 'Production Hardening (Database Isolation): Ensure production SQLite/PostgreSQL connections use WAL mode and SERIALIZABLE / BEGIN IMMEDIATE isolation.';
    }
    if (/Observabilitas & Audit Trail|structured audit logger|audit trail/i.test(clean)) {
      return 'Observability & Audit Trail: Add a structured JSON audit logger for every point transfer success or rejection to detect brute-force anomalies.';
    }
    if (/Batas Plafon Transaksi|MAX_TRANSFER_AMOUNT|Transaction Cap/i.test(clean)) {
      return 'Transaction Cap: Add a MAX_TRANSFER_AMOUNT constant to prevent extreme balance drainage in a single function call.';
    }
    if (/Portabilitas Lintas Platform|Cross-Platform Portability|sys\.platform/i.test(clean)) {
      return 'Cross-Platform Portability: Use sys.platform to adaptively choose the "-n" flag (Windows) or "-c" flag (Linux/macOS).';
    }
    if (/Pembatasan Konkurensi|Concurrency Throttling|semaphore/i.test(clean)) {
      return 'Concurrency Throttling (Semaphore): Limit simultaneous ping subprocesses using a semaphore or worker pool to maintain server CPU stability.';
    }
    if (/Manajemen Memori|Streaming I\/O|createReadStream/i.test(clean)) {
      return 'Memory Management (Streaming I/O): Use fs.createReadStream(realTarget).pipe(res) to stream large report files without exhausting the V8 heap.';
    }
    if (/Allowlist Ekstensi Ketat|Strict Extension Allowlist|ekstensi dokumen/i.test(clean)) {
      return 'Strict Extension Allowlist: Restrict downloads strictly to official document extensions (e.g. /^[a-zA-Z0-9_-]+\\.(pdf|csv|txt)$/).';
    }
    if (/Anti-Coupon Replay|voucher.*database/i.test(clean)) {
      return 'Anti-Coupon Replay: Integrate a database-backed voucher validation service with single-use claims per user ID.';
    }
    if (/Injeksi Dependensi Katalog|Catalog Dependency Injection|repositori katalog/i.test(clean)) {
      return 'Catalog Dependency Injection: Accept price catalog repository as an injected parameter/service for testability and dynamic updates.';
    }
    if (/Kontrak Input Ketat|Strict Input Contracts/i.test(clean)) {
      return 'Defense-in-Depth — Strict Input Contracts: Always validate parameter types, numeric ranges, and maximum lengths at function entry.';
    }
    if (/Penanganan Kesalahan Defensif|Defensive Error Handling/i.test(clean)) {
      return 'Defense-in-Depth — Defensive Error Handling: Catch external failures explicitly and return safe errors without leaking stack traces.';
    }

    // 2. Secondary & granular audit deduction findings
    if (/Endpoint sensitif belum dilengkapi rate-limiting|pembatasan laju request.*JTI blacklist/i.test(clean)) {
      return 'Sensitive billing endpoint lacks request rate-limiting middleware and token revocation list (JTI denylist) verification.';
    }
    if (/findByUserId sinkron|layanan data dilakukan secara sinkron/i.test(clean)) {
      return 'Data service call is synchronous inside route handler; use async/await for production database I/O.';
    }
    if (/verifikasi token sebaiknya diekstrak|Menyatukan ekstraksi Bearer token/i.test(clean)) {
      return 'Combining Bearer token extraction and jwt.verify inside the controller makes authentication difficult to reuse; extract into dedicated middleware.';
    }
    if (/Transaksi SQLite default \(DEFERRED\)|transaksi DEFERRED/i.test(clean)) {
      return 'Default SQLite context manager uses DEFERRED transactions; in high-concurrency systems, execute BEGIN IMMEDIATE explicitly.';
    }
    if (/Belum ada batas maksimum nominal per transaksi|batas plafon maksimum per transaksi/i.test(clean)) {
      return 'Lacks an upper-bound transaction cap (e.g. <= 1,000,000 points) to limit compromised account blast radius.';
    }
    if (/structured audit trail.*mutasi saldo|jejak audit terstruktur.*log imutabel/i.test(clean)) {
      return 'Financial balance mutations lack structured audit logging (timestamp, actor, target, delta) to an immutable log store.';
    }
    if (/Utilitas jaringan publik memerlukan pembatasan kuota|diagnostik ICMP.*rate-limiting/i.test(clean)) {
      return 'Public ICMP diagnostic utilities require caller rate-limiting to prevent traffic flooding abuse.';
    }
    if (/Argumen "-c 2" spesifik POSIX\/Linux|spesifik sistem operasi keluarga Unix\/Linux/i.test(clean)) {
      return 'Command line flag "-c" is specific to Unix/Linux systems and will fail on Windows kernels (requires "-n").';
    }
    if (/batas waktu dan jumlah paket sebaiknya diekstrak|Angka jumlah paket \("2"\)/i.test(clean)) {
      return 'Packet count and timeout values should be extracted into configurable constants.';
    }
    if (/log audit pengunduhan dokumen|Content-Disposition eksplisit/i.test(clean)) {
      return 'Recommend adding explicit Content-Disposition headers and structured file access audit logs.';
    }
    if (/Membaca keseluruhan isi berkas ke memori|lonjakan pemakaian RAM/i.test(clean)) {
      return 'Reading entire files into memory risks V8 heap exhaustion and high RAM spikes for large reports.';
    }
    if (/belum membatasi ekstensi berkas yang diizinkan/i.test(clean)) {
      return 'Endpoint validates directory containment, but does not strictly restrict permitted file extensions via an allowlist.';
    }
    if (/Katalog harga & kode voucher masih didefinisikan inline|Menyimpan daftar harga.*inline/i.test(clean)) {
      return 'Defining price catalogs and discount rules inline makes dynamic price updates difficult without code redeployment.';
    }
    if (/Kode kupon diperiksa secara statis|kuota penggunaan per akun/i.test(clean)) {
      return 'Coupon codes are checked statically without validating per-account usage quotas or single-use sessions in a database.';
    }
    if (/disarankan menggunakan tipe BigInt|satuan terkecil mata uang/i.test(clean)) {
      return 'For production payment systems involving tax or percentage discounts, consider using BigInt or minor currency units.';
    }
    if (/anotasi tipe statis dan pencatatan log terstruktur|Belum dilengkapi structured logging dan anotasi tipe/i.test(clean)) {
      return 'Recommend adding static type annotations and structured logging for long-term maintainability.';
    }
    if (/Masukan fungsi diproses tanpa pemeriksaan tipe data|batas ukuran payload secara defensif/i.test(clean)) {
      return 'Function input is processed without defensive type checking or payload size boundaries.';
    }
    if (/Kode belum mengantisipasi kegagalan runtime|masukan bernilai null\/undefined\/kosong/i.test(clean)) {
      return 'Code does not anticipate runtime failures or null/undefined/empty input values.';
    }
    if (/Fungsi belum mengimplementasikan logika bisnis|kerangka kosong \('pass'\)/i.test(clean)) {
      return 'Function is an empty skeleton lacking business logic, input validation contracts, and return values.';
    }
    if (/Mengirimkan err\.message mentah/i.test(clean)) {
      return `Sending raw err.message to client responses on line ${line} can leak internal filesystem paths or database schemas.`;
    }
    if (/Penggunaan tipe ': any'/i.test(clean)) {
      return `Line ${line}: use of ': any' violates strict TypeScript guidelines and hides object shape mismatches at compile time.`;
    }
    if (/Pencetakan header Authorization mentah/i.test(clean)) {
      return `Logging raw Authorization header to stdout/logs on line ${line} risks leaking active tokens into log aggregators.`;
    }
    if (/Pemanggilan jwt\.verify\(\) pada baris.*algoritma|Algorithm Confusion Attack/i.test(clean)) {
      return `jwt.verify() call on line ${line} does not explicitly specify an algorithm whitelist ({ algorithms: ['HS256'] }), risking Algorithm Confusion Attacks.`;
    }
    if (/Tidak ada penanganan status 404 Not Found/i.test(clean)) {
      return 'Missing 404 Not Found status handling when the user ID has no billing record.';
    }
    if (/Kredensial rahasia dan logika otentikasi dicampur/i.test(clean)) {
      return 'Secret credentials and authentication logic are mixed directly inside the route handler definition.';
    }
    if (/Panggilan subprocess\.run tanpa parameter 'timeout='/i.test(clean)) {
      return `subprocess.run() call on line ${line} lacks a 'timeout=' parameter, risking worker hangs and denial of service.`;
    }
    if (/Risiko zombie\/hanging process/i.test(clean)) {
      return `Risk of hanging/zombie subprocesses on line ${line} due to missing execution timeout and TimeoutExpired handling.`;
    }
    if (/Tanpa pemblokiran IP privat\/loopback|SSRF recon/i.test(clean)) {
      return `Lacks private and loopback IP blocking (127.0.0.1 / 169.254.x.x) on line ${line}, exposing internal network scanning (SSRF reconnaissance).`;
    }
    if (/filePath\.startsWith\(safeBaseDir\)|partial-prefix bypass/i.test(clean)) {
      return `Line ${line}: filePath.startsWith(safeBaseDir) is vulnerable to partial-prefix directory bypass; use path.relative(safeBaseDir, candidatePath).`;
    }
    if (/Resolusi path leksikal.*realpath\(\)/i.test(clean)) {
      return `Lexical path resolution on line ${line} does not verify physical disk location via realpath(), allowing symlinks to escape safe directories.`;
    }
    if (/Penggunaan fungsi sinkron.*event loop/i.test(clean)) {
      return `Synchronous fs operations on line ${line} block the Node.js event loop and introduce TOCTOU race conditions between existsSync and readFileSync.`;
    }
    if (/Manipulasi Harga Klien & Kuantitas Negatif|membiarkan kuantitas minus/i.test(clean)) {
      return `Price calculation on line ${line} allows negative quantities and unbounded discount deductions without a zero floor.`;
    }
    if (/kuantitas tidak dibatasi nilai maksimum|Number\.isSafeInteger/i.test(clean)) {
      return `Line ${line}: item quantity lacks safe upper bound (<= 1000) and Number.isSafeInteger checks, risking IEEE-754 overflow.`;
    }
    if (/Ketiadaan batas atas jumlah item memungkinkan serangan resource/i.test(clean)) {
      return 'Lack of upper limits on item quantities enables resource and inventory exhaustion attacks.';
    }
    if (/Unhandled TypeError jika fetchone\(\)|fetchone\(\) mengembalikan None/i.test(clean)) {
      return `Unhandled TypeError crash on line ${line}: direct index [0] access on fetchone() when the username is not found in database.`;
    }
    if (/Satu fungsi mencampur validasi, query mentah, dan mutasi/i.test(clean)) {
      return `Line ${line}: single function mixes input validation, raw SQL query assembly, and balance mutation without separation of concerns.`;
    }
    if (/Tidak dilengkapi struktur penanganan exception dan unit test/i.test(clean)) {
      return `Line ${line}: lacks standardized exception handling contracts and automated unit test coverage.`;
    }

    // 3. Blocking findings
    const segments: string[] = [];
    if (/JWT_SECRET/i.test(clean) && /hardcoded|rahasia tertanam/i.test(clean)) {
      segments.push(
        `Production secret JWT_SECRET is hardcoded in source (line ${line}), risking credential exposure via Git history.`
      );
    }
    if (/req\.params\.id/i.test(clean) && /JWT|pemilik|IDOR/i.test(clean)) {
      segments.push(
        'Billing endpoint trusts req.params.id without verifying caller ownership against the verified JWT payload (IDOR / BOLA).'
      );
    }
    if (/Injeksi SQL/i.test(clean) && /konkatenasi/i.test(clean)) {
      segments.push(
        `Fatal SQL injection on line ${line} caused by concatenating untrusted input directly into a SQL query string without parameter binding ('?').`
      );
    }
    if (/TOCTOU/i.test(clean) && /SELECT|UPDATE|saldo|mutasi/i.test(clean)) {
      segments.push(
        `Time-of-Check to Time-of-Use (TOCTOU) race condition on line ${line}: reading state before mutating it without an atomic conditional update or transaction allows double-spending.`
      );
    }
    if (/Konkatenasi string perintah|Injeksi Perintah Sistem/i.test(clean) || /os\.system|command injection/i.test(clean)) {
      segments.push(
        `Unsanitized command string concatenation on line ${line} enables OS command injection; validate input strictly and invoke subprocesses with shell=False.`
      );
    }
    if (/Path Traversal/i.test(clean) && /direktori|penggabungan path|path\.basename/i.test(clean)) {
      segments.push(
        `Path traversal on line ${line}: untrusted filename joined directly into a filesystem path without path.basename() and canonical directory-boundary verification.`
      );
    }
    if (/item\.price|manipulasi harga|kuantitas negatif|total negatif/i.test(clean)) {
      segments.push(
        `Business-logic price tampering on line ${line}: trusts client-supplied prices or unvalidated negative/overflow quantities without server-side catalog lookup and bounds checks.`
      );
    }
    if (/eksekusi kode\/perintah dinamis/i.test(clean)) {
      segments.push(
        `Dynamic code or command execution sink detected on line ${line}, exposing Remote Code Execution (RCE) / Command Injection.`
      );
    }
    if (/Phantom dependency/i.test(clean)) {
      const pkgMatch = clean.match(/'([^']+)'/);
      const pkgName = pkgMatch ? `'${pkgMatch[1]}'` : 'package';
      segments.push(
        `Phantom dependency ${pkgName} imported on line ${line} is not declared in package.json.`
      );
    }
    if (/Typosquat|slopsquat/i.test(clean) && INDONESIAN_HINT_RE.test(clean)) {
      segments.push(
        `Suspected typosquatted or hallucinated package import detected on line ${line}; verify package spelling and declaration in package.json.`
      );
    }
    if (/Swallowed exception/i.test(clean) || /blok catch kosong/i.test(clean)) {
      segments.push(
        `Swallowed exception in critical flow on line ${line}: empty or log-only catch block hides failures without rethrowing, rolling back, or returning an explicit error.`
      );
    }
    if (/AbortSignal\.timeout/i.test(clean) && INDONESIAN_HINT_RE.test(clean)) {
      segments.push(
        `External fetch() call on line ${line} omits AbortSignal.timeout(), risking indefinitely hung requests.`
      );
    }

    if (segments.length > 0) {
      return segments.join(' ');
    }

    if (INDONESIAN_HINT_RE.test(clean)) {
      return DEFAULT_FINDING_FALLBACK.en[ruleId] ?? clean;
    }

    return clean;
  }

  // locale === 'id'
  // 1. Advisory & Defense-in-Depth findings
  if (/Token Revocation|Redis revocation|logout paksa|jti/i.test(clean)) {
    return 'Defense-in-Depth (Token Revocation): Tambahkan klaim jti (JWT ID) dan periksa terhadap Redis revocation list untuk mendukung fitur logout paksa.';
  }
  if (/Arsitektur Middleware|Middleware Architecture|requireAuth|middleware autentikasi/i.test(clean)) {
    return 'Arsitektur Middleware: Ekstrak logika verifikasi JWT ke middleware autentikasi khusus (requireAuth) agar controller fokus pada logika bisnis.';
  }
  if (/Rate Limiting.*(?:express-rate-limit|enumerasi token|billing)|express-rate-limit|enumerasi token/i.test(clean)) {
    return 'Rate Limiting: Pasang express-rate-limit pada grup rute /api/users/:id/billing untuk mencegah enumerasi token.';
  }
  if (/Database Isolation|WAL mode|isolation level.*SERIALIZABLE|BEGIN IMMEDIATE/i.test(clean)) {
    return 'Hardening Produksi (Database Isolation): Pastikan koneksi SQLite/PostgreSQL produksi dikonfigurasi dengan WAL mode dan isolation level SERIALIZABLE / BEGIN IMMEDIATE.';
  }
  if (/Observabilitas & Audit Trail|structured audit logger|audit trail/i.test(clean)) {
    return 'Observabilitas & Audit Trail: Tambahkan structured audit logger (JSON) setiap kali transfer poin berhasil maupun ditolak untuk deteksi anomali brute-force.';
  }
  if (/Batas Plafon Transaksi|MAX_TRANSFER_AMOUNT|Transaction Cap/i.test(clean)) {
    return 'Batas Plafon Transaksi: Tambahkan konstanta MAX_TRANSFER_AMOUNT untuk mencegah pengurasan saldo ekstrem dalam satu panggilan fungsi.';
  }
  if (/Portabilitas Lintas Platform|Cross-Platform Portability|sys\.platform/i.test(clean)) {
    return 'Portabilitas Lintas Platform: Gunakan sys.platform untuk memilih flag "-n" (Windows) atau "-c" (Linux/macOS) secara adaptif.';
  }
  if (/Pembatasan Konkurensi|Concurrency Throttling|semaphore/i.test(clean)) {
    return 'Pembatasan Konkurensi (Semaphore): Batasi jumlah subproses ping simultan menggunakan semaphore/worker pool untuk menjaga stabilitas CPU server.';
  }
  if (/Manajemen Memori|Streaming I\/O|createReadStream/i.test(clean)) {
    return 'Manajemen Memori (Streaming I/O): Gunakan fs.createReadStream(realTarget).pipe(res) untuk melayani berkas laporan berukuran besar tanpa membebani heap V8.';
  }
  if (/Allowlist Ekstensi Ketat|Strict Extension Allowlist|ekstensi dokumen/i.test(clean)) {
    return 'Allowlist Ekstensi Ketat: Batasi pengunduhan hanya untuk ekstensi dokumen resmi (misal /^[a-zA-Z0-9_-]+\\.(pdf|csv|txt)$/).';
  }
  if (/Anti-Coupon Replay|voucher.*database/i.test(clean)) {
    return 'Anti-Coupon Replay: Integrasikan layanan validasi voucher berbasis database dengan klaim satu-kali-pakai per user ID.';
  }
  if (/Injeksi Dependensi Katalog|Catalog Dependency Injection|repositori katalog/i.test(clean)) {
    return 'Injeksi Dependensi Katalog: Terima repositori katalog harga sebagai parameter/service agar mudah diuji dan diperbarui secara real-time.';
  }
  if (/Kontrak Input Ketat|Strict Input Contracts/i.test(clean)) {
    return 'Kontrak Input Ketat: Selalu validasi tipe, rentang nilai, dan panjang maksimum parameter di baris pertama fungsi.';
  }
  if (/Penanganan Kesalahan Defensif|Defensive Error Handling/i.test(clean)) {
    return 'Penanganan Kesalahan Defensif: Pastikan seluruh kegagalan eksternal ditangkap dan dikembalikan sebagai pesan kesalahan yang aman tanpa membocorkan stack trace.';
  }

  // 2. Secondary & granular audit deduction findings
  if (/Endpoint sensitif belum dilengkapi rate-limiting|sensitive billing endpoint lacks/i.test(clean)) {
    return 'Endpoint sensitif belum dilengkapi rate-limiting middleware & verifikasi JTI revocation list.';
  }
  if (/findByUserId sinkron|synchronous inside route handler/i.test(clean)) {
    return 'Pemanggilan layanan data dilakukan secara sinkron; gunakan async/await untuk operasi database produksi.';
  }
  if (/verifikasi token sebaiknya diekstrak|difficult to reuse across endpoints/i.test(clean)) {
    return 'Logika verifikasi token sebaiknya diekstrak menjadi Express middleware terpisah agar mudah digunakan ulang.';
  }
  if (/Transaksi SQLite default \(DEFERRED\)|uses DEFERRED transactions/i.test(clean)) {
    return 'Transaksi SQLite default (DEFERRED); gunakan BEGIN IMMEDIATE untuk beban konkuren tinggi.';
  }
  if (/Belum ada batas maksimum nominal per transaksi|lacks an upper-bound transaction cap/i.test(clean)) {
    return 'Belum ada batas maksimum nominal per transaksi (upper-bound cap) & rate limiting.';
  }
  if (/structured audit trail.*mutasi saldo|balance mutations lack structured audit logging/i.test(clean)) {
    return 'Belum ada pencatatan structured audit trail (logging) pada mutasi saldo finansial.';
  }
  if (/Utilitas jaringan publik memerlukan pembatasan kuota|public icmp diagnostic utilities require/i.test(clean)) {
    return 'Utilitas jaringan publik memerlukan pembatasan kuota/rate-limiting per pemanggil.';
  }
  if (/Argumen "-c 2" spesifik POSIX\/Linux|specific to Unix\/Linux systems/i.test(clean)) {
    return 'Argumen "-c 2" spesifik POSIX/Linux; pada host Windows memerlukan flag "-n 2".';
  }
  if (/batas waktu dan jumlah paket sebaiknya diekstrak|packet count and timeout values should be extracted/i.test(clean)) {
    return 'Nilai batas waktu dan jumlah paket sebaiknya diekstrak menjadi konstanta konfigurasi.';
  }
  if (/log audit pengunduhan dokumen|adding explicit Content-Disposition/i.test(clean)) {
    return 'Disarankan menambahkan header Content-Disposition eksplisit dan pencatatan audit akses berkas.';
  }
  if (/Membaca keseluruhan isi berkas ke memori|reading entire files into memory/i.test(clean)) {
    return 'Membaca keseluruhan isi berkas ke memori aplikasi berisiko memicu lonjakan pemakaian RAM jika ukuran laporan sangat besar.';
  }
  if (/belum membatasi ekstensi berkas yang diizinkan|does not strictly restrict permitted file extensions/i.test(clean)) {
    return 'Endpoint memvalidasi batas direktori dengan kuat, namun belum membatasi ekstensi berkas yang diizinkan secara ketat melalui allowlist.';
  }
  if (/Katalog harga & kode voucher masih didefinisikan inline|defining price catalogs and discount rules inline/i.test(clean)) {
    return 'Katalog harga & kode voucher masih didefinisikan inline alih-alih diinjeksi dari repositori.';
  }
  if (/Kode kupon diperiksa secara statis|coupon codes are checked statically/i.test(clean)) {
    return 'Kode kupon diperiksa secara statis tanpa memvalidasi kuota penggunaan per akun atau sesi sekali-pakai di database.';
  }
  if (/disarankan menggunakan tipe BigInt|consider using BigInt/i.test(clean)) {
    return 'Untuk sistem pembayaran produksi yang melibatkan diskon, disarankan menggunakan tipe BigInt atau satuan terkecil mata uang.';
  }
  if (/anotasi tipe statis dan pencatatan log terstruktur|adding static type annotations/i.test(clean)) {
    return 'Disarankan menambahkan anotasi tipe statis dan pencatatan log terstruktur untuk kemudahan pemeliharaan.';
  }
  if (/Masukan fungsi diproses tanpa pemeriksaan tipe data|processed without defensive type checking/i.test(clean)) {
    return 'Masukan fungsi diproses tanpa pemeriksaan tipe data atau batas ukuran payload secara defensif.';
  }
  if (/Kode belum mengantisipasi kegagalan runtime|does not anticipate runtime failures/i.test(clean)) {
    return 'Kode belum mengantisipasi kegagalan runtime atau masukan bernilai null/undefined/kosong.';
  }
  if (/Fungsi belum mengimplementasikan logika bisnis|empty skeleton lacking business logic/i.test(clean)) {
    return 'Fungsi pada kode masih berupa kerangka kosong tanpa validasi kontrak input maupun implementasi logika bisnis.';
  }
  if (/Mengirimkan err\.message mentah|sending raw err\.message/i.test(clean)) {
    return `Mengirimkan err.message mentah ke respons klien pada baris ${line} dapat membocorkan struktur path atau skema database internal.`;
  }
  if (/Penggunaan tipe ': any'|violates strict TypeScript/i.test(clean)) {
    return `Penggunaan tipe ': any' pada baris ${line} melanggar aturan strict TypeScript dan menyembunyikan potensi kesalahan saat kompilasi.`;
  }
  if (/Pencetakan header Authorization mentah|logging raw Authorization header/i.test(clean)) {
    return `Pencetakan header Authorization mentah ke stdout/log pada baris ${line} berisiko membocorkan token aktif ke sistem agregasi log.`;
  }
  if (/Pemanggilan jwt\.verify\(\) pada baris.*algoritma|algorithm whitelist/i.test(clean)) {
    return `Pemanggilan jwt.verify() pada baris ${line} tidak menentukan daftar putih algoritma secara eksplisit ({ algorithms: ['HS256'] }), membuka risiko Algorithm Confusion Attack.`;
  }
  if (/Tidak ada penanganan status 404 Not Found|missing 404 not found/i.test(clean)) {
    return 'Tidak ada penanganan status 404 Not Found ketika ID pengguna tidak memiliki rekaman tagihan.';
  }
  if (/Kredensial rahasia dan logika otentikasi dicampur|credentials and authentication logic are mixed/i.test(clean)) {
    return 'Kredensial rahasia dan logika otentikasi dicampur langsung di dalam definisi route handler.';
  }
  if (/Panggilan subprocess\.run tanpa parameter 'timeout='|lacks a 'timeout=' parameter/i.test(clean)) {
    return `Panggilan subprocess.run pada baris ${line} tanpa parameter 'timeout=' berisiko DoS worker hang.`;
  }
  if (/Risiko zombie\/hanging process|risk of hanging\/zombie/i.test(clean)) {
    return `Risiko zombie/hanging process pada baris ${line} akibat ketiadaan batas waktu subprocess.`;
  }
  if (/Tanpa pemblokiran IP privat\/loopback|lacks private and loopback IP blocking/i.test(clean)) {
    return `Tanpa pemblokiran IP privat/loopback pada baris ${line}, membuka celah pemindaian topologi internal (SSRF reconnaissance).`;
  }
  if (/filePath\.startsWith\(safeBaseDir\)|partial-prefix directory bypass/i.test(clean)) {
    return `Pada baris ${line}, pemeriksaan filePath.startsWith(safeBaseDir) rentan terhadap partial-prefix bypass. Gunakan path.relative(safeBaseDir, candidatePath).`;
  }
  if (/Resolusi path leksikal.*realpath\(\)|lexical path resolution/i.test(clean)) {
    return `Resolusi path leksikal pada baris ${line} belum memeriksa lokasi fisik berkas di disk menggunakan realpath().`;
  }
  if (/Penggunaan fungsi sinkron.*event loop|synchronous fs operations/i.test(clean)) {
    return `Penggunaan fungsi sinkron pada baris ${line} menghentikan event loop Node.js dan memicu race condition.`;
  }
  if (/Manipulasi Harga Klien & Kuantitas Negatif|allows negative quantities/i.test(clean)) {
    return `Kalkulasi harga pada baris ${line} membiarkan kuantitas minus serta pemotongan diskon tanpa batas bawah 0.`;
  }
  if (/kuantitas tidak dibatasi nilai maksimum|lacks safe upper bound/i.test(clean)) {
    return `Pada baris ${line}, kuantitas tidak dibatasi nilai maksimum dan tidak memeriksa Number.isSafeInteger, membuka risiko integer overflow.`;
  }
  if (/Ketiadaan batas atas jumlah item memungkinkan serangan resource|enables resource and inventory exhaustion/i.test(clean)) {
    return 'Ketiadaan batas atas jumlah item memungkinkan serangan resource/inventory exhaustion.';
  }
  if (/Unhandled TypeError jika fetchone\(\)|unhandled typeerror crash/i.test(clean)) {
    return `Crash TypeError unhandled pada baris ${line} karena langsung mengakses indeks [0] pada hasil fetchone() ketika username tidak terdaftar.`;
  }
  if (/Satu fungsi mencampur validasi, query mentah, dan mutasi|single function mixes input validation/i.test(clean)) {
    return `Baris ${line}: satu fungsi mencampur validasi, query mentah, dan mutasi saldo tanpa pemisahan tanggung jawab.`;
  }
  if (/Tidak dilengkapi struktur penanganan exception dan unit test|lacks standardized exception handling/i.test(clean)) {
    return `Baris ${line}: tidak dilengkapi struktur penanganan exception dan unit test otomatis.`;
  }

  // 3. Blocking findings
  if (/JWT_SECRET/i.test(clean) && /hardcoded/i.test(clean)) {
    return `Kunci rahasia produksi JWT_SECRET tertanam secara hardcoded di dalam kode sumber pada baris ${line}, berisiko bocor melalui repositori Git.`;
  }
  if (/req\.params\.id/i.test(clean) && /JWT|payload|IDOR|BOLA/i.test(clean)) {
    return `Endpoint penagihan mempercayai parameter req.params.id pada baris ${line} tanpa memverifikasi kecocokan identitas pemilik di dalam payload token JWT.`;
  }
  if (/SQL injection/i.test(clean)) {
    return `Injeksi SQL fatal pada baris ${line} akibat konkatenasi langsung parameter masukan ke dalam string query SQL tanpa parameter binding ('?').`;
  }
  if (/TOCTOU|race condition/i.test(clean) && /balance|state|mutation|atomic/i.test(clean)) {
    return `Celah Time-of-Check to Time-of-Use (TOCTOU) pada baris ${line}: membaca saldo dengan SELECT lalu menulisnya dengan UPDATE terpisah tanpa 'WHERE poin >= ?' atau 'BEGIN IMMEDIATE' memungkinkan double-spending.`;
  }
  if (/command injection|os\.system/i.test(clean)) {
    return `Injeksi Perintah Sistem (Command Injection) pada baris ${line} akibat mengeksekusi string perintah yang dirangkai dari masukan luar melalui shell sistem.`;
  }
  if (/path traversal/i.test(clean)) {
    return `Path Traversal & Manipulasi Direktori Berkas pada baris ${line} akibat penggabungan path secara langsung menggunakan parameter query tanpa sanitasi path.basename dan verifikasi batasan direktori.`;
  }
  if (/price tampering|negative quantity/i.test(clean)) {
    return `Manipulasi Harga Klien & Kuantitas Negatif pada baris ${line} akibat mempercayai atribut item.price dan item.quantity langsung dari payload klien.`;
  }
  if (/dynamic code execution|Remote Code Execution|RCE/i.test(clean)) {
    return `Ditemukan pemanggilan eksekusi kode/perintah dinamis pada baris ${line} yang membuka celah Remote Code Execution (RCE) / Command Injection.`;
  }
  if (/phantom dependency/i.test(clean)) {
    const pkgMatch = clean.match(/'([^']+)'/);
    const pkgName = pkgMatch ? `'${pkgMatch[1]}'` : 'paket';
    return `Dependensi phantom ${pkgName} yang diimpor pada baris ${line} tidak terdaftar di dalam package.json.`;
  }
  if (/typosquat|slopsquat/i.test(clean)) {
    return `Terdeteksi impor paket yang dicurigai typosquatted atau terhalusinasi pada baris ${line}; verifikasi ejaan nama paket di package.json.`;
  }
  if (/swallowed exception/i.test(clean)) {
    return `Blok catch kosong atau hanya logging menelan pengecualian pada alur kritis pada baris ${line}.`;
  }
  if (/AbortSignal\.timeout/i.test(clean)) {
    return `Pemanggilan fetch() eksternal pada baris ${line} tanpa AbortSignal.timeout(), berisiko request menggantung tanpa batas.`;
  }

  if (ENGLISH_HINT_RE.test(clean)) {
    return DEFAULT_FINDING_FALLBACK.id[ruleId] ?? clean;
  }

  return clean;
}

export function localizeRemediationSummary(summary: string, locale: Locale): string {
  const trimmed = summary.trim();
  if (!trimmed || locale === 'id') {
    return trimmed;
  }

  if (/type\(jumlah\) is not int/i.test(trimmed) || /WHERE username = \? AND poin >= \?/i.test(trimmed)) {
    return 'Enforce strict type(amount) is not int checks (blocking Python bool subclasses), use parameterized "?" queries, and execute an atomic conditional UPDATE (WHERE username = ? AND poin >= ?) to eliminate SQL injection and TOCTOU race conditions.';
  }
  if (/JWT_SECRET/i.test(trimmed) && /HS256/i.test(trimmed)) {
    return 'Load JWT_SECRET from environment variables (min 32 chars), enforce strict Request/Response/JwtPayload types (no any), pin algorithms: ["HS256"] in jwt.verify, and verify String(payload.userId) === String(req.params.id).';
  }
  if (/ipaddress\.ip_address/i.test(trimmed) && /shell=False/i.test(trimmed)) {
    return 'Validate IP addresses with ipaddress.ip_address(), reject private/loopback ranges (is_private / is_loopback) to prevent SSRF, and run subprocess.run with shell=False and timeout=5.';
  }
  if (/path\.basename/i.test(trimmed) && /realpath/i.test(trimmed)) {
    return 'Sanitize filenames with path.basename(), verify directory containment via path.relative(safeBaseDir, candidatePath) to block prefix collisions, resolve symlinks with fs.promises.realpath(), and read files asynchronously.';
  }
  if (/Object\.freeze/i.test(trimmed) && /Number\.isSafeInteger/i.test(trimmed)) {
    return 'Freeze the server-side price catalog with Object.freeze(), validate Number.isSafeInteger(item.quantity) within MAX_QUANTITY_PER_ITEM (<= 1000), guard against arithmetic overflow, and clamp the final total to >= 0.';
  }

  if (INDONESIAN_HINT_RE.test(trimmed)) {
    return 'Apply the hardened reference patch to remediate the detected security and correctness findings.';
  }

  return trimmed;
}

export function localizeNoticeMessage(code: string, message: string, locale: Locale): string {
  const trimmed = message.trim();
  if (locale === 'id') return trimmed;
  if (!INDONESIAN_HINT_RE.test(trimmed)) return trimmed;

  switch (code) {
    case 'DG004-DYN-01':
      return 'Non-scoring notice: dynamic import() uses a non-literal specifier that cannot be statically verified against package.json.';
    case 'DG004-DYN-02':
      return 'Non-scoring notice: dynamic require() uses a non-literal specifier that cannot be statically verified against package.json.';
    case 'DG004-WS-NEW':
      return 'Non-scoring notice: new workspace package added in PR; confirm it is intentional and not a supply-chain bypass.';
    case 'DG004-WS-UNPARSED':
      return 'Non-scoring notice: workspace configuration could not be parsed (fail-closed per source).';
    case 'DG004-WS-SHALLOW':
      return 'Non-scoring notice: base branch ref unavailable in shallow clone; workspace allowlist checks fell back safely.';
    default:
      return trimmed;
  }
}
