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
  /\b(?:pada baris|baris \d+|tidak terdaftar|tertanam secara|mempercayai parameter|konkatenasi|celah|ditemukan|disarankan|gunakan|pastikan|tanpa sanitasi|blok catch|kunci rahasia|pembatasan laju|bekukan katalog|muat )\b/i;

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
  if (locale === 'id') {
    return trimmed;
  }

  // Translate built-in Indonesian analyzer findings into concise technical English
  const segments: string[] = [];

  if (/JWT_SECRET/i.test(trimmed) && /hardcoded/i.test(trimmed)) {
    segments.push(
      `Production secret JWT_SECRET is hardcoded in source (line ${line}), risking credential exposure via Git history.`
    );
  }
  if (/req\.params\.id/i.test(trimmed) && /JWT|pemilik|IDOR/i.test(trimmed)) {
    segments.push(
      'Billing endpoint trusts req.params.id without verifying caller ownership against the verified JWT payload (IDOR / BOLA).'
    );
  }
  if (/Injeksi SQL/i.test(trimmed) && /konkatenasi/i.test(trimmed)) {
    segments.push(
      `Fatal SQL injection on line ${line} caused by concatenating untrusted input directly into a SQL query string without parameter binding ('?').`
    );
  }
  if (/TOCTOU/i.test(trimmed) && /SELECT|UPDATE|saldo|mutasi/i.test(trimmed)) {
    segments.push(
      `Time-of-Check to Time-of-Use (TOCTOU) race condition on line ${line}: reading state before mutating it without an atomic conditional update or transaction allows double-spending.`
    );
  }
  if (/Konkatenasi string perintah/i.test(trimmed) || /os\.system|command injection/i.test(trimmed)) {
    segments.push(
      `Unsanitized command string concatenation on line ${line} enables OS command injection; validate input strictly and invoke subprocesses with shell=False.`
    );
  }
  if (/Path Traversal/i.test(trimmed) && /direktori|penggabungan path|path\.basename/i.test(trimmed)) {
    segments.push(
      `Path traversal on line ${line}: untrusted filename joined directly into a filesystem path without path.basename() and canonical directory-boundary verification.`
    );
  }
  if (/item\.price|manipulasi harga|kuantitas negatif|total negatif/i.test(trimmed)) {
    segments.push(
      `Business-logic price tampering on line ${line}: trusts client-supplied prices or unvalidated negative/overflow quantities without server-side catalog lookup and bounds checks.`
    );
  }
  if (/eksekusi kode\/perintah dinamis/i.test(trimmed)) {
    segments.push(
      `Dynamic code or command execution sink detected on line ${line}, exposing Remote Code Execution (RCE) / Command Injection.`
    );
  }
  if (/Phantom dependency/i.test(trimmed)) {
    const pkgMatch = trimmed.match(/'([^']+)'/);
    const pkgName = pkgMatch ? `'${pkgMatch[1]}'` : 'package';
    segments.push(
      `Phantom dependency ${pkgName} imported on line ${line} is not declared in package.json.`
    );
  }
  if (/Typosquat|slopsquat/i.test(trimmed) && INDONESIAN_HINT_RE.test(trimmed)) {
    segments.push(
      `Suspected typosquatted or hallucinated package import detected on line ${line}; verify package spelling and declaration in package.json.`
    );
  }
  if (/Swallowed exception/i.test(trimmed) || /blok catch kosong/i.test(trimmed)) {
    segments.push(
      `Swallowed exception in critical flow on line ${line}: empty or log-only catch block hides failures without rethrowing, rolling back, or returning an explicit error.`
    );
  }
  if (/AbortSignal\.timeout/i.test(trimmed) && INDONESIAN_HINT_RE.test(trimmed)) {
    segments.push(
      `External fetch() call on line ${line} omits AbortSignal.timeout(), risking indefinitely hung requests.`
    );
  }
  if (/rate-limiting|JTI blacklist/i.test(trimmed) && INDONESIAN_HINT_RE.test(trimmed)) {
    segments.push(
      'Defense-in-Depth: add request rate-limiting and JWT token revocation checks (JTI denylist) on sensitive billing endpoints.'
    );
  }
  if (/Kontrak Input Ketat/i.test(trimmed)) {
    segments.push(
      'Defense-in-Depth — Strict Input Contracts: validate parameter types, numeric ranges, and maximum lengths at function entry.'
    );
  }
  if (/Penanganan Kesalahan Defensif/i.test(trimmed)) {
    segments.push(
      'Defense-in-Depth — Defensive Error Handling: catch external failures explicitly and return safe errors without leaking stack traces.'
    );
  }
  if (/anotasi tipe statis/i.test(trimmed)) {
    segments.push(
      `Line ${line}: add explicit static type annotations and structured logging to improve long-term maintainability.`
    );
  }

  if (segments.length > 0) {
    return segments.join(' ');
  }

  if (INDONESIAN_HINT_RE.test(trimmed)) {
    return DEFAULT_FINDING_FALLBACK.en[ruleId] ?? trimmed;
  }

  return trimmed;
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
