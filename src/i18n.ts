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
