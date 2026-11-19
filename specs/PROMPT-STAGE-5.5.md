# PROMPT IMPLEMENTASI — DevGuard v1.3.0 · Stage 5.5 (External OSS Repo Validation, Documentation, Version Bump v1.3.0 & Final Release Gate)

> Tempel seluruh isi berkas ini ke agen koding di root repo DevGuard setelah CI `main` (`5149ec8`) centang hijau.
> Sumber kebenaran: `specs/SPEC.md` (Rev 2.3) §1, §9, §10, §11.

---

## 0. Konteks & Tujuan

Seluruh fitur inti **DevGuard v1.3.0** (Stage 5.1-hardening, Stage 5.2 `DG004-DYN-01/02`, Stage 5.3a/b `SpanMap` + `FOLD-03/01/02/04` + Pass-V aditif, dan Stage 5.4 `DG008-EV-01` + `DG005-EV-01` + `CRITICAL_FLOW_IDENTIFIERS`) telah selesai dan tergabung ke `main` (`5149ec8`) dengan **75/75 tes lulus**.

Tugasmu di **Stage 5.5 (Stage Final Rilis `v1.3.0`)** adalah memenuhi seluruh kriteria rilis `SPEC.md` §9, §10, dan §11:
1. **External OSS Repo Validation (`SPEC.md` §9 butir 4 & §10):**
   - Menjalankan DevGuard secara langsung (CLI / analyzer offline tanpa network call) terhadap repositori OSS eksternal nyata (minimal 1–2 repo publik berukuran nyata atau clone dangkal sementara di direktori temp sistem di luar repo DevGuard, misalnya `sindresorhus/ky` atau `colinhacks/zod` atau `honojs/hono` — kemudian hapus folder temp tersebut setelah selesai) dan mencatat:
     - Jumlah file teranalisis, jumlah temuan per rule (`DG001`–`DG008`, `DG004-DYN-01/02`),
     - Validasi manual bahwa **0 false positive** muncul pada konstruksi sah (`FOLD-01..04`, `DG004-DYN`, `DG005-EV-01`, `DG008-EV-01`),
     - Validasi SARIF v2.1.0 yang dihasilkan valid 100%,
     - Bukti bahwa tidak ada satu pun file atau folder temp eksternal yang tertinggal di repo DevGuard (`git status --short` bersih).
2. **Pembaruan Dokumentasi (`README.md` & `CHANGELOG.md`) & Version Bump (`package.json` → `1.3.0`):**
   - Memperbarui versi di `package.json` dari `"1.2.1"` menjadi `"1.3.0"` (dan pastikan `Test 51` `getDevGuardVersion()` tetap lulus dinamis!).
   - Memperbarui `README.md` agar mendokumentasikan seluruh kemampuan baru `v1.3.0`:
     - `DG004-DYN-01` & `DG004-DYN-02` (deteksi non-literal `import()` / `require()`, sifat non-scoring `properties.scoring: false`, shadow guard `require`, dan kebijakan suppression allowlist-only via `.devguard.json`),
     - Lexical Constant Folding (`FOLD-01` string concat, `FOLD-02` `[...].join()`, `FOLD-03` no-interpolation template literal, `FOLD-04` bracket-to-dot member access), Pass-V aditif dengan tag `[via-fold]`, batas deterministik (`MAX_FOLD_DEPTH = 4`, `MAX_FOLD_OPERANDS = 64`, `MAX_FOLDED_LENGTH = 4096`, `MAX_FOLD_EDITS = 2000`, `MAX_BACKSCAN = 256`), dan notifikasi SARIF `fold_limit_exceeded`,
     - Varian evasion `DG008-EV-01` (`do { ... } while (true | 1)`) dan `DG005-EV-01` (`.catch(() => {})` pada alur kritikal),
     - Pembaruan tabel hasil benchmark korpus terbaru (129 kasus, 0 FP pada seluruh TN, serta overhead benchmark Pass-O vs Pass-O+V).
   - Membuat/memperbarui `CHANGELOG.md` dengan catatan rilis lengkap untuk **`[1.3.0]`**.
3. **Final Release Gate Audit (`SPEC.md` §9 & §11):**
   - Menjalankan seluruh pengecekan mekanis dan menyusun laporan bukti final `v1.3.0`.

---

## 1. Aturan Keras

1. **Pre-Flight Read-Only (D1–D4) wajib dicetak SEBELUM menyentuh kode/dokumen apa pun**, saat `git status --short` dan `git diff --stat` kosong.
2. **Kebersihan Repo:** Clone repo OSS eksternal untuk validasi wajib ditempatkan di `os.tmpdir()` (di luar direktori kerja `devguard`) dan dihapus tuntas setelah hasil audit dicatat. Jangan pernah men-commit kode eksternal ke repo `devguard`.
3. **Zero Dependency & Zero Regression:**
   - `"dependencies": {}` di `package.json` tetap kosong (`{}`).
   - Seluruh **75/75 tes** wajib tetap lulus tanpa menghapus satu pun baris tes lama (`ZERO_DELETED_TEST_LINES`).

---

## 2. Pre-Flight Read-Only (D1–D4)

Buat branch `stage-5.5-release-v130` dari `main` (`5149ec8`), commit `specs/PROMPT-STAGE-5.5.md`, lalu cetak tabel D1–D4 dengan bukti `path:baris`:
- **D1:** Di `package.json`, `package-lock.json` (jika ada), `action.yml`, dan `src/cli.ts` (`getDevGuardVersion`), di mana saja string versi `1.2.1` muncul saat ini dan apakah pembaruan `package.json` ke `"1.3.0"` otomatis tercermin pada CLI `--version` dan SARIF `tool.driver.version`?
- **D2:** Bagian mana saja di `README.md` yang perlu diperbarui agar konsisten 100% dengan fitur Stage 5.1-hardening hingga Stage 5.4 (termasuk aturan `DG004-DYN-01/02`, `[via-fold]`, `DG008-EV-01`, `DG005-EV-01`, dan angka benchmark korpus)?
- **D3:** Apakah `CHANGELOG.md` sudah ada di root repo atau perlu dibuat baru dengan mengikuti konvensi Keep a Changelog?
- **D4:** Bagaimana skenario eksekusi CLI DevGuard terhadap repo OSS eksternal di `os.tmpdir()` agar mengukur performa, SARIF validity, dan 0 FP pada pola v1.3.0 secara nyata?

Cetak tabel D1–D4, pastikan `git status --short` dan `git diff --stat` kosong, lalu tulis:
`PRE-FLIGHT STAGE 5.5 SELESAI — mulai implementasi.`

---

## 3. Spesifikasi Eksekusi Stage 5.5 (2 Commit Bersih)

### Commit 1 — External OSS Repo Validation Report & Release Documentation (`README.md`, `CHANGELOG.md`)
1. Jalankan validasi eksternal terhadap minimal 2 repositori OSS TypeScript/JavaScript populer (misalnya clone dangkal `--depth 1` di `os.tmpdir()` untuk `honojs/hono` dan `colinhacks/zod`, lalu hapus folder temp-nya setelah selesai). Catat metrik aktualnya (jumlah berkas, waktu eksekusi, jumlah temuan per rule, status SARIF, dan hasil inspeksi FP).
2. Perbarui `README.md` secara menyeluruh dan akurat sesuai `SPEC.md` Rev 2.3 (mencakup fitur v1.3.0, aturan suppression, batas pelipatan, hasil benchmark korpus 129 kasus, dan ringkasan validasi repo OSS eksternal).
3. Buat atau perbarui `CHANGELOG.md` dengan entri **`## [1.3.0]`** yang merangkum seluruh peningkatan dari Stage 5.1 hingga Stage 5.5.

### Commit 2 — Bump Versi ke `1.3.0` (`package.json`) & Verifikasi Release Gate Final
1. Perbarui `"version": "1.3.0"` di `package.json` (dan `package-lock.json` bila ada).
2. Jalankan `npm run lint`, `npm run build`, `npm test` (75/75 lulus), dan `node --experimental-strip-types src/cli.ts --version` (memastikan output menampilkan `1.3.0`).

---

## 4. Bukti Wajib Final Release Gate (`SPEC.md` §11)

Tampilkan output aktual **tanpa pemotongan (`head`/`tail` dilarang)**:
1. Hasil detail validasi pada minimal 2 repositori OSS eksternal nyata (nama repo, commit SHA, jumlah file, waktu eksekusi, rincian temuan, dan verifikasi 0 FP).
2. `npm run lint`
3. `npm run build`
4. `npm test` (wajib **75/75 lulus**, `0` gagal, `0` skipped)
5. Output `node --experimental-strip-types src/cli.ts --version` (`1.3.0`)
6. Pengecekan `"dependencies": {}` di `package.json` dan `ZERO_DELETED_TEST_LINES`
7. `git diff main...HEAD -- package.json README.md CHANGELOG.md` (utuh).