# PROMPT IMPLEMENTASI — DevGuard v1.3.0 · Stage 5.1-hardening (C1–C4, D12 Excluded Path Visibility, Self-Ref Anchoring, & R1–R3)

> Tempel seluruh isi berkas ini ke agen koding di root repo DevGuard.
> Branch kerja: `stage-5.1-fix` (HEAD `87927d8`). Jangan rewrite history; tambahkan commit baru di atasnya.

---

## 0. Konteks & Tujuan

Sebelum merge `stage-5.1-fix` ke `main` dan melakukan rebase `stage-5.2-dyn-specifier`, tutup empat syarat sebelum merge (**C1–C4**), dua celah pra-ada (**Basename Anchoring** & **D12 `excluded_path`**), serta tiga item residual (**R1–R3**):

| ID | Item | Solusi Wajib |
|---|---|---|
| **C4** | Duplikat spesifikasi `docs/specs/` vs `specs/` | Hapus direktori `docs/specs/` (`git rm -r docs/specs/`) dalam commit dokumentasi terpisah, dan perbarui `specs/SPEC.md` ke Rev 2.3 |
| **C2** | Klaim README menyebut `DG004–DG008` dilewati pada `.py`, padahal `DG007` tetap aktif (`if (!isPython)` di `devguardAnalyzer.ts:1314` hanya melewati `DG004`, `DG005`, `DG006`, `DG008`) | Perbarui `README.md` agar akurat 100%: `.py` menjalankan `DG001`, `DG002`, `DG007`, dan heuristik domain SQL/ping; yang dilewati adalah `DG004`, `DG005`, `DG006`, dan `DG008` |
| **C3** | Pembuktian golden `.py` masih membandingkan terhadap nilai statis di Test 40 | Jalankan perbandingan side-by-side langsung antara worktree `e67c869` (`v1.2.1`) dan `HEAD` pada 4 fixture `.py`, lalu diff `runs[0].results` dari kedua SARIF (harus identik 100%) |
| **G1** | Celah basename: `devguardAnalyzer.ts` dan `devguard_verify.py` dikecualikan di path mana pun (mis. `src/devguard_verify.py` di repo pengguna lolos tanpa diaudit) | Jangkar pengecualian *self-reference* hanya ke path repo-relatif eksak (`src/devguardAnalyzer.ts` dan `scripts/devguard_verify.py`) **DAN** hanya aktif bila `package.json` di `cwd` memiliki `name === "devguard"` |
| **G2 (D12)** | Celah direktori pada mode `modified` (`git diff`): file yang diubah di dalam `scripts/`, `build/`, `dist/`, `.github/`, `*.test.*`, dll. dibuang sebelum klasifikasi sehingga tidak terlihat di Coverage | Pada mode `modified` (`git diff`), jangan memfilter keluar path yang dikecualikan sebelum klasifier! Masukkan seluruh baris `git diff` ke klasifier dan petakan path yang ter-exclude (`isExcludedPathFromScope`) menjadi `status: 'ignored', reason: 'excluded_path'`. Tampilkan `- Ignored (excluded path): N` di blok Coverage PR comment bila `N > 0`. Untuk mode `all`, tetap kecualikan saat traversal direktori agar tidak menyusuri `node_modules` |
| **R1** | Jalur `exit 1` awal (konfigurasi `DEVGUARD_FAIL_ON_UNANALYZABLE` tidak valid atau argumen CLI eksplisit tidak ditemukan) keluar sebelum menulis `GITHUB_OUTPUT` | Tulis `overall_score=N/A` dan `audit_status=FAIL` ke `GITHUB_OUTPUT` (jika diset) sebelum `process.exit(1)` pada kedua jalur keluar awal tersebut |
| **R2** | Entri semu `<invariant-mismatch>` dirender sebagai path berkas di komentar PR dan URI SARIF | Jangan gunakan `<invariant-mismatch>` sebagai URI artefak fisik di SARIF (gunakan `locations: []` atau hilangkan `locations` pada notifikasi invarian) dan render sebagai `- Coverage invariant mismatch — Skipped: Internal error` tanpa karakter `< >` di komentar PR |
| **R3** | Tautan anchor `#benchmark-corpus` di `README.md` | Periksa seluruh tautan internal `#...` di `README.md` dan pastikan semuanya cocok dengan judul heading aktual |

---

## 1. Aturan Keras

1. **Scope lock:** Dilarang menyentuh fitur Stage 5.2–5.4 (`DG004-DYN`, `SpanMap`, `FOLD`, `EV-01`, `CRITICAL_FLOW_IDENTIFIERS`, `scoring: false`, `via-fold`, `matchLinearGlob`) di branch `stage-5.1-fix` ini.
2. **Tidak boleh melemahkan tes:** Seluruh 54 tes yang ada di `stage-5.1-fix` wajib tetap lulus, ditambah tes baru untuk G1, G2 (D12), dan R1–R2.
3. **Bukti tanpa pemotongan:** Dilarang memakai `head` atau `tail` untuk bukti diff dan output tes.

---

## 2. Langkah Eksekusi (2 Commit Bersih di `stage-5.1-fix`)

### Commit 1 — Bersihkan `docs/specs/` & Perbarui `specs/SPEC.md` ke Rev 2.3 (C4)
1. Jalankan `git rm -r docs/specs/`.
2. Perbarui `specs/SPEC.md` ke **Rev 2.3** (mencatat:
   - `.py` partial coverage menjalankan `DG001`, `DG002`, `DG007` dan melewati `DG004`, `DG005`, `DG006`, `DG008`;
   - `ignored/excluded_path` untuk mode `modified` (`git diff`) sehingga invarian `analyzed + skipped + ignored === total_diff_files` berlaku atas **seluruh** file di `git diff` tanpa pengecualian tersembunyi;
   - Pengecualian self-reference `src/devguardAnalyzer.ts` & `scripts/devguard_verify.py` dijangkar ke path eksak pada repo `name === "devguard"`;
   - R1 & R2).
3. Simpan berkas prompt ini di `specs/PROMPT-STAGE-5.1-HARDENING.md`.
4. Commit: `git commit -m "docs(specs): remove duplicate docs/specs and update SPEC.md to rev 2.3"`.

### Commit 2 — Implementasi C2, C3, G1, G2 (D12), R1–R3, dan Tes Baru
1. **G1 (Self-Reference Anchoring di `src/cli.ts`):**
   - Buat helper ringan `isDevGuardSelfRepo(cwd: string): boolean` yang memeriksa apakah `path.join(cwd, 'package.json')` memiliki `"name": "devguard"`.
   - Di `isExcludedPathFromScope(filePath, cwd)`:
     - Hanya kecualikan `posix === 'src/devguardAnalyzer.ts' || posix === 'scripts/devguard_verify.py'` (atau `posix === 'devguard_verify.py'`) **jika dan hanya jika** `isDevGuardSelfRepo(cwd)` bernilai `true`.
     - Dengan demikian, berkas bernama `src/devguard_verify.py` atau `pkg/devguardAnalyzer.ts` pada repositori pengguna (atau di luar path eksak tersebut) **tidak pernah** dikecualikan secara diam-diam!
2. **G2 / D12 (`ignored/excluded_path` pada mode `modified` di `src/cli.ts` & `src/githubCommenter.ts`):**
   - Perluas `IgnoredReason` menjadi `'non_code' | 'deleted' | 'excluded_path'`.
   - Di `discoverInScopeFiles(mode, cwd)`:
     - Untuk `mode === 'modified'`, kembalikan **seluruh** path dari `git diff` (unik, non-kosong) **tanpa** memfilter dengan `!isExcludedPathFromScope(f, cwd)`. (Catatan: `discoverWorkspaceFiles('modified', cwd)` tetap memfilter `!isExcludedFromAutoDiscovery(f, cwd)` agar kompatibilitas pemanggil lama terjaga).
     - Untuk `mode === 'all'`, pertahankan perilaku saat ini (tetap melewati `AUTO_DISCOVERY_EXCLUDED_DIRS` saat menyusuri direktori agar tidak memindai `node_modules`).
   - Di `classifyFile(filePath, options)`:
     - Setelah mengecek `!stat.exists` (yang mengembalikan `ignored/deleted` pada mode `modified`), jika `isExcludedPathFromScope(filePath, cwd)` bernilai `true` (dan `options?.sourceMode !== 'explicit'`), kembalikan `{ filePath, status: 'ignored', reason: 'excluded_path', sizeBytes: stat.size }`.
   - Di `PrCoverageSummary` dan `buildPullRequestCommentMarkdown` (`src/githubCommenter.ts`):
     - Tambahkan `ignoredExcludedPathCount?: number`.
     - Jika `ignoredExcludedPathCount > 0`, tambahkan baris `- Ignored (excluded path): ${ignoredExcludedPathCount}` di bawah `- Ignored (non-code): ...` pada blok `Coverage`.
3. **R1 (`GITHUB_OUTPUT` pada Early Exit di `src/cli.ts`):**
   - Pada blok catch `parseFailOnUnanalyzable` dan blok pemeriksaan `explicitFileArgs` yang tidak ditemukan di disk di `runAction()`, panggil:
```ts
const outputFile = process.env.GITHUB_OUTPUT;
writeGitHubOutput(outputFile, 'overall_score', 'N/A');
writeGitHubOutput(outputFile, 'audit_status', 'FAIL');
```
   sebelum `process.exit(1)`.

4. **R2 (Penanganan Bersih Invarian Mismatch Tanpa `<invariant-mismatch>` di URI):**
   - Di `src/githubCommenter.ts` dan `src/sarifGenerator.ts`, jika `item.filePath === '<invariant-mismatch>'` (atau konstanta `INVARIANT_MISMATCH_SENTINEL`), render di PR comment sebagai `    - Coverage invariant mismatch — Skipped: Internal error` (tanpa `< >`) dan di SARIF `toolExecutionNotifications` jangan sertakan array `locations` yang berisi karakter ilegal `< >` pada `uri`.

5. **C2 & R3 (`README.md`):**
   - Koreksi deskripsi cakupan parsial `.py` di `README.md`: jelaskan secara akurat bahwa `.py` menjalankan `DG001` (sink generik `eval`/`exec`/`os.system` & heuristik domain SQL/ping), `DG002` (error-handling resilience), dan `DG007` (hardcoded secrets), sementara detektor spesifik JS/TS/NPM `DG004`, `DG005`, `DG006`, dan `DG008` dilewati.
   - Dokumentasikan `- Ignored (excluded path): N` pada mode `modified` dan batasan mode `all`.
   - Pastikan seluruh tautan anchor `#...` di `README.md` valid.

6. **C3 (Side-by-Side Golden SARIF Diff terhadap Worktree `e67c869`):**
   - Buat worktree sementara `../devguard-v121` di commit `e67c869`, jalankan CLI pada keempat fixture Python (`secret.py`, `eval_sink.py`, `cmd.py`, `clean.py`) baik di `../devguard-v121` maupun di `HEAD`, ekstrak `runs[0].results` dari masing-masing berkas SARIF, bandingkan dengan `diff -u` (harus 0 perbedaan / identik 100%), lalu hapus worktree sementara sebelum commit.

7. **Tambahkan Tes Baru di `tests/integration.test.ts`:**
   - **Test 54:** Membuktikan G1 (berkas `src/devguard_verify.py` dan `pkg/devguardAnalyzer.ts` di repo non-`devguard` **tetap dianalisis**, tidak dikecualikan diam-diam; sedangkan `src/devguardAnalyzer.ts` di repo `name === "devguard"` tetap dikecualikan).
   - **Test 55:** Membuktikan G2 / D12 (pada mode `modified` / `git diff`, berkas yang diubah di `scripts/helper.js`, `src/foo.test.ts`, atau `.github/workflows/ci.yml` masuk ke klasifier sebagai `ignored/excluded_path`, menjaga invarian `analyzed + skipped + ignored === total_diff_files`, dan merender `- Ignored (excluded path): N` di komentar PR).
   - **Test 56:** Membuktikan R1 & R2 (early `exit 1` karena `DEVGUARD_FAIL_ON_UNANALYZABLE=invalid` atau argumen file hilang tetap menulis `overall_score=N/A` dan `audit_status=FAIL` ke `GITHUB_OUTPUT`; serta invarian mismatch tidak menghasilkan URI `<invariant-mismatch>` di SARIF maupun `< >` di komentar PR).

---

## 3. Verifikasi & Bukti Wajib

Setelah Commit 2 selesai, jalankan dan tempelkan output aktual tanpa pemotongan:

1. `npm run lint`
2. `npm run build`
3. `npm test`
4. Output perbandingan side-by-side SARIF `results[]` untuk keempat fixture `.py` antara `e67c869` dan `HEAD` (C3).
5. `git status --short` dan `git ls-files "*spec*" "*PROMPT*"` (membuktikan `docs/specs/` sudah terhapus).
6. `git diff d4801e7...HEAD -- src/ README.md action.yml` (utuh tanpa `head`/`tail`).
7. Pengecekan scope lock:
`git diff e67c869...HEAD -- . ":(exclude)specs" | grep -nE "DYN|SpanMap|FOLD|EV-01|CRITICAL_FLOW_IDENTIFIERS|scoring: false|via-fold|matchLinearGlob" || echo "BERSIH"`
