# PROMPT FIX-UP (rev 2) — DevGuard v1.3.0 · Stage 5.1-fix (menutup temuan review Stage 5.1)

> Tempel seluruh isi berkas ini ke agen koding di root repo DevGuard.
> Sumber kebenaran: **`specs/SPEC.md` rev 2.2** (perilaku sama dengan rev 2.1; hanya referensi dikoreksi). Jika prompt ini bertentangan dengan SPEC, hentikan dan laporkan konflik.

**Perubahan dari prompt rev 1 (wajib dipahami agen):**
1. Stage 5.1 **sudah di-merge ke `main`** (merge `d4801e7`, implementasi `c5f7129`). Kerja dilakukan di **branch baru dari `main` saat ini**, bukan di branch lama.
2. **`main` bukan baseline v1.2.1.** Semua perbandingan "perilaku asli" memakai **`BASE = e67c869`** (commit v1.2.1 terakhir sebelum Stage 5.1; tag `v1.2.1`). Semua `git show main:...`, `git diff main...HEAD`, dan worktree `main` dari versi lama prompt **tidak berlaku**.
3. Berkas spesifikasi berada di **`specs/`** (bukan `docs/specs/`).

---

## 0. Konteks

Stage 5.1 (klasifier, skor `N/A`, ringkasan PR, SARIF, input `fail_on_unanalyzable`) sudah ada di `main`, `45/45` tes lokal. Review diff menemukan cacat yang harus ditutup **sebelum** Stage 5.2. **`main` belum boleh dirilis, di-tag, atau dipakai sebagai referensi `uses: ...@main` sampai fix ini di-merge.** Tugasmu hanya Stage **5.1-fix**.

Temuan yang ditutup (nomor dipakai di laporan):

| # | Temuan | Bukti |
|---|---|---|
| F1 | Special-case nama fixture di kode produksi | `src/cli.ts`: `/^vulnerable_fixture\.py$/i` di `runAction()` |
| F2 | Kebijakan path diubah demi tes: pengecualian `scripts/` dilonggarkan, nama file `devguard_verify.py` ditulis hardcoded, mode `all` ikut menelusuri `scripts/` | `isExcludedPathFromScope`, `discoverInScopeFiles` |
| F3 | `.py` di-skip total padahal v1.2.1 menganalisisnya (regresi kapabilitas) | filter v1.2.1: `/\.(py\|ts\|js\|jsx\|tsx)$/` |
| F4 | `internal_error`/`parse_error` fail-open dan non-fatal (`gateFailed = hasFatalFailure \|\| unanalyzableFailed`); pelanggaran invarian hanya `console.error` | `computeOverallGateVerdict`, `auditClassifiedFiles`, `postCheck` |
| F5 | Badge `✅ PASSED (READY TO MERGE)` untuk nol file teranalisis (`summaries.every` pada array kosong) | `buildPullRequestCommentMarkdown` |
| F6 | `parseFailOnUnanalyzable`: fallback `INPUT_*`, menerima `1`, nilai tak valid diam-diam jadi `false` | `src/cli.ts` |
| F7 | String `v1.3.0` ditulis permanen di dua tempat | `cli.ts`, `githubCommenter.ts` |
| F8 | `classifyFile` memetakan file yang tidak ada ke `ignored/deleted` untuk semua mode (typo path eksplisit jadi "deleted") | `classifyFile` |
| F9 | SARIF `executionSuccessful` dipatok `true` | `sarifGenerator.ts` |
| F10 | Fixture Test 6c diubah dari `.py` ke `.ts`; tes baru memakai `.py` sebagai contoh "skipped" | `tests/integration.test.ts` |
| F11 | Isi tes 36–44 belum pernah ditinjau (bukti sebelumnya terpotong) | laporan sebelumnya |

## 1. Aturan Keras (pelanggaran = gagal)

1. **Pre-flight (§3) selesai dan tabelnya tercetak SEBELUM menyentuh kode.** Saat dicetak: `git status --short` dan `git diff --stat` kosong.
2. **Tidak boleh ada kode produksi yang mengenali nama fixture, nama file tes, atau path tes.** Setelah selesai: `grep -rn "vulnerable_fixture" src/` kosong. `devguard_verify`: biarkan **persis seperti di `BASE`** (jika ada di `BASE`, tetap ada; jika tidak ada di `BASE`, tidak boleh ada).
3. **Scope lock.** Dilarang menyentuh Stage 5.2–5.4 (`DG004-DYN`, `SpanMap`, folding, rule `EV`, `scoring: false`, `CRITICAL_FLOW_IDENTIFIERS`, matcher glob). Dilarang mengubah perilaku rule atau bobot penalti.
4. **Tidak boleh mengubah kebijakan pengecualian path** selain mengembalikannya ke perilaku `BASE` (F2).
5. **Zero dependency.** Tidak ada paket baru.
6. **Tidak boleh melemahkan tes.** Boleh diubah: Test 6 (hanya mengembalikan fixture 6c ke `.py` seperti di `BASE`, mempertahankan asersi kontrak), Test 29 (kontrak), dan tes **baru milik 5.1** (35–44) yang fixture-nya salah (F10). **Test 4 tidak boleh diubah.** Setiap perubahan tes dijustifikasi satu per satu.
7. **Tidak ada asumsi diam-diam.** Konflik SPEC vs kode: ikuti SPEC dan catat DEVIASI. Berhenti dan lapor hanya jika (a) baseline `main` tidak hijau, (b) `BASE` tidak dapat di-checkout/diverifikasi, atau (c) golden `.py` (P1) tidak dapat direproduksi dari `BASE`.
8. **Bukti tanpa pemotongan.** Dilarang menempelkan bukti yang dipotong (`| head`, `| tail`, `-n N`, "..."). Jika output besar, tulis ke berkas lalu tampilkan seluruh isinya bertahap sampai habis. Laporan yang bukti kuncinya terpotong dianggap belum selesai.
9. **Jangan push ke `main`, jangan force-push, jangan rebase `main`.** Kerja di branch baru; hasil diajukan sebagai PR.
10. Klaim "selesai/lulus/hijau" hanya sah dengan output perintah aktual. Jangan mencetak secret.
11. Ikuti konvensi kode repo. Tidak ada refactor di luar kebutuhan fix ini.

## 2. Langkah 0 — Baseline dan penanda commit

Jalankan dan tempel outputnya:

```
git status
git rev-parse --abbrev-ref HEAD
git log --oneline -n 8
git merge-base --is-ancestor c5f7129 HEAD && echo "5.1 ada di HEAD"
git cat-file -t e67c869
git rev-parse e67c869
git rev-parse v1.2.1^{commit}
git show e67c869:package.json
git ls-files | grep -iE "spec|PROMPT"
node --version
npm ci
npm run lint
npm run build
npm test
```

Lalu tetapkan dan cetak (dipakai di seluruh dokumen ini):

```
BASE=e67c869
FIX_START=$(git rev-parse HEAD)
echo "BASE=$BASE FIX_START=$FIX_START"
```

Syarat dan catatan:
- Branch saat ini harus `main` dan memuat merge `d4801e7`; working tree bersih. Jika tidak: **berhenti** dan laporkan.
- `e67c869` harus ada, `version` di `package.json`-nya `1.2.1`. Jika tag `v1.2.1` ada tetapi menunjuk commit lain, **laporkan** dan tetap pakai `e67c869` (ditetapkan pemilik repo).
- `npm test` harus `45` lulus, `0` gagal. Jika tidak: **berhenti**.
- `git ls-files | grep -iE "spec|PROMPT"` menunjukkan lokasi berkas spesifikasi. Spesifikasi resmi ada di **`specs/`**. Jika ada salinan di `docs/specs/` juga, **laporkan, jangan hapus**, dan tulis hanya ke `specs/`.
- Catat bahwa tes lokal berjalan di Node `v26.13.0` sedangkan workflow memakai Node 22.

Buat branch kerja dan commit dokumen:

```
git checkout -b stage-5.1-fix
```

1. Salin SPEC rev 2.2 ke `specs/SPEC.md` (menggantikan versi lama) dan simpan prompt ini sebagai `specs/PROMPT-STAGE-5.1-FIXUP.md`.
2. `git commit -m "docs(specs): SPEC rev 2.2 and Stage 5.1-fix prompt"`.

## 3. Pre-flight read-only (P0–P8)

Hanya `grep`, `rg`, `cat`, `sed -n`, `git show`, `git worktree`. Tidak ada edit kode di repo kerja. **Semua perbandingan "perilaku asli v1.2.1" memakai `BASE`, bukan `main`.**

| ID | Pertanyaan | Dipakai untuk |
|---|---|---|
| **P0** | Verifikasi `BASE`: `git worktree add ../devguard-v121 e67c869`, lalu di worktree itu jalankan `npm ci && npm test`. Harus `35` lulus, `0` gagal. | Memastikan `BASE` utuh sebelum dijadikan golden |
| **P1** | Rule apa yang menghasilkan finding untuk `.py` di v1.2.1? `grep -n "isExplicitJsTsFile"` di `BASE` dan semua cabang yang bergantung padanya. **Golden:** jalankan CLI v1.2.1 dari worktree P0 (cara yang sama seperti Test 4) pada fixture `.py` (minimal: secret hardcoded, `eval`/`exec`, `os.system`, kode bersih); catat rule ID dan nomor baris per fixture. | F3, tes golden |
| **P2** | Exception apa yang bisa lolos dari `evaluateCodeHybrid`? Apakah kegagalan Layer 2 (Gemini, `JSON.parse` respons) selalu ditangkap di dalam? Apakah `SyntaxError`/`ParseError` lain bisa keluar dan salah diklasifikasi `parse_error` oleh `classifyAnalysisErrorReason`? | F4: kegagalan Layer 2 tidak boleh menjadi fatal |
| **P3** | `resolveCliFileArgs`: bagaimana argumen file eksplisit diproses? Apa yang terjadi di `BASE` bila file tidak ada? Bagaimana `DEVGUARD_TARGET` selain `all`/`modified` ditangani? | F8; catat untuk SPEC §4.6 butir 3 |
| **P4** | Tampilkan `git show e67c869:src/cli.ts` untuk seluruh `isExcludedFromAutoDiscovery`, `AUTO_DISCOVERY_EXCLUDED_DIRS`, dan `discoverWorkspaceFiles`. Apakah `devguard_verify.py` ada di `BASE`? Di baris berapa? Tampilkan juga versi di `HEAD` untuk perbandingan. | F2 |
| **P5** | Tipe `VerifiedAllowlistResult`: apakah `sourceMode: 'empty'` valid atau hanya lolos kompilasi karena cast? | Konsistensi tipe |
| **P6** | README di `BASE`: apakah ada klaim dukungan Python/bahasa lain? Apakah `CHANGELOG.md` ada? | F3, dokumentasi |
| **P7** | Bagaimana action dijalankan (`action.yml` → `loader.mjs` → entry apa)? Dari mana `package.json` dapat ditemukan saat runtime pada jalur `src/` (strip-types), `.test-dist/src/` (tes), dan hasil build (jika ada)? | F7 |
| **P8** | Cetak **seluruh** isi tes 35–44 di `tests/integration.test.ts` (tanpa pemotongan), khususnya Tes 40 ("identik dengan baseline") dan Tes 44 (fail-open), plus semua tempat yang menulis ulang literal `v1.3.0` atau memakai `.py` sebagai contoh skipped. Bandingkan Test 6c dan Test 4 dengan versi di `BASE` (`git show e67c869:tests/integration.test.ts`). | F10, F11 |

Cetak tabel temuan (WAJIB sebelum edit pertama):

```
| ID | Temuan | Bukti (path:baris) | Cocok dengan SPEC 2.2? | Keputusan / DEVIASI |
```

Setelah tabel: `git status --short` dan `git diff --stat` (harus kosong; worktree `../devguard-v121` berada di luar repo kerja dan **tidak** boleh ikut commit), lalu satu baris: `PRE-FLIGHT FIX SELESAI — mulai 5.1-fix.`

## 4. Implementasi

Kerjakan sebagai commit-commit kecil; **setiap commit** lulus `npm run lint`, `npm run build`, `npm test`.

### Commit D — Pulihkan kebijakan v1.2.1 dan `.py` parsial (F1, F2, F3, F10)

**T1 (F1). Hapus bridge.** Hapus seluruh blok `Compatibility bridge ...` di `runAction()`. `grep -rn "vulnerable_fixture" src/` harus kosong.

**T2 (F2). Kembalikan kebijakan path ke `BASE`.** Berdasarkan P4, kembalikan `isExcludedPathFromScope`, `AUTO_DISCOVERY_EXCLUDED_DIRS`, dan penelusuran `scripts/` pada mode `all` ke semantik `BASE` **persis** (semua file di bawah `scripts/` tetap dikecualikan). Hapus kondisi `item.name !== 'scripts'` dan cabang `seg === 'scripts'`. Pemisahan fungsi (`isExcludedPathFromScope` vs filter ekstensi) boleh dipertahankan asal hasilnya identik dengan `BASE`. Fixture tes 35–44 yang memakai direktori `scripts/` dipindah ke direktori lain (mis. `tools/`).

**T3 (F3). `.py` analyzed/partial.**
- Konstanta baru `PARTIAL_ANALYSIS_EXTENSIONS = ['.py'] as const`, diekspor berdampingan dengan `ANALYZABLE_EXTENSIONS`.
- `.py` dikeluarkan dari `KNOWN_UNSUPPORTED_CODE_EXTENSIONS` (`.pyw` tetap skipped).
- `ClassifiedFileEntry` mendapat `coverage?: 'full' | 'partial'`. `classifyFile`: JS/TS → `analyzed/full`; `.py` → `analyzed/partial`; ukuran > batas → `skipped/file_too_large` (berlaku untuk keduanya).
- `isExcludedFromAutoDiscovery` / `discoverWorkspaceFiles` mempertahankan perilaku `BASE` untuk `.py` (tetap ditemukan). Analyzer dipanggil tanpa perubahan untuk `.py`.
- **Golden test:** temuan `.py` (rule ID + baris) dari fixture P1 identik dengan baseline `BASE`. Nilai expected ditulis statis di tes (tes tidak boleh memerlukan `git` atau worktree saat dijalankan).

**T4 (F10). Perbaiki fixture tes.**
- Test 6c: kembalikan fixture ke `vuln_fallback.py` dan konten asli (acuan: `git show e67c869:tests/integration.test.ts`); pertahankan asersi kontrak tambahan.
- Test 4 tetap utuh dan harus lulus secara alami.
- Tes baru 35–44 yang memakai `.py` sebagai contoh "skipped" diganti `.go`/`.rb`/`.java`; tambahkan tes `.py`-parsial (§5).

### Commit E — Fail-closed, badge, parsing, versi, deleted, SARIF, dokumentasi (F4–F9)

**T5 (F4). Fail-closed.**
- `computeOverallGateVerdict` menerima `analysisFailureCount` (jumlah `skipped` berreason `parse_error`/`internal_error` + entri invarian-mismatch). `gateFailed = hasFatalFailure || analysisFailureCount > 0 || unanalyzableFailed`.
- Pelanggaran invarian (pre dan post-audit) dihitung sebagai analysis failure, bukan hanya log.
- File lain **tetap diproses** setelah satu file gagal. `audit_status=FAIL`, `exit 1`, dengan pesan konsol terpisah untuk analysis error.
- Kegagalan Layer 2 (Gemini) **tetap tidak fatal**; sesuaikan `classifyAnalysisErrorReason` berdasarkan P2 agar tidak salah klasifikasi.
- Perbaiki urutan di `auditClassifiedFiles` agar exception setelah `summaries.push` tidak membuat file tercatat ganda (analyzed sekaligus skipped).

**T6 (F5). Badge dan headline** sesuai SPEC §4.2: enam baris badge, dievaluasi berurutan; headline dengan segmen `· N partial` hanya bila `N > 0`; blok coverage mencantumkan file partial (`— Partial: language-agnostic rules only`); cap tampilan 20 per daftar dengan `+N more`. `PrCoverageSummary` diperluas (file partial, `analysisFailureCount`). Badge 4 dan 5 tidak mengubah exit code.

**T7 (F9). SARIF.** `executionSuccessful: false` bila ada analysis failure; notifikasi `note` untuk partial dan skipped, `error` untuk analysis failure; tidak ada `result` baru; teks lewat redaksi.

**T8 (F6). Parsing input ketat.** `parseFailOnUnanalyzable`: hanya `DEVGUARD_FAIL_ON_UNANALYZABLE`; nilai di-trim dan lowercase harus `true` atau `false`; kosong/tidak diset → `false`; lainnya → pesan error jelas dan `exit 1`. Hapus fallback `INPUT_*` dan penerimaan `1`.

**T9 (F7). Versi dari `package.json`.** Satu helper (mis. `getDevGuardVersion()`): naik dari `import.meta.url` sampai maksimal 4 tingkat mencari `package.json` ber-`name` `devguard`, di-cache, fallback `'unknown'`. Dipakai di `cli.ts` dan `githubCommenter.ts`. Tidak boleh bergantung pada satu path relatif tetap (P7). Tes: headline memuat versi `package.json` baik dari jalur `src` maupun build `.test-dist`.

**T10 (F8). `deleted` hanya dari diff.** Argumen file eksplisit yang tidak ada → `exit 1` sebelum klasifikasi dengan pesan yang memuat path (hasil P3 menentukan jalur persisnya). `ignored/deleted` hanya untuk file dari `git diff` (mode `modified`) yang tidak ada di disk.

**T11. Dokumentasi.** README: cakupan parsial `.py`, semantik `N/A` dan `overall_score=N/A` untuk konsumen numerik, fail-closed, `fail_on_unanalyzable` ketat, Known limitations (SPEC §4.6), perubahan perilaku (SPEC §4.7). `action.yml` (deskripsi output) dan tes kontrak disinkronkan dalam commit yang sama. Jika `CHANGELOG.md` ada, tambahkan entri "Unreleased"; jika tidak ada, jangan membuatnya (laporkan).

## 5. Tes baru (lanjutkan penomoran setelah tes terakhir yang ada; ikuti gaya `node --test`)

1. **Crash payload (fail-closed):** `evaluateFn` melempar error → file lain tetap dianalisis; verdict FAIL; CLI `exit 1`; `audit_status=FAIL`; SARIF `executionSuccessful: false` dengan notifikasi `error`.
2. **Layer 2 non-fatal:** kegagalan Gemini tidak membuat `exit 1` (Test 6 tetap hijau tanpa dilonggarkan).
3. **Invarian fatal:** simulasi ketidakcocokan hitungan → analysis failure, `exit 1`.
4. **Matriks badge:** satu tes per baris SPEC §4.2 (6 baris).
5. **`.go`-only:** skor `N/A`, badge `NOT ANALYZED`, exit `0`; dengan `fail_on_unanalyzable: 'true'` → exit `1`.
6. **`.py` parsial:** klasifikasi `analyzed/partial`; golden rule ID dan baris identik dengan `BASE`; badge `PARTIALLY ANALYZED` bila hanya `.py`; headline memuat `1 partial`.
7. **Campuran** (`.ts` + `.py` + `.go` + file > 1 MiB + `.md`): headline, blok coverage, dan SARIF benar.
8. **Parsing input:** `true`, `TRUE`, ` false `, kosong → valid; `yes`, `1`, `ture` → `exit 1`.
9. **`INPUT_FAIL_ON_UNANALYZABLE` diabaikan.**
10. **Versi:** headline = versi `package.json` (jalur `src` dan `.test-dist`).
11. **Argumen eksplisit hilang:** `exit 1` dengan pesan jelas; file terhapus pada diff → `ignored/deleted`.
12. **Kebijakan path:** `scripts/*.js` dan `scripts/*.py` tetap dikecualikan (identik `BASE`); penelusuran mode `all` identik `BASE`.
13. **Kontrak** tetap sinkron: `action.yml` ↔ README ↔ workflow ↔ Test 6/29.

## 6. Larangan & pengecekan mekanis (tempel hasilnya)

```
git diff e67c869...HEAD | grep -nE "DYN|SpanMap|FOLD|EV-01|CRITICAL_FLOW_IDENTIFIERS|scoring: false|via-fold" || echo "BERSIH"
git diff $FIX_START...HEAD | grep -nE "DYN|SpanMap|FOLD|EV-01|CRITICAL_FLOW_IDENTIFIERS|scoring: false|via-fold" || echo "BERSIH"
grep -rn "vulnerable_fixture" src/ || echo "BERSIH"
grep -rn "INPUT_FAIL_ON_UNANALYZABLE" src/ || echo "BERSIH"
grep -rn "v1\.3\.0" src/ || echo "BERSIH"
git diff e67c869...HEAD -- tests/integration.test.ts | grep "^-" | grep -v "^---"
```

Lima pengecekan pertama wajib `BERSIH` (pengecekan pertama bersifat kumulatif terhadap v1.2.1; kedua hanya untuk fix ini). Perintah terakhir menampilkan **semua baris tes yang dihapus** relatif terhadap v1.2.1; setiap baris yang muncul wajib dijustifikasi, dan **Test 4 tidak boleh muncul**.

## 7. Bukti wajib (tanpa pemotongan)

Tempel output aktual:

```
npm run lint
npm run build
npm test
git diff --stat e67c869...HEAD
git diff --stat $FIX_START...HEAD
git log --oneline $FIX_START..HEAD
```

Syarat lulus: lint dan build sukses; `npm test` = tes lama + tes baru, `0` gagal, tidak ada tes dinonaktifkan; jumlah tes ≥ `45` + tes baru.

Bukti tambahan:
1. `git diff $FIX_START...HEAD` **lengkap** (disimpan ke berkas, ditampilkan sampai habis) untuk `src/cli.ts`, `src/githubCommenter.ts`, `src/sarifGenerator.ts`, `src/devguardAnalyzer.ts`, `action.yml`, `README.md`, workflow, dan **seluruh** perubahan `tests/integration.test.ts`.
2. Ringkasan PR nyata (hasil `buildPullRequestCommentMarkdown` atau CLI) untuk **setiap baris badge** §4.2 (6 contoh).
3. Potongan SARIF nyata dengan `executionSuccessful: false` dan notifikasi `error`, serta satu dengan notifikasi partial.
4. Tabel golden `.py`: fixture, rule ID/baris di `BASE` (v1.2.1) vs di `HEAD` (harus identik).
5. Hasil pengecekan §6.
6. Bersihkan worktree sementara (`git worktree remove ../devguard-v121`) dan tunjukkan `git worktree list` serta `git status --short` bersih.
7. Jika push dimungkinkan (ke branch `stage-5.1-fix`, **bukan** `main`): link run GitHub Actions. Jika tidak: tulis jelas **"belum dipush, CI belum diverifikasi"**; jangan mengklaim CI hijau.

## 8. Evaluasi risiko (guardrail untuk pelaksana)

**Anti-survivorship:** `45/45` hijau tidak membuktikan keamanan verdict: tes yang ada tidak menguji crash payload, nol-analisis, atau regresi `.py`. Tes §5 butir 1, 4, 6 adalah gerbangnya. Memperbaiki tes dengan special-case di kode produksi (F1) adalah survivorship palsu. Membandingkan terhadap `main` alih-alih `BASE` juga survivorship palsu: `main` sudah memuat perubahan yang sedang diaudit, jadi "identik dengan main" tidak membuktikan apa-apa.

**Single point of failure:** (1) jalur verdict (`computeOverallGateVerdict` + exit code + badge): semua sumber kegagalan masuk satu fungsi; jangan menambah jalur exit baru di tempat lain. (2) **Referensi baseline:** seluruh golden dan pemulihan kebijakan bertumpu pada `BASE`; P0 memverifikasinya sebelum dipakai.

**Pre-mortem:**

| Skenario | Mitigasi |
|---|---|
| Golden dan "pemulihan" mengacu ke `main` yang sudah rusak, sehingga regresi lolos | `BASE=e67c869`, P0, semua perbandingan eksplisit ke `BASE` |
| File yang membuat analyzer crash meloloskan PR | T5, tes 1 |
| Secret di `.py` tidak lagi dipindai | T3, golden tes 6 |
| Lencana hijau untuk nol analisis / parsial | T6, tes 4 |
| Mode ketat mati diam-diam karena typo | T8, tes 8 |
| Kebijakan path berubah tanpa disadari | T2, tes 12 |
| Kegagalan Gemini menjadi fatal | P2, tes 2 |
| Komentar menunjukkan versi yang salah | T9, tes 10 |
| `main` dirilis atau dipush dalam keadaan cacat | Aturan 9; kerja di branch, hasil lewat PR |
| Scope creep ke 5.2–5.4 | Larangan §6 |

## 9. Format laporan akhir (wajib, berurutan)

1. Output Langkah 0 (termasuk `BASE`, `FIX_START`, verifikasi `e67c869`, lokasi berkas spesifikasi) dan tabel pre-flight P0–P8 beserta DEVIASI.
2. Ringkasan perubahan per berkas, dipetakan ke F1–F11.
3. Bukti §7 (output aktual, lengkap).
4. Perubahan pada tes existing, tiap baris dijustifikasi (Test 4 tidak boleh muncul).
5. Pengecekan §6.
6. Temuan yang relevan untuk Stage 5.2 (mis. P5, P3) dan hal yang sengaja tidak dikerjakan.
7. Status jujur: yang terverifikasi (dengan bukti) dan yang belum (CI, Node 22 vs 26).
