# PROMPT IMPLEMENTASI — DevGuard v1.3.0 · Stage 5.0 (Pre-flight) + Stage 5.1 (Explicit Unanalyzable / Skipped Reporting)

> Tempel seluruh isi berkas ini ke agen koding (Antigravity / Claude Code) di root repo DevGuard `v1.2.1`.
> Sumber kebenaran: `SPEC.md` rev 2 di repo (taruh di root jika belum ada). Jika prompt ini bertentangan dengan `SPEC.md`, **hentikan dan laporkan konflik**, jangan memilih sendiri.

---

## 0. Peran & Konteks

Kamu adalah engineer pelaksana untuk **DevGuard** (GitHub Action gatekeeper CI/CD, zero-dependency, engine Layer 1 lexical: `src/rules/lexicalMasker.ts`, bukan AST). Baseline `v1.2.1` hijau di GitHub Actions dengan `35/35` tes lulus.

Tugasmu hanya dua tahap berurutan, tanpa jeda persetujuan di antaranya:

1. **Stage 5.0** — pre-flight read-only: jawab D1–D8 dari `SPEC.md` §13 dengan bukti `path:baris`.
2. **Stage 5.1** — implementasi `SPEC.md` §4 penuh.

Baca dulu `SPEC.md`: §2, §3, §4, §7, §8.4, §10, §11, §13. Bagian lain tidak dikerjakan sekarang.

## 1. Aturan Keras (pelanggaran = gagal)

1. **Stage 5.0 selesai dan tabelnya tercetak SEBELUM menyentuh kode apa pun.** Saat tabel dicetak, `git status` harus bersih dan `git diff --stat` kosong. Cetak keduanya sebagai bukti.
2. **Scope lock.** Dilarang menyentuh fitur Stage 5.2–5.4: `DG004-DYN-*`, `SpanMap`, constant folding, rule `EV` (`DG008-EV-01`, `DG005-EV-01`), flag `scoring: false`, ekstraksi `CRITICAL_FLOW_IDENTIFIERS`, matcher glob allowlist, perubahan perilaku rule apa pun, perubahan bobot penalti.
3. **Zero dependency.** Dilarang menambah paket di `dependencies`/`devDependencies`.
4. **Tidak boleh melemahkan tes.** Dilarang menghapus, men-`skip`, atau melonggarkan asersi tes yang ada. Satu-satunya tes existing yang boleh diubah adalah tes kontrak (Test 6 dan Test 29 di `tests/integration.test.ts`), dan setiap perubahan harus dijustifikasi satu per satu di laporan akhir.
5. **Tidak ada asumsi diam-diam.** Setiap `[ASUMSI]` di SPEC yang menyentuh Stage 5.1 harus dijawab dari kode, bukan ditebak. Jika kode kontradiktif dengan SPEC, gunakan default konservatif di `SPEC.md` §13, catat sebagai **DEVIASI** di laporan, lalu lanjut. **Berhenti dan lapor** hanya jika (a) baseline tidak hijau, atau (b) temuan membuat invarian §4.1 mustahil dipenuhi tanpa mengubah rule/engine.
6. **Klaim "selesai" hanya sah dengan bukti nyata** (diff aktual, output perintah aktual). Narasi tidak dihitung. Jangan menulis kata "selesai/lulus/hijau" tanpa menempelkan output perintahnya.
7. **Jangan mencetak atau meng-commit secret.** `gemini_api_key` dan token lain tidak boleh muncul di log, fixture, atau laporan.
8. Ikuti konvensi kode, penamaan, dan gaya repo yang ada. Tidak ada refactor di luar yang dibutuhkan §4.

## 2. Langkah 0 — Baseline

Jalankan dan tempel output ringkasnya (baris akhir yang memuat jumlah lulus/gagal):

```
git status
git rev-parse --abbrev-ref HEAD
git log --oneline -n 5
node --version
npm ci
npm run lint
npm run build
npm test
```

- Wajib: lint dan build sukses, `npm test` = **35 lulus, 0 gagal**.
- Jika tidak hijau: **berhenti**, laporkan, jangan lanjut.
- Buat branch: `git checkout -b stage-5.1-unanalyzable-reporting`.

## 3. Stage 5.0 — Pre-flight Read-Only

Hanya `grep`, `rg`, `cat`, `sed -n`, dan membaca kode. **Tidak ada edit, tidak ada berkas baru.**

### 3.1 Pertanyaan wajib (D1–D8)

| ID | Pertanyaan | Dampak ke 5.1 |
|---|---|---|
| D1 | Apakah `lexicalMasker.ts` mengekspos klasifikasi region atau hanya string termasking? | Tidak dipakai di 5.1; **catat saja** untuk 5.3a |
| **D2** | Bagaimana skor dan `N/A` dapat direpresentasikan? Cek: tempat `totalScore` dihitung, tempat dibandingkan dengan `min_score`, `outputs:` di `action.yml`, penulisan ke `$GITHUB_OUTPUT`/step summary, renderer komentar PR, konsumen skor lain (SARIF, badge, README). | **Langsung** |
| D3 | Bagaimana `.html`/`.htm` diperlakukan saat ini? | Catat; default SPEC: `ignored/non_code` |
| D4 | Skema `.devguard.json`: apakah glob path sudah didukung? | Tidak dipakai di 5.1; **catat saja** untuk 5.2 |
| D5 | Kebijakan suppression aktual `DG004`, `DG005`, `DG008` | Tidak dipakai di 5.1; **catat saja** |
| D6 | Di mana guard `1_048_576` bytes berada, dan apa perilakunya (skip diam-diam? throw? truncate?) | **Langsung** (pemetaan ke `skipped/file_too_large`) |
| **D7** | Apakah enumerasi file (`discoverWorkspaceFiles`, filter diff, `target_files`) memfilter ekstensi **sebelum** analisis? Di titik mana persisnya daftar "in-scope" tersedia sebelum filter ekstensi? | **Langsung, paling kritis** |
| **D8** | Apakah input lain punya alias env? Bagaimana input dibaca (`INPUT_*`, `process.env`, `core.getInput`-setara tanpa dependency)? | **Langsung** (`fail_on_unanalyzable`) |

### 3.2 Inspeksi tambahan yang dibutuhkan 5.1

Catat `path:baris` untuk masing-masing:

1. Daftar ekstensi analyzable (semua tempat yang mendefinisikannya; apakah ada duplikasi?).
2. Titik masuk `main`/entrypoint dan alur: enumerasi → filter → baca file → analisis → skor → render → SARIF → exit code.
3. Fungsi yang memutuskan exit code (`min_score`, error findings).
4. Renderer ringkasan/komentar PR (format string, tempat baris skor ditulis).
5. Generator SARIF (struktur `runs[0]`, apakah `invocations` sudah ada).
6. Isi `action.yml`: daftar input, `outputs`, `runs`.
7. Isi `.github/workflows/devguard.yml`: input yang dipassing.
8. Bagian README yang mendokumentasikan input dan output.
9. **Test 6 dan Test 29** di `tests/integration.test.ts`: apa yang persisnya diverifikasi (apakah membandingkan daftar input antara `action.yml`, workflow, README?).
10. Cara deteksi file dihapus/rename pada enumerasi diff (untuk `ignored/deleted`).
11. Bagaimana file dibaca (sync/async, encoding) dan apakah ukuran bisa diketahui sebelum membaca isi (`stat`).

### 3.3 Format tabel temuan (WAJIB dicetak di respons sebelum edit pertama)

```
| ID | Temuan singkat | Bukti (path:baris) | Cocok dengan SPEC? | Keputusan / DEVIASI |
```

Satu baris per D1–D8 dan per butir 3.2. Setelah tabel: cetak `git status --short` dan `git diff --stat` (harus kosong), lalu tulis satu baris:

`PRE-FLIGHT SELESAI — mulai Stage 5.1.`

## 4. Stage 5.1 — Implementasi (SPEC §4 penuh)

Kerjakan sebagai commit kecil yang masing-masing lulus `npm run lint`, `npm run build`, `npm test`.

### Commit A — Klasifier + konstanta ekstensi bersama

**T1. Satu konstanta ekstensi.** Ekstrak daftar `.ts .tsx .js .jsx .mjs .cjs .mts .cts` menjadi satu konstanta yang dipakai oleh klasifier **dan** oleh `discoverWorkspaceFiles`/filter diff. Tidak boleh ada dua daftar.

**T2. Klasifier (fungsi murni, mudah dites).** Setiap in-scope file → tepat satu hasil:

| Status | `reason` | Aturan |
|---|---|---|
| `analyzed` | — | ekstensi analyzable dan ukuran ≤ `1_048_576` |
| `skipped` | `unsupported_language` | allowlist ekstensi kode: `.py .go .java .rb .php .rs .cs .kt .swift .c .cpp .h .sh` dll., plus `.vue .svelte .astro .ipynb`; file tanpa ekstensi yang berawalan `#!` |
| `skipped` | `file_too_large` | > `1_048_576` bytes (cek ukuran via `stat` **sebelum** membaca isi) |
| `skipped` | `parse_error` | scanner/masker gagal pada file itu |
| `skipped` | `internal_error` | exception tak terduga pada file itu (fail-open per file) |
| `ignored` | `non_code` | ekstensi tidak dikenal tanpa shebang, lockfile, gambar, `.md`, `.json`, `.yml`, `.txt`, dll. (`.html`/`.htm` mengikuti keputusan D3) |
| `ignored` | `deleted` | hanya jika enumerasi memang memuat file terhapus |

Urutan evaluasi: ekstensi → (jika analyzable) ukuran → scan. Daftar ekstensi kode yang dikenal berupa **allowlist eksplisit**, bukan "semua selain JS/TS".

**T3. Tempatkan klasifier SEBELUM filter ekstensi** (hasil D7). Daftar `analyzed` kemudian masuk ke pipeline analisis yang sudah ada **tanpa perubahan perilaku**. Output rule untuk file `analyzed` harus identik dengan v1.2.1.

**T4. Invarian.** `analyzed + skipped + ignored == |in-scope files|`. Jika dilanggar saat runtime, itu bug: log error jelas dan anggap `internal_error`; jangan menelan diam-diam. Wajib ada tes.

**T5. Guard 1 MiB.** Pemetaan perilaku guard existing ke `skipped/file_too_large` tanpa mengubah fakta bahwa file itu tidak dianalisis.

### Commit B — Skor, exit code, rendering, SARIF, input, kontrak (satu commit untuk sinkronisasi)

**T6. Semantik skor.**
- Skor hanya dari file `analyzed`.
- `analyzed == 0` → `totalScore = null`, ditampilkan `N/A`. Perbandingan `min_score` **dilewati**. Check tidak gagal karena skor.
- `analyzed > 0` → skor seperti sekarang; perhitungan penalti **tidak diubah** (per finding, kumulatif, `Math.max(0, 100 - sum)`, rata-rata kategori).
- Representasi `N/A` di output action/SARIF mengikuti keputusan D2 dari Stage 5.0; dokumentasikan.

**T7. Input `fail_on_unanalyzable`.**
- `snake_case`, default `'false'`, dibaca dengan cara yang sama seperti input lain.
- `'true'` dan `skipped > 0` → exit `1`. Default: skipped tidak menggagalkan check.
- Alias env `DEVGUARD_FAIL_ON_UNANALYZABLE` **hanya jika** D8 menunjukkan konvensi alias env untuk input lain.
- Tidak menambah `fail_on_warning`.

**T8. Ringkasan PR.** Baris skor selalu memuat coverage di baris yang sama, dan blok Coverage mencantumkan tiap file skipped.

Teks baku alasan:

| `reason` | Teks |
|---|---|
| `unsupported_language` | `Skipped: Unsupported language` |
| `file_too_large` | `Skipped: File too large (> 1 MiB)` |
| `parse_error` | `Skipped: Parse error` |
| `internal_error` | `Skipped: Internal error` |

Contoh yang harus dihasilkan:

```
DevGuard v1.3.0 — Score: 100/100  (analyzed 3 of 5 code files · 2 skipped)

Coverage
- Analyzed: 3
- Skipped: 2
    - scripts/deploy.py — Skipped: Unsupported language
    - tools/big.js      — Skipped: File too large (> 1 MiB)
- Ignored (non-code): 4
```

```
DevGuard v1.3.0 — Score: N/A  (analyzed 0 of 2 code files · 2 skipped)
```

Untuk daftar skipped yang sangat panjang, potong dengan `+N more` agar komentar tidak melewati batas ukuran GitHub; daftar penuh tetap ada di SARIF.

**T9. SARIF.** Skipped → `runs[0].invocations[0].toolExecutionNotifications[]` dengan `level: "note"`, `message.text` = alasan, `locations[].physicalLocation.artifactLocation.uri` = path. **Tidak** menambah `result`. Struktur SARIF existing tidak berubah selain penambahan ini.

**T10. Sinkronisasi kontrak (dalam commit yang sama):** `action.yml` (input baru, deskripsi), `README.md` (input, semantik `N/A`, arti coverage, tidak ada klaim baru di luar SPEC §2), `.github/workflows/devguard.yml` (hanya jika perlu mengikuti kontrak), dan tes kontrak Test 6/29.

### Tes baru (tambahkan di struktur tes yang ada; ikuti gaya `node --test`)

1. Invarian jumlah pada daftar campuran (JS/TS, `.py`, `.go`, `.vue`, `.ipynb`, `.md`, `.json`, lockfile, file tanpa ekstensi dengan shebang dan tanpa).
2. File tepat `1_048_576` bytes → analyzed; `1_048_577` → `skipped/file_too_large`.
3. PR hanya `.py` → skor `N/A`, `min_score` dilewati, exit `0` (default).
4. PR hanya `.py` + `fail_on_unanalyzable: 'true'` → exit `1`.
5. PR campuran → skor dari file analyzed saja, baris coverage benar, teks alasan baku.
6. Output rule untuk file analyzed identik dengan baseline v1.2.1 (regression).
7. SARIF memuat `toolExecutionNotifications` untuk skipped, dan jumlah `results` tidak berubah.
8. Daftar skipped panjang terpotong `+N more` di komentar, lengkap di SARIF.
9. Kontrak: input `fail_on_unanalyzable` konsisten di `action.yml` ↔ README ↔ workflow ↔ tes kontrak.
10. Satu file yang melempar exception → `skipped/internal_error`, file lain tetap dianalisis.

## 5. Larangan Eksplisit (cek mekanis di akhir)

Diff Stage 5.1 **tidak boleh** memuat identifier berikut: `DYN`, `SpanMap`, `FOLD`, `EV-01`, `CRITICAL_FLOW_IDENTIFIERS`, `scoring: false`, `via-fold`. Buktikan dengan:

```
git diff main...HEAD | grep -nE "DYN|SpanMap|FOLD|EV-01|CRITICAL_FLOW_IDENTIFIERS|scoring: false|via-fold" || echo "BERSIH"
```

(ganti `main` dengan nama branch dasar yang benar) Output harus `BERSIH`.

## 6. Verifikasi & Bukti Wajib

Di akhir, jalankan dan tempel output aktual:

```
npm run lint
npm run build
npm test
git diff --stat main...HEAD
git log --oneline main..HEAD
```

Syarat lulus: lint dan build sukses; `npm test` = **35 tes lama + tes baru, 0 gagal**, tanpa tes dinonaktifkan; jumlah tes tidak turun dari 35.

Bukti tambahan:
1. `git diff` aktual untuk: klasifier, titik penempatan sebelum filter ekstensi, perhitungan skor/exit code, renderer, generator SARIF, `action.yml`, `README.md`, workflow, tes kontrak.
2. Ringkasan PR nyata dari fixture/uji: satu campuran (`.py` + `.ts`) dan satu hanya-`.py`.
3. Potongan SARIF nyata yang memuat `toolExecutionNotifications`.
4. Bukti invarian lulus (nama tes + output).
5. Hasil pengecekan larangan §5 (`BERSIH`).
6. Jika push dimungkinkan: link run GitHub Actions. Jika tidak dipush, tulis jelas **"belum dipush, CI belum diverifikasi"**; jangan mengklaim CI hijau.

## 7. Evaluasi Risiko (guardrail untuk pelaksana)

**Anti-survivorship — kegagalan umum fitur pelaporan coverage:**
- Laporan coverage yang bohong karena klasifikasi salah (file kode dicap `ignored`).
- Pesan "skipped" yang membuat pengguna menganggap PR aman atau gagal.
- Penghitung yang tidak sinkron dengan daftar file (off-by-one pada rename/delete).

**Single Point of Failure — perkuat dulu:**
1. **Penempatan klasifier sebelum filter ekstensi (D7).** Jika salah tempat, `.py` tidak pernah terlihat dan fitur gagal total. Tes #1 dan #3 adalah gerbangnya.
2. **Jalur `totalScore = null`.** Gerbang CI bergantung padanya; `null` yang bocor ke perbandingan `min_score` dapat menggagalkan atau meloloskan PR secara keliru. Tes #3 dan #4.
3. **Konstanta ekstensi ganda.** Dua daftar akan divergen. T1 menghapusnya.

**Pre-mortem — skenario kegagalan total dan mitigasinya:**

| Skenario | Mitigasi dalam tugas ini |
|---|---|
| Regresi: output rule berubah untuk file analyzed | Tes #6 (identik dengan baseline), tidak menyentuh kode rule |
| `N/A` tak sengaja menggagalkan/meloloskan CI | T6 + tes #3/#4 |
| Komentar PR terlalu panjang | `+N more` + SARIF lengkap (tes #8) |
| Kontrak `action.yml`/README/workflow/tes tidak sinkron | T10 satu commit + tes #9 |
| Satu file buruk meruntuhkan seluruh run | `internal_error` per file, fail-open (tes #10) |
| Scope creep ke 5.2–5.4 | Larangan §5 + pengecekan mekanis `BERSIH` |
| Rahasia bocor lewat log/fixture | Aturan keras #7 |

## 8. Format Laporan Akhir (wajib, berurutan)

1. **Tabel Stage 5.0** (dicetak sebelum edit; salin ulang ringkas di sini) dan daftar **DEVIASI** dari SPEC (jika ada).
2. **Baseline** (output Langkah 0).
3. **Ringkasan perubahan per berkas** (path + tujuan, bukan narasi panjang).
4. **Bukti §6** (output aktual, bukan ringkasan).
5. **Perubahan pada tes existing** (hanya Test 6/29), tiap perubahan dengan alasan.
6. **Hal yang sengaja tidak dikerjakan** (Stage 5.2–5.4) dan **temuan Stage 5.0 yang relevan untuk 5.2/5.3a** (D1, D4, D5) agar prompt berikutnya akurat.
7. **Status jujur:** apa yang terverifikasi (dengan bukti), apa yang belum (mis. CI belum dijalankan).
