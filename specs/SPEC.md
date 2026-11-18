# DevGuard v1.3.0 — SPEC (Stage 5) — Rev 2.3

**Tema:** Explicit Unanalyzable Reporting & Lexical Constant Folding (SpanMap)
**Baseline:** `v1.2.1` — hijau di GitHub Actions, `35/35` tes lulus
**Status:** Stage 5.1 sudah di-merge ke `main` (merge `d4801e7`, implementasi `c5f7129`, `45/45` tes lokal) dan **masih mengandung cacat yang diketahui** (§0, §4.8): `main` belum boleh dirilis atau di-tag. **Referensi baseline v1.2.1 adalah commit `e67c869` (tag `v1.2.1`), bukan `main`.** Berkas ini berada di `specs/SPEC.md` (salinan duplikat `docs/specs/` dihapus di Rev 2.3). §4 rev 2.1–2.3 mengamandemen Stage 5.1 dan diwujudkan oleh Stage **5.1-fix / 5.1-hardening** (§4.8). §5–§9 tidak berubah dari rev 2.
**Catatan:** dokumen ini tidak mengubah kode apa pun.

Konvensi penanda:
- `[TERVERIFIKASI]` = fakta repo `v1.2.1` yang dilaporkan pemilik repo atau terlihat di diff. Tetap dikonfirmasi ulang di pre-flight.
- `[ASUMSI]` = belum diverifikasi; dicek di pre-flight tahap terkait.

---

## 0. Perubahan dari Rev 2

> **Rev 2.1 → 2.2:** hanya koreksi referensi (status merge ke `main`, baseline v1.2.1 = `e67c869`, lokasi berkas `specs/`). Tidak ada perubahan perilaku.
> **Rev 2.2 → 2.3 (`Stage 5.1-hardening`):**
> - **C4:** Duplikat `docs/specs/` dihapus (`git rm -r docs/specs/`); `specs/SPEC.md` menjadi sumber kebenaran tunggal.
> - **C2:** Cakupan parsial `.py` didokumentasikan akurat: menjalankan `DG001`, `DG002`, `DG007` (serta heuristik domain SQL/ping), sedangkan detektor spesifik JS/TS/NPM `DG004`, `DG005`, `DG006`, dan `DG008` dilewati.
> - **G1 (Self-Ref Anchoring):** Pengecualian self-reference (`src/devguardAnalyzer.ts`, `scripts/devguard_verify.py`, `devguard_verify.py`) dijangkar ke path repo-relatif eksak dan hanya aktif bila `package.json` pada `cwd` memiliki `"name": "devguard"`.
> - **G2 / D12 (`ignored/excluded_path` pada mode `modified`):** `discoverInScopeFiles('modified', cwd)` mengembalikan seluruh path dari `git diff` tanpa pre-filter sebelum klasifier; path yang cocok `isExcludedPathFromScope` dipetakan ke `status: 'ignored', reason: 'excluded_path'` sehingga invarian `analyzed + skipped + ignored === total_diff_files` berlaku atas **seluruh** berkas diff dan dirender sebagai `- Ignored (excluded path): N` bila `N > 0`.
> - **R1 (`GITHUB_OUTPUT` Early Exit):** Jalur `exit 1` awal (`DEVGUARD_FAIL_ON_UNANALYZABLE` tidak valid atau argumen CLI eksplisit hilang) menulis `overall_score=N/A` dan `audit_status=FAIL` ke `GITHUB_OUTPUT` sebelum `process.exit(1)`.
> - **R2 (SARIF & PR Clean Invariant Mismatch):** Sentinel `<invariant-mismatch>` tidak dimasukkan ke URI `locations` SARIF (menghilangkan `locations` pada notifikasi invarian) dan dirender sebagai `- Coverage invariant mismatch — Skipped: Internal error` tanpa karakter `< >` pada komentar PR.

| Area | Rev 2 | Rev 2.1 | Alasan |
|---|---|---|---|
| `.py` | `skipped/unsupported_language` | `analyzed` dengan `coverage: partial` (hanya rule bahasa-agnostik, persis seperti v1.2.1) | Filter discovery v1.2.1 sudah menyertakan `.py`; skip total = regresi kapabilitas keamanan (mis. deteksi secret) `[TERVERIFIKASI]` |
| `parse_error` / `internal_error` | fail-open, non-fatal | file lain tetap diproses, **verdict gagal (`exit 1`)**, SARIF `executionSuccessful: false` | Crash payload membuat PR lolos hijau; terkonfirmasi di diff: `gateFailed = hasFatalFailure \|\| unanalyzableFailed` |
| Pelanggaran invarian coverage | hanya log | fatal | Konsisten dengan fail-closed |
| Badge saat `analyzed == 0` | tidak ditetapkan | `⚠️ NOT ANALYZED — no supported code files` | Implementasi menampilkan `READY TO MERGE` untuk nol analisis |
| Badge saat hanya ada analisis parsial | — | `⚠️ PARTIALLY ANALYZED — language-agnostic rules only` | Skor 100/100 dari `.py` tidak boleh terbaca sebagai cakupan penuh |
| Parsing `fail_on_unanalyzable` | `'true'` | ketat `true`/`false`; nilai lain → exit `1`; hanya `DEVGUARD_*`, tanpa fallback `INPUT_*` | Salah ketik tidak boleh mematikan mode ketat secara diam-diam; ikuti konvensi |
| Versi di komentar PR/log | `v1.3.0` ditulis permanen | diturunkan dari `package.json` (satu helper) | Menghindari komentar yang berbohong sebelum Stage 5.5 |
| `ignored/deleted` | semua mode | hanya dari `git diff` (mode `modified`); argumen file eksplisit yang tidak ada → gagal jelas | Typo path tidak boleh menjadi "deleted" |
| Kebijakan path (`scripts/`, nama file hardcoded) | tidak dibahas | **dilarang diubah di Stage 5.1** | Implementasi mengubah pengecualian `scripts/` dan menambah nama file hardcoded demi fixture tes |
| Known limitations | — | §4.6 | Pengecualian path sebelum klasifikasi tidak terlihat di coverage |
| Perubahan perilaku | — | §4.7 | Harus didokumentasikan |

## 1. Tujuan

1. **Tidak ada silent miss.** Setiap in-scope file berakhir di `analyzed` (penuh atau parsial), `skipped` (dengan alasan), atau `ignored` (dengan alasan). Skor `100/100` tidak boleh muncul untuk PR tanpa file teranalisis.
2. **Tidak ada fail-open pada keputusan.** Kegagalan analisis menggagalkan verdict, tidak meloloskannya.
3. **Menutup bypass lexical murah** (`"ev"+"al"`, `obj["prop"]`, `["a","b"].join("")`) tanpa false positive baru.
4. **Dua varian evasion** (`DG008-EV-01`, `DG005-EV-01`) dan **peringatan dynamic specifier** (`DG004-DYN-01/02`).
5. **Disiplin promosi severity** lewat gerbang bukti (§9).

## 2. Non-Goals (v1.3.0)

- Analyzer bahasa selain JS/TS (selain perilaku parsial `.py` yang diwarisi dari v1.2.1).
- Parser AST penuh, tokenizer baru, atau data-flow/taint.
- Constant propagation lintas variabel (`const a = "ev"; a + "al"` tidak dilipat).
- Dekode string (`atob`, `String.fromCharCode`, escape `\x..`/`\u....`), `.concat()`, template berisi ekspresi, kurung pembungkus `("a")`.
- Resolusi alias (`const e = eval; e(x)`).
- Mengubah kebijakan pengecualian path (§4.6).
- Promosi otomatis severity di dalam rilis v1.3.0.
- Klaim "zero false positive" absolut. Klaim README yang diizinkan: *"tidak ada FP yang diketahui pada corpus dan repo validasi yang terdaftar."*

## 3. Terminologi

| Istilah | Definisi |
|---|---|
| **In-scope files** | File yang dienumerasi action: pada mode `modified`, seluruh berkas `git diff` masuk langsung ke klasifier (termasuk path yang akhirnya diklasifikasikan sebagai `ignored/excluded_path`); pada mode `all` tetap setelah pengecualian direktori `AUTO_DISCOVERY_EXCLUDED_DIRS` (§4.6) agar tidak menyusuri `node_modules`. Klasifier menerima daftar ini sebelum filter ekstensi. |
| **Analyzed (full)** | Ekstensi `.ts .tsx .js .jsx .mjs .cjs .mts .cts` `[TERVERIFIKASI]`, ukuran ≤ `MAX_FILE_BYTES`. |
| **Analyzed (partial)** | Ekstensi `PARTIAL_ANALYSIS_EXTENSIONS = ['.py']`, ukuran ≤ `MAX_FILE_BYTES`. Analyzer dipanggil persis seperti v1.2.1 (menjalankan `DG001`, `DG002`, `DG007`, serta heuristik domain SQL/ping; melewati `DG004`, `DG005`, `DG006`, `DG008`). |
| **Skipped** | File kode yang seharusnya diperiksa tetapi tidak bisa. Selalu ada `reason`. |
| **Analysis failure** | `skipped` dengan `reason` `parse_error` atau `internal_error`, atau pelanggaran invarian coverage. Selalu fatal. |
| **Ignored** | File non-kode atau tidak relevan. Dihitung terpisah. |
| **Virtual view (V)** | String hasil lipatan dari source asli (O), dipakai untuk pass aditif, selalu disertai `SpanMap`. |
| **Non-scoring warning** | Finding `warning` tanpa penalti skor dan tanpa dampak exit code. |

---

## 4. Fitur A — Pelaporan Unanalyzable / Skipped *(Stage 5.1, diamandemen rev 2.1)*

### 4.1 Klasifikasi

Setiap in-scope file diklasifikasikan **tepat satu kali**:

| Status | `coverage` / `reason` | Aturan |
|---|---|---|
| `analyzed` | `coverage: full` | ekstensi JS/TS (8) dan ukuran ≤ `1_048_576` |
| `analyzed` | `coverage: partial` | `.py` dan ukuran ≤ `1_048_576`; analyzer dipanggil tanpa perubahan dari v1.2.1 |
| `skipped` | `unsupported_language` | allowlist ekstensi kode (kecuali `.py`): `.pyw .go .java .kt .rb .php .rs .cs .swift .c .cpp .h .sh` dll., plus `.vue .svelte .astro .ipynb`; file tanpa ekstensi berawalan `#!` |
| `skipped` | `file_too_large` | > `1_048_576` bytes, berlaku untuk full maupun partial (cek `stat` sebelum membaca isi). `console.warn` v1.2.1 dipertahankan |
| `skipped` | `parse_error` | scanner/masker gagal pada file itu. **Fatal.** |
| `skipped` | `internal_error` | exception tak terduga pada file itu. **Fatal.** |
| `ignored` | `non_code` | lockfile, gambar, `.md`, `.json`, `.yml`, `.txt`, `.html`/`.htm`, direktori/submodule, dll. |
| `ignored` | `deleted` | **hanya** untuk file yang muncul dari `git diff` (mode `modified`) dan tidak ada di disk |
| `ignored` | `excluded_path` | path pada mode `modified` (`git diff`) yang cocok dengan `isExcludedPathFromScope` (`scripts/`, `tests/`, `dist/`, `.github/`, `*.test.*`, `*.spec.*`, `*.d.ts`, dan pengecualian self-reference terjangkar `src/devguardAnalyzer.ts` / `scripts/devguard_verify.py` saat `package.json` `name === "devguard"`) |

Aturan:
- **Invarian (diuji):** `analyzed + skipped + ignored == |in-scope files|`. Pada mode `modified` (`git diff`), invarian ini berlaku atas **seluruh** file di `git diff` tanpa pengecualian tersembunyi karena `discoverInScopeFiles('modified', cwd)` menyerahkan semua path diff ke klasifier dan memetakan path ter-exclude ke `ignored/excluded_path`. Mode `all` tetap melewati `AUTO_DISCOVERY_EXCLUDED_DIRS` saat traversal direktori agar tidak menyusuri `node_modules`. Pelanggaran invarian saat runtime = analysis failure (fatal).
- **Self-reference anchoring:** pengecualian `src/devguardAnalyzer.ts`, `scripts/devguard_verify.py`, dan `devguard_verify.py` dijangkar ke path repo-relatif eksak dan **hanya** aktif ketika `package.json` pada `cwd` bernilai `"name": "devguard"`. Berkas seperti `src/devguard_verify.py` atau `pkg/devguardAnalyzer.ts` pada repo pengguna tetap diaudit.
- Daftar ekstensi analyzable (JS/TS) adalah satu konstanta bersama (`ANALYZABLE_EXTENSIONS`) yang dipakai klasifier, analyzer, dan discovery. `PARTIAL_ANALYSIS_EXTENSIONS` berdampingan dengannya.
- Discovery mempertahankan perilaku v1.2.1 untuk `.py`: `discoverWorkspaceFiles` tetap mengembalikan `.py` seperti sebelumnya.
- **Argumen file eksplisit** (CLI) yang tidak ditemukan di disk → gagal jelas sebelum klasifikasi (`exit 1`, pesan memuat path). Tidak boleh menjadi `ignored/deleted`.
- Urutan evaluasi: ekstensi → (analyzable/partial) ukuran → scan.

### 4.2 Semantik skor dan badge

Perhitungan penalti v1.2.1 tidak berubah `[TERVERIFIKASI]`: per finding, kumulatif, tanpa cap, `Math.max(0, 100 - sum)` per kategori, dirata-rata, dibandingkan dengan `min_score` (default `85`).

- Skor dihitung dari semua file `analyzed` (full dan partial, paritas v1.2.1).
- `analyzed == 0` → `totalScore = null`, ditampilkan `N/A`, perbandingan `min_score` dilewati, `overall_score=N/A` ditulis ke `GITHUB_OUTPUT` (string `N/A`).
- Badge status komentar PR, dievaluasi **berurutan**, yang pertama cocok dipakai:

| # | Kondisi | Badge |
|---|---|---|
| 1 | gerbang gagal karena skor/finding (perilaku v1.2.1) | `🚫 REJECTED (SECURITY GATE FAILED)` |
| 2 | ada analysis failure | `🚫 REJECTED (ANALYSIS ERROR)` |
| 3 | `fail_on_unanalyzable` aktif dan `skipped > 0` | `🚫 REJECTED (UNANALYZED FILES)` |
| 4 | `analyzed == 0` | `⚠️ NOT ANALYZED — no supported code files` |
| 5 | `analyzed > 0` dan semua file analyzed berstatus partial | `⚠️ PARTIALLY ANALYZED — language-agnostic rules only` |
| 6 | selain itu | `✅ PASSED (READY TO MERGE)` |

Badge 4 dan 5 tidak mengubah exit code (`0`) secara default. `audit_status` mengikuti exit code (`PASS`/`FAIL`).

Headline (satu baris, versi dari `package.json`):

```
DevGuard v<versi> — Score: 97/100  (analyzed 3 of 5 code files · 1 partial · 2 skipped)
```

Segmen `· N partial` hanya muncul bila `N > 0`. Contoh blok coverage:

```
Coverage
- Analyzed: 3
    - scripts/etl.py — Partial: language-agnostic rules only
- Skipped: 2
    - tools/deploy.go — Skipped: Unsupported language
    - tools/big.js    — Skipped: File too large (> 1 MiB)
- Ignored (non-code): 4
- Ignored (excluded path): 1
```

Baris `- Ignored (excluded path): N` hanya muncul bila `N > 0`. Entri mismatch invarian internal dirender sebagai `    - Coverage invariant mismatch — Skipped: Internal error` (tanpa karakter `< >`). Daftar partial dan skipped dipotong dengan `+N more` di komentar (cap tampilan 20 per daftar); daftar penuh ada di SARIF.

### 4.3 Input action & exit code

- Input: **`fail_on_unanalyzable`**, `snake_case`, default `'false'`, dibaca dari `DEVGUARD_FAIL_ON_UNANALYZABLE` via `process.env`. **Tidak ada** fallback `INPUT_FAIL_ON_UNANALYZABLE` (konvensi input lain hanya `DEVGUARD_*` `[TERVERIFIKASI]`).
- **Parsing ketat:** nilai yang di-trim dan di-lowercase harus `true` atau `false`; kosong/tidak diset → `false`. Nilai lain (`yes`, `1`, `ture`) → menulis `overall_score=N/A` dan `audit_status=FAIL` ke `GITHUB_OUTPUT`, pesan error jelas, dan `exit 1`. Alasan: salah ketik pada tombol gerbang tidak boleh berubah menjadi "mati" secara diam-diam.
- Tidak ada input `fail_on_warning` `[TERVERIFIKASI: belum ada]`; tidak ditambahkan.
- **Exit `1`** bila salah satu: (a) gerbang per-file gagal (skor/finding, v1.2.1), (b) ada analysis failure, (c) `fail_on_unanalyzable: 'true'` dan `skipped > 0`, (d) konfigurasi input tidak valid (menulis `overall_score=N/A` & `audit_status=FAIL` ke `GITHUB_OUTPUT`), (e) argumen file eksplisit tidak ditemukan (menulis `overall_score=N/A` & `audit_status=FAIL` ke `GITHUB_OUTPUT`).
- Skipped biasa (`unsupported_language`, `file_too_large`) dan `ignored/*` **tidak** menggagalkan secara default.
- **Kontrak:** `action.yml`, `README.md`, workflow `.github/workflows/devguard.yml`, dan tes kontrak (Test 6 dan Test 29) disinkronkan dalam satu commit.

### 4.4 SARIF

- `runs[0].invocations[0].executionSuccessful` = `false` bila ada analysis failure; selain itu `true`.
- `toolExecutionNotifications[]`:
  - skipped → `level: "note"`, teks baku alasan, `uri` = path;
  - partial → `level: "note"`, teks `Partial: language-agnostic rules only`;
  - analysis failure → `level: "error"`, teks `Skipped: Parse error` / `Skipped: Internal error`. Notifikasi pelanggaran invarian (`INVARIANT_MISMATCH_SENTINEL`) menghilangkan array `locations` (tidak menulis `<invariant-mismatch>` sebagai URI artefak fisik).
- Tidak ada `result` baru untuk semua di atas. Teks lewat redaksi secret.

### 4.5 Teks baku alasan

| `reason` | Teks |
|---|---|
| `unsupported_language` | `Skipped: Unsupported language` |
| `file_too_large` | `Skipped: File too large (> 1 MiB)` |
| `parse_error` | `Skipped: Parse error` |
| `internal_error` | `Skipped: Internal error` |
| (coverage partial) | `Partial: language-agnostic rules only` |

### 4.6 Known limitations (pra-ada di v1.2.1, diperbarui Rev 2.3, harus diungkapkan di README)

1. **Pengecualian path menurut mode:** Pada mode `modified` (`git diff`), direktori titik (`.github/`, `.husky/`), `node_modules`, `dist`, `scripts/`, `tests/`, `*.d.ts`, `*.test.*`, `*.spec.*`, dan self-reference terjangkar `devguard` kini tetap terlihat di klasifier dan dilaporkan sebagai `ignored/excluded_path` (`- Ignored (excluded path): N` bila `N > 0`) tanpa pengecualian tersembunyi. Pada mode `all`, direktori dalam `AUTO_DISCOVERY_EXCLUDED_DIRS` tetap dilewati saat traversal agar tidak menyusuri `node_modules`.
2. **Mode eksplisit CLI** di v1.2.1 tidak memfilter ekstensi; di v1.3.0 argumen eksplisit mengikuti klasifier (D10) dan tidak masuk `excluded_path`.
3. **`target_files` selain `all`/`modified`:** perilaku aktual diperiksa di pre-flight; tidak diubah di sini `[ASUMSI]`.

### 4.7 Perubahan perilaku yang wajib didokumentasikan (README/CHANGELOG)

- `.mjs .cjs .mts .cts` kini ditemukan oleh discovery (sebelumnya tidak diaudit di CLI).
- PR tanpa file teranalisis menghasilkan `overall_score=N/A` (sebelumnya `100`) dan komentar PR sticky tetap diposting (sebelumnya tanpa komentar). Konsumen numerik `overall_score` perlu menyesuaikan.
- Kegagalan analisis menggagalkan check (sebelumnya crash/diam, tergantung jalur).
- File di atas 1 MiB kini muncul di coverage sebagai skipped.
- `.py` dilaporkan sebagai cakupan parsial.

### 4.8 Stage 5.1-fix (menutup temuan review)

Wajib dalam fix-up (detail di `PROMPT-STAGE-5.1-FIXUP.md`):
1. Hapus special-case nama fixture di kode produksi.
2. Kembalikan pengecualian path `scripts/` dan nama file hardcoded ke perilaku v1.2.1 (`e67c869`).
3. Implementasi `coverage: partial` untuk `.py` (baseline golden dari v1.2.1).
4. Fail-closed untuk analysis failure dan pelanggaran invarian; SARIF `executionSuccessful`.
5. Badge §4.2; headline dan blok coverage dengan partial.
6. Parsing input ketat; hapus `INPUT_*`.
7. Versi dari `package.json`.
8. `deleted` hanya dari diff; argumen eksplisit hilang → gagal jelas.
9. README: partial, `N/A`, fail-closed, §4.6, §4.7.
10. Pulihkan fixture asli Test 6c (`.py`); fixture "skipped" pada tes baru memakai bahasa yang benar-benar skipped (mis. `.go`).

---

## 5. Fitur B — Constant Folding via `SpanMap` (Stage 5.3)

### 5.1 Prinsip

1. **Lexical, bukan AST.** Tidak ada parser baru. Klasifikasi region (kode / string / template / komentar / regex) berasal dari `src/rules/lexicalMasker.ts`. Pre-flight D1 `[TERVERIFIKASI]`: `analyzeLexicalStructure` hanya mengembalikan `{ maskedCode, stringLiterals, suppressions }`; Stage 5.3a menambah ekspor klasifikasi region **tanpa mengubah output masked**.
2. **Konservatif:** jika ada keraguan sintaktis, tidak dilipat.
3. **Source asli tidak pernah dimutasi.** V adalah string terpisah.
4. **Fail-open pada pelipatan** (bukan pada verdict): exception, batas terlampaui, atau ambiguitas → tidak ada edit; V tetap sama dengan O untuk bagian itu.
5. **Lokasi selalu dihitung dari O melalui `SpanMap`.** Aturan di V melaporkan **offset**, bukan nomor baris V.

### 5.2 Pipeline

```
O (source asli)
 └─► [1] Masker: klasifikasi region O
      └─► [2] Fold (hanya di region kode), maksimal MAX_FOLD_DEPTH pass
           urutan per pass: FOLD-03 → FOLD-01 → FOLD-02 → FOLD-04
           └─► [3] V + SpanMap  (jika 0 edit: V == O, pass aditif dilewati)
                └─► [4] Masker dijalankan ulang pada V
                     └─► [5] Eksekusi rule aditif pada V
                          └─► [6] Petakan finding ke O via SpanMap,
                               buang duplikat terhadap finding pass-O,
                               tag evidence `via-fold`
```

Pass-O (rule v1.2.1 pada O) berjalan **persis seperti sekarang**. Pass-V hanya menambah.

### 5.3 SpanMap

```ts
type Seg = { vStart: number; vEnd: number; oStart: number; oEnd: number; kind: 'copy' | 'fold' };
type SpanMap = Seg[]; // terurut, tidak overlap, menutup [0, |V|)
```

- `copy`: panjang V sama dengan O; offset dipetakan linear.
- `fold`: seluruh rentang V dipetakan ke seluruh rentang O dari ekspresi asal.
- Komposisi antar-pass: peta pass-n dikomposisi dengan pass-(n-1); `fold` pada pass lanjut mengambil gabungan rentang O.
- `toOrig(vStart, vEnd)`: binary search; posisi di dalam segmen `fold` diperluas ke seluruh rentang O segmen itu. Hasil dipakai untuk line/col, redaksi, dan suppression, semuanya pada O.
- **Invarian (property test):** (a) segmen terurut dan menutup V; (b) untuk setiap karakter di segmen `copy`, `V[i] === O[toOrig(i)]`; (c) `toOrig` monoton; (d) rentang O hasil pemetaan berada dalam `[0, |O|]`.

### 5.4 Operasi lipatan

Semua operan literal **tanpa backslash** dan tanpa newline. Operan berisi `\` → ekspresi itu tidak dilipat. Literal hasil memakai tanda kutip operan pertama; jika konten hasil memuat tanda kutip itu, tidak dilipat.

| ID | Input | Output di V |
|---|---|---|
| `FOLD-03` | template tanpa `${}`, tanpa newline, tanpa backslash, bukan tagged | string literal biasa |
| `FOLD-01` | `"ev" + "al"` (rantai `+` literal) | `"eval"` |
| `FOLD-02` | `["a","b"].join("")`, `.join("-")`, atau `.join()` | `"ab"`, `"a-b"`, `"a,b"` |
| `FOLD-04` | `obj["balance"]`, `obj?.["balance"]` | `obj.balance`, `obj?.balance` |

**Guard prioritas operator (FOLD-01).** Sub-rantai literal `L1 + L2 + ...` boleh dilipat hanya jika:
- token sebelum `L1` termasuk: pembuka (`(` `[` `{` `,` `;` `:` `?` `=` `=>` `...` `return`), operator berprioritas lebih rendah dari `+` (`==` `!=` `===` `!==` `<` `>` `<=` `>=` `<<` `>>` `>>>` `&` `^` `|` `&&` `||` `??`), atau `+` **biner** (token sebelum `+` itu adalah identifier/literal/`)`/`]`). Tidak boleh: `-` `*` `/` `%` `**` `!` `~` `typeof` `void` `delete` `await` `new` `.` `?.`, atau `+` unary.
- token setelah literal terakhir bukan `.` `?.` `[` `(` `` ` `` `*` `/` `%` `**`.

Contoh yang **tidak** boleh dilipat: `x - "a" + "b"`, `2 * "a" + "b"`, `"a" + "b".length`, `"a" + "b" * 2`, `+"a" + "b"`, `typeof "a" + "b"`.

**Guard posisi `[` (FOLD-02 dan FOLD-04).** `[` adalah *array literal* bila token sebelumnya bukan identifier non-keyword / `)` / `]` / `?.`; selain itu *member access*.
- `FOLD-04` hanya pada member access. Token sebelum `[` harus: identifier bukan keyword (`return typeof in of instanceof new delete void throw case do else yield await extends` dikecualikan), `]`, `?.`, atau `)` — dengan syarat kurung pembukanya (back-scan maksimum `MAX_BACKSCAN`) **bukan** milik `if|while|for|with|switch|catch`. Token sebelumnya `}`, angka, atau template tidak dinormalisasi.
- `FOLD-04`: isi bracket (selain whitespace) harus tepat satu string literal berisi identifier name ASCII `/^[A-Za-z_$][\w$]*$/`. `obj["a-b"]`, `obj["0"]`, `obj[""]` tidak diubah. Untuk `?.["x"]`, penggantian mencakup `?.` sehingga hasilnya `?.x`, bukan `?..x`.
- `FOLD-02` hanya pada array literal, elemen hanya string literal (hasil lipatan pass sebelumnya boleh), tanpa spread/hole/trailing comma. Argumen `join` string literal atau kosong. Hasilnya ekspresi primer; boleh diikuti `.length`, `(`, dll.
- Template tagged (didahului identifier/`)`/`]`) tidak dilipat.

**Contoh komposisi:** `x[["ev","al"].join("")]` → pass 1: F02 menghasilkan `x["eval"]` → F04 menghasilkan `x.eval`. `window["ev"+"al"](a)` → `window.eval(a)`.

### 5.5 Batas (deterministik, berbasis hitungan)

`[ASUMSI]` nilai awal; **wajib divalidasi dengan benchmark** (gate §10, Stage 5.3b). Tidak ada klaim performa tanpa angka terukur.

| Konstanta | Nilai awal | Bila terlampaui |
|---|---|---|
| `MAX_FILE_BYTES` | 1_048_576 | `skipped/file_too_large` |
| `MAX_FOLD_DEPTH` (jumlah pass) | 4 | berhenti; V = hasil pass terakhir yang valid |
| `MAX_FOLD_OPERANDS` | 64 per rantai/array | ekspresi itu tidak dilipat |
| `MAX_FOLDED_LENGTH` | 4096 karakter | ekspresi itu tidak dilipat |
| `MAX_FOLD_EDITS` | 2000 per file | pelipatan berhenti; V = edit yang sudah valid |
| `MAX_BACKSCAN` | 256 karakter | bracket tidak dinormalisasi |

Bila batas terpicu: SARIF notification `fold_limit_exceeded` (`note`, dedupe per file), bukan finding, tidak crash. Seluruh batas berbasis hitungan, bukan wall-clock.

### 5.6 Eksekusi rule & dedupe

- Pass-V dijalankan **hanya jika ≥ 1 edit** diterapkan.
- Finding pass-V dianggap duplikat bila ada finding pass-O dengan `ruleId` sama yang rentang O-nya **overlap** dengan hasil `toOrig`.
- Finding yang lolos diberi tag evidence `via-fold`.
- Suppression, redaksi, dan penomoran baris dijalankan pada rentang O hasil pemetaan.
- **Mode rule:** rule v1.2.1 = `original + additive-virtual`. `DG004-DYN-*` = `virtual-only`.

---

## 6. Fitur C — Deteksi Baru

### 6.1 `DG004-DYN-01` / `DG004-DYN-02` — dynamic specifier *(non-scoring warning)*

| ID | Pola |
|---|---|
| `DG004-DYN-01` | `import(<non-literal>)` |
| `DG004-DYN-02` | `require(<non-literal>)` |

Deteksi (lexical, pada V, di region kode):
- **Literal** = tepat satu token string literal atau template tanpa ekspresi, diikuti `)` atau `,`. Selain itu non-literal. Panggilan tanpa argumen tidak dilaporkan.
- `import(`: token sebelumnya bukan `.`/`?.`. `import.meta` dan `import x from` tidak cocok. Bila setelah `)` penutup langsung diikuti `{`, ini definisi method, dilewati.
- `require(`: token sebelumnya bukan `.`/`?.`; pengecualian method definition sama.
- **Shadow guard (file-level, konservatif):** kemunculan token `require` hanya diizinkan sebagai `require(`, `require.<member>`, atau `typeof require`. Kemunculan lain → DYN-02 dilewati untuk file itu, metrik `dyn_scope_uncertain`.
- Pesan finding tidak memuat teks ekspresi mentah; hanya `file:line` dan kategori. Snippet (bila ada) lewat redaksi secret v1.2.1.
- Cap tampilan `MAX_DYN_FINDINGS_PER_FILE = 20`; sisanya `+N more`. Semua finding ada di SARIF.

Severity dan skor:
- `warning`, **tidak mengurangi skor** dan tidak mempengaruhi exit code. Alasan: penalti existing `-10` per finding tanpa cap `[TERVERIFIKASI]`.
- Ditampilkan terpisah sebagai "Warnings (non-scoring)". SARIF `level: "warning"`, `properties.scoring: false`.
- Perubahan scoring: finding berflag `scoring: false` dilewati penghitung penalti. Wajib tes bahwa N finding DYN menghasilkan skor identik dengan 0 finding DYN.

**Suppression:** hanya lewat `.devguard.json` dari **base branch**. **Tidak ada inline suppression** (penulis PR tidak dipercaya; kebijakan seluruh sub-aturan `DG004` `[TERVERIFIKASI]`).
- Pre-flight D4 `[TERVERIFIKASI]`: `.devguard.json` saat ini hanya mendukung path eksak atau akhiran `/**` tunggal. Stage 5.2 menambah matcher glob **linear-time buatan sendiri** (tanpa mengompilasi pola pengguna menjadi RegExp) dan tes.

### 6.2 `DG008-EV-01` — `do { ... } while (true | 1)`

Perluasan `DG008` existing `[TERVERIFIKASI]`: DG008 mendeteksi `while (true)`, `while (1)`, `for (;;)` yang memuat `await` tanpa `break`, `return`, `throw`, `process.exit`, atau bounded retry check. EV-01 menambah `do { ... } while (true | 1)` dengan **syarat body lexical yang sama**.

- Jangkar deteksi: token `do` (bukan `.do`, bukan nama method/properti `do`) diikuti `{`; kurung kurawal dicocokkan pada teks termasking; setelah `}` harus muncul `while ( true | 1 )`.
- Blok biasa diikuti `while(true){...}` bukan do-while: tanpa token `do` yang mengawali blok, tidak ada finding.
- Body scan memakai **helper yang sama** dengan DG008 existing (diekstrak, **tidak disalin**).
- Tidak didukung: body tanpa kurung kurawal.
- Severity/skor: **mewarisi DG008 `warning`** (`-10` correctness per finding). Paritas: jika varian `do/while` bebas penalti, menulis ulang `while` menjadi `do/while` menjadi cara murah menghindari penalti.
- Suppression: mengikuti DG008 existing. Pre-flight D5 `[TERVERIFIKASI]`: inline suppression `DG008` diizinkan untuk semua severity dengan alasan ≥ 8 karakter dan ≥ 2 kata alfabetis.

### 6.3 `DG005-EV-01` — `.catch(() => {})` pada flow kritikal

- **Callback kosong:** arrow/function expression dengan body kosong setelah masking: `() => {}`, `_ => {}`, `(e) => {}`, `function () {}`, `function (e) {}`. Bukan: `() => null`, `() => undefined`, `.catch(noop)`, callback dengan statement apa pun, `try {} catch {}`, `.then(a, () => {})`.
- **Critical flow:** konstanta tunggal `CRITICAL_FLOW_IDENTIFIERS` diekstrak ke `src/rules/` dan dipakai bersama `try/catch` DG005 existing dan EV-01. Isi saat ini `[TERVERIFIKASI]`: `payment`, `balance`, `wallet`, `ledger`, `transfer`, `charge`, `refund`, `deduct`, `invoice`, `auth`, `token`, `jwt`, `password`, `execute`, `query`, `transaction`, `writeFileSync`. Fungsi pencocokan yang sama dengan DG005 existing.
- **Cakupan pencocokan:** hanya **nama dalam rantai receiver** (pemanggilan/properti pada rantai yang berakhir di `.catch`), **bukan** argumen pemanggilan atau identifier di fungsi sekitarnya.
- **Pengecualian cleanup:** pengecualian existing DG005 (`unlink`, `rmSync`, `close`, `JSON.parse`) dievaluasi pada **pemanggilan yang langsung mendahului `.catch`**. `pay.charge(x).then(() => fs.unlink(f)).catch(() => {})` tetap dilaporkan.
- Severity/skor: `warning`, **mewarisi penalti DG005 warning** (`-10` maintainability). Tidak naik ke `error` di v1.3.0.
- Suppression: kebijakan DG005 `warning` existing (inline dengan alasan ≥ 2 kata alfabetis, atau base-branch). `DG005` `error` tidak dapat di-suppress `[TERVERIFIKASI]`. Paritas dengan induk, dicatat sebagai risiko di §12.

---

## 7. Ringkasan Severity & Dampak

| Rule | Tingkat v1.3.0 | Skor | Exit code | Suppression |
|---|---|---|---|---|
| `DG004-DYN-01/02` | warning (non-scoring) | tidak ada penalti | tidak | base-branch `.devguard.json` saja |
| `DG005-EV-01` | warning | `-10` maintainability / finding | via `min_score` | paritas DG005 warning |
| `DG008-EV-01` | warning | `-10` correctness / finding | via `min_score` | paritas DG008 |
| skipped biasa / partial / `fold_limit_exceeded` | bukan finding | tidak ada | hanya `fail_on_unanalyzable` (skipped) | n/a |
| analysis failure | bukan finding | tidak ada | **selalu `exit 1`** | n/a |

---

## 8. Corpus Test

Layout aktual `[TERVERIFIKASI]`: `tests/corpus.test.ts` + `tests/corpus/cases.ts`. Kasus baru ditambahkan di sana (boleh dipecah ke berkas saudara yang diimpor `cases.ts`), mengikuti shape kasus yang ada. Setiap kasus mencatat: id, rule, label TP/TN, alasan singkat, dan provenance (sumber, lisensi, commit SHA) bila diadaptasi dari repo eksternal.

### 8.1 Kuota minimum

| Pola | TP min | **TN min (kode aman realistis)** |
|---|---|---|
| `DG004-DYN-01` | 3 | **5** |
| `DG004-DYN-02` | 3 | **5** |
| `DG005-EV-01` | 3 | **5** |
| `DG008-EV-01` | 3 | **5** |
| `FOLD-01`, `-02`, `-03`, `-04` | 3 per operasi | **5 per operasi** |

Total TN baru ≥ 40. Jumlah tes tidak boleh turun; tidak ada tes dinonaktifkan.

### 8.2 TN wajib (contoh minimum)

- **DYN:** `require("./a")`, `import("./chunk")`, `require("a" + "b")` (terlipat jadi literal), `module.require(x)`, `foo.require(x)`, method bernama `import(x) {}` pada class, `const require = createRequire(import.meta.url)` (dilewati shadow guard), `typeof require !== "undefined"`.
- **FOLD:** `x - "a" + "b"`, `2 * "a" + "b"`, `"a" + "b".length`, `obj["content-type"]`, `obj["0"]`, `if (x) ["a"].forEach(f)`, `return ["a"]`, `const a = ["a", "b"]`, `{ ["k"]: 1 }`, tagged template `` tag`ab` ``, operan dengan `\n`/`\x41`.
- **DG005-EV-01:** `fs.unlink(tmp).catch(() => {})`, `server.close().catch(() => {})`, `analytics.track(e).catch(() => {})`, `.catch(err => logger.warn(err))`, `.catch(() => null)`, `.catch(() => {})` pada rantai tanpa nama kritikal, `fetch(url, { headers: { token } }).catch(() => {})`.
- **DG008-EV-01:** `do { ... } while (cond)`, do-while(true) dengan `break` / `return` / `process.exit` / bounded retry check, objek dengan method `do`, blok biasa diikuti `while (true) { ... }`.

### 8.3 Syarat kualitas TN

- "Realistis" = potongan pola pemrograman nyata, bukan `foo`/`bar`.
- Tiap TN memuat alasan aman.
- Minimal 2 TN per pola berasal dari kode repo OSS nyata (provenance di atas).

### 8.4 Tes khusus

- **Invarian coverage**, termasuk file > 1 MiB, `.vue`/`.ipynb`, dan file terhapus dari diff.
- **PR hanya `.go` (atau bahasa skipped lain):** skor `N/A`, badge `NOT ANALYZED`, exit `0` default; dengan `fail_on_unanalyzable` → exit `1`.
- **`.py` parsial:** terklasifikasi `analyzed/partial`; temuan **identik dengan baseline v1.2.1** (golden: rule ID dan baris dari corpus `.py` tetap); badge `PARTIALLY ANALYZED` bila hanya `.py`; Test 4 dan Test 6c berjalan alami dengan fixture `.py`.
- **Fail-closed:** `evaluateFn` yang melempar error → file lain tetap dianalisis dan dilaporkan, `exit 1`, `audit_status=FAIL`, SARIF `executionSuccessful: false`. Kegagalan Layer 2 (Gemini) tetap **tidak fatal** (Test 6).
- **Matriks badge:** satu tes per baris tabel §4.2.
- **Parsing input:** `true`, `TRUE`, ` false `, kosong → valid; `yes`, `1`, `ture` → `exit 1`; `INPUT_FAIL_ON_UNANALYZABLE` diabaikan.
- **Versi:** headline memuat versi `package.json`, baik dari `src` maupun build `.test-dist`.
- **Path:** argumen eksplisit yang hilang → `exit 1`; file terhapus pada diff → `ignored/deleted`; kebijakan `scripts/` identik dengan v1.2.1 (`e67c869`).
- **Non-scoring** (Stage 5.2): skor dengan N finding DYN identik dengan tanpa DYN.
- **Baseline aditif:** output pass-O pada seluruh corpus v1.2.1 identik byte-per-byte.
- **Differential fold:** pada semua kasus TN, pass-V tidak menambah finding.
- **SpanMap property test:** invarian §5.3, termasuk lipatan lintas baris dan karakter UTF-16 non-BMP.
- **Batas DoS:** rantai `+` ribuan operand, array besar, banyak edit → selesai, deterministik, `fold_limit_exceeded`, tidak crash.
- **Redaksi:** pesan DYN/EV tidak membocorkan secret yang ditanam di argumen.
- **Glob allowlist:** pola patologis selesai linear-time.
- **Kontrak:** `action.yml` ↔ `README.md` ↔ workflow ↔ tes kontrak konsisten (Test 6 dan Test 29).

---

## 9. Gerbang Promosi

Tangga severity:

```
DYN:  warning non-scoring ──► warning scoring ──► error
EV:   warning scoring     ──► error
```

Tidak ada promosi di v1.3.0. Tiap langkah hanya di rilis berikutnya, bila **semua** terpenuhi:

1. Kuota TN §8.1 terpenuhi dan CI hijau.
2. Validasi pada **≥ 10 repo OSS eksternal** (campuran; commit SHA dipin), dicatat di `docs/validation/v1.3.0-external.md` dengan label TP/FP per finding.
3. **Nol FP tak terjelaskan.** Setiap FP diperbaiki, dijadikan TN baru, validasi diulang.
4. Pengukuran dampak skor pada repo validasi (berapa repo jatuh di bawah `min_score` akibat rule itu); untuk DYN ini syarat utama sebelum menjadi scoring.
5. Benchmark runtime tidak melewati batas yang ditetapkan `[ASUMSI: ≤ +25% total waktu pada corpus benchmark]`.
6. Persetujuan maintainer pada commit terpisah yang hanya mengubah severity.

Catatan: 10 repo bukan bukti ketiadaan FP, hanya penurun risiko.

---

## 10. Rencana Implementasi

| Stage | Deliverable | Gate (bukti wajib) |
|---|---|---|
| **5.0 Pre-flight** | *(selesai)* D1–D8 dijawab dengan `path:baris` | Tabel pre-flight |
| **5.1** | *(sudah di-merge ke `main` sebagai `d4801e7`, implementasi `c5f7129`)* klasifier, skor `N/A`, ringkasan, SARIF, input | `45/45` lokal; **mengandung cacat yang diketahui (F1–F10); main tidak boleh dirilis sebelum 5.1-fix** |
| **5.1-fix** | §4.8 (branch baru dari `main`, PR ke `main`): hapus special-case fixture, kembalikan kebijakan path ke v1.2.1, `.py` parsial, fail-closed, badge, parsing ketat, versi, `deleted`, README | `npm run lint/build/test` hijau, **diff lengkap tanpa pemotongan**, golden `.py` terhadap `e67c869`, CI hijau setelah push |
| **5.2** | `DG004-DYN-01/02` (pada O dulu), non-scoring, allowlist base-branch + glob linear, TN | Output tes, TN ≥ 5 per sub-rule, tes skor identik |
| **5.3a** | Ekspor region masker, `SpanMap`, infrastruktur edit, **0 lipatan aktif** | Baseline pass-O identik, property test SpanMap hijau |
| **5.3b** | FOLD-03/01/02/04, batas, pass-V aditif, DYN → `virtual-only` | Differential fold, tes DoS, **angka benchmark** |
| **5.4** | `DG008-EV-01`, `DG005-EV-01`, ekstraksi `CRITICAL_FLOW_IDENTIFIERS`, TN | Output tes, TN ≥ 5 per rule |
| **5.5** | Validasi repo eksternal, audit klaim README, bump `v1.3.0`, CHANGELOG | `docs/validation/v1.3.0-external.md`, CI hijau, tag |

Stage 5.2 **tidak dimulai** sebelum 5.1-fix disetujui dan CI hijau.

## 11. Acceptance Criteria (berbasis bukti)

Sebuah stage selesai **hanya** jika tersedia bukti nyata, bukan narasi:

- Diff kode aktual (`git diff` / link PR) **lengkap**, tidak dipotong (`head`, `tail`, atau sejenisnya tidak boleh dipakai untuk bukti).
- Output `npm run lint`, `npm run build`, `npm test` aktual (`tsc` ke `.test-dist` lalu `node --test`) dengan jumlah lulus/gagal.
- Link run GitHub Actions hijau (atau pernyataan jujur "belum dipush").
- 5.1-fix: ringkasan PR nyata untuk setiap baris badge §4.2, potongan SARIF dengan `executionSuccessful: false`, dan hasil golden `.py` dibandingkan dengan v1.2.1.
- 5.3b: output differential test, property test, tes DoS, dan angka benchmark (sebelum/sesudah).
- 5.5: berkas validasi eksternal berisi repo + SHA + label tiap finding.

---

## 12. Evaluasi Risiko

### 12.1 Anti-Survivorship Bias

Scanner serupa umumnya gagal karena:
- **Alert fatigue dari FP.** Rule berbasis akses/impor dinamis sering dimatikan massal (contoh yang lazim dikeluhkan: `detect-object-injection` di `eslint-plugin-security`). `DG004-DYN` menghadapi risiko serupa; karena itu non-scoring dan punya allowlist.
- **False assurance.** Skor tinggi tanpa pernyataan coverage; diperbaiki Fitur A. Sebuah tes 45/45 hijau tidak membuktikan ketiadaan celah: tes yang ada tidak menguji crash payload atau badge nol-analisis, dan keduanya lolos di implementasi awal.
- **Fail-open pada kegagalan analisis.** Scanner yang menelan exception per file dan tetap lulus memberi penyerang jalur bypass murah (file yang membuat analyzer crash).
- **Perlombaan obfuscation.** Folding hanya menutup trik trivial.
- **Insentif evasion dari paritas yang tidak konsisten.** Varian yang lebih murah penaltinya daripada induknya menjadi jalur bypass; EV mewarisi skor induk.
- **Perbaikan tes dengan hack produksi.** Menyiasati tes lama dengan special-case di kode produksi menyembunyikan kontradiksi kontrak dan membuka jalur khusus di alat keamanan.
- **Bias korpus** dan **klaim performa tanpa data**: dilawan TN dari OSS nyata, validasi repo, dan benchmark gate.

### 12.2 Single Point of Failure (Abraham Wald)

Diperkuat lebih dulu:
1. **Jalur verdict** (`computeOverallGateVerdict` + penentuan exit code + badge). Menentukan apakah PR lolos; bug di sini mengalahkan semua rule. *Penguatan:* semua sumber kegagalan masuk satu fungsi verdict; tes matriks badge; tes crash payload.
2. **`SpanMap` dan urutan pipeline dengan masker** (Stage 5.3). *Penguatan:* model aditif, property test, 5.3a membuktikan infrastruktur dengan 0 lipatan.
3. **Guard prioritas operator.** *Penguatan:* tabel TN §8.2 sebelum FOLD-01 aktif; differential fold.
4. **Klasifier coverage.** *Penguatan:* satu konstanta ekstensi, klasifier menerima daftar sebelum filter ekstensi, golden `.py`.
5. **Jalur scoring** (`scoring: false`, Stage 5.2). *Penguatan:* tes skor identik; perubahan dibatasi satu fungsi.
6. **Jalur redaksi secret.** *Penguatan:* tanpa snippet mentah; tes redaksi.

### 12.3 Inversion Thinking / Pre-Mortem

Skenario: "v1.3.0 gagal total dalam 3 bulan."

| # | Skenario kegagalan | Penyebab | Mitigasi sejak awal |
|---|---|---|---|
| 1 | Pengguna mencopot action | Banjir `DYN` menjatuhkan skor di bawah `min_score` | DYN non-scoring, cap tampilan, allowlist base-branch, ukur dampak sebelum DYN boleh scoring |
| 2 | Supply-chain miss lewat suppression | Inline suppression pada rule `DG004` | Tanpa inline suppression untuk DYN |
| 3 | CI timeout / DoS | Fold/backscan pada input adversarial | Batas berbasis hitungan, fail-open pada pelipatan, tes DoS, benchmark gate |
| 4 | FP karena lipatan mengubah semantik | Salah baca prioritas operator / posisi `[` | Guard §5.4, TN wajib, differential fold |
| 5 | Lokasi finding salah / suppression meleset | `SpanMap` keliru | Selalu hitung dari O via `toOrig`, property test |
| 6 | ReDoS lewat allowlist | Glob dikompilasi jadi RegExp | Matcher linear-time buatan sendiri |
| 7 | Ringkasan PR disalahartikan | `skipped`/`N/A`/partial terbaca sebagai aman | Badge §4.2, coverage satu baris dengan skor, README |
| 8 | Merge terblokir salah | Promosi dini ke `error` | Tidak ada promosi di v1.3.0; gerbang §9 |
| 9 | Kebocoran secret via komentar/SARIF | Pesan menyalin argumen | Pesan tanpa snippet, redaksi, tes redaksi |
| 10 | Regresi kontrak/fork PR | Input baru tidak sinkron | Satu commit `action.yml` + README + workflow + Test 6/29 |
| 11 | Runtime membengkak | Pass-V menggandakan biaya rule | Pass-V hanya bila ada edit, batas edit, benchmark gate |
| 12 | Evasion lewat penalti lebih murah | Varian EV lebih ringan dari induk | Paritas skor |
| 13 | **PR berbahaya lolos hijau lewat file yang membuat analyzer crash** | `internal_error` fail-open | Fail-closed: `exit 1`, `executionSuccessful: false`, tes crash payload |
| 14 | **Secret di `.py` tidak lagi dipindai** | `.py` di-skip total padahal v1.2.1 menganalisisnya | `.py` tetap `analyzed/partial`, golden terhadap baseline v1.2.1 |
| 15 | **Lencana hijau pada nol analisis atau cakupan parsial** | `READY TO MERGE` untuk `summaries` kosong | Badge #4 dan #5, matriks badge diuji |
| 16 | **Mode ketat mati diam-diam** | Salah ketik `fail_on_unanalyzable` | Parsing ketat, nilai tak valid → `exit 1` |
| 17 | **Kebijakan path berubah tanpa disadari** | Pengecualian `scripts/` diubah demi fixture tes | Larangan §4.8 butir 2; tes kebijakan `scripts/` identik dengan v1.2.1 (`e67c869`) |
| 18 | **Konsumen numerik `overall_score` rusak** | `100` → `N/A` untuk PR tanpa analisis | Dokumentasi §4.7, deskripsi `action.yml` |

Risiko yang diterima (dicatat): suppression inline `DG005-EV-01` mengikuti induknya, sehingga penulis PR masih dapat menekannya dengan alasan dua kata. Itu sifat tier warning DG005 existing; layak ditinjau ulang sebelum EV-01 dipromosikan ke `error`. Selain itu, pengecualian path (§4.6) tetap membuat sebagian file tidak terlihat di coverage sampai D12 diputuskan.

---

## 13. Keputusan Terbuka & Asumsi

| ID | Pertanyaan | Status |
|---|---|---|
| D1 | Masker mengekspos klasifikasi region? | **Resolved:** tidak; hanya `{ maskedCode, stringLiterals, suppressions }`. Stage 5.3a menambah ekspor tanpa mengubah `maskedCode`. |
| D2 | Representasi `N/A` di output | **Resolved:** string `N/A` di `GITHUB_OUTPUT` dan komentar; perbandingan `min_score` dilewati. |
| D3 | `.html`/`.htm` | **Resolved:** `ignored/non_code`. |
| D4 | Skema `.devguard.json` untuk glob | **Resolved:** hanya path eksak dan akhiran `/**`; glob linear-time ditambah di Stage 5.2. |
| D5 | Suppression aktual | **Resolved:** `DG008` inline semua severity; `DG005` inline hanya `warning`; `DG004`/`DG006` base-branch saja. |
| D6 | Nilai batas §5.5 dan ambang benchmark | Terbuka: ditetapkan dari benchmark Stage 5.3b. |
| D7 | Filter ekstensi sebelum klasifier? | **Resolved:** klasifier ditempatkan sebelum filter; discovery dipisah dari filter. |
| D8 | Alias env | **Resolved:** hanya `DEVGUARD_*`; tidak ada `INPUT_*`. |
| D9 | Cakupan parsial | **Putusan:** hanya `.py`, sama dengan filter discovery v1.2.1. Bahasa lain tetap `skipped`. |
| D10 | Argumen file eksplisit dengan ekstensi lain (v1.2.1 tidak memfilter) | **Putusan:** mengikuti klasifier; hanya `.py` parsial. Dicatat di README. |
| D11 | Komentar PR untuk PR tanpa file kode | **Putusan:** tetap diposting (badge `NOT ANALYZED`) agar tidak ada komentar usang; noise diterima dan didokumentasikan. |
| D12 | `ignored/excluded_path` agar pengecualian path terlihat | Terbuka; diusulkan untuk rilis berikutnya (mode `modified` saja). |

Asumsi yang masih harus dicek di pre-flight 5.1-fix: aturan apa saja yang aktif untuk `.py` di v1.2.1 (golden), exception apa yang bisa lolos dari `evaluateCodeHybrid`, perilaku `target_files` selain `all`/`modified`, dan resolusi `package.json` saat runtime dari `src`, `.test-dist`, dan jalur eksekusi action.

## 14. Definisi Selesai (v1.3.0)

- [ ] Stage 5.0–5.5 (termasuk 5.1-fix) lulus gate masing-masing dengan bukti §11.
- [ ] CI hijau; jumlah tes ≥ 35 + tes baru; tidak ada tes dinonaktifkan.
- [ ] Tidak ada PR yang menghasilkan `100/100` atau `READY TO MERGE` tanpa file `analyzed`; cakupan parsial selalu berlabel.
- [ ] Tidak ada kegagalan analisis yang menghasilkan exit `0`.
- [ ] Kode produksi tidak mengandung nama fixture tes.
- [ ] Output pass-O pada corpus v1.2.1 identik dengan baseline; temuan `.py` identik dengan baseline v1.2.1.
- [ ] Semua rule baru berstatus `warning`; `DG004-DYN` non-scoring; promosi hanya lewat §9.
- [ ] `docs/validation/v1.3.0-external.md` ada dengan label per finding.
- [ ] README dan CHANGELOG diperbarui (termasuk §4.6 dan §4.7) tanpa klaim di luar §2.
