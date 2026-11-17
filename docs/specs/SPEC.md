# DevGuard v1.3.0 — SPEC (Stage 5) — Rev 2

**Tema:** Explicit Unanalyzable Reporting & Lexical Constant Folding (SpanMap)
**Baseline:** `v1.2.1` — hijau di GitHub Actions, `35/35` tes lulus
**Status:** §4 (Stage 5.1) **TERKUNCI** untuk implementasi. §5–§9 siap, dengan pre-flight Stage 5.0 yang wajib lebih dulu.
**Catatan:** dokumen ini tidak mengubah kode apa pun.

Konvensi penanda:
- `[TERVERIFIKASI]` = fakta tentang repo `v1.2.1` yang dilaporkan pemilik repo. Tetap dikonfirmasi ulang di Stage 5.0 dengan `grep`/eksekusi.
- `[ASUMSI]` = belum diverifikasi; harus dicek di Stage 5.0.

---

## 0. Perubahan dari Rev 1

| Area | Rev 1 | Rev 2 | Alasan |
|---|---|---|---|
| Representasi view | node AST + `origin_span` + "node budget" | `SpanMap` berbasis rentang karakter UTF-16 di atas lexical masker | Engine v1.2.1 lexical, bukan AST `[TERVERIFIKASI]` |
| Eksekusi rule | rule membaca virtual view | rule v1.2.1 tetap jalan di source asli; pass kedua di virtual view bersifat **aditif** (`via-fold`) | Menjaga baseline 35/35 tidak berubah |
| `DG004-DYN-*` | warning yang ikut skor | **non-scoring warning**; hanya allowlist base-branch, tanpa inline suppression | Penalti `-10` per finding tanpa cap `[TERVERIFIKASI]` |
| `DG008-EV-01` | semantik "await di loop tanpa exit" | perluasan `DG008` existing ke `do{...}while(true\|1)` | Semantik asli DG008 `[TERVERIFIKASI]` |
| `DG005-EV-01` | sink set buatan sendiri | `CRITICAL_FLOW_IDENTIFIERS` (diekstrak dari DG005) pada rantai receiver | Menghindari divergensi dan FP |
| Input action | `fail-on-unanalyzable` | `fail_on_unanalyzable` | Konvensi `snake_case` `[TERVERIFIKASI]` |
| Path corpus | `test/corpus/...` file per kasus | `tests/corpus/cases.ts` + `tests/corpus.test.ts` | Layout aktual `[TERVERIFIKASI]` |
| Batas DoS | nilai awal | nilai awal + gate benchmark wajib | Tidak ada bukti performa |
| Guard 1 MiB | tidak dibahas | dipetakan ke `skipped/file_too_large` | Saat ini silent `[TERVERIFIKASI]` |
| Ekstensi | 8 JS/TS | 8 JS/TS + `.vue .svelte .astro .ipynb` → skipped | Komponen berisi `<script>` yang tidak diaudit |

## 1. Tujuan

1. **Tidak ada silent miss.** Setiap file dalam scope berakhir di `analyzed`, `skipped` (dengan alasan), atau `ignored` (dengan alasan). Skor `100/100` tidak boleh muncul untuk PR tanpa file teranalisis.
2. **Menutup bypass lexical murah** (`"ev"+"al"`, `obj["prop"]`, `["a","b"].join("")`) tanpa false positive baru.
3. **Dua varian evasion** (`DG008-EV-01`, `DG005-EV-01`) dan **peringatan dynamic specifier** (`DG004-DYN-01/02`).
4. **Disiplin promosi severity** lewat gerbang bukti (§9).

## 2. Non-Goals (v1.3.0)

- Analyzer bahasa selain JS/TS (hanya dilaporkan sebagai skipped).
- Parser AST penuh, tokenizer baru, atau data-flow/taint.
- Constant propagation lintas variabel (`const a = "ev"; a + "al"` tidak dilipat).
- Dekode string (`atob`, `String.fromCharCode`, escape `\x..`/`\u....`), `.concat()`, template berisi ekspresi, kurung pembungkus `("a")`.
- Resolusi alias (`const e = eval; e(x)`).
- Promosi otomatis severity di dalam rilis v1.3.0.
- Klaim "zero false positive" absolut. Klaim README yang diizinkan: *"tidak ada FP yang diketahui pada corpus dan repo validasi yang terdaftar."*

## 3. Terminologi

| Istilah | Definisi |
|---|---|
| **In-scope files** | Daftar file yang dienumerasi action (diff-filter / `discoverWorkspaceFiles` / `target_files`) **sebelum** filter ekstensi. Klasifier harus menerima daftar ini, bukan daftar yang sudah difilter. |
| **Analyzable** | Ekstensi `.ts .tsx .js .jsx .mjs .cjs .mts .cts` `[TERVERIFIKASI]`, ukuran ≤ `MAX_FILE_BYTES`. |
| **Skipped** | File kode yang seharusnya diperiksa tetapi tidak bisa. Selalu ada `reason`. |
| **Ignored** | File non-kode atau tidak relevan. Dihitung terpisah, bukan coverage gap. |
| **Virtual view (V)** | String hasil lipatan dari source asli (O), dipakai untuk pass aditif. Selalu disertai `SpanMap`. |
| **Non-scoring warning** | Finding bertingkat `warning` yang tidak menghasilkan penalti skor dan tidak mempengaruhi exit code. |

---

## 4. Fitur A — Pelaporan Unanalyzable / Skipped *(TERKUNCI untuk Stage 5.1)*

### 4.1 Klasifikasi

Setiap in-scope file diklasifikasikan **tepat satu kali**:

| Status | `reason` | Contoh |
|---|---|---|
| `analyzed` | — | `src/a.ts` |
| `skipped` | `unsupported_language` | `.py .go .java .rb .php .rs .cs .kt .swift .c .cpp .h .sh` dll., plus `.vue .svelte .astro .ipynb`; file tanpa ekstensi berisi shebang `#!` |
| `skipped` | `file_too_large` | > `1_048_576` bytes (guard v1.2.1 dipetakan ke sini) |
| `skipped` | `parse_error` | scanner/masker gagal |
| `skipped` | `internal_error` | exception tak terduga pada file itu (fail-open per file; file lain tetap diproses) |
| `ignored` | `non_code` | lockfile, gambar, `.md`, `.json`, `.yml`, `.txt`, dst. |
| `ignored` | `deleted` | file dihapus pada diff `[ASUMSI: sesuai cara enumerasi saat ini]` |

Aturan:
- **Invarian wajib (diuji):** `analyzed + skipped + ignored == |in-scope files|`.
- Ekstensi kode yang dikenal adalah **allowlist eksplisit**. Ekstensi tak dikenal tanpa shebang → `ignored/non_code`.
- Urutan evaluasi: ekstensi → (analyzable) ukuran → scan. Ukuran dicek sebelum membaca isi.
- Klasifier dan `discoverWorkspaceFiles`/filter diff **berbagi satu konstanta** daftar ekstensi, supaya tidak bisa divergen.

### 4.2 Semantik skor (selaras dengan perhitungan v1.2.1)

Perhitungan existing `[TERVERIFIKASI]`: penalti dihitung **per finding** secara kumulatif tanpa cap per-rule, `Math.max(0, 100 - sum(penalties))` per kategori, lalu dirata-rata menjadi `totalScore`, dibandingkan dengan `min_score` (default `85`).

- Skor hanya dihitung dari file `analyzed`.
- Jika `analyzed == 0`: `totalScore` = `null`, ditampilkan `N/A`. Perbandingan `min_score` **dilewati** (tidak gagal karena skor); check hanya gagal jika `fail_on_unanalyzable: 'true'` dan `skipped > 0`.
- Jika `analyzed > 0`: skor seperti biasa, dengan baris coverage di tempat yang sama.
- Representasi `N/A` pada output action/SARIF `[ASUMSI]`: ditentukan di Stage 5.0 setelah memeriksa `action.yml` outputs dan konsumen skor. Keputusan terbuka D2.

Contoh ringkasan PR:

```
DevGuard v1.3.0 — Score: 100/100  (analyzed 3 of 5 code files · 2 skipped)

Coverage
- Analyzed: 3
- Skipped: 2
    - scripts/deploy.py — Skipped: Unsupported language
    - tools/big.js      — Skipped: File too large (> 1 MiB)
- Ignored (non-code): 4
```

PR hanya berisi `.py`:

```
DevGuard v1.3.0 — Score: N/A  (analyzed 0 of 2 code files · 2 skipped)
```

### 4.3 Input action & exit code

- Input baru: **`fail_on_unanalyzable`**, default `'false'`, mengikuti konvensi `snake_case` (`gemini_api_key`, `min_score`, `target_files`). Alias env `DEVGUARD_FAIL_ON_UNANALYZABLE` hanya jika konvensi alias env sudah ada untuk input lain `[ASUMSI]`.
- Default: skipped **tidak** menggagalkan check.
- `fail_on_unanalyzable: 'true'` dan `skipped > 0` → exit `1`.
- Tidak ada input `fail_on_warning` di v1.3.0 `[TERVERIFIKASI: belum ada]`; tidak ditambahkan.
- **Kontrak:** `action.yml`, `README.md`, workflow `.github/workflows/devguard.yml`, dan tes kontrak (`tests/integration.test.ts`, Test 6 dan Test 29) diubah **dalam satu commit** yang sama.

### 4.4 SARIF

- Skipped → `runs[0].invocations[0].toolExecutionNotifications[]`: `level: "note"`, `message.text` berisi alasan, `locations[].physicalLocation.artifactLocation.uri` = path.
- Tidak ada `result` baru untuk skipped. Invocation `executionSuccessful` tidak berubah oleh skipped.

### 4.5 Batas Stage 5.1 (apa yang termasuk / tidak)

Termasuk: klasifier, mapping guard 1 MiB, semantik skor `N/A`, ringkasan PR, SARIF notifications, input `fail_on_unanalyzable`, pembaruan kontrak, tes.
Tidak termasuk: `DG004-DYN`, `SpanMap`, folding, `EV` rules, perubahan scoring penalty.

---

## 5. Fitur B — Constant Folding via `SpanMap` (Stage 5.3)

### 5.1 Prinsip

1. **Lexical, bukan AST.** Tidak ada parser baru. Klasifikasi region (kode / string / template / komentar / regex) berasal dari `src/rules/lexicalMasker.ts`. Pelipatan hanya terjadi di region **kode**. `[ASUMSI]` masker mengekspos klasifikasi region; jika hanya mengembalikan string termasking, Stage 5.3a menambah ekspor minimal **tanpa mengubah output masked** (baseline tetap hijau).
2. **Zero-FP bukan tujuan yang bisa dijamin, tetapi desainnya konservatif:** jika ada keraguan sintaktis, tidak dilipat.
3. **Source asli tidak pernah dimutasi.** V adalah string terpisah.
4. **Fail-open:** exception, batas terlampaui, atau ambiguitas → tidak ada edit; V tetap sama dengan O untuk bagian itu.
5. **Lokasi selalu dihitung dari O melalui `SpanMap`.** Aturan yang berjalan di V melaporkan **offset**, bukan nomor baris V (lipatan lintas baris membuat baris V berbeda dari O).

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

Ilustrasi tipe (nama final menyusul di implementasi):

```ts
type Seg = { vStart: number; vEnd: number; oStart: number; oEnd: number; kind: 'copy' | 'fold' };
type SpanMap = Seg[]; // terurut, tidak overlap, menutup [0, |V|)
```

- `copy`: panjang V sama dengan panjang O; offset dipetakan linear.
- `fold`: seluruh rentang V dipetakan ke seluruh rentang O dari ekspresi asal.
- Komposisi antar-pass: peta pass-n dikomposisi dengan peta pass-(n-1); `fold` pada pass lanjut mengambil gabungan rentang O.
- `toOrig(vStart, vEnd)`: binary search; posisi di dalam segmen `fold` diperluas ke seluruh rentang O segmen itu. Hasil `[oStart, oEnd]` dipakai untuk line/col, redaksi, dan pengecekan suppression, semuanya pada O.
- **Invarian (property test):** (a) segmen terurut dan menutup V; (b) untuk setiap karakter di segmen `copy`, `V[i] === O[toOrig(i)]`; (c) `toOrig` monoton; (d) rentang O hasil pemetaan selalu berada dalam `[0, |O|]`.

### 5.4 Operasi lipatan

Semua operan literal **tanpa backslash** (tidak ada escape) dan tanpa newline. Operan yang mengandung `\` membuat ekspresi itu tidak dilipat. Literal hasil memakai tanda kutip operan pertama; jika konten hasil memuat tanda kutip itu, tidak dilipat.

| ID | Input | Output di V |
|---|---|---|
| `FOLD-03` | template tanpa `${}`, tanpa newline, tanpa backslash, bukan tagged | string literal biasa |
| `FOLD-01` | `"ev" + "al"` (rantai `+` literal) | `"eval"` |
| `FOLD-02` | `["a","b"].join("")`, `.join("-")`, atau `.join()` | `"ab"`, `"a-b"`, `"a,b"` |
| `FOLD-04` | `obj["balance"]`, `obj?.["balance"]` | `obj.balance`, `obj?.balance` |

**Guard prioritas operator (FOLD-01).** Karena lexical, pelipatan `+` hanya aman bila literal tidak terikat operator yang lebih kuat. Sebuah sub-rantai literal `L1 + L2 + ...` boleh dilipat hanya jika:
- token sebelum `L1` termasuk: pembuka (`(` `[` `{` `,` `;` `:` `?` `=` `=>` `...` `return`), operator berprioritas lebih rendah dari `+` (`==` `!=` `===` `!==` `<` `>` `<=` `>=` `<<` `>>` `>>>` `&` `^` `|` `&&` `||` `??`), atau `+` **biner** (token sebelum `+` itu adalah identifier/literal/`)`/`]`). Tidak boleh: `-` `*` `/` `%` `**` `!` `~` `typeof` `void` `delete` `await` `new` `.` `?.`, atau `+` unary.
- token setelah literal terakhir bukan `.` `?.` `[` `(` `` ` `` `*` `/` `%` `**`.

Contoh yang **tidak** boleh dilipat: `x - "a" + "b"`, `2 * "a" + "b"`, `"a" + "b".length`, `"a" + "b" * 2`, `+"a" + "b"`, `typeof "a" + "b"`.

**Guard posisi `[` (FOLD-02 dan FOLD-04).** `[` adalah *array literal* bila token sebelumnya bukan identifier non-keyword / `)` / `]` / `?.`; selain itu adalah *member access*.
- `FOLD-04` hanya pada member access. Token sebelum `[` harus: identifier bukan keyword (`return typeof in of instanceof new delete void throw case do else yield await extends` dikecualikan), `]`, `?.`, atau `)` — dengan syarat untuk `)` bahwa kurung pembukanya (back-scan maksimum `MAX_BACKSCAN`) **bukan** milik `if|while|for|with|switch|catch`. Token sebelumnya `}`, angka, atau template tidak dinormalisasi.
- `FOLD-04`: isi bracket (selain whitespace) harus tepat satu string literal berisi identifier name ASCII valid `/^[A-Za-z_$][\w$]*$/`. `obj["a-b"]`, `obj["0"]`, `obj[""]` tidak diubah. Untuk bentuk `?.["x"]`, penggantian mencakup `?.` sehingga hasilnya `?.x`, bukan `?..x`.
- `FOLD-02` hanya pada array literal, elemen hanya string literal (hasil lipatan pass sebelumnya boleh), tanpa spread/hole/trailing comma. Argumen `join` berupa string literal atau kosong. Hasilnya adalah ekspresi primer; boleh diikuti `.length`, `(`, dll.
- Template tagged: template yang didahului identifier/`)`/`]` tidak dilipat.

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

Bila batas terpicu: SARIF notification `fold_limit_exceeded` (`note`, dedupe per file), bukan finding, tidak crash. Seluruh batas berbasis hitungan, bukan wall-clock, supaya hasil identik antar mesin.

### 5.6 Eksekusi rule & dedupe

- Pass-V dijalankan **hanya jika ≥ 1 edit** diterapkan.
- Finding pass-V dianggap duplikat bila ada finding pass-O dengan `ruleId` sama yang rentang O-nya **overlap** dengan hasil `toOrig`. (Bukan sekadar baris yang sama: dua finding berbeda di satu baris tetap dipertahankan.)
- Finding yang lolos diberi tag evidence `via-fold`.
- Suppression, redaksi, dan penomoran baris dijalankan pada rentang O hasil pemetaan.
- **Mode rule:** rule v1.2.1 = `original + additive-virtual`. `DG004-DYN-*` = `virtual-only` (agar `require("a"+"b")` yang terlipat menjadi literal tidak diperingatkan sebagai dinamis).

---

## 6. Fitur C — Deteksi Baru

### 6.1 `DG004-DYN-01` / `DG004-DYN-02` — dynamic specifier *(non-scoring warning)*

| ID | Pola |
|---|---|
| `DG004-DYN-01` | `import(<non-literal>)` |
| `DG004-DYN-02` | `require(<non-literal>)` |

Deteksi (lexical, pada V, di region kode):
- **Literal** = tepat satu token string literal atau template tanpa ekspresi, diikuti `)` atau `,` (untuk argumen kedua `import()`). Selain itu non-literal. Panggilan tanpa argumen tidak dilaporkan.
- `import(`: token sebelumnya bukan `.`/`?.`. `import.meta` dan `import x from` tidak cocok. Bila setelah `)` penutup langsung diikuti `{` ini adalah definisi method, bukan panggilan, jadi dilewati.
- `require(`: token sebelumnya bukan `.`/`?.`; sama untuk pengecualian method definition.
- **Shadow guard (file-level, konservatif):** kemunculan token `require` hanya diizinkan sebagai `require(`, `require.<member>`, atau `typeof require`. Kemunculan lain (deklarasi, parameter, destructuring, `const r = require;`) → DYN-02 dilewati untuk file itu dan dicatat metrik `dyn_scope_uncertain`.
- Pesan finding tidak memuat teks ekspresi mentah; hanya `file:line` dan kategori. Bila ada snippet, wajib lewat redaksi secret v1.2.1.
- Cap tampilan `MAX_DYN_FINDINGS_PER_FILE = 20`; sisanya `+N more`. Seluruh finding tetap ada di SARIF.

Severity dan skor:
- Tingkat: `warning`, **tidak mengurangi skor** dan tidak mempengaruhi exit code. Alasan: penalti existing `-10` per finding tanpa cap `[TERVERIFIKASI]`; repo dengan loader dinamis sah akan jatuh di bawah `min_score = 85` hanya karena DYN.
- Ditampilkan di ringkasan sebagai bagian terpisah "Warnings (non-scoring)".
- SARIF `level: "warning"`, `properties.scoring: false`.
- Perubahan scoring: finding dengan flag `scoring: false` dilewati oleh penghitung penalti. Wajib ada tes eksplisit bahwa N finding DYN menghasilkan skor yang identik dengan 0 finding DYN.

**Suppression:** hanya lewat `.devguard.json` yang dibaca dari **base branch** (konsisten dengan kebijakan seluruh sub-aturan `DG004`). **Tidak ada inline suppression.** Alasan: penulis PR tidak dipercaya; `// devguard-ignore ... alasan dua kata` di atas `require(payload)` akan menghapus warning persis pada kasus supply-chain yang ingin ditutup. Alert fatigue ditangani dengan allowlist base-branch berbasis `rule + path glob` (mis. `src/i18n/**`).
- `[ASUMSI]` skema `.devguard.json` existing mungkin belum mendukung glob path. Jika belum, Stage 5.2 menambahkannya dengan matcher glob **linear-time yang ditulis tangan** (tanpa mengompilasi pola pengguna menjadi RegExp, untuk menghindari ReDoS) dan tes.

### 6.2 `DG008-EV-01` — `do { ... } while (true | 1)`

Perluasan `DG008` existing `[TERVERIFIKASI]`: DG008 saat ini mendeteksi `while (true)`, `while (1)`, `for (;;)` yang memuat `await` tanpa `break`, `return`, `throw`, `process.exit`, atau bounded retry check. EV-01 menambah bentuk `do { ... } while (true | 1)` dengan **syarat body lexical yang sama**.

- Jangkar deteksi adalah token `do` (bukan `.do`, bukan nama method/properti `do`) diikuti `{`. Pencocokan kurung kurawal dilakukan pada teks termasking. Setelah `}` yang cocok harus muncul `while ( true | 1 )`.
- Jangan salah baca blok biasa diikuti `while(true){...}` sebagai do-while: tanpa token `do` yang mengawali blok, tidak ada finding.
- Body scan memakai **helper yang sama** dengan DG008 existing (diekstrak jika perlu; **tidak disalin**), agar syarat exit/bounded-retry tidak divergen.
- Tidak didukung (dicatat): body tanpa kurung kurawal (`do await x(); while(true)`).
- Severity/skor: **mewarisi DG008 `warning`** (`-10` correctness per finding). Alasan paritas: jika varian `do/while` bebas penalti, menulis ulang `while` menjadi `do/while` menjadi cara murah menghindari penalti (insentif evasion).
- Suppression: mengikuti kebijakan DG008 existing `[ASUMSI: dikonfirmasi di Stage 5.0]`.

### 6.3 `DG005-EV-01` — `.catch(() => {})` pada flow kritikal

- **Callback kosong:** arrow/function expression dengan body kosong setelah masking (komentar dihitung kosong): `() => {}`, `_ => {}`, `(e) => {}`, `function () {}`, `function (e) {}`. Bukan: `() => null`, `() => undefined`, `.catch(noop)`, callback dengan statement apa pun, `try {} catch {}`, `.then(a, () => {})`.
- **Critical flow:** konstanta tunggal `CRITICAL_FLOW_IDENTIFIERS` diekstrak ke `src/rules/` dan dipakai bersama oleh `try/catch` DG005 existing dan EV-01. Isi saat ini `[TERVERIFIKASI]`: `payment`, `balance`, `wallet`, `ledger`, `transfer`, `charge`, `refund`, `deduct`, `invoice`, `auth`, `token`, `jwt`, `password`, `execute`, `query`, `transaction`, `writeFileSync`. Memakai fungsi pencocokan yang sama dengan DG005 existing (ekstrak, jangan salin).
- **Cakupan pencocokan:** hanya **nama dalam rantai receiver** (nama pemanggilan/properti pada rantai `a.b(...).c(...)` yang berakhir di `.catch`), **bukan** argumen pemanggilan dan bukan identifier di fungsi sekitarnya. Alasan: `token`, `auth`, `query` sangat umum.
- **Pengecualian cleanup:** pengecualian existing DG005 (`unlink`, `rmSync`, `close`, `JSON.parse`) dievaluasi pada **pemanggilan yang langsung mendahului `.catch`** (immediate receiver call). Bila itu salah satunya → tidak dilaporkan. `pay.charge(x).then(() => fs.unlink(f)).catch(() => {})` tetap dilaporkan karena pemanggilan langsungnya `then`.
- Severity/skor: `warning`, **mewarisi penalti DG005 warning** (`-10` maintainability). Tidak naik ke `error` di v1.3.0 (berbeda dari eskalasi `try/catch` kosong existing). Promosi mengikuti §9.
- Suppression: mengikuti kebijakan DG005 `warning` existing (inline dengan alasan ≥ 2 kata alfabetis, atau base-branch). Ini paritas dengan induknya, bukan perubahan. Dicatat sebagai risiko di §12.

---

## 7. Ringkasan Severity & Dampak

| Rule | Tingkat v1.3.0 | Skor | Exit code | Suppression |
|---|---|---|---|---|
| `DG004-DYN-01/02` | warning (non-scoring) | tidak ada penalti | tidak | base-branch `.devguard.json` saja |
| `DG005-EV-01` | warning | `-10` maintainability / finding (paritas DG005) | via `min_score` | paritas DG005 warning |
| `DG008-EV-01` | warning | `-10` correctness / finding (paritas DG008) | via `min_score` | paritas DG008 |
| skipped / `fold_limit_exceeded` | bukan finding | tidak ada | hanya `fail_on_unanalyzable` | n/a |

---

## 8. Corpus Test

Layout aktual `[TERVERIFIKASI]`: `tests/corpus.test.ts` + `tests/corpus/cases.ts`. Kasus baru ditambahkan di sana (boleh dipecah ke berkas saudara yang diimpor `cases.ts`), **mengikuti shape kasus yang ada**. Setiap kasus mencatat: id, rule, label TP/TN, alasan singkat mengapa aman/berbahaya, dan provenance (sumber, lisensi, commit SHA) bila diadaptasi dari repo eksternal.

### 8.1 Kuota minimum

| Pola | TP min | **TN min (kode aman realistis)** |
|---|---|---|
| `DG004-DYN-01` | 3 | **5** |
| `DG004-DYN-02` | 3 | **5** |
| `DG005-EV-01` | 3 | **5** |
| `DG008-EV-01` | 3 | **5** |
| `FOLD-01`, `-02`, `-03`, `-04` | 3 per operasi | **5 per operasi** |

Total TN baru ≥ 40. Jumlah tes baseline `35` tidak boleh turun; tidak ada tes dinonaktifkan.

### 8.2 TN wajib (contoh minimum, bukan daftar penuh)

- **DYN:** `require("./a")`, `import("./chunk")` (code splitting), `require("a" + "b")` (terlipat jadi literal), `module.require(x)`, `foo.require(x)`, method bernama `import(x) {}` pada class, file dengan `const require = createRequire(import.meta.url)` (dilewati karena shadow guard), `typeof require !== "undefined"`.
- **FOLD:** `x - "a" + "b"`, `2 * "a" + "b"`, `"a" + "b".length`, `obj["content-type"]`, `obj["0"]`, `if (x) ["a"].forEach(f)`, `return ["a"]`, `const a = ["a", "b"]`, `{ ["k"]: 1 }`, tagged template `` tag`ab` ``, operan dengan `\n`/`\x41`.
- **DG005-EV-01:** `fs.unlink(tmp).catch(() => {})`, `server.close().catch(() => {})`, `analytics.track(e).catch(() => {})`, `.catch(err => logger.warn(err))`, `.catch(() => null)`, `.catch(() => {})` pada rantai tanpa nama kritikal, `fetch(url, { headers: { token } }).catch(() => {})` (token hanya di argumen).
- **DG008-EV-01:** `do { ... } while (cond)`, do-while(true) dengan `break`, dengan `return`, dengan `process.exit`, dengan bounded retry check, objek dengan method `do`, blok biasa diikuti `while (true) { ... }`.

### 8.3 Syarat kualitas TN

- "Realistis" = potongan pola pemrograman nyata, bukan `foo`/`bar`.
- Tiap TN memuat alasan aman.
- Minimal 2 TN per pola berasal dari kode repo OSS nyata (provenance di atas).

### 8.4 Tes khusus

- **Invarian coverage:** `analyzed + skipped + ignored == |in-scope|`, termasuk file > 1 MiB dan `.vue`/`.ipynb`.
- **PR hanya `.py`:** skor `N/A`, bukan `100/100`; check tidak gagal kecuali `fail_on_unanalyzable`.
- **Non-scoring:** skor dengan N finding DYN identik dengan tanpa DYN.
- **Baseline aditif:** output pass-O pada seluruh corpus v1.2.1 identik byte-per-byte dengan baseline sebelum perubahan.
- **Differential fold:** pada semua kasus TN, pass-V tidak menambah finding.
- **SpanMap property test:** invarian §5.3, termasuk lipatan lintas baris dan karakter UTF-16 non-BMP.
- **Batas DoS:** rantai `+` ribuan operand, array besar, banyak edit → selesai, deterministik antar run, `fold_limit_exceeded`, tidak crash.
- **Redaksi:** pesan DYN/EV tidak membocorkan secret yang ditanam di argumen.
- **Glob allowlist:** pola patologis pada matcher glob selesai linear-time.
- **Kontrak:** `action.yml` ↔ `README.md` ↔ workflow ↔ tes kontrak konsisten (Test 6 dan Test 29).

---

## 9. Gerbang Promosi

Tangga severity:

```
DYN:  warning non-scoring ──► warning scoring ──► error
EV:   warning scoring     ──► error
```

Tidak ada promosi di v1.3.0. Tiap langkah hanya boleh terjadi di rilis berikutnya, bila **semua** terpenuhi:

1. Kuota TN §8.1 terpenuhi dan CI hijau.
2. Validasi pada **≥ 10 repo OSS eksternal** (campuran library, web app, CLI, monorepo; commit SHA dipin), dicatat di `docs/validation/v1.3.0-external.md` dengan label TP/FP per finding.
3. **Nol FP tak terjelaskan.** Setiap FP diperbaiki, dijadikan TN baru, dan validasi diulang.
4. Pengukuran dampak skor pada repo validasi: berapa repo yang jatuh di bawah `min_score` akibat rule itu. Untuk DYN, ini syarat utama sebelum menjadi scoring.
5. Benchmark runtime tidak melewati batas yang ditetapkan `[ASUMSI: ≤ +25% total waktu pada corpus benchmark]`.
6. Persetujuan maintainer pada commit terpisah yang hanya mengubah severity (mudah di-revert).

Catatan: 10 repo bukan bukti ketiadaan FP, hanya penurun risiko.

---

## 10. Rencana Implementasi

| Stage | Deliverable | Gate (bukti wajib) |
|---|---|---|
| **5.0 Pre-flight** | Konfirmasi semua `[ASUMSI]` dengan `grep`/eksekusi: titik enumerasi file, API masker, skema `.devguard.json`, kebijakan suppression DG004/DG005/DG008, output `action.yml`, bentuk output skor, helper body-scan DG008 | Catatan temuan (path + baris kode) |
| **5.1** | §4 penuh | `npm test` hijau, `git diff`, contoh ringkasan PR dari PR uji (`.py` + `.ts`) dan PR hanya-`.py`, CI hijau |
| **5.2** | `DG004-DYN-01/02` (pada O dulu), non-scoring, allowlist base-branch + glob linear, TN | Output tes, TN ≥ 5 per sub-rule, tes skor identik |
| **5.3a** | Ekspor region masker (jika perlu), `SpanMap`, infrastruktur edit, **0 lipatan aktif** | Baseline pass-O identik, property test SpanMap hijau |
| **5.3b** | FOLD-03/01/02/04, batas, pass-V aditif, DYN pindah ke `virtual-only` | Differential fold, tes DoS, **angka benchmark** |
| **5.4** | `DG008-EV-01`, `DG005-EV-01`, ekstraksi `CRITICAL_FLOW_IDENTIFIERS`, TN | Output tes, TN ≥ 5 per rule |
| **5.5** | Validasi repo eksternal, audit klaim README, bump `v1.3.0`, CHANGELOG | `docs/validation/v1.3.0-external.md`, CI hijau, tag |

Urutan menempatkan reporting (5.1) lebih dulu karena ia menutup risiko terbesar (false assurance) dan tidak bergantung pada fitur lain. Folding dipecah (5.3a/5.3b) agar diff kecil dan infrastruktur terbukti sebelum ada lipatan nyata.

## 11. Acceptance Criteria (berbasis bukti)

Sebuah stage selesai **hanya** jika tersedia bukti nyata, bukan narasi:

- Diff kode aktual (`git diff` / link PR).
- Output `npm test` aktual (`tsc` ke `.test-dist` lalu `node --test`) dengan jumlah lulus/gagal.
- Link run GitHub Actions hijau.
- 5.1: ringkasan PR nyata dari dua PR uji (campuran dan hanya-`.py`).
- 5.3b: output differential test, property test, tes DoS, dan angka benchmark (sebelum/sesudah).
- 5.5: berkas validasi eksternal berisi repo + SHA + label tiap finding.

---

## 12. Evaluasi Risiko

### 12.1 Anti-Survivorship Bias

Scanner serupa umumnya gagal karena:
- **Alert fatigue dari FP.** Rule berbasis akses/impor dinamis sering dimatikan massal (contoh yang lazim dikeluhkan: `detect-object-injection` di `eslint-plugin-security`). `DG004-DYN` menghadapi risiko yang sama karena `require(variable)` umum pada kode sah. Itu sebabnya DYN non-scoring dan punya allowlist.
- **False assurance.** Skor tinggi tanpa pernyataan coverage; diperbaiki Fitur A.
- **Perlombaan obfuscation.** Folding hanya menutup trik trivial; penyerang beralih ke variabel, `fromCharCode`, `atob`, alias. Folding menaikkan biaya serangan sedikit, bukan menutupnya.
- **Insentif evasion dari paritas yang tidak konsisten.** Jika varian baru lebih murah penaltinya daripada induknya, varian itu menjadi jalur bypass. Karena itu EV mewarisi skor induk.
- **Bias korpus.** TN tulisan sendiri cenderung mudah; dilawan dengan TN dari kode OSS nyata dan validasi repo.
- **Klaim performa tanpa data.** Ditolak; benchmark adalah gate.

### 12.2 Single Point of Failure (Abraham Wald)

Diperkuat lebih dulu:
1. **`SpanMap` dan urutan pipeline dengan masker.** Bug pemetaan membuat finding menunjuk lokasi salah, melewati suppression, atau merusak masking. *Penguatan:* model aditif (pass-O tidak berubah, baseline byte-identik), property test invarian §5.3, Stage 5.3a membuktikan infrastruktur dengan **0 lipatan** sebelum 5.3b mengaktifkan lipatan.
2. **Guard prioritas operator.** Kesalahan di sini mengubah semantik di V dan memunculkan finding palsu. *Penguatan:* tabel TN prioritas operator §8.2 wajib sebelum FOLD-01 aktif; differential fold pada seluruh TN.
3. **Klasifier coverage.** Kesalahan klasifikasi membuat laporan coverage berbohong. *Penguatan:* berbagi satu konstanta ekstensi dengan discovery, klasifier menerima daftar **sebelum** filter, invarian jumlah sebagai tes.
4. **Jalur scoring.** Perubahan flag `scoring: false` menyentuh penghitung skor yang menjadi gerbang CI. *Penguatan:* tes skor identik; perubahan dibatasi pada satu fungsi.
5. **Jalur redaksi secret.** Pesan baru bisa membocorkan source. *Penguatan:* tanpa snippet mentah; tes redaksi.

### 12.3 Inversion Thinking / Pre-Mortem

Skenario: "v1.3.0 gagal total dalam 3 bulan."

| # | Skenario kegagalan | Penyebab | Mitigasi sejak awal |
|---|---|---|---|
| 1 | Pengguna mencopot action | Banjir `DYN` menjatuhkan skor di bawah `min_score` | DYN non-scoring, cap tampilan, allowlist base-branch, ukur dampak sebelum DYN boleh scoring |
| 2 | Supply-chain miss lewat suppression | Inline suppression pada rule `DG004` oleh penulis PR | Tanpa inline suppression untuk DYN; hanya base-branch |
| 3 | CI timeout / DoS oleh PR jahat | Fold/backscan pada input adversarial | Batas berbasis hitungan, fail-open, tes DoS, benchmark gate |
| 4 | FP karena lipatan mengubah semantik | Salah baca prioritas operator / posisi `[` | Guard §5.4, TN wajib, differential fold, hanya literal tanpa escape |
| 5 | Lokasi finding salah / suppression meleset | `SpanMap` keliru, memakai baris V | Selalu hitung dari O via `toOrig`, property test |
| 6 | ReDoS lewat allowlist `.devguard.json` | Glob dikompilasi jadi RegExp | Matcher glob linear-time buatan sendiri, tes pola patologis |
| 7 | Ringkasan PR disalahartikan | "Skipped" terbaca sebagai aman/gagal; `N/A` membingungkan | Teks baku, coverage satu baris dengan skor, README menjelaskan `N/A` |
| 8 | Merge terblokir salah | Promosi dini ke `error` | Tidak ada promosi di v1.3.0; gerbang §9; commit promosi terpisah |
| 9 | Kebocoran secret via komentar/SARIF | Pesan menyalin argumen | Pesan tanpa snippet, redaksi wajib |
| 10 | Regresi kontrak/fork PR | Input baru tidak sinkron dengan README/workflow/tes | Satu commit untuk `action.yml` + README + workflow + Test 6/29; tes regresi fork PR tetap hijau |
| 11 | Runtime membengkak | Pass-V menggandakan biaya rule | Pass-V hanya bila ada edit, batas edit, benchmark gate |
| 12 | Evasion lewat penalti lebih murah | Varian EV dihukum lebih ringan dari induk | Paritas skor dengan induk |

Risiko yang diterima (dicatat): suppression `DG005-EV-01` inline mengikuti induknya, sehingga penulis PR masih dapat menekannya dengan alasan dua kata. Itu sifat tier warning DG005 existing, bukan sesuatu yang diubah di v1.3.0; layak ditinjau ulang sebelum EV-01 dipromosikan ke `error`.

---

## 13. Keputusan Terbuka & Asumsi untuk Stage 5.0

| ID | Pertanyaan | Default sementara |
|---|---|---|
| D1 | Apakah masker mengekspos klasifikasi region, atau hanya string termasking? | Tambah ekspor minimal tanpa mengubah output masked |
| D2 | Bagaimana `N/A` direpresentasikan di output action dan SARIF? | Periksa konsumen skor; usulan: output kosong/`N/A` terdokumentasi, perbandingan `min_score` dilewati |
| D3 | Apakah `.html`/`.htm` (inline `<script>`) harus `skipped/unsupported_language`? | `ignored/non_code` untuk mengurangi noise; tinjau ulang |
| D4 | Skema `.devguard.json` untuk allowlist: sudah ada glob path? | Tambah matcher glob linear-time bila belum |
| D5 | Kebijakan suppression aktual DG008 | Ikuti induk |
| D6 | Nilai batas §5.5 dan ambang benchmark | Tetapkan dari angka benchmark Stage 5.3b |
| D7 | Apakah enumerasi file memfilter ekstensi sebelum klasifier? | Klasifier harus ditempatkan sebelum filter itu |
| D8 | Alias env `DEVGUARD_FAIL_ON_UNANALYZABLE` mengikuti konvensi yang ada? | Hanya jika input lain punya alias |

## 14. Definisi Selesai (v1.3.0)

- [ ] Stage 5.0–5.5 lulus gate masing-masing dengan bukti §11.
- [ ] CI hijau; jumlah tes ≥ 35 + tes baru; tidak ada tes dinonaktifkan.
- [ ] Tidak ada PR yang menghasilkan `100/100` tanpa file `analyzed`.
- [ ] Output pass-O pada corpus v1.2.1 identik dengan baseline.
- [ ] Semua rule baru berstatus `warning`; `DG004-DYN` non-scoring; promosi hanya lewat §9.
- [ ] `docs/validation/v1.3.0-external.md` ada dengan label per finding.
- [ ] README dan CHANGELOG diperbarui tanpa klaim di luar §2.
