# PROMPT IMPLEMENTASI — DevGuard v1.3.0 · Stage 5.2 (`DG004-DYN-01/02` Non-Scoring Warning + Base-Branch Linear-Time Glob Allowlist)

> Tempel seluruh isi berkas ini ke agen koding (Antigravity / Claude Code) di root repo DevGuard setelah Stage 5.1-fix berada di `main` (`87927d8`).
> Sumber kebenaran: `specs/SPEC.md` (Rev 2.1 / Rev 2.2). Jika prompt ini bertentangan dengan `specs/SPEC.md`, **hentikan dan laporkan konflik**, jangan memilih sendiri.

---

## 0. Peran & Konteks

Kamu adalah engineer pelaksana untuk **DevGuard** (GitHub Action gatekeeper CI/CD, zero-dependency, engine Layer 1 lexical: `src/rules/lexicalMasker.ts`, bukan AST). Baseline pasca Stage 5.1-fix memiliki `54/54` tes lulus (`Corpus Benchmark` + `Tests 1–53`).

Tugasmu di sesi ini adalah mengeksekusi **Stage 5.2** secara penuh sesuai `specs/SPEC.md` §6.1, §7, §8.1–§8.4, §10, §11, dan §12:
1. **Pre-flight Read-Only (S1–S7)** untuk memetakan struktur internal `DG004`, penghitung skor, allowlist `.devguard.json`, renderer PR, SARIF generator, dan `tests/corpus/cases.ts` dengan bukti `path:baris` **sebelum** mengedit kode apa pun.
2. **Implementasi `DG004-DYN-01` (`import(<non-literal>)`) & `DG004-DYN-02` (`require(<non-literal>)`)** pada source asli (O) menggunakan region kode dari `lexicalMasker.ts` (tanpa constant folding dulu, karena folding adalah Stage 5.3).
3. **Semantik Non-Scoring Warning (`scoring: false`):** `0` penalti skor (tidak pernah mengurangi skor kategori maupun `totalScore`, tidak mempengaruhi exit code).
4. **Kebijakan Suppression & Linear-Time Glob Allowlist:** **Dilarang keras** mendukung *inline suppression* (`// devguard-ignore`) untuk `DG004-DYN-*`; hanya dapat di-allowlist melalui `.devguard.json` yang dibaca dari **base branch** dengan matcher glob **linear-time $O(N \cdot M)$ buatan sendiri** (tanpa mengompilasi pola pengguna menjadi `RegExp` agar kebal ReDoS).
5. **Tampilan Komentar PR & SARIF:** Bagian terpisah `"Warnings (non-scoring)"` dengan batas tampilan `MAX_DYN_FINDINGS_PER_FILE = 20` (`+N more`), pesan tanpa snippet ekspresi mentah (bebas kebocoran secret), dan SARIF `level: "warning"` dengan `properties: { scoring: false }`.
6. **Ekspansi Corpus & Tes Integrasi:** Minimal **3 TP** dan **5 TN kode aman realistis** (termasuk minimal 2 TN per sub-rule dengan provenance repo OSS nyata: sumber, lisensi, commit SHA) untuk masing-masing `DG004-DYN-01` dan `DG004-DYN-02`, ditambah tes integrasi khusus Stage 5.2.

---

## 1. Aturan Keras (Pelanggaran = Gagal)

1. **Pre-flight (§3) selesai dan tabel S1–S7 tercetak SEBELUM menyentuh kode apa pun.** Saat dicetak, `git status --short` dan `git diff --stat` wajib kosong.
2. **Scope Lock Ketat.** Dilarang menyentuh fitur Stage 5.3–5.4: `SpanMap`, constant folding (`FOLD-01` s.d. `FOLD-04`), virtual view (`via-fold`), `DG008-EV-01`, `DG005-EV-01`, atau ekstraksi `CRITICAL_FLOW_IDENTIFIERS`.
3. **Zero Dependency.** Dilarang menambah paket di `dependencies` maupun `devDependencies`.
4. **Larangan `new RegExp` untuk Glob Pengguna.** Matcher glob allowlist `.devguard.json` wajib ditulis menggunakan algoritma pencocokan linear-time (misalnya *two-pointer backtracking* / DP karakter-demi-karakter untuk `*`, `**`, dan `?`), **bukan** mengubah pola glob dari `.devguard.json` menjadi `RegExp`.
5. **Larangan Inline Suppression untuk `DG004-DYN-*`.** Komentar `// devguard-ignore DG004-DYN-01 ...` atau `// devguard-ignore DG004 ...` di dalam kode sumber PR harus **ditolak/diabaikan** untuk `DG004-DYN-01` dan `DG004-DYN-02`, persis seperti `DG004` induk. Hanya `.devguard.json` dari *base branch* yang boleh menekan `DG004-DYN-01`, `DG004-DYN-02`, atau `DG004` (mencakup sub-rule `DG004-DYN-*`).
6. **Tidak Boleh Melemahkan Tes Lama.** Seluruh 54 tes baseline wajib tetap lulus tanpa dihapus atau dilonggarkan. Jika `Corpus Benchmark` di `tests/corpus.test.ts` memeriksa jumlah rule atau tabel laporan corpus, pastikan penambahan kasus `DG004-DYN-01/02` kompatibel dan tidak merusak asersi baseline `DG001`, `DG004`–`DG008`.
7. **Bukti Utuh Tanpa Pemotongan.** Dilarang menggunakan `| head`, `| tail`, atau memotong output bukti `git diff` dan `npm test`.
8. **Jangan Mencetak atau Membocorkan Secret.** Pesan finding `DG004-DYN-01/02` **dilarang** menyalin isi ekspresi argumen mentah (mis. `require("secret_" + process.env.KEY)` tidak boleh mengutip string literal di dalamnya). Gunakan format baku berbasis `file:line` dan kategori; jika ada teks tambahan, wajib melewati `redactSecretsPreservingLayout`.

---

## 2. Langkah 0 — Verifikasi Baseline & Branch

Jalankan dan tempel output ringkasnya:

```bash
git status
git rev-parse --abbrev-ref HEAD
git log --oneline -n 5
node --version
npm run lint
npm run build
npm test
```

- Wajib: `54` tes lulus (`Corpus Benchmark` + `Tests 1–53`), `0` gagal. Jika tidak hijau: **berhenti** dan laporkan.
- Buat branch kerja: `git checkout -b stage-5.2-dyn-specifier` (dan commit berkas `specs/PROMPT-STAGE-5.2.md` terlebih dahulu dengan pesan `docs(specs): add Stage 5.2 implementation prompt` agar working tree bersih sebelum Pre-flight §3).

---

## 3. Pre-Flight Read-Only (S1–S7)

Hanya membaca kode (`grep`, `rg`, `cat`, `sed -n`). **Dilarang mengedit berkas apa pun.**

| ID | Pertanyaan Inspeksi | Bukti yang Dicari (`path:baris`) |
|---|---|---|
| **S1** | Bagaimana `analyzeLexicalStructure` (`src/rules/lexicalMasker.ts`) memetakan komentar, string literal (`'`/`"`), template literal (`` ` `` dengan/tanpa `${}`), dan regex literal? Bagaimana `DG004` saat ini (`src/rules/packageAndExceptionRules.ts`) memindai `import` dan `require`? | `path:baris` fungsi masker, struktur `stringLiterals`, dan fungsi detektor `DG004` |
| **S2** | Di mana persisnya `InlineFinding` didefinisikan, di mana penalti skor dihitung dari daftar finding, dan bagaimana `severity: 'warning'` vs `scoring?: boolean` akan melewati pengurangan skor tanpa memicu kegagalan gerbang? | `path:baris` tipe `InlineFinding` dan fungsi kalkulasi skor di `src/devguardAnalyzer.ts` |
| **S3** | Bagaimana kebijakan *inline suppression* vs *external allowlist* (`.devguard.json`) dievaluasi di `src/devguardAnalyzer.ts` dan `src/cli.ts` (`loadVerifiedAllowlist`, `matchAllowlistForFile`)? Aturan ID apa saja yang saat ini diterima oleh `.devguard.json`? | `path:baris` validasi rule ID dan pencocokan path di `src/cli.ts` & `src/devguardAnalyzer.ts` |
| **S4** | Bagaimana `src/githubCommenter.ts` merender detail temuan per berkas dan inline review comments (`postInlineReviewComments`), serta bagaimana `src/sarifGenerator.ts` mendaftarkan `rulesMap` dan membuat objek `result` SARIF? | `path:baris` di `src/githubCommenter.ts` dan `src/sarifGenerator.ts` |
| **S5** | Bagaimana `tests/corpus/cases.ts` dan `tests/corpus.test.ts` mendefinisikan tipe kasus corpus (`CorpusCase`), kategori (`TP` / `TN` / `EVASION`), dan asersi tabel benchmark? | `path:baris` di `tests/corpus/cases.ts` dan `tests/corpus.test.ts` |
| **S6** | Bagaimana metrik internal (seperti `dyn_scope_uncertain` saat `require` terkena shadow guard) dapat diekspos secara bersih pada hasil analisis tanpa merusak kontrak API yang ada? | `path:baris` tipe return `ParsedDevGuardReport` / `analyzeCodeDeterministically` |
| **S7** | Apakah ada tempat di `src/cli.ts` atau `src/githubCommenter.ts` yang memfilter finding berdasarkan `severity === 'warning'` untuk komentar PR atau ringkasan? | `path:baris` terkait |

Cetak tabel temuan S1–S7 dengan format:

```text
| ID | Temuan | Bukti (path:baris) | Cocok dengan SPEC? | Keputusan / DEVIASI |
```

Setelah tabel: cetak `git status --short` dan `git diff --stat` (wajib kosong), lalu tulis satu baris:
`PRE-FLIGHT STAGE 5.2 SELESAI — mulai implementasi Stage 5.2.`

---

## 4. Spesifikasi Implementasi Stage 5.2

Kerjakan dalam 2 commit terstruktur yang masing-masing lulus `npm run lint`, `npm run build`, dan `npm test`.

### Commit A — Detektor Lexical `DG004-DYN-01/02`, Non-Scoring (`scoring: false`), & Linear-Time Glob Allowlist

#### T1. Deteksi Lexical `DG004-DYN-01` & `DG004-DYN-02` (`src/rules/packageAndExceptionRules.ts` & `src/devguardAnalyzer.ts`)
Evaluasi dilakukan secara leksikal pada region kode (menggunakan hasil `analyzeLexicalStructure` sehingga segala kemunculan di dalam komentar, string literal, template literal, atau regex literal diabaikan):

1. **Definisi Argumen Literal vs Non-Literal:**
   - Sebuah panggilan `import(...)` atau `require(...)` dianggap **literal** jika dan hanya jika argumen pertamanya (setelah mengabaikan whitespace/komentar di dalam kurung) adalah **tepat satu token string literal** (`'...'` atau `"..."`) atau **template literal tanpa ekspresi `${...}`** (`` `...` ``), yang langsung diikuti oleh `)` (untuk `require(lit)` dan `import(lit)`) atau `,` (untuk `import(lit, options)`).
   - Panggilan **tanpa argumen** (`import()`, `require()`) atau argumen kosong **tidak** dilaporkan oleh `DG004-DYN-*`.
   - Segala ekspresi argumen lainnya (variabel `import(modName)`, konkatenasi `require("./locales/" + lang)` — *ingat belum ada constant folding di Stage 5.2*, template dengan ekspresi `` import(`./pages/${page}.js`) ``, pemanggilan fungsi `require(getPath())`, member access `import(cfg.entry)`) adalah **non-literal** dan menghasilkan finding:
     - `DG004-DYN-01`: `import(<non-literal>)`
     - `DG004-DYN-02`: `require(<non-literal>)`

2. **Guard Sintaktis Wajib (Zero-FP):**
   - **Bukan Member Property / Method Call:** Token sebelum `import` atau `require` **tidak boleh** `.` atau `?.` (sehingga `obj.import(x)`, `foo?.require(x)`, `module.require(x)`, `require.resolve(x)`, `import.meta.resolve(x)` **tidak** dilaporkan).
   - **Bukan Deklarasi / Method Definition / Class Method:**
     - Jika sebelum `import` atau `require` adalah keyword deklarasi (`function`, `async`, `get`, `set`, `static`), lewati.
     - Jika setelah kurung penutup `)` yang berpasangan dengan `import(` / `require(` (setelah melewati anotasi tipe TypeScript opsional `: ReturnType` bila ada, atau secara konservatif jika diikuti `{` pada konteks deklarasi method class/object seperti `import(x) { ... }` atau `require(x: string): void { ... }`), lewati karena itu adalah definisi method, bukan pemanggilan!
   - **Shadow Guard Konservatif Level File untuk `DG004-DYN-02` (`require`):**
     - Pindai seluruh token identifier `require` di region kode pada berkas tersebut.
     - Kemunculan token `require` **hanya** diizinkan dalam tiga bentuk:
       1. Pemanggilan `require(` (yang bukan definisi method/fungsi `function require(`),
       2. Akses properti `require.<member>` (seperti `require.resolve`, `require.cache`, `require.main`, `require.extensions`), atau
       3. Pemeriksaan `typeof require`.
     - Jika terdapat kemunculan identifier `require` lainnya di mana pun dalam berkas tersebut (misalnya `const require = createRequire(import.meta.url)`, `let require = ...`, `var require = ...`, `function require(...)`, parameter fungsi `(require) => ...` / `function(a, require)`, destructuring `{ require } = ...`, atau alias `const r = require`), maka **seluruh `DG004-DYN-02` dilewati untuk berkas tersebut** dan metrik internal `dynScopeUncertain` (`dyn_scope_uncertain`) dinaikkan `+1` untuk berkas itu.

3. **Pesan Finding Tanpa Snippet Mentah (Bebas Bocor Secret):**
   - Pesan finding **dilarang** memuat isi ekspresi argumen mentah dari kode sumber.
   - Gunakan pesan baku yang informatif dan aman, misalnya:
     - `DG004-DYN-01`: `[DG004-DYN-01] Unanalyzable dynamic import() specifier at ${fileName}:${line} (supply-chain static verification skipped; allowlist in base-branch .devguard.json if intentional).`
     - `DG004-DYN-02`: `[DG004-DYN-02] Unanalyzable dynamic require() specifier at ${fileName}:${line} (supply-chain static verification skipped; allowlist in base-branch .devguard.json if intentional).`
   - Tidak ada `suggestion` inline yang menyalin ekspresi argumen.

#### T2. Semantik Non-Scoring Warning (`scoring: false`)
1. Tambahkan properti opsional `scoring?: boolean` (default `true` untuk seluruh rule existing `DG001`–`DG008`) pada `InlineFinding`.
2. Untuk `DG004-DYN-01` dan `DG004-DYN-02`, tetapkan:
   - `ruleId: 'DG004-DYN-01'` atau `'DG004-DYN-02'`
   - `severity: 'warning'`
   - `scoring: false`
3. Di penghitung skor (`src/devguardAnalyzer.ts`):
   - Finding dengan `scoring === false` **tidak pernah mengurangi skor** kategori (`security`, `correctness`, `maintainability`) sebesar `1` poin pun (`0` penalti) dan **tidak pernah** mengubah `isHardened` atau menggagalkan gerbang `passed`.
   - File dengan $N$ finding `DG004-DYN-01/02` wajib menghasilkan skor `security`, `correctness`, `maintainability`, dan `totalScore` yang **100% identik** dengan file yang sama tanpa finding `DG004-DYN-01/02`.

#### T3. Kebijakan Suppression & Linear-Time Glob Allowlist (`.devguard.json`)
1. **Tolak Inline Suppression:**
   - Di `src/devguardAnalyzer.ts`, pastikan `DG004-DYN-01` dan `DG004-DYN-02` diperlakukan sebagai non-inline-suppressible (sama seperti `DG004`). Komentar `// devguard-ignore DG004-DYN-01 ...` atau `// devguard-ignore DG004 ...` di kode sumber PR harus dicatat sebagai `rejected` (tidak menekan finding).
2. **Base-Branch Allowlist (`.devguard.json`) + Linear-Time Glob Matcher:**
   - Perbarui validasi rule ID pada `.devguard.json` di `src/cli.ts` / `src/devguardAnalyzer.ts` agar menerima `'DG004-DYN-01'` dan `'DG004-DYN-02'` (selain `DG001`–`DG008`). Jika entri `.devguard.json` di base branch mengizinkan `'DG004'` atau `'DG004-DYN-01'` / `'DG004-DYN-02'` untuk path berkas yang cocok, maka finding `DG004-DYN-*` yang bersangkutan ditekan secara sah (`suppressed`).
   - Buat dan ekspor fungsi murni `matchLinearGlob(pattern: string, targetPath: string): boolean` yang ditulis tangan dengan kompleksitas waktu terjamin **$O(|\text{pattern}| \times |\text{targetPath}|)$** dan memori $O(|\text{targetPath}|)$ atau $O(1)$ tanpa pernah memanggil `new RegExp(...)`:
     - Normalisasi kedua path ke POSIX (`/`), hapus awalan `./`.
     - Dukung segmen wildcard:
       - `?` mencocokkan tepat 1 karakter selain `/`.
       - `*` mencocokkan 0 atau lebih karakter selain `/`.
       - `**` mencocokkan 0 atau lebih karakter termasuk `/` (mis. `src/i18n/**`, `**/plugins/*.ts`, `packages/*/src/**/*.js`).
     - Batasi panjang pola glob maksimal (mis. `MAX_GLOB_PATTERN_LENGTH = 512`) untuk keamanan ekstra.

---

### Commit B — Rendering Komentar PR, SARIF `properties.scoring`, Corpus TP/TN, & Tes Integrasi

#### T4. Rendering Komentar PR (`src/githubCommenter.ts`) & Cap `MAX_DYN_FINDINGS_PER_FILE = 20`
1. Ekspor konstanta `MAX_DYN_FINDINGS_PER_FILE = 20`.
2. Di komentar ringkasan PR (`buildPullRequestCommentMarkdown`):
   - Tampilkan temuan non-scoring (`scoring === false` / `DG004-DYN-*`) pada bagian terpisah berlabel **`Warnings (non-scoring)`** agar pengguna langsung paham bahwa peringatan ini tidak menjatuhkan skor.
   - Untuk setiap berkas, batasi tampilan maksimum `MAX_DYN_FINDINGS_PER_FILE` (`20`) baris `DG004-DYN-*`; jika suatu berkas memiliki lebih dari `20` temuan `DG004-DYN-*`, tampilkan `20` temuan pertama diikuti baris ringkasan `+N more` (mis. `- ... +5 more`).
   - Di `postInlineReviewComments`, jangan membanjiri GitHub Review API dengan lebih dari `MAX_DYN_FINDINGS_PER_FILE` komentar inline untuk `DG004-DYN-*` (atau hanya kirim temuan yang memiliki `suggestion`, konsisten dengan perilaku `postInlineReviewComments` saat ini).

#### T5. SARIF Generator (`src/sarifGenerator.ts`)
1. Daftarkan deskripsi rule `DG004-DYN-01` dan `DG004-DYN-02` di `rulesMap` pada `src/sarifGenerator.ts` (dengan `security-severity` yang sesuai untuk warning informasi supply-chain dan penjelasan bahwa rule ini *non-scoring*).
2. Saat menghasilkan `result` SARIF untuk setiap `inlineFindings`:
   - Seluruh finding `DG004-DYN-*` (tanpa dipotong cap 20) tetap dimasukkan ke `runs[0].results[]` dengan `level: 'warning'`.
   - Jika `finding.scoring === false`, sertakan `properties: { scoring: false }` pada objek `result` SARIF tersebut.

#### T6. Corpus Benchmark (`tests/corpus/cases.ts` & `tests/corpus.test.ts`)
Tambahkan kasus berlabel untuk `DG004-DYN-01` dan `DG004-DYN-02` sesuai kuota wajib `specs/SPEC.md` §8.1–§8.3:
- **`DG004-DYN-01` (`import(<non-literal>)`):**
  - Minimal **3 TP** (mis. `await import(pluginPath)`, `` await import(`./locales/${locale}.js`) ``, `import(getModuleName())`).
  - Minimal **5 TN kode aman realistis**, mencakup:
    1. `await import('./chunk.js')` (code splitting literal),
    2. `` await import(`lodash`) `` (template literal tanpa ekspresi),
    3. `await import('./feature.js', { with: { type: 'json' } })` (literal dengan argumen kedua),
    4. Class/object dengan definisi method bernama `import(source: string) { return source; }`,
    5. Pemanggilan method objek `loader.import(dynamicVar)` atau `import.meta.url`.
    *(Minimal 2 TN menyertakan komentar provenance sumber repo OSS nyata + lisensi + commit SHA).*
- **`DG004-DYN-02` (`require(<non-literal>)`):**
  - Minimal **3 TP** (mis. `require(driverName)`, `require('./locales/' + lang)`, `` require(`@scope/${pkg}`) ``).
  - Minimal **5 TN kode aman realistis**, mencakup:
    1. `require('node:fs')` / `require('./config.json')` (string literal),
    2. `` require(`path`) `` (template literal tanpa ekspresi),
    3. `module.require(dynamicId)` / `loader.require(dynamicId)` (member call),
    4. Berkas ESM dengan `const require = createRequire(import.meta.url); require(dynamicPath);` (dilewati oleh shadow guard level file + menaikkan `dynScopeUncertain`),
    5. `typeof require !== 'undefined'` dan `require.resolve(dynamicPath)` / method class `require(name: string) {}`.
    *(Minimal 2 TN menyertakan komentar provenance sumber repo OSS nyata + lisensi + commit SHA).*

#### T7. Tes Integrasi Baru (`tests/integration.test.ts`, lanjutkan penomoran mulai `54.`)
Tambahkan tes integrasi komprehensif:
- **Test 54:** `DG004-DYN-01` dan `DG004-DYN-02` mendeteksi seluruh varian non-literal dan mengabaikan seluruh varian TN (literal, template tanpa ekspresi, `import(lit, opts)`, `obj.import(x)`, `module.require(x)`, `require.resolve(x)`, method class `import(x) {}` / `require(x) {}`, komentar/string).
- **Test 55:** Shadow guard `DG004-DYN-02` melewatkan berkas ketika `require` dideklarasikan/di-shadow (`const require = ...`, `function require()`, parameter `(require) => ...`, destructuring `{ require }`) dan mencatat metrik `dynScopeUncertain` (`dyn_scope_uncertain`).
- **Test 56:** Jaminan Non-Scoring: berkas dengan $0$, $1$, $5$, dan $25$ temuan `DG004-DYN-01/02` menghasilkan skor `security`, `correctness`, `maintainability`, dan `totalScore` yang **100% identik** serta tidak pernah menggagalkan `min_score` maupun exit code.
- **Test 57:** Kebijakan Suppression & Linear-Time Glob Allowlist:
  - Inline suppression `// devguard-ignore DG004-DYN-01 reason two words` dan `// devguard-ignore DG004 reason two words` **ditolak**.
  - Base-branch `.devguard.json` dengan pola glob seperti `src/i18n/**`, `packages/*/plugins/*.ts`, dan `**/*.locale.js` berhasil menekan `DG004-DYN-01/02` secara sah.
  - Uji ketahanan ReDoS pada `matchLinearGlob`: pola patologis seperti `'a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*b'` terhadap string `'a'.repeat(200)` selesai dalam `< 20ms` (linear-time).
- **Test 58:** Cap tampilan komentar PR (`MAX_DYN_FINDINGS_PER_FILE = 20` + `+N more` di bagian `Warnings (non-scoring)`), SARIF menyimpan seluruh $> 20$ temuan dengan `level: 'warning'` dan `properties.scoring === false`, serta pesan finding terbukti tidak membocorkan secret yang ditanam di dalam ekspresi `require("sk-live-..." + x)` / `import("ghp_..." + y)`.

---

## 5. Larangan & Pengecekan Mekanis (§6)

Jalankan di akhir dan tempelkan output aktualnya:

```bash
git diff main...HEAD -- . ":(exclude)specs" ":(exclude)docs/specs" | grep -nE "SpanMap|FOLD-0|EV-01|CRITICAL_FLOW_IDENTIFIERS|via-fold" || echo "BERSIH"
grep -rn "vulnerable_fixture" src/ || echo "BERSIH"
grep -rn "INPUT_FAIL_ON_UNANALYZABLE" src/ || echo "BERSIH"
grep -rn "v1\.3\.0" src/ || echo "BERSIH"
git diff main...HEAD -- tests/integration.test.ts | grep -n "^-" | grep -v "^.*---" || echo "ZERO_DELETED_TEST_LINES"
```

Seluruh pengecekan di atas wajib menghasilkan `BERSIH` / `ZERO_DELETED_TEST_LINES`.

---

## 6. Verifikasi & Format Laporan Akhir

Tempelkan output aktual tanpa pemotongan:
1. **Tabel Pre-Flight S1–S7** (dicetak sebelum edit pertama saat working tree bersih).
2. **Output `npm run lint`, `npm run build`, dan `npm test`** (seluruh 54 tes lama + tes baru 54–58 + Corpus Benchmark wajib lulus 100%, 0 gagal).
3. **`git diff main...HEAD` lengkap** untuk seluruh berkas kode dan tes yang berubah (tanpa `head`/`tail`).
4. **Hasil Pengecekan Mekanis §5.**
5. **Status jujur push/CI.**