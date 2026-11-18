# PROMPT IMPLEMENTASI — DevGuard v1.3.0 · Stage 5.3b (Lexical Constant Folding FOLD-03/01/02/04, Additive Virtual Pass, DYN Virtual-Only Mode & DoS Benchmark Gate)

> Tempel seluruh isi berkas ini ke agen koding di root repo DevGuard.
> Sumber kebenaran: `specs/SPEC.md` (Rev 2.3) §5, §6.1, §8, §10, §11.

---

## 0. Konteks & Tujuan

Stage 5.3a (`b22b37f`, `66/66` tes lulus) telah menyediakan ekspor `regions: LexicalRegion[]` dan infrastruktur `SpanMap` (`applyTextEditsWithSpanMap`, `composeSpanMaps`, `toOrigSpan`, `toOrigLineAndCol`, `verifySpanMapInvariants`).

Tugasmu di **Stage 5.3b** adalah mengaktifkan **Constant Folding Leksikal (`FOLD-03`, `FOLD-01`, `FOLD-02`, `FOLD-04`)** beserta **Pass-V Aditif** sesuai `specs/SPEC.md` §5.2–§5.6, §8, dan §10:
1. Mengimplementasikan 4 operasi lipatan leksikal konservatif di region `'code'` dalam urutan per pass: **`FOLD-03` → `FOLD-01` → `FOLD-02` → `FOLD-04`**, hingga maksimal `MAX_FOLD_DEPTH = 4` pass, dengan batas deterministik berbasis hitungan (`MAX_FOLD_OPERANDS = 64`, `MAX_FOLDED_LENGTH = 4096`, `MAX_FOLD_EDITS = 2000`, `MAX_BACKSCAN = 256`).
2. Menjalankan **Pass-V Aditif** di `analyzeCodeDeterministically` **hanya jika `editsApplied >= 1`**:
   - Rule v1.2.1 (`DG001`, `DG004`, `DG005`, `DG006`, `DG007`, `DG008`) berjalan pada `O` seperti biasa, lalu bila `editsApplied >= 1` dijalankan juga pada `V`. Finding baru dari `V` dipetakan kembali ke baris/offset `O` melalui `SpanMap` (`toOrigSpan` / `toOrigLineAndCol`), dideduplikasi terhadap finding Pass-O (berdasarkan `ruleId` sama dan rentang `O` yang overlap), dievaluasi terhadap suppression & redaksi pada `O`, dan diberi penanda `[via-fold]` (atau properti `viaFold: true`).
   - **`DG004-DYN-01/02` beroperasi dalam mode `virtual-only` (`SPEC.md` §5.6 & §8.2):** `detectDynamicModuleSpecifiers` dijalankan pada `V` (yang sama dengan `O` bila `editsApplied === 0`), sehingga `require("a" + "b")` atau ``import(`./chunk`)`` yang terlipat menjadi string literal murni di `V` **tidak lagi** memicu peringatan `DG004-DYN-01/02` (dan sebagai gantinya diperiksa oleh `DG004` di Pass-V untuk mendeteksi paket palsu/typosquatting!).
3. Memancarkan notifikasi SARIF `fold_limit_exceeded` (`level: 'note'`, dideduplikasi per berkas, tanpa menambah `results[]`) apabila batas pelipatan (`limitExceeded === true`) terpicu.
4. Menambahkan minimal **3 TP + 5 TN realistis per operasi (`FOLD-01`, `FOLD-02`, `FOLD-03`, `FOLD-04` = minimal 12 TP + 20 TN baru)** di `tests/corpus/cases.ts` (termasuk minimal 2 TN ber-provenance repo OSS nyata per pola) serta tes differential fold, tes DoS limit, dan **angka benchmark terukur (sebelum vs sesudah)** di `tests/integration.test.ts`.

---

## 1. Aturan Keras (Pelanggaran = Gagal)

1. **Pre-Flight Read-Only (B1–B6) wajib dicetak SEBELUM menyentuh kode apa pun**, saat `git status --short` dan `git diff --stat` kosong.
2. **Scope Lock Stage 5.3b:**
   - **DILARANG** mengimplementasikan fitur Stage 5.4 (`DG008-EV-01` `do { ... } while`, `DG005-EV-01` `.catch(() => {})`, atau ekstraksi `CRITICAL_FLOW_IDENTIFIERS`).
3. **Konservatisme & Guard Sintaktis Wajib (`SPEC.md` §5.4):**
   - Operan string/template literal yang mengandung backslash (`\`) atau karakter newline (`\n` / `\r`) **TIDAK BOLEH** dilipat.
   - Literal hasil memakai tanda kutip operan pertama (`'` atau `"`, atau `"` jika berasal dari template `` ` ``); jika konten hasil memuat tanda kutip tersebut, **jangan dilipat**.
   - Patuhi 100% **Guard Prioritas Operator (`FOLD-01`)** dan **Guard Posisi `[` (`FOLD-02` vs `FOLD-04`)** di `SPEC.md` §5.4.
4. **Zero Dependency & Zero Regression:**
   - Seluruh 66 tes yang ada wajib tetap lulus tanpa menghapus baris tes lama.
   - Output Pass-O pada seluruh kasus di `tests/corpus/cases.ts` v1.2.1 wajib tetap identik, dan pada seluruh kasus TN di korpus, Pass-V **tidak boleh** menambah finding palsu (*differential fold test*).

---

## 2. Pre-Flight Read-Only (B1–B6)

Buat branch `stage-5.3b-constant-folding` dari `main`, commit `specs/PROMPT-STAGE-5.3b.md`, lalu jawab B1–B6 dengan bukti `path:baris`:
- **B1:** Bagaimana `analyzeLexicalStructure` menyimpan `stringLiterals` dan `regions`, serta bagaimana kita dapat mengetahui apakah sebuah string/template literal memiliki backslash `\` atau newline `\n`/`\r`?
- **B2:** Bagaimana cara memverifikasi token sebelum dan sesudah rantai `L1 + L2 + ...` pada `FOLD-01` menggunakan `maskedCode` + `regions` agar semua kasus terlarang (`x - "a" + "b"`, `2 * "a" + "b"`, `"a" + "b".length`, `"a" + "b" * 2`, `+"a" + "b"`, `typeof "a" + "b"`) ditolak?
- **B3:** Bagaimana cara membedakan *array literal* (`FOLD-02`: `["a","b"].join("")`) dari *member access* (`FOLD-04`: `obj["prop"]`, `obj?.["prop"]`) beserta back-scan `MAX_BACKSCAN = 256` untuk menolak `if (x) ["a"].forEach(f)` atau `return ["a"]` sebagai member access?
- **B4:** Bagaimana `analyzeCodeDeterministically` di `src/devguardAnalyzer.ts` mengeksekusi rule pada `O`, bagaimana cara menjalankan rule aditif pada `V` saat `virtualView.editsApplied > 0`, memetakan baris finding `V` ke baris `O` via `SpanMap`, mendeduplikasi terhadap finding Pass-O, dan menjaga `DG004-DYN-01/02` berjalan `virtual-only` (dengan lokasi dipetakan ke `O`)?
- **B5:** Bagaimana `sarifGenerator.ts` dan `cli.ts` meneruskan notifikasi per berkas ke `toolExecutionNotifications[]` untuk menambahkan notifikasi `fold_limit_exceeded` (`level: 'note'`, dedupe per file)?
- **B6:** Bagaimana cara mengukur waktu eksekusi corpus benchmark sebelum dan sesudah aktivasi folding untuk memenuhi gate benchmark `SPEC.md` §5.5 & §10?

Cetak tabel B1–B6, pastikan `git status --short` dan `git diff --stat` kosong, lalu tulis:
`PRE-FLIGHT STAGE 5.3b SELESAI — mulai implementasi.`

---

## 3. Spesifikasi Teknis Implementasi (2 Commit Bersih)

### Commit 1 — Engine Pelipatan `FOLD-03/01/02/04` & Batas Deterministik di `src/rules/spanMap.ts`
1. Ekspor konstanta batas sesuai `SPEC.md` §5.5:
   ```ts
   export const MAX_FOLD_DEPTH = 4;
   export const MAX_FOLD_OPERANDS = 64;
   export const MAX_FOLDED_LENGTH = 4096;
   export const MAX_FOLD_EDITS = 2000;
   export const MAX_BACKSCAN = 256;
   Implementasikan keempat operasi lipatan per pass dalam urutan FOLD-03 → FOLD-01 → FOLD-02 → FOLD-04:

        Syarat Literal Aman (Berlaku untuk Semua FOLD):

            Tidak boleh mengandung karakter \ (backslash), \n, atau \r.

            Untuk FOLD-03: template literal `...` tanpa ${}, tanpa \, tanpa newline, dan bukan tagged template (token non-whitespace tepat sebelum ` bukan identifier, ), ], atau literal). Dikonversi menjadi string literal "..." (atau '...' bila isi memuat " tetapi tidak memuat '; jika memuat keduanya, jangan dilipat).

        FOLD-01 ("ev" + "al" → "eval"):

            Hanya melipat rantai ≥ 2 string literal berturut-turut yang dipisahkan operator + di region 'code'.

            Jumlah operan dalam rantai ≤ MAX_FOLD_OPERANDS (jika > 64, rantai itu tidak dilipat dan tandai limitExceeded = true).

            Panjang string hasil ≤ MAX_FOLDED_LENGTH (jika > 4096, tidak dilipat dan tandai limitExceeded = true).

            Guard Token Sebelum L1: Hanya boleh berada di awal file/statement atau didahului oleh pembuka ((, [, {, ,, ;, :, ?, =, =>, ..., return), operator berprioritas lebih rendah dari + (==, !=, ===, !==, <, >, <=, >=, <<, >>, >>>, &, ^, |, &&, ||, ??), atau + biner (yaitu token sebelum + tersebut adalah identifier non-keyword, literal, ), atau ]). Tolak jika didahului -, *, /, %, **, !, ~, typeof, void, delete, await, new, ., ?., atau + unary!

            Guard Token Setelah Literal Terakhir: Tidak boleh diikuti oleh ., ?., [, (, `, *, /, %, atau **.

        FOLD-02 (["a", "b"].join("") / .join("-") / .join() → "ab" / "a-b" / "a,b"):

            Hanya pada array literal (token sebelum [ bukan identifier non-keyword, ), ], atau ?.).

            Semua elemen array harus berupa string literal aman (≥ 1 elemen, ≤ MAX_FOLD_OPERANDS), dipisahkan koma tunggal tanpa hole ([,]), tanpa trailing comma (["a",]), dan tanpa spread (...).

            Tepat setelah ] harus diikuti .join( (dengan whitespace opsional), argumen join berupa kosong () (default separator ",") atau 1 string literal aman tanpa \, diikuti ).

            Panjang string hasil ≤ MAX_FOLDED_LENGTH.

        FOLD-04 (obj["balance"] → obj.balance, obj?.["balance"] → obj?.balance):

            Hanya pada member access: token tepat sebelum [ (atau sebelum ?.[ untuk optional chaining) harus berupa:

                Identifier yang bukan keyword (return, typeof, in, of, instanceof, new, delete, void, throw, case, do, else, yield, await, extends dikecualikan),

                ], atau

                ) — dengan syarat kurung pembukanya yang dicari mundur maksimal MAX_BACKSCAN = 256 karakter bukan milik if, while, for, with, switch, atau catch (jika melampaui MAX_BACKSCAN, jangan dilipat dan tandai limitExceeded = true).

            Token sebelum [ tidak boleh }, angka, atau literal string/template.

            Isi di dalam [ dan ] (selain whitespace) harus tepat satu string literal aman yang nilainya cocok dengan /^[A-Za-z_$][\w$]*$/.

            Untuk obj?.["prop"], rentang edit dimulai dari ?. (atau [) sehingga menghasilkan obj?.prop (bukan obj?..prop).

    Di buildVirtualView(originalSource, options):

        Jalankan hingga MAX_FOLD_DEPTH = 4 pass sementara masih ada edit dan total edit kumulatif < MAX_FOLD_EDITS.

        Di setiap pass, kumpulkan edit non-overlapping dari FOLD-03, FOLD-01, FOLD-02, FOLD-04 secara berurutan (atau sub-pass terkomposisi dengan composeSpanMaps), terapkan dengan applyTextEditsWithSpanMap, dan komposisikan SpanMap-nya ke SpanMap utama.

        Berhenti segera jika dalam suatu pass tidak ada edit baru (appliedCount === 0) atau totalEdits >= MAX_FOLD_EDITS (set limitExceeded = true bila dipangkas oleh MAX_FOLD_EDITS).

Commit 2 — Integrasi Pass-V Aditif, DG004-DYN Virtual-Only, Notifikasi SARIF fold_limit_exceeded, Corpus & Tests 66–70

    Integrasi Pass-V Aditif di src/devguardAnalyzer.ts (SPEC.md §5.2 & §5.6):

        Jalankan Pass-O pada code seperti sekarang, kecuali untuk detectDynamicModuleSpecifiers (DG004-DYN-01/02) yang merupakan rule virtual-only.

        Jika virtualView.editsApplied === 0:

            Jalankan detectDynamicModuleSpecifiers pada lexical.maskedCode dan lexical.stringLiterals seperti biasa.

        Jika virtualView.editsApplied > 0:

            Jalankan detectDynamicModuleSpecifiers pada virtualView.virtualCode (menggunakan virtualLexical = analyzeLexicalStructure(virtualView.virtualCode, isPython)) dan petakan setiap nomor baris finding kembali ke nomor baris asli di code (O) menggunakan toOrigLineAndCol(code, virtualView.spanMap, vOffsetStart, vOffsetEnd).

            Jalankan detektor rule v1.2.1 (DG001, DG004, DG005, DG006, DG007, DG008) pada virtualView.virtualCode, petakan setiap lokasi finding dari baris/offset di V kembali ke baris/rentang di O via virtualView.spanMap, buang duplikat bila sudah ada finding di Pass-O dengan ruleId sama yang baris/rentang O-nya overlap, tambahkan tag [via-fold] pada deskripsi/pesan finding aditif yang baru, dan jalankan evaluasi suppression pada baris O hasil pemetaan!

    Notifikasi SARIF fold_limit_exceeded (SPEC.md §5.5 & §7):

        Jika report.virtualView?.limitExceeded === true pada suatu berkas, catat flag foldLimitExceeded?: boolean pada FileAuditSummary (src/githubCommenter.ts & src/cli.ts), dan di src/sarifGenerator.ts tambahkan 1 notifikasi level: 'note' per berkas yang melampaui batas dengan pesan 'Fold limit exceeded (fold_limit_exceeded): partial virtual folding applied' di toolExecutionNotifications[] tanpa mengubah executionSuccessful dan tanpa menambah results[].

    Tambahkan Kasus Corpus FOLD-01..04 (tests/corpus/cases.ts) (SPEC.md §8.1–§8.3):

        Tambahkan minimal 3 TP dan 5 TN realistis untuk masing-masing FOLD-01, FOLD-02, FOLD-03, dan FOLD-04 (total ≥ 12 TP + ≥ 20 TN baru), termasuk minimal 2 TN per pola dengan provenance repo OSS nyata dan mencakup seluruh contoh TN wajib di SPEC.md §8.2 (x - "a" + "b", 2 * "a" + "b", "a" + "b".length, obj["content-type"], obj["0"], if (x) ["a"].forEach(f), return ["a"], const a = ["a", "b"], { ["k"]: 1 }, tag`ab`, operan dengan \n/\x41, serta require("a" + "b") sebagai TN untuk DG004-DYN-02).

    Tambahkan Tests 66–70 di tests/integration.test.ts:

        Test 66 (FOLD-03, FOLD-01, FOLD-02, FOLD-04 & Multi-Pass Composition Detection):
        Menguji deteksi nyata window["ev" + "al"](userInput) (DG001), x[["ev", "al"].join("")](userInput) (DG001), account?.["bal" + "ance"] across await (DG006), require("lod" + "ahs") (DG004 typosquatting terdeteksi via fold, bukan DG004-DYN-02!), dan require("./local" + "Chunk.js") (terlipat jadi literal sehingga 0 warning DG004-DYN-02), lengkap dengan bukti nomor baris O yang akurat dan tag [via-fold].

        Test 67 (Operator Precedence & Bracket Position Guards — Zero False Folding):
        Menguji seluruh ekspresi jebakan di SPEC.md §5.4 & §8.2 (x - "a" + "b", 2 * "a" + "b", "a" + "b".length, "a" + "b" * 2, +"a" + "b", typeof "a" + "b", if (cond) ["a"].forEach(fn), return ["a"], { ["k"]: 1 }, obj["a-b"], obj["0"], tag`hello`, "a\\nb" + "c") dan memastikan editsApplied === 0 (tidak dilipat).

        Test 68 (Differential Fold Test across Entire Corpus):
        Memverifikasi bahwa pada seluruh kasus berlabel 'TN' di CORPUS_CASES, menjalankan analyzer dengan Pass-V aktif tidak menambah satu pun finding dibandingkan Pass-O (0 false positives).

        Test 69 (Adversarial DoS Limits & SARIF fold_limit_exceeded Notification):
        Menguji rantai "a" + "a" + ... dengan 200 operan (> MAX_FOLD_OPERANDS), array .join("") besar, string hasil > MAX_FOLDED_LENGTH (4096), file dengan > MAX_FOLD_EDITS (2000) kandidat lipatan, dan back-scan > MAX_BACKSCAN (256) — memastikan semuanya selesai cepat (< 100ms), deterministik, tidak crash, menghasilkan limitExceeded === true, dan memancarkan notifikasi note fold_limit_exceeded (dedupe 1 per file) di SARIF.

        Test 70 ( suppression & Redaction on Folded Spans + Benchmark Gate):
        Memverifikasi bahwa inline suppression (mis. // devguard-ignore DG008: ...) di baris asli O tetap bekerja akurat untuk finding yang berasal dari lipatan multi-baris di V, secret yang terpecah ("sk_live_" + "...") terdeteksi oleh DG007 di Pass-V dan tetap teredaksi penuh tanpa bocor, serta mencetak perbandingan waktu eksekusi benchmark korpus (Pass-O vs Pass-O+V).

4. Pengecekan Mekanis & Bukti Wajib

Setelah kedua commit selesai, tampilkan output aktual tanpa pemotongan (head/tail dilarang):

    npm run lint

    npm run build

    npm test (wajib 71/71 lulus, 0 gagal, 0 skipped)

    Angka benchmark waktu eksekusi korpus (sebelum vs sesudah / Pass-O vs Pass-O+V).

    Scope lock Stage 5.4:
    Bash

    git diff main...HEAD -- . ":(exclude)specs" | grep -nE "DG008-EV-01|DG005-EV-01|CRITICAL_FLOW_IDENTIFIERS" || echo "BERSIH"

    Pengecekan 0 baris tes lama yang dihapus:
    Bash

    git diff main...HEAD -- tests/integration.test.ts | grep "^-" | grep -v "^---" || echo "ZERO_DELETED_TEST_LINES"

    git diff main...HEAD -- src/ (tampilkan utuh).