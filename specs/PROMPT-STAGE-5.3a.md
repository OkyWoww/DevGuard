# PROMPT IMPLEMENTASI — DevGuard v1.3.0 · Stage 5.3a (Lexical Region Export, SpanMap Infrastructure, Multi-Pass Composition & Property Tests — 0 Active Folds)

> Tempel seluruh isi berkas ini ke agen koding di root repo DevGuard.
> Sumber kebenaran: `specs/SPEC.md` (Rev 2.3). Jika prompt ini bertentangan dengan `specs/SPEC.md`, hentikan dan laporkan konflik.

---

## 0. Peran & Konteks

Kamu adalah engineer pelaksana untuk **DevGuard**. Saat ini `main` (`1179119`) hijau di GitHub Actions dengan **62/62 tes lulus** (Stage 5.1-hardening + Stage 5.2 selesai).

Tugasmu di **Stage 5.3a** adalah membangun dan menguji **infrastruktur `SpanMap` dan klasifikasi region leksikal** sesuai `specs/SPEC.md` §5.1–§5.3 & §10, **dengan 0 operasi lipatan aktif (0 active folds)** sehingga:
1. `analyzeLexicalStructure` di `src/rules/lexicalMasker.ts` mengekspos daftar region leksikal (`code`, `string`, `template`, `comment`, `regex`) yang **menutup penuh `[0, code.length)`** tanpa celah dan tanpa tumpang tindih, sambil menjaga output `maskedCode`, `stringLiterals`, dan `suppressions` **identik byte-per-byte** dengan baseline.
2. Modul/fungsi `SpanMap` menyediakan:
   - Konstruksi `SpanMap` dari daftar edit non-overlapping pada region `code` (`applyTextEditsWithSpanMap`),
   - Komposisi dua `SpanMap` lintas pass (`composeSpanMaps`),
   - Pemetaan balik rentang virtual `[vStart, vEnd]` ke rentang asli `[oStart, oEnd]` menggunakan **binary search** (`toOrigSpan` / `toOrigLineAndCol`),
   - Verifikasi invarian struktural `SpanMap` (`verifySpanMapInvariants`),
   - Stub pipeline virtual view (`buildVirtualView(code, options)`) yang pada Stage 5.3a menjalankan **0 lipatan aktif** (`editsApplied: 0`, `virtualCode === code`, `spanMap` berupa 1 segmen `copy` `[0, |O|)`), sehingga pass-O berjalan identik 100% dan pass-V aditif otomatis dilewati ketika `editsApplied === 0` sesuai `SPEC.md` §5.2 & §5.6.

---

## 1. Aturan Keras (Pelanggaran = Gagal)

1. **Pre-Flight Read-Only (A1–A5) wajib dicetak SEBELUM menyentuh kode apa pun**, saat `git status --short` dan `git diff --stat` kosong.
2. **Scope Lock Stage 5.3a (0 Lipatan Aktif):**
   - **DILARANG** mengaktifkan logika pelipatan `FOLD-01`, `FOLD-02`, `FOLD-03`, atau `FOLD-04` pada kode produksi di Stage 5.3a (itu adalah tugas Stage 5.3b).
   - **DILARANG** menyentuh fitur Stage 5.4 (`DG008-EV-01`, `DG005-EV-01`, `CRITICAL_FLOW_IDENTIFIERS`).
3. **Zero Dependency & Zero Regression:**
   - `"dependencies": {}` di `package.json` tidak boleh berubah.
   - Seluruh 62 tes yang sudah ada wajib tetap lulus tanpa menghapus atau melemahkan satu baris pun asersi tes lama.
   - Output `analyzeLexicalStructure` (`maskedCode`, `stringLiterals`, `suppressions`) dan output `analyzeCodeDeterministically` pada seluruh kasus di `tests/corpus/cases.ts` wajib **identik byte-per-byte** sebelum dan sesudah perubahan Stage 5.3a.
4. **Bukti Tanpa Pemotongan:** Dilarang memotong output diff atau hasil tes dengan `head` atau `tail`.

---

## 2. Langkah 0 & Pre-Flight Read-Only (A1–A5)

### Langkah 0 — Verifikasi Baseline & Buat Branch
Jalankan pada `main` (`1179119`):
1. `npm run lint`
2. `npm run build`
3. `npm test` (wajib 62/62 lulus)
4. Buat branch `stage-5.3a-spanmap-infra` dari `main`, simpan berkas prompt ini di `specs/PROMPT-STAGE-5.3a.md` jika belum di-commit, dan pastikan working tree bersih.

### Pre-Flight Read-Only (A1–A5)
Periksa kode dan cetak tabel temuan dengan bukti `path:baris`:
- **A1:** Di `src/rules/lexicalMasker.ts`, bagaimana loop `analyzeLexicalStructure(code, isPython)` memindai komentar (`//`, `/* */`, `#`), string (`'`, `"`, `"""`, `'''`), template literal (`` ` `` dengan `${...}`), dan regex literal (`skipRegexLiteral`)? Bagaimana cara merekam `regions: LexicalRegion[]` dalam satu pass yang sama tanpa mengubah satu karakter pun pada `chars` (`maskedCode`)?
- **A2:** Bagaimana `ExtractedStringLiteral` disimpan saat ini, dan apakah template literal berinterpolasi (`hasInterpolation: true`) dicatat sebagai satu rentang utuh?
- **A3:** Di `src/devguardAnalyzer.ts`, di titik mana `analyzeLexicalStructure` dipanggil dan bagaimana nomor baris dihitung dari offset karakter pada rule yang ada?
- **A4:** Bagaimana cara merancang tipe `SpanMapSegment`, `SpanMap`, `TextEdit`, `applyTextEditsWithSpanMap`, `composeSpanMaps`, dan `toOrigSpan` agar memenuhi seluruh invarian `specs/SPEC.md` §5.3?
- **A5:** Di mana sebaiknya fungsi-fungsi `SpanMap` diekspor (mis. di `src/rules/spanMap.ts` dan di-re-export dari `src/rules/lexicalMasker.ts` serta `src/devguardAnalyzer.ts`) agar modular dan mudah diuji?

Cetak tabel A1–A5, bukti `git status --short` & `git diff --stat` kosong, lalu tulis:
`PRE-FLIGHT STAGE 5.3a SELESAI — mulai implementasi.`

---

## 3. Spesifikasi Teknis Stage 5.3a (1 atau 2 Commit Bersih)

### T1. Ekspor Klasifikasi Region di `src/rules/lexicalMasker.ts` (`SPEC.md` §5.1)
1. Definisikan tipe:
   ```ts
   export type LexicalRegionKind = 'code' | 'string' | 'template' | 'comment' | 'regex';

   export interface LexicalRegion {
     start: number; // inclusive UTF-16 code unit offset in input string
     end: number;   // exclusive UTF-16 code unit offset in input string
     kind: LexicalRegionKind;
   }

```

2. Perluas hasil kembalian `analyzeLexicalStructure(code: string, isPython: boolean = false)` dengan properti baru `regions: LexicalRegion[]` (tanpa mengubah properti existing `maskedCode`, `stringLiterals`, dan `suppressions`).
3. **Invarian wajib `regions`:**
* Untuk string kosong `""`, `regions` adalah `[]`.
* Untuk string dengan `code.length > 0`:
* `regions[0].start === 0` dan `regions[regions.length - 1].end === code.length`.
* Setiap region memiliki `region.start < region.end`.
* Untuk setiap `k` (`1 <= k < regions.length`), `regions[k].start === regions[k - 1].end` (kontigu dan tidak overlap) serta region bersebelahan yang memiliki `kind` sama digabung (*coalesced*) menjadi satu region.
* Semua komentar (`//...`, `/*...*/`, dan `#...` saat `isPython === true`) berjenis `'comment'` (karakter newline `\n` / `\r\n` di akhir komentar satu baris boleh masuk `'code'` atau `'comment'` secara konsisten, disarankan `'code'` karena di `maskedCode` newline dipertahankan).
* String kutip tunggal/ganda (`'...'`, `"..."`, serta triple-quote Python) berjenis `'string'`.
* Template literal (``...``) berjenis `'template'`.
* Regex literal (`/pattern/flags`) berjenis `'regex'`.
* Seluruh kode di luar empat kategori di atas berjenis `'code'`.


* Buat juga helper `isRangeStrictlyInCodeRegion(regions: ReadonlyArray<LexicalRegion>, start: number, end: number): boolean` menggunakan binary search yang mengembalikan `true` jika dan hanya jika rentang `[start, end)` berada sepenuhnya di dalam satu region berjenis `'code'`.



### T2. Implementasi `SpanMap` (`src/rules/spanMap.ts`, diekspor juga lewat `lexicalMasker.ts` & `devguardAnalyzer.ts`) (`SPEC.md` §5.3)

1. Definisikan tipe sesuai `SPEC.md` §5.3:
```ts
export interface SpanMapSeg {
  vStart: number;
  vEnd: number;
  oStart: number;
  oEnd: number;
  kind: 'copy' | 'fold';
}

export type SpanMap = SpanMapSeg[];

export interface FoldTextEdit {
  start: number; // inclusive offset in source string before pass
  end: number;   // exclusive offset in source string before pass (start < end)
  replacement: string; // non-empty replacement string in virtual view
}

```


2. Implementasikan fungsi-fungsi murni berikut:
* `createIdentitySpanMap(length: number): SpanMap`:
Mengembalikan `length > 0 ? [{ vStart: 0, vEnd: length, oStart: 0, oEnd: length, kind: 'copy' }] : []`.
* `applyTextEditsWithSpanMap(source: string, edits: ReadonlyArray<FoldTextEdit>, codeRegions?: ReadonlyArray<LexicalRegion>): { virtualText: string; spanMap: SpanMap; appliedCount: number }`:
* Menyaring dan mengurutkan edit berdasarkan `start` menaik.
* **Fail-open per edit (`SPEC.md` §5.1 #4):** Jika suatu edit memiliki `start < 0`, `end > source.length`, `start >= end`, `replacement.length === 0`, overlap dengan edit sebelumnya (`edit.start < prevEnd`), atau (bila `codeRegions` diberikan) `!isRangeStrictlyInCodeRegion(codeRegions, edit.start, edit.end)`, maka edit tersebut **dilewati dengan aman** tanpa melempar exception.
* Membangun `virtualText` dan `spanMap` (`kind: 'copy'` untuk bagian yang tidak disentuh dengan `vEnd - vStart === oEnd - oStart`, dan `kind: 'fold'` untuk setiap edit yang diterapkan).


* `composeSpanMaps(prevMap: ReadonlyArray<SpanMapSeg>, nextMap: ReadonlyArray<SpanMapSeg>): SpanMap`:
* Mengomposisikan `prevMap` (yang memetakan `O -> V1`) dengan `nextMap` (yang memetakan `V1 -> V2`) sehingga menghasilkan `SpanMap` tunggal yang memetakan `O -> V2` secara langsung.
* Sesuai `SPEC.md` §5.3:
* Bagian `copy` di `nextMap` yang jatuh di dalam `copy` pada `prevMap` tetap menjadi `copy` dengan offset linear ke `O`.
* Bagian `copy` di `nextMap` yang menyentuh segmen `fold` pada `prevMap`, atau segmen `fold` di `nextMap`, menjadi segmen `fold` yang memetakan ke gabungan rentang asal `[min(oStart), max(oEnd)]` dari seluruh segmen `prevMap` yang tersentuh oleh rentang `[v1Start, v1End)` milik segmen `nextMap` tersebut.
* Segmen `copy` bersebelahan yang kontigu di kedua sisi (`v` dan `o` berdampingan dengan `kind === 'copy'`) dapat digabung jika linear, dan seluruh segmen hasil komposisi wajib memenuhi `verifySpanMapInvariants`.




* `toOrigSpan(spanMap: ReadonlyArray<SpanMapSeg>, vStart: number, vEnd?: number): { oStart: number; oEnd: number }`:
* Menggunakan **binary search** ($O(\log N)$) pada `spanMap`.
* Sesuai `SPEC.md` §5.3:
* Untuk titik/rentang yang jatuh di dalam segmen `copy`, offset dipetakan secara linear: `oOffset = seg.oStart + (vOffset - seg.vStart)`.
* Untuk posisi/rentang yang menyentuh segmen `fold`, diperluas ke **seluruh rentang O (`[seg.oStart, seg.oEnd]`)** dari segmen `fold` tersebut!
* Jika rentang `[vStart, vEnd]` membentang melintasi beberapa segmen, `oStart` adalah hasil pemetaan batas awal pada segmen pertama yang tersentuh dan `oEnd` adalah hasil pemetaan batas akhir pada segmen terakhir yang tersentuh.




* `toOrigLineAndCol(originalSource: string, spanMap: ReadonlyArray<SpanMapSeg>, vStart: number, vEnd?: number): { oStart: number; oEnd: number; line: number; col: number; endLine: number; endCol: number }`:
* Memetakan `[vStart, vEnd]` ke `[oStart, oEnd]` pada `originalSource` via `toOrigSpan`, lalu menghitung nomor baris (`1`-based) dan kolom (`1`-based, UTF-16 offset dalam baris) dari `originalSource` (bukan dari `V`!).


* `verifySpanMapInvariants(originalSource: string, virtualText: string, spanMap: ReadonlyArray<SpanMapSeg>): { valid: boolean; error?: string }`:
* Memverifikasi keempat invarian wajib `SPEC.md` §5.3:
(a) Segmen terurut, tidak overlap, `vStart < vEnd`, `oStart < oEnd`, dan menutup penuh `[0, virtualText.length)`.
(b) Untuk setiap indeks `i` di dalam segmen `copy`, `virtualText[i] === originalSource[toOrigSpan(spanMap, i, i + 1).oStart]`.
(c) `toOrigSpan` bersifat monoton (`i <= j ==> toOrigSpan(i).oStart <= toOrigSpan(j).oStart` dan `toOrigSpan(i).oEnd <= toOrigSpan(j).oEnd`).
(d) Untuk setiap segmen dan setiap hasil `toOrigSpan`, `0 <= oStart <= oEnd <= originalSource.length`.





### T3. Stub Pipeline Virtual View dengan 0 Lipatan Aktif (`buildVirtualView`) (`SPEC.md` §5.2 & §10)

1. Buat fungsi `buildVirtualView(originalSource: string, options?: { isPython?: boolean }): { virtualCode: string; spanMap: SpanMap; editsApplied: number; limitExceeded: boolean }`:
* Pada Stage 5.3a (0 lipatan aktif), fungsi ini menjalankan fail-open try/catch dan mengembalikan `{ virtualCode: originalSource, spanMap: createIdentitySpanMap(originalSource.length), editsApplied: 0, limitExceeded: false }`.
* Sesuai `SPEC.md` §5.2 (`jika 0 edit: V == O, pass aditif dilewati`), di `analyzeCodeDeterministically` (`src/devguardAnalyzer.ts`) pass-O berjalan persis seperti sekarang dan ketika `editsApplied === 0`, pass-V aditif tidak perlu dijalankan.



### T4. Tes Baru di `tests/integration.test.ts` (Tests 62–65)

Tambahkan 4 tes komprehensif berikut di bagian akhir `tests/integration.test.ts`:

1. **Test 62 (`LexicalRegion` Contiguity & Classification Accuracy):**
* Menguji `analyzeLexicalStructure` pada berbagai kode kompleks (komentar `//` dan `/* */`, komentar `#` Python, string `'`/`"`, template literal biasa & berinterpolasi `${...}`, regex literal `/a\/b/gi` vs operator pembagian `a / b / c`, karakter emoji/UTF-16 surrogate pair non-BMP `🚀`, dan string kosong `""`).
* Memverifikasi bahwa `regions` menutup penuh `[0, code.length)` tanpa celah/overlap, serta `isRangeStrictlyInCodeRegion` menerima hanya rentang di dalam `'code'` dan menolak rentang yang menyentuh `'string'`, `'template'`, `'comment'`, atau `'regex'`.


2. **Test 63 (`SpanMap` Single-Pass, Multi-Pass Composition & Binary Search `toOrigSpan`):**
* Menguji `applyTextEditsWithSpanMap` dan `composeSpanMaps` pada simulasi komposisi 2 pass (misalnya Pass 1 melipat `["ev","al"].join("")` menjadi `"eval"` pada `x[["ev","al"].join("")](a)`, lalu Pass 2 menormalisasi `x["eval"](a)` menjadi `x.eval(a)`), termasuk lipatan lintas-baris (multi-line expression) dan karakter UTF-16 non-BMP (emoji di sebelum/sesudah lipatan).
* Memverifikasi bahwa `toOrigSpan` dan `toOrigLineAndCol` memetakan finding di `V` (`x.eval`) kembali ke rentang byte/UTF-16 dan nomor baris:kolom yang **100% tepat di source asli `O**`, serta melewati edit yang overlap atau jatuh di dalam komentar/string secara fail-open.


3. **Test 64 (`SpanMap` Property Test — Invarian §5.3):**
* Menjalankan *property test* deterministik (berbasis PRNG ber-seed tetap untuk ratusan kombinasi string + edit acak non-overlapping dan multi-pass) yang membuktikan keempat invarian `SPEC.md` §5.3:
(a) segmen terurut dan menutup `[0, |V|)`,
(b) untuk setiap karakter `i` di segmen `copy`, `V[i] === O[toOrig(i)]`,
(c) `toOrigSpan` monoton di seluruh `0 <= i <= j <= |V|`,
(d) rentang O selalu berada dalam `[0, |O|]`.


4. **Test 65 (Baseline Pass-O Byte-for-Byte Identity Proof):**
* Menguji seluruh kasus di `CORPUS_CASES` (`tests/corpus/cases.ts`) dan memverifikasi bahwa:
* `analyzeLexicalStructure(c.code)` menghasilkan `maskedCode` dengan panjang identik `c.code.length` dan `regions` valid,
* `buildVirtualView(c.code)` pada Stage 5.3a menghasilkan `editsApplied === 0` dan `verifySpanMapInvariants` lulus,
* Output `analyzeCodeDeterministically(c.code, ...)` (`skor`, `inlineFindings`, `temuanUtama`, `isHardened`) tidak mengalami regresi sedikit pun.





---

## 4. Pengecekan Mekanis & Bukti Wajib

Setelah implementasi selesai, jalankan dan tempelkan output aktual **tanpa pemotongan (`head`/`tail` dilarang)**:

1. `npm run lint`
2. `npm run build`
3. `npm test` (wajib **66/66 lulus**, `0` gagal, `0` skipped)
4. Scope lock Stage 5.3b & 5.4:
```bash
git diff main...HEAD -- . ":(exclude)specs" | grep -nE "FOLD-0[1-4]|EV-01|CRITICAL_FLOW_IDENTIFIERS" || echo "BERSIH"

```


5. Pengecekan 0 baris tes lama yang dihapus:
```bash
git diff main...HEAD -- tests/integration.test.ts | grep "^-" | grep -v "^---" || echo "ZERO_DELETED_TEST_LINES"

```


6. `git diff main...HEAD -- src/` (tampilkan utuh).
