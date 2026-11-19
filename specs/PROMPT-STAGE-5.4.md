# PROMPT IMPLEMENTASI — DevGuard v1.3.0 · Stage 5.4 (DG008-EV-01 do/while(true|1), DG005-EV-01 .catch(() => {}) on Critical Flows & Shared CRITICAL_FLOW_IDENTIFIERS)

> Tempel seluruh isi berkas ini ke agen koding di root repo DevGuard.
> Sumber kebenaran: `specs/SPEC.md` (Rev 2.3) §6.2, §6.3, §7, §8, §10.

---

## 0. Konteks & Tujuan

Saat ini `main` (`39af33b`, `71/71` tes lulus) sudah mencakup Stage 5.1-hardening, Stage 5.2 (`DG004-DYN-01/02`), dan Stage 5.3a/b (`SpanMap` + `FOLD-03/01/02/04` + Pass-V aditif).

Tugasmu di **Stage 5.4** adalah mengimplementasikan dua detektor varian *evasion* sesuai `specs/SPEC.md` §6.2, §6.3, §7, §8, dan §10:
1. **`DG008-EV-01` (`do { ... } while (true | 1)` tanpa exit/retry guard pada async loop) — `SPEC.md` §6.2:**
   - Memperluas detektor `DG008` di `src/rules/secretAndResilienceRules.ts` untuk mendeteksi `do { ... } while (true)` atau `do { ... } while (1)` yang memuat `await` tanpa `break`, `return`, `throw`, `process.exit`, atau bounded retry check.
   - **Wajib mengekstrak dan memakai helper pemindaian body yang SAMA** dengan `while (true)` / `while (1)` / `for (;;)` di `DG008` existing (tidak boleh menyalin/menduplikasi logika pemindaian body!).
   - Mewarisi tingkat `warning` dan penalti skor `DG008` (`-10` correctness per finding) serta kebijakan inline suppression `DG008`.
2. **Ekstraksi Konstanta Bersama `CRITICAL_FLOW_IDENTIFIERS` & `DG005-EV-01` (`.catch(() => {})` pada Critical Flow) — `SPEC.md` §6.3:**
   - Mengekstrak konstanta tunggal `CRITICAL_FLOW_IDENTIFIERS` di `src/rules/packageAndExceptionRules.ts` (dan di-re-export lewat `src/rules/lexicalMasker.ts` serta `src/devguardAnalyzer.ts`) berisi tepat 17 identifier yang terverifikasi di `SPEC.md` §6.3:
     `['payment', 'balance', 'wallet', 'ledger', 'transfer', 'charge', 'refund', 'deduct', 'invoice', 'auth', 'token', 'jwt', 'password', 'execute', 'query', 'transaction', 'writeFileSync'] as const`.
   - Memakai `CRITICAL_FLOW_IDENTIFIERS` dan fungsi pencocokan yang sama baik pada `try/catch` `DG005` existing maupun pada `DG005-EV-01`.
   - Mendeteksi `.catch(<empty_callback>)` pada rantai pemanggilan yang memuat identifier kritikal di **rantai receiver** (bukan di argumen pemanggilan atau fungsi sekitar), dengan pengecualian cleanup (`unlink`, `rmSync`, `close`, `JSON.parse`) yang dievaluasi **hanya pada pemanggilan yang langsung mendahului `.catch`**.
   - Mewarisi tingkat `warning` dan penalti skor `DG005` warning (`-10` maintainability per finding) serta kebijakan suppression `DG005` warning.
3. **Pass-V & Corpus/Integration Tests (`SPEC.md` §8.1–§8.3):**
   - Memastikan `DG008-EV-01` dan `DG005-EV-01` juga berjalan pada Pass-V saat ada lipatan (mis. `pay["ch" + "arge"](x).catch(() => {})` tertangkap di Pass-V!).
   - Menambahkan minimal **3 TP + 5 TN realistis untuk `DG008-EV-01`** dan **3 TP + 5 TN realistis untuk `DG005-EV-01`** di `tests/corpus/cases.ts` (minimal 2 TN per pola ber-provenance repo OSS nyata, mencakup seluruh contoh TN wajib di `SPEC.md` §8.2).
   - Menambahkan **Tests 71–74** di `tests/integration.test.ts`.

---

## 1. Aturan Keras (Pelanggaran = Gagal)

1. **Pre-Flight Read-Only (C1–C5) wajib dicetak SEBELUM menyentuh kode apa pun**, saat `git status --short` dan `git diff --stat` kosong.
2. **Scope Lock Stage 5.4:**
   - Jangan mengubah versi di `package.json` ke `1.3.0` dulu (bump versi & validasi eksternal adalah tugas Stage 5.5).
3. **Rule ID & Paritas Skor/Suppression (`SPEC.md` §6.2, §6.3, §7):**
   - Periksa bagaimana `DG005` dan `DG008` saat ini melaporkan `ruleId` di `InlineFinding` dan `CorpusCase`:
     - Apakah `InlineFinding.ruleId` tetap `'DG008'` / `'DG005'` (seperti kasus `EVASION` di `cases.ts` dan registrasi SARIF `DG001–DG008`) atau apakah pesan finding memuat tag `[DG008-EV-01]` / `[DG005-EV-01]`? Pastikan konsisten dengan `SARIF` (`sarifGenerator.ts`), `applySuppressionPolicy` (`devguardAnalyzer.ts`), dan `tests/corpus.test.ts`!
4. **Zero Dependency & Zero Regression:**
   - Seluruh 71 tes yang ada wajib tetap lulus tanpa menghapus satu baris pun tes lama (`ZERO_DELETED_TEST_LINES`).

---

## 2. Pre-Flight Read-Only (C1–C5)

Buat branch `stage-5.4-evasion-detectors` dari `main` (`39af33b`), commit `specs/PROMPT-STAGE-5.4.md`, lalu cetak tabel C1–C5 dengan bukti `path:baris`:
- **C1:** Di `src/rules/secretAndResilienceRules.ts`, bagaimana `detectMissingTimeoutsAndLoops` (`DG008`) saat ini memindai `while (true)`, `while (1)`, dan `for (;;)` serta memeriksa `await`, `break`, `return`, `throw`, `process.exit`, dan bounded retry? Bagaimana cara mengekstrak helper body-scan bersama untuk dipakai juga oleh `do { ... } while (true | 1)`?
- **C2:** Di `src/rules/packageAndExceptionRules.ts`, bagaimana `detectSwallowedExceptions` (`DG005`) saat ini mendeteksi `try/catch`, mencocokkan kata kunci kritikal, dan mengecualikan cleanup (`unlink`, `rmSync`, `close`, `JSON.parse`)?
- **C3:** Bagaimana cara mem-parsing rantai receiver yang berakhir di `.catch(<empty_callback>)` pada `maskedCode` + `code` sehingga:
  - Hanya mencocokkan nama method/properti/objek di **rantai receiver** (mis. `paymentService.charge(userId).catch(() => {})` atau `db.query(sql).then( map ).catch(_ => {})` terdeteksi),
  - **TIDAK** mencocokkan identifier di dalam argumen pemanggilan (mis. `fetch(url, { headers: { token } }).catch(() => {})` **AMAN / TN**!),
  - Pengecualian cleanup (`unlink`, `rmSync`, `close`, `JSON.parse`) dievaluasi **hanya pada pemanggilan yang langsung mendahului `.catch`** (sehingga `fs.unlink(tmp).catch(() => {})` dan `server.close().catch(() => {})` adalah **TN**, sedangkan `pay.charge(x).then(() => fs.unlink(f)).catch(() => {})` **TETAP DILAPORKAN sebagai TP**!)?
- **C4:** Bagaimana `InlineFinding.ruleId`, `LineFinding`, `applySuppressionPolicy`, `sarifGenerator.ts`, dan `tests/corpus.test.ts` menangani `DG008-EV-01` dan `DG005-EV-01`?
- **C5:** Di `src/devguardAnalyzer.ts` (Pass-V baris `1436–1443`), guard regex cepat apa yang dipakai sebelum memanggil `detectSwallowedExceptions` dan `detectMissingTimeoutsAndLoops` pada `V`? (Perhatikan: saat ini di baris `1436` tertulis `if (/\b(?:try|catch)\b/.test(vLex.maskedCode))` dan di baris `1442` tertulis `if (/\b(?:while|for|fetch)\b/.test(vLex.maskedCode))` — pastikan `do` juga tercakup!).

Cetak tabel C1–C5, pastikan `git status --short` dan `git diff --stat` kosong, lalu tulis:
`PRE-FLIGHT STAGE 5.4 SELESAI — mulai implementasi.`

---

## 3. Spesifikasi Teknis Implementasi (2 Commit Bersih)

### Commit 1 — `DG008-EV-01` (`do { ... } while (true | 1)`) & `CRITICAL_FLOW_IDENTIFIERS` + `DG005-EV-01` (`.catch(() => {})`)

1. **`DG008-EV-01` di `src/rules/secretAndResilienceRules.ts` (`SPEC.md` §6.2):**
   - Ekstrak fungsi helper bersama (mis. `isUnboundedAsyncLoopBody(rawBody: string, maskedBody: string): boolean`) yang memeriksa apakah body loop memiliki `\bawait\b` di `maskedBody` dan tidak memiliki `\b(?:break|return|throw)\b`, `process.exit`, atau bounded retry counter check — dipakai bersama oleh `while (true|1)` / `for (;;)` dan `do { ... } while (true|1)`.
   - Jangkar deteksi `do/while`:
     - Token `do` di `maskedCode` (bukan `.do`, `?.do`, atau nama properti/method `do(...)` / `do:`), diikuti `{` (dengan whitespace opsional; body `do` tanpa `{` tidak didukung sesuai `SPEC.md` §6.2).
     - Cocokkan kurung kurawal penutup `}` yang berpasangan pada `maskedCode`.
     - Tepat setelah `}` (dengan whitespace opsional) harus muncul `while\s*\(\s*(?:true|1)\s*\)`.
     - **Guard anti-false-positive wajib (`SPEC.md` §6.2 & §8.2):** Blok biasa `{ ... }` yang tidak diawali token `do` lalu kebetulan diikuti `while (true) { ... }` **bukan** `do-while`! Selain itu, setelah `while (true | 1)` pada `do-while` tidak boleh diikuti `{` (karena `while (true) {` adalah awal statement `while` baru setelah blok biasa, bukan klausa penutup `do-while`!).
   - Jika `isUnboundedAsyncLoopBody` bernilai `true`:
     - Dorong `LineFinding` (`category: 'correctness', penalty: 10`, baris awal `do`) dan `InlineFinding` (`ruleId: 'DG008'`, `severity: 'warning'`, pesan memuat `[DG008-EV-01]`).
     - Pastikan inline suppression `// devguard-ignore DG008: ...` (atau `DG008-EV-01`) pada baris `do` bekerja persis mengikuti kebijakan `DG008`.

2. **`CRITICAL_FLOW_IDENTIFIERS` & `DG005-EV-01` di `src/rules/packageAndExceptionRules.ts` (`SPEC.md` §6.3):**
   - Ekspor konstanta tunggal:
```ts
export const CRITICAL_FLOW_IDENTIFIERS = [
  'payment', 'balance', 'wallet', 'ledger', 'transfer', 'charge',
  'refund', 'deduct', 'invoice', 'auth', 'token', 'jwt', 'password',
  'execute', 'query', 'transaction', 'writeFileSync',
] as const;

```

```
 dan re-export dari `src/rules/lexicalMasker.ts` serta `src/devguardAnalyzer.ts`.

```

* Gunakan `CRITICAL_FLOW_IDENTIFIERS` (dengan pencocokan boundary identifier / camelCase token yang sama) untuk `try/catch` `DG005` existing **dan** `DG005-EV-01`.
* **Deteksi `.catch(<empty_callback>)` (`DG005-EV-01`):**
* Cari pemanggilan `.catch(` (atau `?.catch(`) pada `maskedCode`.
* **Syarat Callback Kosong (`SPEC.md` §6.3):** Argumen di dalam `.catch(...)` pada `maskedCode` (setelah komentar di dalam `{}` otomatis menjadi spasi oleh `analyzeLexicalStructure`) harus berupa arrow function atau function expression dengan **body `{}` kosong**:
* Cocok: `() => {}`, `_ => {}`, `(e) => {}`, `(err: unknown) => {}`, `async (e) => {}`, `function () {}`, `function (e) {}` (termasuk jika di dalam `{ /* komentar */ }` hanya ada komentar/spasi).
* **TIDAK cocok (harus diabaikan / TN):** `() => null`, `() => undefined`, `.catch(noop)`, `.catch(err => logger.warn(err))`, `.then(a, () => {})`, atau callback dengan statement apa pun di dalam `{ ... }`.


* **Ekstraksi Rantai Receiver (Tanpa Isi Argumen `( ... )`):**
* Telusuri mundur dari titik `.` sebelum `catch` melewati rantai pemanggilan/properti (`obj.prop`, `fn(...)`, `?.`, `[...]`).
* Saat melewati pasangan kurung `(...)` milik pemanggilan fungsi di rantai receiver (mis. `fetch(url, { headers: { token } })` atau `pay.charge(amount).then(() => fs.unlink(f))`), **lompati isi di dalam `(...)` argumen tersebut** sehingga identifier di dalam argumen (`{ headers: { token } }`) **TIDAK** ikut dicocokkan sebagai nama rantai receiver!
* Kumpulkan hanya nama-nama identifier/properti pada tulang punggung (*backbone*) rantai receiver (mis. pada `pay.charge(x).then(() => fs.unlink(f)).catch(() => {})`, tulang punggung rantainya adalah `['pay', 'charge', 'then']`, dan pemanggilan yang langsung mendahului `.catch` adalah `'then'`).


* **Evaluasi Pengecualian Cleanup (`unlink`, `rmSync`, `close`, `JSON.parse`):**
* Evaluasi pengecualian cleanup **hanya pada pemanggilan yang langsung mendahului `.catch**` (yaitu segmen pemanggilan terakhir sebelum `.catch`, misalnya `fs.unlink(tmp).catch(() => {})` atau `server.close().catch(() => {})`).
* Dengan demikian, `pay.charge(x).then(() => fs.unlink(f)).catch(() => {})` memiliki pemanggilan terakhir `.then(...)` (bukan `.unlink(...)`) dan tulang punggungnya memuat `charge` $\rightarrow$ **tetap dilaporkan sebagai `DG005-EV-01`!**


* **Severity, Skor, & Suppression (`SPEC.md` §6.3 & §7):**
* `severity: 'warning'`, penalti `-10` pada `maintainability` (`LineFinding` + `InlineFinding` dengan `ruleId: 'DG005'`, pesan memuat `[DG005-EV-01]`). Tidak naik ke `error` di v1.3.0.
* Mengikuti kebijakan suppression `DG005` `warning` existing (inline `// devguard-ignore DG005: <alasan >= 2 kata>` atau base-branch allowlist).





### Commit 2 — Corpus TP/TN (`DG008-EV-01` & `DG005-EV-01`) + Tests 71–74 di `tests/integration.test.ts`

1. **Tambahkan Kasus Corpus di `tests/corpus/cases.ts` (`SPEC.md` §8.1–§8.3):**
* Perbarui juga kasus `EVASION` existing yang relevan di `tests/corpus/cases.ts` bila kini telah terdeteksi (`status: 'expected'`), dan tambahkan bagian khusus:
* **`DG008-EV-01`:** Minimal **3 TP** dan **5 TN** realistis (minimal 2 TN dengan `provenance` repo OSS nyata; wajib mencakup `do { ... } while (cond)`, `do { ... } while (true)` dengan `break` / `return` / `process.exit` / bounded retry check, objek dengan method `.do()`, serta blok biasa `{ ... }` diikuti `while (true) { break; }`).
* **`DG005-EV-01`:** Minimal **3 TP** dan **5 TN** realistis (minimal 2 TN dengan `provenance` repo OSS nyata; wajib mencakup `fs.unlink(tmp).catch(() => {})`, `server.close().catch(() => {})`, `analytics.track(e).catch(() => {})`, `.catch(err => logger.warn(err))`, `.catch(() => null)`, `.catch(() => {})` pada rantai tanpa nama kritikal, dan `fetch(url, { headers: { token } }).catch(() => {})`).




2. **Tambahkan Tests 71–74 di `tests/integration.test.ts`:**
* **Test 71 (`DG008-EV-01` Detection, Shared Body-Scan Parity, & False-Positive Guards):**
Menguji `do { await poll(); } while (true)` dan `do { await step(); } while (1)` (terdeteksi `-10` correctness, warning), memastikan semua variasi keluar (`break`, `return`, `throw`, `process.exit`, retry counter `attempts++ > max`), `do { syncOnly(); } while (true)`, `stream.do(() => {})`, dan blok `{ await init(); } while (true) { await tick(); break; }` **tidak** ter-flag, serta menguji inline suppression `// devguard-ignore DG008: ...`.
* **Test 72 (`DG005-EV-01` Receiver Backbone Matching, Cleanup Immediate-Predecessor Rule, & Shared `CRITICAL_FLOW_IDENTIFIERS`):**
Memverifikasi ekspor `CRITICAL_FLOW_IDENTIFIERS` (17 item), menguji semua bentuk callback kosong (`() => {}`, `_ => {}`, `(e) => {}`, `function () {}`, `function(e) { /* comment */ }`) pada rantai kritikal (`payment.charge(x).catch(() => {})`, `db.query(q).then(r => r).catch(_ => {})`, `pay.charge(x).then(() => fs.unlink(f)).catch(() => {})`), serta memastikan seluruh TN wajib (`fs.unlink(tmp).catch(() => {})`, `server.close().catch(() => {})`, `fetch(url, { headers: { token } }).catch(() => {})`, `.catch(() => null)`, `.catch(noop)`, `.then(ok, () => {})`) menghasilkan **0 finding**.
* **Test 73 (Pass-V Additive Interaction with `DG005-EV-01` & `DG008-EV-01` + Redaction Safety):**
Menguji `wallet["ded" + "uct"](amt).catch(() => {})` (terlipat oleh `FOLD-01` + `FOLD-04` di Pass-V menjadi `wallet.deduct(amt).catch(() => {})` dan terdeteksi sebagai `DG005-EV-01` `[via-fold]` pada baris asli `O`), menguji inline suppression `// devguard-ignore DG005: ...`, serta memastikan secret yang ditanam di argumen rantai kritikal tidak pernah bocor di pesan `DG005-EV-01` maupun `DG008-EV-01`.
* **Test 74 (Total Corpus TN Quota Verification — `SPEC.md` §8.1):**
Memverifikasi secara mekanis bahwa kuota minimum TP (≥ 3) dan TN (≥ 5) untuk setiap pola baru di `SPEC.md` §8.1 (`DG004-DYN-01`, `DG004-DYN-02`, `DG005-EV-01`, `DG008-EV-01`, `FOLD-01`, `FOLD-02`, `FOLD-03`, `FOLD-04`) terpenuhi seluruhnya (total TN baru ≥ 40) dan seluruh TN memiliki 0 false positive lintas semua rule.



---

## 4. Pengecekan Mekanis & Bukti Wajib

Setelah kedua commit selesai, jalankan dan tempelkan output aktual **tanpa pemotongan (`head`/`tail` dilarang)**:

1. `npm run lint`
2. `npm run build`
3. `npm test` (wajib **75/75 lulus**, `0` gagal, `0` skipped)
4. Pengecekan 0 baris tes lama yang dihapus:
```bash
git diff main...HEAD -- tests/integration.test.ts | grep "^-" | grep -v "^---" || echo "ZERO_DELETED_TEST_LINES"

```


5. `git diff main...HEAD -- src/ tests/corpus/ tests/integration.test.ts` (tampilkan utuh).


