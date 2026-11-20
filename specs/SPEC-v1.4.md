# DevGuard — SPEC rev 1.2 (Blueprint v1.4.0 → v2.0.0)

| Field | Value |
|---|---|
| Status | **P0 + Stage 6: LOCKED (rev 1.2).** Stage 7–10: DRAFT. Perubahan pada bagian locked wajib menaikkan rev dan dicatat di log revisi |
| Baseline | v1.3.0 (**harus diverifikasi di P0, bukan diasumsikan**) |
| Lokasi | `specs/SPEC-v1.4.md` (file ini); `specs/SPEC.md` milik v1.3.0 tidak ditimpa |
| Prinsip kerja | Spec-driven, stage-gated, setiap klaim "selesai" wajib berbukti (section 7) |

### Log revisi

| Rev | Perubahan |
|---|---|
| 1 | Draf awal |
| 1.1 | Hasil review: (a) P0-5/E2 mengacu ke skrip `test` yang aktif di `package.json`; (b) aturan resolusi ancestor vs sibling dipertegas, penggabungan dependency sibling dilarang (6.2); (c) aturan parser JSONC/YAML + fuzz test (6.1a, A6-8, A6-11); (d) P0-1 memverifikasi tag yang sudah di-push dan commit rilis; (e) D-6.4 diperjelas, D-6.5 dan D-6.6 ditambah; (f) R11 dan R12 |
| 1.2 | Lock P0 + Stage 6: D-6.1–D-6.6 diputuskan sesuai rekomendasi; definisi "akar" dipertegas (hanya `package.json` di akar repo, ancestor perantara dan sibling tidak pernah dipakai); semantik tanpa-override dijelaskan; `resolvedVia` ditambahkan agar urutan 6.2 dapat diuji (A6-10 ditulis ulang); known limitation pnpm strict + A6-12 |

---

## 1. Tujuan & Non-Tujuan

### 1.1 Tujuan
1. **Adopsi nyata oleh tim developer**: turunkan false positive (FP) sampai tool tidak dimatikan pada hari pertama.
2. **Geser ke kiri**: DevGuard berjalan sebelum PR (CLI, pre-commit, MCP), bukan hanya di CI.
3. **Perkuat deteksi tanpa merusak invarian**: tutup sebagian evasion aliasing (lihat `knownMiss`) secara deterministik.
4. **Perluas bahasa** secara bertahap dan jujur (partial coverage tetap dilaporkan sebagai partial).

### 1.2 Non-Tujuan
- Tidak menambah pola regex baru hanya demi jumlah rule. Prioritas rilis ini adalah **presisi dan jangkauan**, bukan kuantitas.
- Tidak membangun full AST / data-flow engine / taint tracking lintas file.
- Tidak menambah dependensi runtime (`"dependencies": {}` tetap `{}`).
- Tidak ada telemetri.
- Tidak mengubah semantik scoring v1.3.0 (penalti per finding, `min_score`) tanpa keputusan eksplisit.

---

## 2. Evaluasi Strategis (wajib sebelum fitur)

### 2.1 Anti-Survivorship Bias
Pola sukses yang mudah dikutip: "linter/SAST kecil yang elegan dan cepat". Yang jarang dibahas adalah alasan alat sejenis mati:

| Alasan kegagalan umum alat sejenis | Relevansi ke DevGuard | Respons dalam spec ini |
|---|---|---|
| **Alert fatigue**: FP tinggi, lalu dimatikan atau di-`continue-on-error` | **Terbukti nyata**: uji `nestjs/nest` (481 FP), `vitejs/vite` (48), `commander.js` (39) pada DG004 | Stage 6 dikerjakan **pertama** |
| Konfigurasi manual terlalu berat untuk pengguna baru | `.devguard.json` manual untuk workspace internal | Auto-discovery workspace; config hanya untuk pengecualian |
| Feedback datang terlambat (hanya di CI) | DevGuard hanya hidup di GitHub Actions | Stage 7 (CLI/pre-commit) dan Stage 8 (MCP) |
| Maintainer tunggal berhenti, tool jadi usang | Proyek solo | Scope dijaga kecil, test corpus berlabel, dokumentasi kontrak rule |
| Alat keamanan menjadi vektor supply-chain itu sendiri | Dipublikasikan ke npm dan Marketplace | Section 6.4 (hardening distribusi) |
| Klaim cakupan melebihi kenyataan, lalu kepercayaan runtuh | Sudah pernah ada koreksi README (`.py` partial) | Aturan "klaim README = kemampuan yang teruji" (section 6.5) |

### 2.2 Single Point of Failure (logika Abraham Wald)
Yang dianalisis adalah **di mana kerusakan fatal berkumpul**, bukan hanya di mana pertahanan sudah tebal.

| Kandidat SPOF | Dampak jika gagal | Keputusan |
|---|---|---|
| **DG004 FP di monorepo** | Seluruh tool ditolak; semua rule lain ikut tidak terpakai | **SPOF #1.** Diperkuat lebih dulu (Stage 6) |
| **Resolver workspace menjadi bypass** (penyerang menambah package workspace palsu agar nama paket halusinasi lolos) | DG004 bisa dibungkam lewat PR itu sendiri | Glob workspace dibaca dari **base branch**; package baru dari PR diberi notice non-scoring (Stage 6, D-6.3) |
| **Engine lexical** (SpanMap di atas masker) | Salah mask string/comment = FP/FN sistemik di semua rule | Tidak ada fitur baru di atas masker sebelum fuzz/test masker diperluas (Stage 9 prasyarat) |
| **Satu jalur kode untuk CI, CLI, MCP** | Divergensi hasil antar-mode merusak kepercayaan | Satu `core`, tiga adapter tipis; golden parity test (Stage 7) |
| **Distribusi npm/Action** | Kompromi akun = kompromi semua pengguna | 2FA, provenance, pin action by SHA (6.4) |

### 2.3 Inversion / Pre-Mortem
Asumsikan v2.0.0 gagal total 12 bulan dari sekarang. Penyebab paling mungkin:

1. Resolver monorepo punya edge case tak terduga → FP baru di repo yang tidak ada di corpus → pengguna pergi.
   *Mitigasi:* corpus eksternal berlabel dengan commit pinned; mode `workspaces.mode: "off"` sebagai escape hatch; unparseable config → **unanalyzable notice**, bukan tebak-tebakan. Parser tulisan sendiri wajib di-fuzz (A6-8) dan dependency antar-sibling dilarang digabung (6.2 butir 3).
2. CLI lokal lambat atau berbeda hasil dari CI → developer tidak percaya.
   *Mitigasi:* performance budget terukur + parity test golden.
3. MCP server dipakai sebagai jalur prompt injection (potongan kode berbahaya di output finding mempengaruhi agen).
   *Mitigasi:* read-only, path jail ke root workspace, output di-truncate dan ditandai sebagai kutipan tak tepercaya (Stage 8).
4. Alias tracking menghasilkan FP karena lexical scope salah.
   *Mitigasi:* rule baru selalu mulai sebagai **warning**; promosi ke error hanya setelah validasi repo eksternal (kebijakan yang sudah berlaku).
5. Ekspansi bahasa terlalu cepat → banyak "coverage" palsu.
   *Mitigasi:* tiap bahasa wajib punya masker sendiri dan hanya rule yang bahasa-agnostik/terbukti yang aktif; sisanya dilaporkan *not analyzed*.
6. Scope creep: 5 stage berjalan paralel, tidak ada yang selesai.
   *Mitigasi:* **satu stage aktif dalam satu waktu**; stage berikutnya terkunci sampai gate stage sebelumnya lulus (section 7).

---

## 3. Invarian (tidak boleh dilanggar oleh stage mana pun)

| ID | Invarian |
|---|---|
| INV-1 | Zero runtime dependency (`"dependencies": {}`), termasuk MCP dan CLI (tanpa SDK pihak ketiga, tanpa parser YAML/JSONC dari npm) |
| INV-2 | Offline-first: lapisan deterministik tidak butuh jaringan; Gemini Layer 2 opsional |
| INV-3 | Secret di-redact sebelum data apa pun keluar ke API eksternal |
| INV-4 | Fail-closed: `internal_error`/`parse_error` → exit 1, SARIF `executionSuccessful: false` |
| INV-5 | Determinisme: input sama → output (SARIF, skor) identik antar-run dan antar-mode |
| INV-6 | Policy/allowlist hanya dari base branch `.devguard.json`; tanpa inline suppression |
| INV-7 | Hal yang tidak dianalisis **dilaporkan** (unanalyzable), tidak diam-diam dianggap bersih |
| INV-8 | Rule baru: minimal 5 TN case per pola + validasi repo eksternal sebelum warning → error |

---

## 4. Peta Rilis

| Rilis | Stage | Tema | Gate masuk | Alasan urutan |
|---|---|---|---|---|
| v1.3.x | **P0** | Verifikasi baseline | — | Tidak membangun di atas fondasi yang belum diverifikasi |
| **v1.4.0** | **6** | DG004 Workspace Resolver | P0 lulus | SPOF #1: kebisingan monorepo |
| v1.5.0 | 7 | Core extraction + CLI + pre-commit + `npx` | Stage 6 lulus | Geser ke kiri, memakai resolver yang sudah benar |
| v1.6.0 | 8 | MCP Server (`devguard mcp`) | Stage 7 lulus | Memakai CLI core yang sudah teruji parity |
| v1.7.0 | 9 | Intra-procedural alias tracking (ringan) | Stage 8 lulus + masker fuzz | Menyentuh engine; risiko tertinggi, jadi belakangan |
| v2.0.0 | 10 | Multi-language (Python dulu) | Keputusan D-10 | Hanya jika v1.4–v1.7 stabil |

Aturan: **satu stage aktif**. Stage N+1 tidak dimulai sebelum gate Stage N lulus (section 7).

---

## 5. Spesifikasi per Stage

### P0 — Pre-flight baseline (wajib, sebelum Stage 6)
Agen mencetak tabel temuan (path + baris/commit) **sebelum menyentuh kode**:

| # | Pemeriksaan | Bukti yang dicetak |
|---|---|---|
| P0-1 | Tag `v1.3.0` ada, **sudah di-push ke remote**, dan menunjuk ke commit rilis yang CI-nya hijau (Node 22). Commit rilis yang diklaim (mis. `fff7deb`) dicocokkan dengan hasil `rev-parse`, bukan dipercaya dari catatan | `git tag -l`, `git ls-remote --tags origin v1.3.0`, `git rev-parse v1.3.0^{commit}`, tautan run CI |
| P0-2 | `main` == tag atau selisihnya terjelaskan | `git log --oneline v1.3.0..main` |
| P0-3 | Tidak ada spek ganda (`docs/specs/` lama) | `git ls-files \| grep -i spec` |
| P0-4 | Corpus FP eksternal (`nestjs/nest`, `vitejs/vite`, `commander.js`) dipin ke commit SHA dan hasil awal tercatat | Tabel jumlah finding DG004 per repo |
| P0-5 | Cetak isi `scripts.lint`, `scripts.build`, `scripts.test` dari `package.json` yang aktif, lalu jalankan **skrip itu** (bukan perintah tebakan); hijau di baseline | Isi `scripts` + output perintah apa adanya |

Kalau ada P0 yang gagal, **berhenti dan laporkan**; jangan lanjut ke Stage 6.

---

### Stage 6 — v1.4.0: DG004 Workspace Resolver

**Masalah:** paket internal workspace tidak terbaca di `package.json` akar sehingga import-nya dianggap paket fiktif (slopsquatting FP).

**6.1 Sumber workspace yang didukung (semua dengan parser tulisan sendiri, INV-1)**

| Sumber | Dukungan |
|---|---|
| `package.json` → `workspaces` (array dan bentuk `{ "packages": [...] }`) | Penuh |
| `pnpm-workspace.yaml` → daftar `packages:` | Subset YAML terbatas (list sederhana + negasi `!`). Di luar subset → **unanalyzable notice**, bukan tebakan |
| `tsconfig.json` → `compilerOptions.paths` / `baseUrl` | JSONC (komentar, trailing comma); `extends` maksimal kedalaman 3, siklus terdeteksi dan dilaporkan |
| `package.json` → `imports` (`#internal`) dan self-reference by `name` | Penuh |
| `lerna.json` → `packages` | Opsional (D-6.4) |
| Protokol `workspace:`, `link:`, `file:`, alias `npm:` | `workspace:`/`file:`/`link:` dianggap internal; `npm:alias@x` di-resolve ke nama paket sebenarnya |

**6.1a Aturan parser (edge case parser tulisan sendiri)**
- Setiap parser (JSONC, subset YAML, glob) dibangun sebagai tokenizer berstatus, **bukan regex berlapis** (hindari backtracking katastrofik). Ukuran input dibatasi; angka batas didokumentasikan.
- JSONC: `//`, `/* */`, dan `#` di dalam string literal **bukan** komentar; BOM dan CRLF didukung; trailing comma hanya diterima di luar string.
- Subset YAML pnpm: hanya `packages:` berisi list blok sederhana (`- 'glob'`, kutip tunggal/ganda/tanpa kutip). Konstruk di luar itu (flow sequence `[...]`, anchor/alias, block scalar `|`/`>`, multi-dokumen `---`, tab sebagai indentasi) → **bail-out**.
- **Bail-out bersifat per sumber dan fail-closed**: sumber yang gagal parse menyumbang **nol** nama (tidak ada hasil parsial), memicu `DG004-WS-UNPARSED` dengan kode alasan (`yaml_unsupported_construct`, `jsonc_syntax`, `extends_external`, `extends_cycle`, `size_limit`), dan sumber lain tetap dipakai.
- Parser tidak boleh melempar exception tak tertangani maupun hang pada input apa pun; input rusak → bail-out.

**6.2 Aturan resolusi**
1. Bangun peta `nama paket → direktori` dari glob workspace (ekspansi `*` dan `**`, negasi `!`).
2. Untuk tiap file F, import bare `X` di-resolve dengan **urutan tetap** (berhenti di kecocokan pertama):
   1. dependency yang dideklarasikan di `package.json` **terdekat** dari F (`dependencies`, `devDependencies`, `peerDependencies`, `optionalDependencies`);
   2. dependency yang dideklarasikan di `package.json` **akar** repo, yakni `package.json` di direktori akar repo tempat workspace dideklarasikan. Ancestor perantara (mis. `packages/group/package.json`) dan paket sibling **tidak pernah** dipakai (D-6.6);
   3. nama paket workspace (peta langkah 1) → internal;
   4. `tsconfig` `paths`/`baseUrl` dan `package.json` `imports`/self-reference → internal.
   Tidak ada kecocokan → perilaku DG004 v1.3.0 (finding).
3. **Larangan penggabungan sibling**: `dependencies` dari `package.json` paket *saudara* (bukan ancestor terdekat, bukan akar) **tidak pernah** digabung. Menggabungkannya akan menyembunyikan phantom dependency (mis. `apps/web` mengimpor paket eksternal yang hanya dideklarasikan `packages/ui`).
4. **Impor workspace tanpa deklarasi**: impor paket workspace yang tidak dideklarasikan di `package.json` terdekat/akar tetap lolos DG004 (nama itu nyata, bukan paket fiktif), tetapi dihitung dan ditampilkan sebagai satu baris ringkasan di PR comment ("N impor workspace tanpa deklarasi"), tanpa finding dan tanpa penalti pada v1.4.0 (D-6.5).
5. Subpath (`@scope/pkg/sub/file`) dipetakan ke nama dasar paket.
6. Builtin Node (`node:`-prefix dan daftar builtin) tetap diabaikan seperti sekarang.
7. Hasil resolusi di-cache per run (determinisme: urutan iterasi diurutkan leksikografis).
8. **Tidak ada semantik override/pembatasan**: dependency di paket nested tidak "menutup" dependency akar. Langkah 2.1 dan 2.2 sama-sama berarti *resolved*; urutannya hanya menentukan `resolvedVia`, bukan lolos/tidaknya.
9. Setiap hasil resolusi mencatat `resolvedVia` (`nearest` | `root` | `workspace` | `tsconfig` | `imports` | `unresolved`) pada API resolver internal. Nilai ini **tidak** ditulis ke SARIF (menjaga golden parity); fungsinya agar urutan dapat diuji di level unit.

**6.2a Known limitation (pnpm strict)**: pada repo pnpm yang tidak melakukan hoisting, impor dependency yang hanya dideklarasikan di akar dari paket nested akan gagal saat runtime, tetapi DevGuard tetap menganggapnya *resolved* (`resolvedVia: root`) demi determinisme lintas mode. Ini kompromi yang disadari: DG004 mendeteksi nama paket fiktif, sedangkan nama yang dideklarasikan di `package.json` akar adalah nama nyata. Dicatat di README bagian Known limitations dan dikunci oleh A6-12.

**6.3 Anti-bypass (hasil analisis SPOF)**
- Glob workspace dibaca dari **base branch** (konsisten dengan INV-6).
- Package workspace yang **baru muncul di PR** tetap di-resolve (agar PR sah yang menambah package tidak penuh FP), tetapi menghasilkan notice non-scoring `DG004-WS-NEW` ("workspace baru ditambahkan oleh PR ini: periksa nama paket").
- Nama workspace yang sama persis dengan paket npm populer tidak diperlakukan khusus; keputusan manusia lewat notice.

**6.4 Konfigurasi (`.devguard.json`, tambahan minimal)**
```json
{
  "workspaces": { "mode": "auto" }
}
```
`mode`: `"auto"` (default) | `"off"` (perilaku v1.3.0, sebagai escape hatch). Tidak ada opsi per-path pada rilis ini.

**6.5 Pelaporan**
- Config workspace ada tetapi tidak terbaca → notice `DG004-WS-UNPARSED` (non-scoring, masuk hitungan unanalyzable; tunduk pada `fail_on_unanalyzable`).
- PR comment menampilkan jumlah workspace yang terdeteksi dan sumbernya.

**6.6 Kriteria penerimaan (harus berbukti, section 7)**

| ID | Kriteria | Bukti |
|---|---|---|
| A6-1 | Corpus eksternal berlabel (pinned SHA): FP DG004 turun ke **target 0** pada `nestjs/nest`, `vitejs/vite`, `commander.js`. Sisa >0 harus didaftar satu per satu dengan alasan | Tabel sebelum/sesudah dari script corpus |
| A6-2 | True positive tidak hilang: kasus slopsquatting yang sudah ada di corpus berlabel tetap terdeteksi (0 regresi) | Output test + diff golden SARIF |
| A6-3 | ≥5 TN per sumber workspace (npm array, npm object, pnpm, tsconfig paths, `imports`) + ≥5 kasus TP "nama halusinasi di dalam monorepo tetap tertangkap" | Daftar fixture + output test |
| A6-4 | Unparseable/di luar subset → notice, tidak crash, tidak diam | Test fixture khusus |
| A6-5 | Skenario bypass: PR menambah workspace berisi nama halusinasi → `DG004-WS-NEW` muncul | Test fixture |
| A6-6 | `workspaces.mode: "off"` identik dengan golden v1.3.0 | Diff SARIF byte-identik |
| A6-7 | Run time pada corpus terbesar dicatat sebelum/sesudah (tanpa klaim target; angka apa adanya) | Log pengukuran |
| A6-8 | Fuzz/property test parser JSONC dan subset YAML: PRNG ber-seed tetap tulisan sendiri (seed dan jumlah iterasi dicetak di log); invarian: tidak throw, tidak hang (batas waktu per input), keluaran deterministik. Seed corpus memuat `//` dan `#` di dalam string, CRLF, BOM, flow sequence, anchor, block scalar, tab | Output test + seed + jumlah iterasi |
| A6-9 | Anti-phantom: fixture `apps/web` mengimpor paket eksternal yang hanya dideklarasikan di `packages/ui` → **tetap** finding | Test fixture |
| A6-10 | Urutan 6.2 terbukti di level unit resolver lewat `resolvedVia`: dependency sama di terdekat + akar → `nearest`; hanya di akar → `root`; hanya di sibling → `unresolved` (finding); hanya di ancestor perantara → `unresolved` (finding) | Unit test resolver |
| A6-11 | Setiap kode alasan bail-out (6.1a) punya ≥1 fixture yang menghasilkan `DG004-WS-UNPARSED` dengan kode benar dan nol nama parsial dari sumber itu | Test fixture |
| A6-12 | Known limitation 6.2a terkunci: fixture repo dengan `pnpm-workspace.yaml`, dependency hanya di akar, diimpor dari paket nested → `resolvedVia: root` (perilaku sama dengan layout npm) | Test fixture |

---

### Stage 7 — v1.5.0: Core extraction, CLI, pre-commit, `npx`

**7.1 Arsitektur**
```
core/        ← engine + rules + resolver (tanpa I/O spesifik platform)
adapters/
  action     ← GitHub Action (perilaku v1.4.0, tidak berubah)
  cli        ← devguard check ...
```
Refactor hanya memindahkan kode; **tidak ada perubahan perilaku**. Dibuktikan oleh golden parity: SARIF adapter action sebelum vs sesudah refactor byte-identik.

**7.2 Perintah CLI** (parser argumen tulisan sendiri)

| Perintah | Fungsi |
|---|---|
| `devguard check [paths...]` | Periksa file/direktori |
| `devguard check --staged` | Hanya file yang di-stage git (untuk pre-commit) |
| `devguard check --changed-since <ref>` | Hanya file berubah sejak ref |
| `devguard install-hook` | Pasang pre-commit hook; **tidak menimpa** hook yang ada tanpa `--force`; deteksi husky/lefthook → cetak instruksi, jangan modifikasi |
| `devguard explain <RULE_ID>` | Jelaskan rule, contoh TP/TN |

Opsi: `--format text|json|sarif`, `--config <path>`, `--fail-on-unanalyzable`.
Exit code: `0` bersih, `1` ada pelanggaran/internal error (fail-closed), `2` salah penggunaan.

**7.3 Aturan perilaku lokal**
- Gemini Layer 2 **mati secara default** di CLI; aktif hanya jika key disediakan eksplisit (INV-2, INV-3 tetap berlaku).
- Config policy lokal dibaca dari working tree, tetapi output CLI menandai bahwa ini **bukan** pengganti gate CI (CI tetap memakai base-branch policy, INV-6).
- Hook gagal karena error internal → blok commit dengan pesan jelas dan cara bypass resmi (`git commit --no-verify`) disebutkan sebagai tanggung jawab developer.

**7.4 Distribusi**
- Field `bin`, shebang, `files` whitelist di `package.json`.
- `npx devguard check` bekerja tanpa clone repo.
- Listing GitHub Marketplace (D-7.1).
- Detail hardening publikasi: section 6.4.

**7.5 Kriteria penerimaan**

| ID | Kriteria | Bukti |
|---|---|---|
| A7-1 | Parity: input sama → SARIF CLI == SARIF Action (kecuali metadata invocation yang didaftar eksplisit) | Diff golden |
| A7-2 | Refactor tidak mengubah perilaku: seluruh test v1.4.0 lulus tanpa modifikasi ekspektasi | Output test + `git diff` pada file test hanya import path |
| A7-3 | `install-hook` tidak menimpa hook yang ada; idempoten | Test pada repo git sementara |
| A7-4 | `--staged` hanya memeriksa file staged (termasuk file yang dihapus/di-rename tidak membuat crash) | Test git fixture |
| A7-5 | Percobaan `npx` dari direktori bersih pada paket hasil `npm pack` | Log perintah apa adanya |
| A7-6 | Waktu run `--staged` untuk perubahan tipikal dicatat (angka terukur, tanpa klaim target kosong) | Log pengukuran |

---

### Stage 8 — v1.6.0: MCP Server (`devguard mcp`)

**8.1 Transport & protokol**
- stdio, JSON-RPC 2.0, tulisan sendiri (INV-1: tanpa SDK MCP).
- Versi protokol MCP yang didukung **harus diverifikasi terhadap spesifikasi resmi saat implementasi** (jangan hardcode dari ingatan); negosiasi versi di `initialize` dan menolak versi tak dikenal dengan error jelas.

**8.2 Tools (read-only)**

| Tool | Input | Output |
|---|---|---|
| `devguard_check_files` | daftar path (relatif root workspace) | findings terstruktur (rule ID, file, baris, severity, saran perbaikan) |
| `devguard_check_snippet` | `language`, `code`, `virtual_path` opsional | findings terstruktur (tanpa menyentuh disk) |
| `devguard_explain_rule` | `rule_id` | deskripsi, contoh TP/TN |

**8.3 Keamanan (hasil pre-mortem #3)**
- **Path jail**: semua path di-resolve terhadap root workspace; `..`, symlink keluar root, dan path absolut di luar root ditolak.
- **Tidak ada** eksekusi shell, tulis file, atau akses jaringan di jalur MCP.
- Teks dari kode yang dikutip di output (snippet) adalah **data tak tepercaya**: di-truncate, dan dibungkus field terpisah (`quoted_source`) agar tidak bercampur dengan instruksi/saran.
- Secret di snippet di-redact sebelum dikirim kembali (INV-3).
- Batas ukuran input/output dan jumlah file per panggilan (angka dipilih saat implementasi dan didokumentasikan).

**8.4 Kriteria penerimaan**

| ID | Kriteria | Bukti |
|---|---|---|
| A8-1 | Hasil `devguard_check_files` setara dengan CLI untuk file yang sama (parity JSON) | Diff otomatis |
| A8-2 | Percobaan path traversal (`../../etc/passwd`, symlink keluar root) ditolak | Test negatif |
| A8-3 | Snippet berisi teks mirip instruksi ("abaikan aturan sebelumnya...") muncul hanya di `quoted_source`, tidak di field saran | Test fixture |
| A8-4 | Server tidak menulis apa pun ke stdout selain pesan JSON-RPC valid (log ke stderr) | Test framing |
| A8-5 | Uji interop minimal dengan setidaknya satu klien MCP nyata (dicatat klien dan versinya) | Transkrip sesi apa adanya |

---

### Stage 9 — v1.7.0: Intra-procedural alias tracking (ringan)

**Prasyarat gate:** suite fuzz/property test untuk masker (string, template literal, regex literal, komentar, JSX) lulus. Alasan: engine lexical adalah SPOF; fitur baru tidak dibangun di atas masker yang belum diuji keras.

**9.1 Lingkup (sengaja sempit)**
- Satu fungsi/blok; pelacakan penugasan `const x = <expr>` dengan kedalaman alias maksimal 2.
- Kasus target (dari `knownMiss`): `const fn = eval; fn(input)` dan `const p = charge(); p.catch(() => {})`.
- Variabel `let`/`var` yang di-reassign, destructuring kompleks, dan alias lintas fungsi/file → **bail out dan dilaporkan unanalyzable** (INV-7), bukan ditebak.

**9.2 Kebijakan promosi**
- Rule/evidence baru dari tracking mulai sebagai **warning non-scoring**; promosi ke scoring hanya setelah validasi repo eksternal (INV-8).

**9.3 Kriteria penerimaan**

| ID | Kriteria | Bukti |
|---|---|---|
| A9-1 | Dua kasus `knownMiss` di atas terdeteksi, dan entri `knownMiss` yang tertutup dihapus/diperbarui | Test + diff dokumen |
| A9-2 | ≥5 TN per pola alias (termasuk shadowing, reassign, nama mirip) | Fixture + test |
| A9-3 | Corpus eksternal: finding baru dari tracking didaftar dan dikategorikan TP/FP satu per satu; FP rate dilaporkan apa adanya | Tabel corpus |
| A9-4 | Tidak ada perubahan pada hasil rule lama (golden SARIF identik pada corpus tanpa alias) | Diff golden |

---

### Stage 10 — v2.0.0: Multi-language (arah, belum spesifikasi final)

Hanya dimulai bila D-10 diputuskan "ya". Kerangka:
- **Language adapter**: tiap bahasa menyediakan masker sendiri dan menghasilkan virtual view (SpanMap) yang sama dengan JS/TS.
- Urutan usulan: **Python → Go → bahasa lain**, masing-masing hanya setelah corpus berlabel tersedia.
- Rule hanya aktif untuk bahasa tempat ia **teruji**; sisanya dilaporkan *not analyzed* per bahasa.
- Spec terpisah (SPEC rev untuk v2.0) wajib ditulis dan di-lock sebelum implementasi.

---

## 6. Lintas Stage

### 6.1 Versi rule dan SARIF
- Rule ID stabil; perubahan semantik rule → catat di changelog dan naikkan versi.
- SARIF: `executionSuccessful`, `ruleId`, dan fingerprint stabil antar-rilis kecuali ada perubahan yang dicatat.

### 6.2 Action inputs
Konvensi snake_case. Tidak ada input baru di Stage 6; input baru lain diusulkan per stage dan masuk spek stage tersebut.

### 6.3 Performance
Setiap stage mengukur dan mencatat waktu pada corpus tetap. **Tidak ada klaim performa tanpa angka terukur.**

### 6.4 Hardening distribusi (kritis: DevGuard adalah alat keamanan)
- 2FA wajib pada akun npm dan GitHub pemilik repo.
- Publikasi npm dengan **provenance** dari GitHub Actions (OIDC), bukan dari laptop.
- Semua `uses:` pada workflow rilis dan workflow DevGuard sendiri dipin ke **commit SHA**.
- Tag rilis Action tidak dipindahkan diam-diam; tag mayor (`v1`) hanya digeser lewat prosedur terdokumentasi.
- `files` whitelist di `package.json`; `npm pack --dry-run` diperiksa sebelum rilis.

### 6.5 Kejujuran dokumentasi
- Setiap klaim di README harus menunjuk ke test/corpus yang mendukungnya.
- Bagian "Known limitations" diperbarui di setiap rilis (termasuk apa yang **belum** tertutup).

---

## 7. Kebijakan Bukti & Gate Stage

Klaim "selesai" tanpa bukti **tidak diterima**. Setiap laporan stage wajib menyertakan:

| # | Bukti | Bentuk |
|---|---|---|
| E1 | Diff nyata | `git diff --stat` + commit SHA |
| E2 | Output apa adanya | Skrip `lint`, `build`, `test` **sebagaimana didefinisikan di `package.json` saat itu** (bentuk skrip `test` boleh berubah antar-rilis; yang dicetak adalah yang aktif), tidak diringkas |
| E3 | Hasil corpus | Tabel sebelum/sesudah dari script, dengan SHA repo eksternal |
| E4 | Golden SARIF diff | Output diff (kosong = identik) |
| E5 | **CI hijau di Node 22** | Tautan run. Hijau lokal saja **belum** terverifikasi |
| E6 | Daftar yang belum tercakup | Eksplisit, bukan dihilangkan |

Aturan agen:
1. Cetak tabel temuan pre-flight (path + baris) **sebelum** mengubah kode.
2. Jangan menyentuh stage lain (stage berikutnya tetap terkunci).
3. Jangan menambah workaround spesifik-nama-file (pola jembatan `vulnerable_fixture.py` tidak boleh terulang).
4. Branch per stage, merge hanya setelah gate E1–E6 lulus; `main` tidak dirilis dari stage setengah jadi.
5. Cross-audit oleh agen kedua atas laporan stage sebelum lock.

---

## 8. Register Risiko

| ID | Risiko | Kemungkinan | Dampak | Mitigasi | Pemilik gate |
|---|---|---|---|---|---|
| R1 | Edge case resolver menimbulkan FP baru di repo di luar corpus | Sedang | Tinggi | Corpus pinned, `workspaces.mode: off`, unanalyzable notice | Stage 6 |
| R2 | Workspace palsu dipakai membungkam DG004 | Rendah–sedang | Tinggi | Base-branch glob, `DG004-WS-NEW` | Stage 6 |
| R3 | Divergensi CLI vs Action | Sedang | Tinggi | Core tunggal, golden parity | Stage 7 |
| R4 | Kompromi akun npm/GitHub | Rendah | Sangat tinggi | 6.4 | Stage 7 |
| R5 | Prompt injection lewat output MCP | Sedang | Tinggi | 8.3 | Stage 8 |
| R6 | Salah mask di lexical engine | Sedang | Tinggi | Fuzz masker sebagai prasyarat Stage 9 | Stage 9 |
| R7 | Alias tracking → FP | Sedang | Sedang | Warning-first, bail-out | Stage 9 |
| R8 | Scope creep / banyak stage setengah jadi | Tinggi | Tinggi | Satu stage aktif, gate E1–E6 | Semua |
| R9 | Klaim README melampaui bukti | Sedang | Sedang | 6.5 | Semua |
| R10 | Beban maintainer tunggal | Tinggi | Sedang | Scope sempit, non-tujuan eksplisit | Semua |
| R11 | Parser buatan sendiri salah pada edge case (`//`/`#` dalam string, YAML di luar subset) → peta workspace salah → FP/FN senyap | Sedang | Tinggi | 6.1a (bail-out per sumber, fail-closed), A6-8, A6-11 | Stage 6 |
| R12 | Penggabungan dependency sibling menyembunyikan phantom dependency / nama fiktif | Sedang | Tinggi | 6.2 butir 3, A6-9, A6-10 | Stage 6 |

---

## 9. Keputusan

**Status rev 1.2:** D-6.1 s.d. D-6.6 **TERKUNCI** sesuai kolom ketiga. D-7.1 s.d. D-10 masih rekomendasi sementara (belum dikunci).

| ID | Pertanyaan | Keputusan (D-6.x) / rekomendasi sementara (lainnya) |
|---|---|---|
| D-6.1 | Sertakan `lerna.json`? | Tunda; npm/pnpm/yarn workspaces sudah mencakup mayoritas |
| D-6.2 | Parser YAML pnpm: subset terbatas atau tolak semua selain bentuk baku? | Subset terbatas + unanalyzable notice di luar subset |
| D-6.3 | `DG004-WS-NEW` scoring atau non-scoring? | Non-scoring (konsisten dengan DG004-DYN) |
| D-6.4 | Dukungan `tsconfig` `extends` ke paket npm (mis. `@tsconfig/node20`)? | Tidak; hanya path relatif. `extends` ke paket npm → `DG004-WS-UNPARSED` kode `extends_external` (sumber itu menyumbang nol nama) |
| D-6.5 | Impor workspace tanpa deklarasi (phantom antar-paket): finding, notice, atau hanya ringkasan? | Hanya baris ringkasan di PR comment pada v1.4.0; naikkan ke notice jika data corpus menunjukkan nilainya |
| D-6.6 | Fallback ke `package.json` akar untuk file di paket nested (mencerminkan hoisting npm/yarn; pnpm strict tidak begitu)? | **Ya.** "Akar" hanya `package.json` di akar repo; ancestor perantara dan sibling tidak pernah dipakai. Urutan tetap di 6.2; pada pnpm strict perilaku sama (6.2a) |
| D-7.1 | Listing GitHub Marketplace di v1.5.0 atau setelahnya? | Setelah CLI stabil (v1.5.x) |
| D-7.2 | Pre-commit: hook native saja atau juga integrasi `pre-commit` framework? | Native saja; framework lain lewat dokumentasi |
| D-8.1 | Apakah MCP perlu mode tulis (auto-fix)? | Tidak; read-only pada v1.6.0 |
| D-9.1 | Kedalaman alias maksimal 2 cukup? | Mulai 2; naikkan hanya dengan bukti dari corpus |
| D-10 | Mulai multi-language setelah v1.7.0 atau tahan? | Putuskan setelah v1.4–v1.6 punya bukti stabilitas dari penggunaan nyata (sinyal publik, bukan telemetri) |

---

## 10. Out of Scope (rilis ini)

- Taint tracking / data-flow lintas fungsi dan lintas file.
- Auto-fix yang menulis ke disk melalui MCP.
- Dashboard/SaaS, telemetri, akun pengguna.
- Dukungan IDE extension native (VS Code/Cursor) selain lewat MCP dan CLI.
- Perubahan model scoring.

---

## 11. Urutan Eksekusi Segera

1. ~~Putuskan D-6.1 s.d. D-6.6 → lock SPEC~~ — selesai di rev 1.2 (P0 + Stage 6 locked).
2. Jalankan **P0** dan cetak tabelnya.
3. Jalankan prompt Stage 6.0 (pre-flight) + 6.1 (resolver): `PROMPT-STAGE-6.0-6.1.md`, dengan aturan pada section 7.
4. Stage 7 baru dibuka setelah E1–E6 Stage 6 lengkap, termasuk CI hijau di Node 22.
