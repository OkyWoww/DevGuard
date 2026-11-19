# PROMPT — DevGuard P0 + Stage 6.0 (Pre-Flight) + Stage 6.1 (Workspace Resolver)

Kamu adalah agen koding yang mengerjakan DevGuard v1.4.0 (DG004 Workspace Resolver).
Sumber kebenaran: **`specs/SPEC-v1.4.md` rev 1.2** (bagian P0 dan Stage 6 sudah LOCKED). Jika prompt ini dan spek berbeda, **spek menang**; laporkan perbedaannya, jangan memilih sendiri.

---

## 0. Aturan keras (berlaku sepanjang pekerjaan)

1. **Bukti, bukan narasi.** Setiap klaim "selesai/hijau/lulus" wajib disertai output asli perintah (utuh, tidak diringkas) dan commit SHA. Tanpa bukti, tulis **"TIDAK TERVERIFIKASI"**.
2. **Cetak tabel temuan sebelum menyentuh kode** (fase P0 dan 6.0). Jangan mengubah file apa pun sebelum kedua tabel itu tercetak.
3. **Berhenti jika P0 gagal.** Laporkan baris yang gagal dan tunggu instruksi.
4. **Hanya Stage 6.** Jangan menyentuh Stage 7–10 (CLI, MCP, alias tracking, multi-language). Jangan refactor di luar yang dibutuhkan Stage 6.
5. **Invarian (SPEC section 3) tidak boleh dilanggar:** `"dependencies": {}` tetap `{}` (parser YAML/JSONC/glob ditulis sendiri), fail-closed, deterministik, policy hanya dari base branch `.devguard.json`, tanpa inline suppression.
6. **Dilarang workaround spesifik-nama-file/repo** (mis. jembatan per nama fixture). Perilaku harus berlaku umum.
7. **Jangan merge ke `main`.** Kerjakan di branch `stage-6-workspace-resolver` dari commit baseline yang terverifikasi di P0. Push hanya jika diminta; jika belum push, tulis eksplisit **"CI Node 22: TIDAK TERVERIFIKASI"**.
8. Jika spek ambigu atau ada konflik dengan kode yang ada: **berhenti dan tanyakan**, jangan menebak.
9. **Jangan membuat, memindahkan, atau mendorong tag apa pun** (termasuk `v1.3.0`). Tag rilis adalah keputusan manusia setelah CI hijau. Jika P0-1 GAGAL karena tag belum ada, itu hasil yang benar: laporkan dan berhenti; jangan "memperbaikinya" sendiri.

---

## Prasyarat (cek sebelum P0)

| # | Prasyarat | Bukti |
|---|---|---|
| R1 | `specs/SPEC-v1.4.md` dan `specs/PROMPT-STAGE-6.0-6.1.md` ada di branch kerja | `git ls-files specs/` |
| R2 | Spek yang dibaca adalah **rev 1.2**, bukan salinan lama | `head -n 5 specs/SPEC-v1.4.md` harus memuat "SPEC rev 1.2" dan status "P0 + Stage 6: LOCKED" |
| R3 | Tidak ada salinan unduhan ganda di repo (mis. `SPEC-v1.4(1).md`) | `git ls-files \| grep -i "spec-v1.4"`; jika ada duplikat, laporkan dan jangan dipakai |

R1 atau R2 gagal → berhenti. Catatan untuk P0-2: commit setelah tag yang **hanya** menambah berkas `specs/` adalah selisih yang diterima; selisih lain harus dijelaskan satu per satu.

---

## 1. Fase P0 — Verifikasi baseline

Jalankan dan cetak hasilnya apa adanya:

| # | Pemeriksaan | Perintah / bukti |
|---|---|---|
| P0-1 | Tag `v1.3.0` ada, sudah di-push, menunjuk ke commit rilis yang CI-nya hijau (Node 22) | `git tag -l`; `git ls-remote --tags origin v1.3.0`; `git rev-parse v1.3.0^{commit}`; tautan run CI. Commit yang diklaim (`fff7deb`) harus dicocokkan dengan hasil `rev-parse`, bukan dipercaya |
| P0-2 | `main` == tag, atau selisih terjelaskan | `git log --oneline v1.3.0..main` |
| P0-3 | Tidak ada spek ganda | `git ls-files \| grep -i spec` (harus jelas: `specs/SPEC.md` v1.3.0 dan `specs/SPEC-v1.4.md`; tidak ada `docs/specs/`) |
| P0-4 | Corpus FP eksternal dipin ke SHA dan hasil awal DG004 tercatat | Tabel: repo, SHA, jumlah finding DG004 (baseline v1.3.0) untuk `nestjs/nest`, `vitejs/vite`, `commander.js` |
| P0-5 | Skrip build/lint/test yang aktif | Cetak isi `scripts.lint`, `scripts.build`, `scripts.test` dari `package.json`, lalu jalankan **skrip itu** (bukan perintah tebakan) dan cetak output utuh |

**Keluaran P0:** tabel 5 baris (LULUS / GAGAL + bukti). Satu saja GAGAL → berhenti.

---

## 2. Fase 6.0 — Pre-flight kode (tabel temuan)

Sebelum mengubah kode, cetak tabel **F1–F8** dengan **path + nomor baris** (hasil membaca kode, bukan ingatan):

| # | Yang dicari |
|---|---|
| F1 | Implementasi DG004 saat ini: file/baris logika "paket tidak terdeklarasi" dan sumber daftar dependency (bagaimana `package.json` dibaca) |
| F2 | Cara DG004 mencari `package.json` (akar saja, atau per-file?) |
| F3 | Tempat `.devguard.json` dibaca dan validasi skema config (titik masuk `workspaces.mode`) |
| F4 | Tempat notice non-scoring DG004-DYN-01/02 dibuat dan dihitung sebagai unanalyzable (pola yang akan ditiru oleh `DG004-WS-NEW` dan `DG004-WS-UNPARSED`) |
| F5 | Tempat PR comment dirender (titik masuk baris ringkasan workspace) |
| F6 | Skrip/test corpus yang sudah ada dan format fixture berlabel (TP/TN) |
| F7 | Struktur golden SARIF yang ada dan cara membandingkannya |
| F8 | Lokasi I/O filesystem yang bisa dipakai resolver tanpa menambah dependensi (dan di mana mode diff vs mode all menentukan daftar file) |

Setelah tabel tercetak, **nyatakan** apakah ada temuan yang bertentangan dengan spek. Jika ada → berhenti dan tanyakan.

---

## 3. Fase 6.1 — Implementasi (urut, satu commit per sub-langkah)

Branch: `stage-6-workspace-resolver`. Setiap sub-langkah: kode + test, lalu jalankan skrip `lint`, `build`, `test` yang aktif sebelum commit.

Pemetaan sub-langkah prompt ke bagian spek (gunakan sebagai awalan pesan commit, mis. `6.1.a: ...`):

| Sub-langkah | Bagian SPEC-v1.4 | Acceptance utama |
|---|---|---|
| 6.1.a | 6.1, 6.1a | A6-8, A6-11 (kode alasan parser) |
| 6.1.b | 6.2, 6.2a | A6-9, A6-10, A6-12 |
| 6.1.c | 6.3, 6.4, 6.5 | A6-4, A6-5, A6-6 |
| 6.1.d | 6.6 | A6-1, A6-2, A6-3, A6-7 |

### 6.1.a Parser (SPEC 6.1, 6.1a)
- Tokenizer berstatus tulisan sendiri (bukan regex berlapis) untuk: JSONC, subset YAML `pnpm-workspace.yaml` (hanya `packages:` list blok sederhana), glob (`*`, `**`, negasi `!`).
- Batas ukuran input config: **256 KiB**; di atasnya → bail-out `size_limit`. (Angka ini dipilih di prompt sesuai SPEC 6.1a; dokumentasikan di kode dan README. Ini melengkapi spek, bukan konflik; laporkan di E6 sebagai keputusan beserta lokasi konstantanya.)
- Bail-out **per sumber, fail-closed**: nol nama parsial dari sumber yang gagal; kode alasan: `yaml_unsupported_construct`, `jsonc_syntax`, `extends_external`, `extends_cycle`, `size_limit`.
- `tsconfig` `extends`: hanya path relatif, kedalaman maksimal 3; siklus → `extends_cycle`; `extends` ke paket npm → `extends_external`.
- **Fuzz/property test (A6-8):** PRNG ber-seed tulisan sendiri; seed default tetap dan dicetak di log; override lewat variabel lingkungan `DEVGUARD_FUZZ_SEED`; **10.000 iterasi per parser**. Invarian: tidak throw, deterministik, waktu per input ≤ **100 ms** (ukur dan gagal jika terlampaui). Seed corpus wajib memuat: `//` dan `#` di dalam string, CRLF, BOM, flow sequence, anchor/alias, block scalar, tab sebagai indentasi, input kosong dan terpotong. Catat **total durasi suite fuzz** di laporan (E2). Jangan menurunkan jumlah iterasi tanpa bertanya. Hindari alokasi berat berulang di inner loop (pakai ulang buffer/array); pembanding diferensial (mis. `JSON.parse` pada input JSON valid) boleh sebagai oracle tambahan, bukan pengganti invarian.

### 6.1.b Peta workspace + resolver (SPEC 6.2)
- Peta `nama paket → direktori` dari `package.json` `workspaces` (array dan `{ "packages": [...] }`) dan `pnpm-workspace.yaml`.
- Urutan resolusi **tetap**, berhenti di kecocokan pertama: (1) `package.json` terdekat; (2) `package.json` **akar repo saja**; (3) nama workspace; (4) `tsconfig` `paths`/`baseUrl` dan `imports`/self-reference.
- **Dilarang** menggabungkan dependency paket sibling; ancestor perantara tidak dipakai (SPEC 6.2 butir 2–3).
- Tidak ada semantik override (butir 8). API resolver mengembalikan `resolvedVia` (`nearest|root|workspace|tsconfig|imports|unresolved`); **tidak** ditulis ke SARIF (butir 9).
- Subpath (`@scope/pkg/sub/file`) → nama dasar; builtin Node tetap diabaikan; protokol `workspace:`/`file:`/`link:` internal, `npm:alias@x` di-resolve ke nama sebenarnya.
- Cache per run, iterasi diurutkan leksikografis.

### 6.1.c Integrasi DG004 + config + pelaporan (SPEC 6.3–6.5)
- Config: `workspaces.mode` = `"auto"` (default) | `"off"` (identik v1.3.0). Dibaca dari base-branch `.devguard.json`. Tidak ada input Action baru.
- Glob workspace dibaca dari **base branch**; package workspace yang baru muncul di PR tetap di-resolve tetapi memicu notice non-scoring **`DG004-WS-NEW`**.
- **`DG004-WS-UNPARSED`** (non-scoring, masuk hitungan unanalyzable, tunduk pada `fail_on_unanalyzable`) dengan kode alasan.
- PR comment: jumlah workspace terdeteksi + sumbernya, dan satu baris ringkasan "N impor workspace tanpa deklarasi" (tanpa finding, tanpa penalti).

### 6.1.d Corpus & fixture (SPEC 6.6)
- Script corpus yang menjalankan DG004 pada tiga repo eksternal (SHA dari P0-4) dan mencetak tabel sebelum/sesudah. Nama script: ikuti konvensi yang sudah ada (temuan F6); jika membuat baru, laporkan namanya.
- Fixture: ≥5 TN per sumber (npm array, npm object, pnpm, tsconfig paths, `imports`); ≥5 TP "nama halusinasi di dalam monorepo tetap tertangkap"; fixture bypass (`DG004-WS-NEW`); satu fixture per kode alasan bail-out (A6-11); anti-phantom (A6-9); urutan `resolvedVia` di level unit (A6-10); pnpm strict known limitation (A6-12).

---

## 4. Kriteria penerimaan (harus lulus semua, dengan bukti)

A6-1 sampai A6-12 pada SPEC section 5 (Stage 6.6). Ringkasnya:

- A6-1: FP DG004 corpus eksternal → target 0; sisa >0 didaftar satu per satu dengan alasan.
- A6-2: 0 regresi true positive (diff golden SARIF).
- A6-3 / A6-9 / A6-10 / A6-11 / A6-12: fixture dan unit test seperti di atas.
- A6-4 / A6-5: unparseable → notice (tidak crash, tidak diam); bypass → `DG004-WS-NEW` muncul.
- A6-6: `workspaces.mode: "off"` → SARIF byte-identik dengan golden v1.3.0.
- A6-7: waktu run corpus terbesar sebelum/sesudah (angka apa adanya, tanpa klaim target).
- A6-8: fuzz test lulus dengan seed dan jumlah iterasi tercetak.

---

## 5. Format laporan akhir (wajib)

| # | Bukti | Isi |
|---|---|---|
| E1 | Diff nyata | `git diff --stat v1.3.0..HEAD` (atau baseline P0) + daftar commit SHA per sub-langkah |
| E2 | Output apa adanya | Skrip `lint`, `build`, `test` yang aktif — utuh, tidak diringkas |
| E3 | Hasil corpus | Tabel sebelum/sesudah per repo (dengan SHA) + daftar sisa FP satu per satu |
| E4 | Golden SARIF diff | Output diff untuk `mode: off` (kosong = identik) dan untuk corpus tanpa workspace |
| E5 | CI Node 22 | Tautan run hijau, atau **"TIDAK TERVERIFIKASI"** jika belum push |
| E6 | Belum tercakup | Daftar eksplisit: apa yang belum, apa yang menyimpang dari spek, apa yang diputuskan sendiri dan alasannya |

Tambahkan tabel pemetaan **A6-1…A6-12 → LULUS / GAGAL / TIDAK TERVERIFIKASI → bukti**.
Jangan menyatakan Stage 6 "selesai" jika ada satu pun baris yang bukan LULUS dengan bukti.

---

## 6. Risiko eksekusi (pre-mortem singkat untuk run ini)

| Risiko | Mitigasi dalam prompt ini |
|---|---|
| Agen melaporkan "hijau" tanpa menjalankan skrip yang benar | Aturan 1; P0-5 mencetak isi `scripts` dulu, lalu menjalankan skrip itu |
| Resolver terlalu lenient → nama fiktif lolos | Larangan sibling, A6-9, fixture TP dalam monorepo |
| Parser salah pada edge case → peta salah senyap | Fail-closed per sumber, fuzz 10.000 iterasi, A6-11 |
| Perubahan menyentuh perilaku `mode: off` | A6-6, golden byte-identik |
| Scope creep ke CLI/MCP | Aturan 4 |
| Hijau lokal dianggap hijau CI | Aturan 7, E5 |
