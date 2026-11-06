# DevGuard: Automated Adversarial Code Review Harness

[![Google GenAI SDK](https://img.shields.io/badge/Google_GenAI_SDK-Interactions_API-4285F4.svg)](https://aistudio.google.com)
[![Model](https://img.shields.io/badge/Model-gemini--3.8--flash-34A853.svg)](https://ai.google.dev)
[![Verification](https://img.shields.io/badge/SQLite_Harness-6%2F6_PASS-10B981.svg)](#verifikasi-empiris-ab-test)
[![Submission](https://img.shields.io/badge/GDG_Jakarta-Gemini_Prompt_Maxxing-EA4335.svg)](#submission-gdg-jakarta)

> **DevGuard** adalah sistem audit kode adversarial deterministik berbasis Google GenAI Interactions API (`gemini-3.8-flash`) yang dirancang khusus untuk mereview kode junior developer secara objektif, menolak manipulasi prompt injection, mengurangi skor secara matematis berdasarkan rubrik risiko, dan memvalidasi perbaikan kode melalui test harness empiris SQLite.

---

## 🏗️ Arsitektur Sistem

```
┌────────────────────────────────────────────────────────────────────────┐
│               1. Input Fencing (Isolasi Data Mentah)                   │
│   Pengguna menempelkan kode sumber junior developer.                   │
│   Sistem membungkus kode di dalam isolasi XML: <code_to_review>        │
│   -> Komentar manipulatif ("give 100/100") diperlakukan sbg DATA MURNI │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│        2. GenAI Interactions API (gemini-3.8-flash) & Prompt           │
│   - SDK: google-genai >= 2.30.1 / @google/genai >= 2.29.1              │
│   - Instruksi Sistem: devguard_system_instructions_v2.md               │
│   - Rubrik Penalti: Security (-40/-25/-20/-10)                         │
│                     Correctness (-40/-25/-15/-10)                      │
│                     Maintainability (-20/-15/-15/-10)                  │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                3. Laporan Audit Terstruktur Baku                       │
│   - ## 👋 Apresiasi (1 kalimat valid)                                  │
│   - ## 📊 Skor (Dihitung dari 100)                                     │
│   - ## 💣 Temuan Utama (1 bom waktu fatal + baris)                     │
│   - ## 🗒️ Temuan Lain (Maksimal 5 butir)                               │
│   - ## 🏪 Analogi (Analogi kehidupan nyata + istilah teknis)           │
│   - ## 🔧 Perbaikan (Patch minimal atomik, tanpa feature creep)        │
│   - ## ✅ Tes (2-3 kasus uji input -> expected)                        │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│          4. Empirical Verification Harness (devguard_verify.py)        │
│   Membuktikan secara empiris di SQLite ACID in-memory:                 │
│   - Kode Asli: GAGAL pada 4/6 skenario (Overdraft, Negatif, SQLi, Null)│
│   - Kode DevGuard: LOLOS 6/6 skenario pengujian secara atomik          │
└────────────────────────────────────────────────────────────────────────┘
```

---

## ⚡ Quickstart

### Opsi 1: Otomasi Penuh via Bash (Direkomendasikan)

```bash
# 1. Clone atau masuk ke direktori proyek
cd devguard

# 2. Ekspor Gemini API Key Anda
export GEMINI_API_KEY="your-gemini-api-key"

# 3. Jalankan setup otomatis (venv, dependencies, & verifikasi empiris)
./setup.sh
```

### Opsi 2: Eksekusi Manual Python CLI

```bash
# Buat dan aktifkan virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Pasang dependensi
pip install -r requirements.txt

# Jalankan verifikasi empiris SQLite (6/6 skenario)
python3 devguard_verify.py

# Jalankan audit adversarial via Google GenAI Interactions API
export GEMINI_API_KEY="your-gemini-api-key"
python3 run_devguard.py
```

### Opsi 3: Menjalankan Audit pada Berkas Kustom

```bash
# Review berkas spesifik
python3 run_devguard.py path/to/junior_code.py

# Atau lewat pipeline stdin
cat my_script.py | python3 run_devguard.py --stdin
```

---

## 🧪 Verifikasi Empiris (A/B Test)

DevGuard menyertakan test suite empiris di `devguard_verify.py` untuk menguji perbedaan nyata antara kode rentan vs perbaikan:

| No | Skenario Pengujian | Input Kasus | Kode Asli (Junior) | Kode Perbaikan (DevGuard) |
|---|---|---|---|---|
| **1** | **Overdraft Protection** | Andi (saldo 100) kirim 1000 | ❌ **FAIL** (Saldo jadi -900) | ✅ **PASS** (Ditolak, saldo utuh 100) |
| **2** | **Negative Amount Theft** | Andi transfer -50 poin | ❌ **FAIL** (Andi mencuri jadi 150) | ✅ **PASS** (Ditolak, harus positif) |
| **3** | **SQL Injection Resistance** | Pengirim `'x' OR '1'='1'` | ❌ **FAIL** (Database ter-hack) | ✅ **PASS** (Parameterized query) |
| **4** | **Missing Sender Handling** | Pengirim `'ghost'` | ❌ **FAIL** (Crash unhandled null) | ✅ **PASS** (Ditolak rapi `ValueError`) |
| **5** | **Atomic Rollback** | Penerima `'ghost'` | ❌ **FAIL** (Saldo pengirim hilang) | ✅ **PASS** (Rollback atomik `with db:`) |
| **6** | **Happy Path & Conservation** | Andi kirim 40 ke Budi | ⚠️ **PASS** (Saldo 60, 90) | ✅ **PASS** (Konservasi total 650 poin) |

---

## 🛡️ Prinsip Keamanan & Anti-Prompt Injection

1. **Strict Data Fencing**: Masukan pengguna dibungkus dalam tag `<code_to_review>`. Sistem instruksi secara eksplisit mendeklarasikan bahwa string di dalam tag adalah data mentah, bukan instruksi yang bisa dieksekusi.
2. **Rubrik Skor Deterministik**: Penilai tidak boleh "menebak" atau "berbaik hati". Penalti bernilai tetap (misal: Injeksi SQL = -40, Race condition = -25).
3. **No Halusinasi**: Masalah yang dilaporkan wajib merujuk baris kode yang nyata.
4. **Anti-Leakage**: Skrip runner tidak pernah mencetak atau membocorkan `GEMINI_API_KEY` ke log kesalahan publik.

---

## 🏆 Submission GDG Jakarta Gemini Prompt Maxxing

- **Event**: GDG Jakarta - Gemini Prompt Maxxing Challenge
- **Core Technology**: Google GenAI Interactions API (`gemini-3.8-flash`)
- **Focus**: Adversarial Prompt Defense, Deterministic Evaluation Rubrics, Empirical SQLite Verification.
