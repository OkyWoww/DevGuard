#!/usr/bin/env python3
"""
DevGuard Empirical Verification Test Harness
(A) Membuktikan bug fatal di kode 'spaghetti' asli:
    - Overdraft (saldo negatif)
    - Nilai transfer negatif (mencuri saldo)
    - SQL injection via konkatenasi string
    - Crash unhandled missing user
(B) Memvalidasi versi perbaikan (kirim_poin_aman) lolos 6 dari 6 skenario atomik.

Jalankan langsung:
    python3 devguard_verify.py
Atau output JSON:
    python3 devguard_verify.py --json
"""

import sys
import json
import sqlite3

# ==============================================================================
# 1. KODE ASLI (Cuplikan Junior Developer - Penuh Kerentanan)
# ==============================================================================
def kirim_poin(db, user_pengirim, user_penerima, jumlah):
    """
    Kode rentan:
    - SQL injection melalui konkatenasi string langsung
    - Tanpa validasi batas saldo (overdraft)
    - Tanpa validasi angka positif (bisa transfer negatif)
    - Tidak atomik (transaksi terpisah, race condition)
    - Tidak menangani akun yang tidak ditemukan (NoneType crash)
    """
    q1 = "SELECT poin FROM members WHERE username = '" + user_pengirim + "'"
    saldo = db.execute(q1).fetchone()[0]
    if saldo > 0:
        saldo_baru = saldo - jumlah
        db.execute("UPDATE members SET poin = " + str(saldo_baru) + " WHERE username = '" + user_pengirim + "'")
        q2 = "SELECT poin FROM members WHERE username = '" + user_penerima + "'"
        saldo_penerima = db.execute(q2).fetchone()[0]
        db.execute("UPDATE members SET poin = " + str(saldo_penerima + jumlah) + " WHERE username = '" + user_penerima + "'")
        return "Berhasil transfer!"
    else:
        return "Gagal!"


# ==============================================================================
# 2. VERSI PERBAIKAN DEVGUARD (Aman, Atomik, Parameterized)
# ==============================================================================
def kirim_poin_aman(db, user_pengirim, user_penerima, jumlah):
    """
    Kode aman perbaikan DevGuard (Upgraded Zero-Leniency Patch):
    - Validasi tipe int murni (`type(jumlah) is not int` menolak subclass bool) dan nilai positif
    - Satu blok context manager transaksi atomik (`with db:`)
    - Parameterized query (mencegah SQL Injection 100%)
    - Pengecekan saldo dan pengurangan dalam satu statement atomik (`AND poin >= ?`) mencegah TOCTOU
    - Rollback otomatis jika penerima tidak ditemukan atau terjadi exception
    """
    if type(jumlah) is not int or jumlah <= 0:
        raise ValueError("Jumlah transfer harus bilangan bulat positif murni")
    if not isinstance(user_pengirim, str) or not isinstance(user_penerima, str):
        raise ValueError("Identitas pengguna harus berupa string valid")
    if user_pengirim == user_penerima:
        raise ValueError("Pengirim dan penerima tidak boleh sama")
    
    with db:  # satu transaksi: commit jika sukses, rollback jika exception
        cur = db.execute(
            "UPDATE members SET poin = poin - ? WHERE username = ? AND poin >= ?",
            (jumlah, user_pengirim, jumlah)
        )  # cek saldo + kurangi dalam SATU statement atomik (Anti-TOCTOU)
        if cur.rowcount != 1:
            raise ValueError("Saldo tidak mencukupi atau pengirim tidak ditemukan")
        
        cur_penerima = db.execute(
            "UPDATE members SET poin = poin + ? WHERE username = ?",
            (jumlah, user_penerima)
        )
        if cur_penerima.rowcount != 1:
            raise ValueError("Penerima tidak ditemukan (transaksi di-rollback secara atomik)")

    return "Berhasil transfer!"


# ==============================================================================
# 3. HELPER DATABASE & STATE
# ==============================================================================
def fresh():
    """Membuat database SQLite in-memory baru dengan data awal baseline."""
    db = sqlite3.connect(":memory:")
    db.execute("CREATE TABLE members (username TEXT PRIMARY KEY, poin INTEGER)")
    db.executemany("INSERT INTO members VALUES (?,?)", [
        ("andi", 100),
        ("budi", 50),
        ("citra", 500)
    ])
    db.commit()
    return db

def saldo(db):
    """Mengambil dictionary saldo seluruh member terurut."""
    return dict(db.execute("SELECT username, poin FROM members ORDER BY username").fetchall())


# ==============================================================================
# 4. HARNESS VERIFIKASI EMPIRIS 6 SKENARIO
# ==============================================================================
def run_all_tests():
    results = []

    # Skenario 1: Overdraft (andi saldo 100 transfer 1000)
    db_buggy = fresh()
    kirim_poin(db_buggy, "andi", "budi", 1000)
    saldo_buggy_1 = saldo(db_buggy)
    buggy_failed_1 = saldo_buggy_1["andi"] < 0  # Buggy loloskan saldo negatif (-900)

    db_fixed = fresh()
    before_fixed_1 = saldo(db_fixed)
    fixed_passed_1 = False
    try:
        kirim_poin_aman(db_fixed, "andi", "budi", 1000)
    except ValueError:
        fixed_passed_1 = (saldo(db_fixed) == before_fixed_1)

    results.append({
        "scenario": 1,
        "title": "Overdraft Protection",
        "description": "Andi saldo 100 transfer 1000 poin ke Budi",
        "buggy": {
            "status": "FAIL (VULNERABLE)" if buggy_failed_1 else "PASS",
            "detail": f"Saldo Andi menjadi negatif: {saldo_buggy_1['andi']} (Budi: {saldo_buggy_1['budi']})",
            "balances": saldo_buggy_1
        },
        "fixed": {
            "status": "PASS (SECURED)" if fixed_passed_1 else "FAIL",
            "detail": "Transaksi ditolak, saldo utuh terlindungi",
            "balances": saldo(db_fixed)
        }
    })

    # Skenario 2: Jumlah Negatif (andi transfer -50)
    db_buggy = fresh()
    kirim_poin(db_buggy, "andi", "budi", -50)
    saldo_buggy_2 = saldo(db_buggy)
    buggy_failed_2 = saldo_buggy_2["andi"] > 100  # Andi mencuri saldo dari Budi

    db_fixed = fresh()
    before_fixed_2 = saldo(db_fixed)
    fixed_passed_2 = False
    try:
        kirim_poin_aman(db_fixed, "andi", "budi", -50)
    except ValueError:
        fixed_passed_2 = (saldo(db_fixed) == before_fixed_2)

    results.append({
        "scenario": 2,
        "title": "Negative Amount Validation",
        "description": "Andi transfer nilai negatif (-50) untuk mencuri saldo",
        "buggy": {
            "status": "FAIL (VULNERABLE)" if buggy_failed_2 else "PASS",
            "detail": f"Andi saldo naik jadi {saldo_buggy_2['andi']}, Budi berkurang jadi {saldo_buggy_2['budi']}",
            "balances": saldo_buggy_2
        },
        "fixed": {
            "status": "PASS (SECURED)" if fixed_passed_2 else "FAIL",
            "detail": "Input negatif ditolak, saldo utuh",
            "balances": saldo(db_fixed)
        }
    })

    # Skenario 3: SQL Injection (x' OR '1'='1)
    db_buggy = fresh()
    try:
        kirim_poin(db_buggy, "x' OR '1'='1", "budi", 10)
        saldo_buggy_3 = saldo(db_buggy)
        buggy_failed_3 = True  # injection tereksekusi tanpa error
    except Exception as e:
        saldo_buggy_3 = saldo(db_buggy)
        buggy_failed_3 = False

    db_fixed = fresh()
    before_fixed_3 = saldo(db_fixed)
    fixed_passed_3 = False
    try:
        kirim_poin_aman(db_fixed, "x' OR '1'='1", "budi", 10)
    except ValueError:
        fixed_passed_3 = (saldo(db_fixed) == before_fixed_3)

    results.append({
        "scenario": 3,
        "title": "SQL Injection Resistance",
        "description": "Payload 'x\\' OR \\'1\\'=\\'1' sebagai nama user pengirim",
        "buggy": {
            "status": "FAIL (VULNERABLE)" if buggy_failed_3 else "PASS",
            "detail": f"Payload SQL tereksekusi memodifikasi member: {saldo_buggy_3}",
            "balances": saldo_buggy_3
        },
        "fixed": {
            "status": "PASS (SECURED)" if fixed_passed_3 else "FAIL",
            "detail": "Parameterized query menganggap payload sebagai string literal; user ditolak",
            "balances": saldo(db_fixed)
        }
    })

    # Skenario 4: Pengirim Tidak Terdaftar (ghost)
    db_buggy = fresh()
    buggy_failed_4 = False
    try:
        kirim_poin(db_buggy, "ghost", "budi", 10)
    except Exception as e:
        buggy_failed_4 = True
        buggy_err_4 = f"{type(e).__name__}: {str(e)}"

    db_fixed = fresh()
    before_fixed_4 = saldo(db_fixed)
    fixed_passed_4 = False
    try:
        kirim_poin_aman(db_fixed, "ghost", "budi", 10)
    except ValueError:
        fixed_passed_4 = (saldo(db_fixed) == before_fixed_4)

    results.append({
        "scenario": 4,
        "title": "Missing Sender Handling",
        "description": "User 'ghost' yang tidak ada mencoba mengirim poin",
        "buggy": {
            "status": "FAIL (VULNERABLE)" if buggy_failed_4 else "PASS",
            "detail": f"Aplikasi crash tanpa penanganan exception ({buggy_err_4})",
            "balances": saldo(db_buggy)
        },
        "fixed": {
            "status": "PASS (SECURED)" if fixed_passed_4 else "FAIL",
            "detail": "Exception ValueError ditangani secara bersih, saldo aman",
            "balances": saldo(db_fixed)
        }
    })

    # Skenario 5: Penerima Tidak Terdaftar (andi kirim ke ghost)
    db_buggy = fresh()
    buggy_failed_5 = False
    try:
        kirim_poin(db_buggy, "andi", "ghost", 10)
    except Exception as e:
        buggy_failed_5 = True
        saldo_buggy_5 = saldo(db_buggy)
        # Pada kode buggy, saldo Andi sudah dipotong sebelum query penerima crash!
        andi_lost = saldo_buggy_5["andi"] == 90
        buggy_err_5 = f"Crash {type(e).__name__}, saldo Andi hilang 10 poin tanpa penerima ({saldo_buggy_5})"

    db_fixed = fresh()
    before_fixed_5 = saldo(db_fixed)
    fixed_passed_5 = False
    try:
        kirim_poin_aman(db_fixed, "andi", "ghost", 10)
    except ValueError:
        fixed_passed_5 = (saldo(db_fixed) == before_fixed_5)

    results.append({
        "scenario": 5,
        "title": "Atomic Rollback on Missing Recipient",
        "description": "Andi transfer 10 ke 'ghost' (penerima tidak terdaftar)",
        "buggy": {
            "status": "FAIL (VULNERABLE)" if buggy_failed_5 else "PASS",
            "detail": buggy_err_5,
            "balances": saldo_buggy_5
        },
        "fixed": {
            "status": "PASS (SECURED)" if fixed_passed_5 else "FAIL",
            "detail": "Rollback atomik berhasil: saldo Andi tetap 100 utuh",
            "balances": saldo(db_fixed)
        }
    })

    # Skenario 6: Transfer Normal (andi transfer 40 ke budi)
    db_buggy = fresh()
    kirim_poin(db_buggy, "andi", "budi", 40)
    saldo_buggy_6 = saldo(db_buggy)
    buggy_passed_6 = (saldo_buggy_6["andi"] == 60 and saldo_buggy_6["budi"] == 90)

    db_fixed = fresh()
    kirim_poin_aman(db_fixed, "andi", "budi", 40)
    saldo_fixed_6 = saldo(db_fixed)
    total_tetap = sum(saldo_fixed_6.values()) == 650
    fixed_passed_6 = (saldo_fixed_6["andi"] == 60 and saldo_fixed_6["budi"] == 90 and total_tetap)

    results.append({
        "scenario": 6,
        "title": "Happy Path Transfer & Invariant Conservation",
        "description": "Andi (100) kirim 40 ke Budi (50); invariant total saldo 650 poin",
        "buggy": {
            "status": "PASS" if buggy_passed_6 else "FAIL",
            "detail": f"Transfer normal selesai: {saldo_buggy_6}",
            "balances": saldo_buggy_6
        },
        "fixed": {
            "status": "PASS (SECURED)" if fixed_passed_6 else "FAIL",
            "detail": f"Transfer sukses sempurna, saldo {saldo_fixed_6}, konservasi total poin 650",
            "balances": saldo_fixed_6
        }
    })

    return results


def main():
    if "--json" in sys.argv:
        results = run_all_tests()
        print(json.dumps(results, indent=2))
        return

    print("======================================================================")
    print("      DEVGUARD EMPIRICAL VERIFICATION HARNESS (SQLITE ACID TEST)      ")
    print("======================================================================")
    print("Membuktikan secara empiris perbedaan kode 'spaghetti' vs 'kirim_poin_aman'\n")

    results = run_all_tests()
    all_passed = True

    for r in results:
        print(f"[{r['scenario']}/6] {r['title']}")
        print(f"    Kasus   : {r['description']}")
        print(f"    Asli    : {r['buggy']['status']} -> {r['buggy']['detail']}")
        print(f"    Aman    : {r['fixed']['status']} -> {r['fixed']['detail']}")
        print("    " + "-" * 62)
        if r['fixed']['status'] != "PASS (SECURED)":
            all_passed = False

    print("\n======================================================================")
    if all_passed:
        print("HASIL AKHIR: 6 DARI 6 SKENARIO PENGUJIAN LOLOS DENGAN SUKSES! [PASS]")
        print("Bukti empiris: Semua kerentanan kode junior berhasil dinetralisir.")
    else:
        print("HASIL AKHIR: DITEMUKAN SKENARIO YANG GAGAL. [FAIL]")
    print("======================================================================\n")


if __name__ == "__main__":
    main()
