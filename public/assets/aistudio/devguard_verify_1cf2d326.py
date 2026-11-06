"""
Verifikasi kode demo DevGuard: (A) buktikan bug di kode 'spaghetti' asli,
(B) buktikan versi perbaikan lolos tes. Jalankan: python3 devguard_verify.py
"""
import sqlite3

# ---------- KODE ASLI (dari blueprint Gemini, tidak diubah) ----------
def kirim_poin(db, user_pengirim, user_penerima, jumlah):
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

# ---------- VERSI PERBAIKAN ----------
def kirim_poin_aman(db, pengirim, penerima, jumlah):
    if not isinstance(jumlah, int) or isinstance(jumlah, bool) or jumlah <= 0:
        raise ValueError("jumlah harus bilangan bulat positif")
    if pengirim == penerima:
        raise ValueError("pengirim dan penerima tidak boleh sama")
    with db:  # satu transaksi: commit jika sukses, rollback jika exception
        cur = db.execute(
            "UPDATE members SET poin = poin - ? WHERE username = ? AND poin >= ?",
            (jumlah, pengirim, jumlah))          # cek saldo + kurangi dalam SATU statement (atomik)
        if cur.rowcount != 1:
            raise ValueError("saldo tidak cukup atau pengirim tidak ditemukan")
        cur = db.execute(
            "UPDATE members SET poin = poin + ? WHERE username = ?", (jumlah, penerima))
        if cur.rowcount != 1:
            raise ValueError("penerima tidak ditemukan")   # exception -> sisi pengirim ikut di-rollback
    return "Berhasil transfer!"

def fresh():
    db = sqlite3.connect(":memory:")
    db.execute("CREATE TABLE members (username TEXT PRIMARY KEY, poin INTEGER)")
    db.executemany("INSERT INTO members VALUES (?,?)", [("andi", 100), ("budi", 50), ("citra", 500)])
    db.commit()
    return db

def saldo(db):
    return dict(db.execute("SELECT username, poin FROM members ORDER BY username").fetchall())

print("=== A. BUG DI KODE ASLI ===")
db = fresh(); kirim_poin(db, "andi", "budi", 1000)
print("1 Overdraft (andi 100 poin kirim 1000):", saldo(db))
db = fresh(); kirim_poin(db, "andi", "budi", -50)
print("2 Jumlah negatif (andi 'mencuri' dari budi):", saldo(db))
db = fresh(); kirim_poin(db, "x' OR '1'='1", "budi", 10)
print("3 SQL injection (citra awalnya 500):", saldo(db))
db = fresh()
try: kirim_poin(db, "ghost", "budi", 10)
except Exception as e: print("4 User tidak ada ->", type(e).__name__, e)

print("\n=== B. VERSI PERBAIKAN ===")
def expect_error(label, fn):
    db = fresh(); before = saldo(db)
    try: fn(db); print(label, "-> GAGAL: tidak ditolak"); return
    except ValueError as e: pass
    print(label, "-> ditolak, saldo utuh:", saldo(db) == before)
expect_error("1 Overdraft          ", lambda d: kirim_poin_aman(d, "andi", "budi", 1000))
expect_error("2 Jumlah negatif     ", lambda d: kirim_poin_aman(d, "andi", "budi", -50))
expect_error("3 Injection string   ", lambda d: kirim_poin_aman(d, "x' OR '1'='1", "budi", 10))
expect_error("4 Pengirim tak ada   ", lambda d: kirim_poin_aman(d, "ghost", "budi", 10))
expect_error("5 Penerima tak ada   ", lambda d: kirim_poin_aman(d, "andi", "ghost", 10))
db = fresh(); kirim_poin_aman(db, "andi", "budi", 40)
print("6 Transfer normal:", saldo(db), "| total poin tetap 650:", sum(saldo(db).values()) == 650)
