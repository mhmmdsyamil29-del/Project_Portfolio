"""
SUSPICIOUS NUMBER HISTORY (Local Tracker)

Stores records of suspicious numbers/repeated callers
in a local SQLite database, so you have your own history if
the same number calls again.

100% local on your computer — does not send data anywhere,
unless you enable the number info check feature (NumVerify, optional).

Usage:
    python suspicious_number_history.py
"""

import os
import sqlite3
from datetime import datetime

try:
    import requests  # only used if number info check feature is enabled
except ImportError:
    requests = None

DB_PATH = "suspicious_numbers.db"
NUMVERIFY_API_KEY = "ENTER_YOUR_API_KEY_HERE"  # optional, from numverify.com

# Number is considered "needs caution" if it has called >= this threshold
CAUTION_THRESHOLD = 3


# -------- DATABASE SETUP --------
def init_db():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            number TEXT NOT NULL,
            call_count INTEGER DEFAULT 1,
            first_seen TEXT,
            last_seen TEXT,
            notes TEXT,
            status TEXT DEFAULT 'unverified'
        )
    """)
    conn.commit()
    return conn


# -------- MAIN FUNCTIONS --------
def record_number(conn, number, notes=""):
    """Record a call from a number. If it exists, increment the count."""
    cur = conn.cursor()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    cur.execute("SELECT id, call_count FROM history WHERE number = ?", (number,))
    row = cur.fetchone()

    if row:
        rid, count = row
        cur.execute("""
            UPDATE history
            SET call_count = ?, last_seen = ?,
                notes = CASE WHEN ? != '' THEN ? ELSE notes END
            WHERE id = ?
        """, (count + 1, now, notes, notes, rid))
        conn.commit()
        print(f"[+] Number {number} already recorded before. "
              f"Total calls now: {count + 1}")
        if count + 1 >= CAUTION_THRESHOLD:
            print(f"[!] CAUTION: this number has called {count + 1} times!")
    else:
        cur.execute("""
            INSERT INTO history (number, call_count, first_seen, last_seen, notes)
            VALUES (?, 1, ?, ?, ?)
        """, (number, now, now, notes))
        conn.commit()
        print(f"[+] Number {number} newly recorded.")


def mark_status(conn, number, status):
    """Mark a number's status, e.g., 'fraud', 'safe', 'unknown'."""
    cur = conn.cursor()
    cur.execute("UPDATE history SET status = ? WHERE number = ?", (status, number))
    conn.commit()
    if cur.rowcount == 0:
        print(f"[!] Number {number} not found in history.")
    else:
        print(f"[+] Status for number {number} changed to '{status}'.")


def view_history(conn):
    cur = conn.cursor()
    cur.execute("""
        SELECT number, call_count, first_seen, last_seen, status, notes
        FROM history
        ORDER BY call_count DESC, last_seen DESC
    """)
    rows = cur.fetchall()

    if not rows:
        print("[!] No history saved yet.")
        return

    print("\n" + "=" * 90)
    print(f"{'NUMBER':<18}{'COUNT':<8}{'FIRST SEEN':<20}{'LAST SEEN':<20}{'STATUS':<18}NOTES")
    print("-" * 90)
    for number, count, first, last, status, notes in rows:
        warning = " ⚠" if count >= CAUTION_THRESHOLD else ""
        print(f"{number:<18}{str(count)+warning:<8}{first:<20}{last:<20}{status:<18}{notes or ''}")
    print("=" * 90 + "\n")


def check_number_info(number):
    """Optional: check public number info via NumVerify (requires API key & internet)."""
    if requests is None:
        print("[!] Library 'requests' not installed. Run: pip install requests")
        return
    if NUMVERIFY_API_KEY == "ENTER_YOUR_API_KEY_HERE":
        print("[!] NumVerify API key not set. Skip this feature or sign up at numverify.com")
        return

    try:
        resp = requests.get(
            "http://apilayer.net/api/validate",
            params={"access_key": NUMVERIFY_API_KEY, "number": number, "format": 1},
            timeout=10,
        )
        data = resp.json()
        if not data.get("valid"):
            print("[!] Number invalid / not found.")
            return
        print(f"    Country   : {data.get('country_name')}")
        print(f"    Carrier   : {data.get('carrier') or 'Unknown'}")
        print(f"    Line Type : {data.get('line_type') or 'Unknown'}")
    except Exception as e:
        print(f"[!] Failed to check number info: {e}")


def export_csv(conn, filename="history_export.csv"):
    import csv
    cur = conn.cursor()
    cur.execute("SELECT number, call_count, first_seen, last_seen, status, notes FROM history")
    rows = cur.fetchall()

    with open(filename, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["number", "call_count", "first_seen", "last_seen", "status", "notes"])
        writer.writerows(rows)

    print(f"[+] History exported to: {filename}")


# -------- MENU --------
def show_menu():
    os.system("cls" if os.name == "nt" else "clear")
    print("=" * 50)
    print(" SUSPICIOUS NUMBER HISTORY ")
    print("=" * 50)
    print("1. Record a number that just called")
    print("2. View all history")
    print("3. Mark number status (fraud/safe/etc)")
    print("4. Check public number info (optional, requires internet)")
    print("5. Export history to CSV")
    print("6. Exit")
    print("-" * 50)


def main():
    conn = init_db()
    while True:
        show_menu()
        choice = input("Select option (1-6): ").strip()

        if choice == "1":
            number = input("Enter phone number: ").strip()
            notes = input("Notes (optional, e.g., 'claimed to be from bank'): ").strip()
            record_number(conn, number, notes)
        elif choice == "2":
            view_history(conn)
        elif choice == "3":
            number = input("Number to mark: ").strip()
            status = input("Status (fraud/safe/unknown): ").strip()
            mark_status(conn, number, status)
        elif choice == "4":
            number = input("Number to check: ").strip()
            check_number_info(number)
        elif choice == "5":
            filename = input("CSV filename (default: history_export.csv): ").strip()
            export_csv(conn, filename or "history_export.csv")
        elif choice == "6":
            print("[+] Exiting. Data saved at:", os.path.abspath(DB_PATH))
            break
        else:
            print("[!] Invalid choice.")

        input("\nPress Enter to continue...")


if __name__ == "__main__":
    main()