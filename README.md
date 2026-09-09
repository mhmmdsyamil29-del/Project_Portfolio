# Suspicious Number History
Sistem Pelacakan Nomor Telepon Mencurigakan Berbasis Lokal


# 🎯 Domain
**Suspicious Number History** adalah sistem pelacakan lokal untuk mencatat dan memonitor nomor telepon mencurigakan atau penelepon berulang. Sistem ini menyimpan seluruh data dalam database SQLite lokal, sehingga riwayat tetap tersimpan jika nomor yang sama menelepon kembali.

### Keunggulan utama:

✅ 100% lokal di komputer Anda

✅ Tidak mengirim data ke mana pun

✅ Opsional pengecekan informasi publik (NumVerify)

# 📊 Struktur Class
*Atribut (Database Schema)*
|  Field   |	    Type      |	       Keterangan                   |
|----------|----------------|-------------------------------------|
| `id`     | `INTEGER (PK)` |	`Identifikasi unik setiap record`   |
| `number` | `TEXT`         |	`Nomor telepon yang direkam (wajib)`|
| `call_count` |	`INTEGER` |	`Jumlah panggilan dari nomor tersebut` |
| `first_seen` | `TEXT` |	`Waktu pertama kali nomor tercatat` |
| `last_seen` |	`TEXT` |	`Waktu terakhir nomor menelepon` |
| `notes` |	`TEXT (nullable)` |	`Catatan tambahan tentang nomor` |
| `status` | `TEXT` |	`Status: 'unverified', 'fraud', 'safe', 'unknown` |

# Method
| Method |	Deskripsi |
|--------|------------|
| `init_db()` |	`Menginisialisasi koneksi dan struktur database` |
| `record_number(conn, number, notes)` |	`Mencatat panggilan baru; increment call_count jika sudah ada` |
| `mark_status(conn, number, status)` |	`Mengubah status nomor` |
| `view_history(conn)` |	`Menampilkan seluruh riwayat dengan urutan berdasarkan jumlah panggilan` |
| `check_number_info(number)` |	`(Opsional) Mengecek informasi publik via NumVerify API` |
| `export_csv(conn, filename)` |	`Mengekspor seluruh riwayat ke file CSV` |
# 🔒 Invarian & Alasan
1. Database Harus Terinisialisasi Sebelum Operasi
Aturan: Semua fungsi bergantung pada koneksi database yang valid.
Alasan: Tanpa inisialisasi yang benar, operasi pencatatan dan pembacaan data akan gagal.
Penanganan Error: sqlite3.Error (Python)

2. Nomor Telepon Tidak Boleh Kosong
Aturan: record_number() membutuhkan nomor telepon sebagai identitas unik.
Alasan: Tanpa nomor yang valid, tidak ada entitas yang bisa direkam secara bermakna untuk pelacakan riwayat panggilan.
Penanganan Error: ValueError (Python)

3. Status Hanya Boleh Nilai yang Valid
Aturan: mark_status() hanya menerima status yang sesuai dengan pilihan.
Alasan: Menjaga konsistensi data dan memudahkan klasifikasi nomor.
Status Valid: 'fraud', 'safe', 'unknown'

# ✨ Fitur Utama
### Fitur	Deskripsi
- 🏠 100% Lokal	Seluruh data tersimpan di komputer, tidak pernah dikirim ke server
- ⚠️ Peringatan Otomatis	Nomor dengan panggilan ≥ 3 kali ditandai dengan simbol ⚠
- 📝 Pelacakan Riwayat	Mencatat waktu pertama dan terakhir panggilan
- 📤 Ekspor CSV	Kemudahan analisis data dengan format CSV
- 🌐 Integrasi Opsional	Pengecekan informasi nomor via NumVerify (memerlukan API key)
- 🏷️ Status Management	Tandai nomor sebagai fraud/safe/unknown
# 📁 Struktur Berkas
```Struktur Folder
SuspiciousNumberHistory/
│
├── suspicious_number_history.py   # Program utama
├── suspicious_numbers.db          # Database SQLite (auto-generated)
├── history_export.csv             # Hasil ekspor CSV
└── README.md                      # Dokumentasi
```
# 🚀 Cara Menjalankan
### 1. Prasyarat
```Struktur Folder
*/ Pastikan Python 3.6+ terinstal
python --version
*/ Install library opsional untuk NumVerify
pip install requests
```
### 2. Menjalankan Program
```Struktur Folder
*/ Jalankan program utama
python suspicious_number_history.py
```
### 3. Menu Penggunaan
```Struktur Folder
==================================================
 SUSPICIOUS NUMBER HISTORY 
==================================================
1. Record a number that just called
2. View all history
3. Mark number status (fraud/safe/etc)
4. Check public number info (optional)
5. Export history to CSV
6. Exit
--------------------------------------------------
```
# 📱 Contoh Penggunaan
### Skenario 1: Mencatat Panggilan Baru
```Struktur Folder
Select option (1-6): 1
Enter phone number: +62123456789
Notes (optional, e.g., 'claimed to be from bank'): Mengaku dari bank
[+] Number +62123456789 newly recorded.
Press Enter to continue...
```
  
### Skenario 2: Melihat Riwayat
```Struktur Folder
Select option (1-6): 2

========================================================================================================
NUMBER             COUNT   FIRST SEEN          LAST SEEN           STATUS                 NOTES
--------------------------------------------------------------------------------------------------------
+62123456789       5 ⚠    2026-09-01 10:00   2026-09-09 14:30      fraud              Mengaku dari bank
+62898765432       2       2026-09-05 08:15   2026-09-08 09:45     unknown             Unknown number
========================================================================================================
```
### Skenario 3: Menandai Status
```Struktur Folder
Select option (1-6): 3
Number to mark: +62123456789
Status (fraud/safe/unknown): fraud
[+] Status for number +62123456789 changed to 'fraud'.
```
### Skenario 4: Cek Informasi Publik Nomor (Opsional)
Prasyarat:

- Library requests terinstal

- API Key dari numverify.com telah diisi
```Struktur Folder

Select option (1-6): 4
Number to check: +62123456789

    Country   : Indonesia
    Carrier   : Telkomsel
    Line Type : mobile

Press Enter to continue...
```
### Jika API Key belum diatur:
```Struktur Folder
Select option (1-6): 4
Number to check: +62123456789
[!] NumVerify API key not set. Skip this feature or sign up at numverify.com
```
### Jika library requests belum terinstal:
```Struktur Folder
Select option (1-6): 4
Number to check: +62123456789
[!] Library 'requests' not installed. Run: pip install requests
```
# Skenario 5: Ekspor History ke CSV
```Struktur Folder
Select option (1-6): 5
CSV filename (default: history_export.csv): my_history.csv
[+] History exported to: my_history.csv

Press Enter to continue...
```
### Jika menggunakan default:
```Struktur Folder
Select option (1-6): 5
CSV filename (default: history_export.csv): 
[+] History exported to: history_export.csv
```
### Hasil CSV yang diekspor:
```Struktur Folder
number,call_count,first_seen,last_seen,status,notes
+62123456789,5,2026-09-01 10:00:00,2026-09-09 14:30:00,fraud,Mengaku dari bank
+62898765432,2,2026-09-05 08:15:00,2026-09-08 09:45:00,unknown,Unknown number
```
# Skenario 6: Keluar dari Program
```Struktur Folder
Select option (1-6): 6
[+] Exiting. Data saved at: /home/user/SuspiciousNumberHistory/suspicious_numbers.db
````
# ⚙️ Konfigurasi
### Ambang Batas Peringatan
```Struktur Folder
### python
Ubah nilai ini untuk mengatur jumlah panggilan yang memicu peringatan
CAUTION_THRESHOLD = 3  # Default: 3 kali
```
### API Key NumVerify (Opsional)
```Struktur Folder
### python
Dapatkan API key gratis dari numverify.com
NUMVERIFY_API_KEY = "your_api_key_here"
```
### Lokasi Database
```Struktur Folder
### python
Ubah untuk menggunakan lokasi database berbeda
DB_PATH = "suspicious_numbers.db"
```
# 🐛 Penanganan Error
| Error |	Penyebab |	Solusi |
|-------|----------|---------|
| `ModuleNotFoundError: No module named 'requests'`	| `Library requests tidak terinstal` |	`pip install requests` |
| `NumVerify API key not set` |	`API key belum diisi` |	`Dapatkan key dari numverify.com` |
| `sqlite3.OperationalError` | `Database tidak dapat diakses` |	`Periksa izin file dan folder` |
| `Number invalid / not found` | `Nomor tidak valid` |	`Gunakan format dengan kode negara (+62...)` |
| `ValueError: empty number` |	`Nomor kosong saat dicatat` |	`Pastikan memasukkan nomor telepon` |

# 🔮 Pengembangan Kedepan
 ### Beberapa fitur yang dapat dikembangkan:

- Validasi nomor telepon sebelum pencatatan
- Integrasi dengan aplikasi VoIP
- Notifikasi real-time untuk panggilan mencurigakan
- Antarmuka grafis (GUI)
- Export ke format lain (JSON, Excel)
- Integrasi dengan database cloud (opsional)
- Sistem rekomendasi blokir otomatis
- Fitur pencarian dan filter data
- Backup otomatis database
  
# 📄 Lisensi
Proyek ini bersifat open-source. Bebas digunakan, dimodifikasi, dan didistribusikan sesuai kebutuhan.

# 🤝 Kontribusi
### Kontribusi sangat diterima! Silakan:

- Laporkan bug

- Sarankan fitur baru

- Ajukan pull request

- Perbaiki dokumentasi

# 📝 Deklarasi Penggunaan AI
### Asisten AI (Claude, Anthropic) digunakan untuk membantu:

- Menyusun struktur dan format dokumen README.md

- Merapikan dokumentasi agar lebih terstruktur dan profesional

- Membuat tabel dan format yang konsisten

AI tidak digunakan untuk menulis kode Python pada tugas ini. Seluruh implementasi kode dikerjakan secara mandiri sesuai dengan pemahaman konsep pemrograman dan pengembangan perangkat lunak.

# 📞 Kontak & Dukungan
### Jika mengalami masalah:

- Periksa error message untuk troubleshooting

- Verifikasi versi Python dan dependencies

- Pastikan izin menulis ke file database
  
- Cek koneksi internet untuk fitur NumVerify

