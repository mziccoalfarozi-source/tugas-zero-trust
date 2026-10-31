# Tugas Praktikum Zero Trust Security

Implementasi Zero Trust Architecture pada Sistem Nilai (NIST SP 800-207) menggunakan Node.js dan Express.

## Cara Menjalankan
1. Install dependencies: `npm install`
2. Inisialisasi database & seed data: `node db.js`
3. Jalankan ketiga service di terminal yang berbeda:
   - `node gateway.js` (Port 3000 - PEP)
   - `node service-nilai.js` (Port 3001 - Resource)
   - `node service-transkrip.js` (Port 3002 - Resource)

## Daftar Akun & Device ID (Seed Data)
| Role      | Username | Password | Device ID      | Keterangan                  |
|-----------|----------|----------|----------------|-----------------------------|
| Admin     | admin1   | pass123  | device-admin-1 |                             |
| Dosen     | dosen1   | pass123  | device-dosen-1 | Mengampu Keamanan Informasi |
| Dosen     | dosen2   | pass123  | device-dosen-2 | Mengampu Pemrograman Web    |
| Mahasiswa | mhs1     | pass123  | device-mhs-1   |                             |
| Mahasiswa | mhs2     | pass123  | device-mhs-2   |                             |
| Mahasiswa | mhs3     | pass123  | device-mhs-3   |                             |