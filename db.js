const Database = require('better-sqlite3');
const db = new Database('app.db');

// Buat skema tabel sesuai arsitektur Zero Trust
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    username TEXT PRIMARY KEY,
    password TEXT,
    role TEXT
  );
  
  CREATE TABLE IF NOT EXISTS devices (
    device_id TEXT PRIMARY KEY,
    username TEXT
  );
  
  CREATE TABLE IF NOT EXISTS transkrip (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT,
    mata_kuliah TEXT,
    nilai TEXT
  );
  
  CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    subjek TEXT,
    endpoint TEXT,
    device TEXT,
    hasil TEXT,
    alasan TEXT,
    waktu DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  -- Bersihkan data lama agar tidak bentrok jika file dijalankan ulang
  DELETE FROM users;
  DELETE FROM devices;
  DELETE FROM transkrip;
`);

// Siapkan query untuk seed data
const insertUser = db.prepare('INSERT INTO users (username, password, role) VALUES (?, ?, ?)');
const insertDevice = db.prepare('INSERT INTO devices (device_id, username) VALUES (?, ?)');
const insertTranskrip = db.prepare('INSERT INTO transkrip (username, mata_kuliah, nilai) VALUES (?, ?, ?)');

// Eksekusi seed data sekaligus
db.transaction(() => {
  // Data user
  insertUser.run('mhs1', 'pass123', 'mahasiswa');
  insertUser.run('mhs2', 'pass123', 'mahasiswa');
  insertUser.run('dosen1', 'pass123', 'dosen');

  // Data device terdaftar
  insertDevice.run('device-mhs-1', 'mhs1');
  insertDevice.run('device-mhs-2', 'mhs2');
  insertDevice.run('device-dosen-1', 'dosen1');

  // Data transkrip
  insertTranskrip.run('mhs1', 'Keamanan Informasi', 'A');
  insertTranskrip.run('mhs2', 'Keamanan Informasi', 'B');
})();

console.log("✅ Seed data berhasil dibuat! Database sudah siap.");