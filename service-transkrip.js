const express = require('express');
const jwt = require('jsonwebtoken');
const Database = require('better-sqlite3');

const app = express();
const db = new Database('app.db');

const JWT_SECRET = 'rahasia-token-zero-trust';
const GATEWAY_SECRET = 'gateway-secret-123';

app.use(express.json());

// ==========================================
// 1. MIDDLEWARE DEFENSE IN DEPTH
// ==========================================
const defenseInDepth = (req, res, next) => {
    console.log('\n[DEBUG] Request masuk ke Service Transkrip:', req.path);

    // Verifikasi Gateway Secret
    if (req.headers['x-gateway-secret'] !== GATEWAY_SECRET) {
        return res.status(403).json({ error: 'Akses langsung ke service ditolak. Harus melalui Gateway.' });
    }

    // Verifikasi ulang Token
    const authHeader = req.headers['authorization'];
    if (!authHeader) return res.status(401).json({ error: 'Token diperlukan' });

    const token = authHeader.split(' ')[1];
    try {
        req.user = jwt.verify(token, JWT_SECRET);
        next();
    } catch (err) {
        return res.status(401).json({ error: 'Token tidak valid atau kadaluarsa' });
    }
};

app.use(defenseInDepth);

// ==========================================
// 2. ENDPOINT SERVICE TRANSKRIP
// ==========================================

// GET /transkrip/:nim
// Note: Kita menggunakan parameter username sebagai NIM (misal: 'mhs1')
app.get('/transkrip/:nim', (req, res) => {
    const { role, username } = req.user;
    const targetNim = req.params.nim;

    // Kebijakan Akses: Hanya mahasiswa dan admin yang boleh[cite: 3]
    if (role !== 'admin' && role !== 'mahasiswa') {
        return res.status(403).json({ error: 'Akses ditolak. Role tidak diizinkan.' });
    }

    // Mahasiswa hanya boleh melihat NIM sendiri[cite: 3]
    if (role === 'mahasiswa' && username !== targetNim) {
        return res.status(403).json({ error: 'Anda hanya diizinkan melihat transkrip milik sendiri.' });
    }

    const transkrip = db.prepare(
        'SELECT mata_kuliah, nilai FROM transkrip WHERE username = ?'
    ).all(targetNim);

    res.json({ nim: targetNim, transkrip });
});

// POST /transkrip/sinkron
app.post('/transkrip/sinkron', (req, res) => {
    // Hanya izinkan jika request membawa token service, tolak token user mana pun[cite: 3]
    if (req.user.role !== 'service') {
        return res.status(403).json({ error: 'Akses ditolak. Endpoint ini hanya untuk komunikasi antar-service.' });
    }

    const { kelas_id } = req.body;
    if (!kelas_id) return res.status(400).json({ error: 'kelas_id diperlukan' });

    // Pindahkan data nilai yang sudah difinalisasi ke tabel transkrip
    const insertTranskrip = db.prepare(`
    INSERT INTO transkrip (mahasiswa_id, kelas_id, nilai)
    SELECT mahasiswa_id, kelas_id, nilai FROM nilai 
    WHERE kelas_id = ? AND status = 'final'
  `);

    const info = insertTranskrip.run(kelas_id);
    res.json({ message: `Sinkronisasi berhasil. ${info.changes} data masuk ke transkrip.` });
});

app.listen(3002, () => {
    console.log('Service Transkrip (Resource) berjalan di http://localhost:3002');
});