const express = require('express');
const jwt = require('jsonwebtoken');
const Database = require('better-sqlite3');

const app = express();
const db = new Database('app.db');

// Rahsia mesti sama dengan Gateway
const JWT_SECRET = 'rahasia-token-zero-trust';
const GATEWAY_SECRET = 'gateway-secret-123';

app.use(express.json());

// ==========================================
// 1. MIDDLEWARE DEFENSE IN DEPTH
// ==========================================
const defenseInDepth = (req, res, next) => {
    // Sahkan Gateway Secret (Halang akses langsung)
    if (req.headers['x-gateway-secret'] !== GATEWAY_SECRET) {
        return res.status(403).json({ error: 'Akses langsung ke service ditolak. Mesti melalui Gateway.' });
    }

    // Sahkan semula Token (Assume Breach)
    const authHeader = req.headers['authorization'];
    if (!authHeader) return res.status(401).json({ error: 'Token diperlukan' });

    const token = authHeader.split(' ')[1];
    try {
        req.user = jwt.verify(token, JWT_SECRET);
        next();
    } catch (err) {
        return res.status(401).json({ error: 'Token tidak sah atau tamat tempoh' });
    }
};

app.use(defenseInDepth);

// Fungsi semak jam akses (07.00 - 21.00)
const cekJamAkses = () => {
    const hour = new Date().getHours();
    return hour >= 7 && hour <= 21;
};

// ==========================================
// 2. ENDPOINT SERVICE NILAI
// ==========================================

// GET /nilai
app.get('/', (req, res) => {
    const { sub, role } = req.user; // sub adalah user.id

    if (role === 'mahasiswa') {
        // Object-Level Authorization: Mahasiswa hanya lihat nilai sendiri
        const nilai = db.prepare(`
      SELECT kelas.nama_kelas, nilai.nilai, nilai.status 
      FROM nilai 
      JOIN kelas ON nilai.kelas_id = kelas.id 
      WHERE nilai.mahasiswa_id = ?
    `).all(sub);
        return res.json(nilai);
    }

    if (role === 'dosen') {
        // Object-Level Authorization: Dosen hanya lihat nilai untuk kelas yang diajar
        const nilai = db.prepare(`
      SELECT users.username as mahasiswa, kelas.nama_kelas, nilai.id as nilai_id, nilai.nilai, nilai.status
      FROM nilai
      JOIN kelas ON nilai.kelas_id = kelas.id
      JOIN users ON nilai.mahasiswa_id = users.id
      WHERE kelas.dosen_id = ?
    `).all(sub);
        return res.json(nilai);
    }

    return res.status(403).json({ error: 'Peranan tidak dibenarkan' });
});

// PUT /nilai/:id
app.put('/:id', (req, res) => {
    if (req.user.role !== 'dosen') return res.status(403).json({ error: 'Hanya dosen dibenarkan' });
    if (!cekJamAkses()) return res.status(403).json({ error: 'Di luar jam akses (07.00-21.00)' });

    const nilaiId = req.params.id;
    const nilaiBaru = req.body.nilai;
    const dosenId = req.user.sub;

    // Semak jika nilai ini kepunyaan kelas yang diajar oleh dosen tersebut (Object-Level)
    const cekNilai = db.prepare(`
    SELECT nilai.status, kelas.dosen_id 
    FROM nilai 
    JOIN kelas ON nilai.kelas_id = kelas.id 
    WHERE nilai.id = ?
  `).get(nilaiId);

    if (!cekNilai) return res.status(404).json({ error: 'Data nilai tidak dijumpai' });
    if (cekNilai.dosen_id !== dosenId) return res.status(403).json({ error: 'Anda bukan pensyarah untuk kelas ini' });
    if (cekNilai.status === 'final') return res.status(400).json({ error: 'Nilai sudah dimuktamadkan' });

    db.prepare('UPDATE nilai SET nilai = ? WHERE id = ?').run(nilaiBaru, nilaiId);
    res.json({ message: 'Nilai berjaya dikemaskini' });
});

// POST /kelas/:id/finalisasi
app.post('/kelas/:id/finalisasi', (req, res) => {
    if (req.user.role !== 'dosen') return res.status(403).json({ error: 'Hanya dosen dibenarkan' });
    return res.json({
        message: 'Finalisasi nilai berhasil dilakukan oleh Dosen',
        kelas_id: req.params.id
    });
});

app.listen(3001, () => {
    console.log('Service Nilai (Resource) berjalan di http://localhost:3001');
});