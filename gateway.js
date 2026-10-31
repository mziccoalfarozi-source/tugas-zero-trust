const express = require('express');
const jwt = require('jsonwebtoken');
const Database = require('better-sqlite3');

const app = express();
const db = new Database('app.db');

// Konfigurasi rahasia
const JWT_SECRET = 'rahasia-token-zero-trust';
const GATEWAY_SECRET = 'gateway-secret-123'; // Secret untuk komunikasi antar service

app.use(express.json());

// Fungsi Helper untuk Audit Log
function logAudit(subjek, endpoint, device, hasil, alasan) {
    const stmt = db.prepare('INSERT INTO audit_log (subjek, endpoint, device, hasil, alasan) VALUES (?, ?, ?, ?, ?)');
    stmt.run(subjek, endpoint, device, hasil, alasan);
    console.log(`[AUDIT] ${subjek} | ${endpoint} | ${device} | ${hasil} | ${alasan}`);
}

// ==========================================
// 1. ENDPOINT AUTENTIKASI (POLICY ENGINE)
// ==========================================

// Login User
app.post('/auth/login', (req, res) => {
    const { username, password } = req.body;
    const deviceId = req.headers['x-device-id'];

    if (!deviceId) {
        logAudit(username || 'unknown', '/auth/login', 'unknown', 'deny', 'Header X-Device-ID tidak ada');
        return res.status(400).json({ error: 'Header X-Device-ID wajib disertakan' });
    }

    // Cek Kredensial
    const user = db.prepare('SELECT * FROM users WHERE username = ? AND password = ?').get(username, password);
    if (!user) {
        logAudit(username, '/auth/login', deviceId, 'deny', 'Kredensial salah');
        return res.status(401).json({ error: 'Username atau password salah' });
    }

    // Cek apakah device terdaftar untuk user tersebut
    const device = db.prepare('SELECT * FROM devices WHERE device_id = ? AND username = ?').get(deviceId, user.username);
    if (!device) {
        logAudit(user.username, '/auth/login', deviceId, 'deny', 'Device tidak terdaftar');
        return res.status(403).json({ error: 'Device tidak terdaftar untuk user ini' });
    }

    // Generate Access Token (Berlaku 10 menit)
    const token = jwt.sign({ sub: user.username, username: user.username, role: user.role }, JWT_SECRET, { expiresIn: '10m' });

    logAudit(user.username, '/auth/login', deviceId, 'allow', 'Login berhasil');
    res.json({ access_token: token });
});

// Login Service (Untuk antar-service)
app.post('/auth/service', (req, res) => {
    const { client_id, secret } = req.body;

    // Hardcode sederhana untuk validasi service client
    if (client_id === 'service-nilai' && secret === 'rahasia-service-nilai') {
        // Token service berlaku 5 menit dengan role khusus 'service'
        const token = jwt.sign({ sub: 'service-nilai', role: 'service' }, JWT_SECRET, { expiresIn: '5m' });
        logAudit('service-nilai', '/auth/service', 'server', 'allow', 'Token service diterbitkan');
        return res.json({ token });
    }

    logAudit(client_id || 'unknown', '/auth/service', 'server', 'deny', 'Kredensial service salah');
    return res.status(401).json({ error: 'Unauthorized' });
});

// ==========================================
// 2. MIDDLEWARE ZERO TRUST (POLICY ENFORCEMENT)
// ==========================================
const zeroTrustMiddleware = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const deviceId = req.headers['x-device-id'] || 'unknown';
    const endpoint = req.path;

    if (!authHeader) {
        logAudit('unknown', endpoint, deviceId, 'deny', 'Tidak ada token');
        return res.status(401).json({ error: 'Token otorisasi dibutuhkan' });
    }

    const token = authHeader.split(' ')[1];

    try {
        const decoded = jwt.verify(token, JWT_SECRET);

        // Bypass cek device jika yang request adalah service internal
        if (decoded.role !== 'service') {
            if (deviceId === 'unknown') {
                logAudit(decoded.username, endpoint, deviceId, 'deny', 'Header X-Device-ID hilang saat akses resource');
                return res.status(403).json({ error: 'Header X-Device-ID dibutuhkan' });
            }
            // Verifikasi ulang device setiap request
            const device = db.prepare('SELECT * FROM devices WHERE device_id = ? AND username = ?').get(deviceId, decoded.username);
            if (!device) {
                logAudit(decoded.username, endpoint, deviceId, 'deny', 'Akses ditolak: Device tidak cocok dengan token');
                return res.status(403).json({ error: 'Device tidak terdaftar untuk token ini' });
            }
        }

        logAudit(decoded.username || decoded.sub, endpoint, deviceId, 'allow', 'Lolos pemeriksaan Gateway');
        next();
    } catch (err) {
        logAudit('unknown', endpoint, deviceId, 'deny', 'Token tidak valid atau kadaluarsa');
        return res.status(401).json({ error: 'Token tidak valid atau sudah kadaluarsa' });
    }
};

// ==========================================
// 3. FORWARD MANUAL KE SERVICE NILAI
// ==========================================
app.get('/nilai', zeroTrustMiddleware, async (req, res) => {
    try {
        const upstreamResponse = await fetch('http://localhost:3001/', {
            headers: {
                Authorization: req.headers.authorization,
                'x-gateway-secret': GATEWAY_SECRET
            }
        });
        const data = await upstreamResponse.json();

        return res.status(upstreamResponse.status).json(data);
    } catch (err) {
        console.error('[GATEWAY] Gagal menghubungi Service Nilai:', err.message);
        return res.status(502).json({ error: 'Service Nilai tidak dapat dihubungi' });
    }
});

app.put('/nilai/:id', zeroTrustMiddleware, async (req, res) => {
    try {
        const upstreamResponse = await fetch(
            `http://localhost:3001/${encodeURIComponent(req.params.id)}`,
            {
                method: 'PUT',
                headers: {
                    Authorization: req.headers.authorization,
                    'x-gateway-secret': GATEWAY_SECRET,
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(req.body)
            }
        );
        const data = await upstreamResponse.json();

        return res.status(upstreamResponse.status).json(data);
    } catch (err) {
        console.error('[GATEWAY] Gagal menghubungi Service Nilai:', err.message);
        return res.status(502).json({ error: 'Service Nilai tidak dapat dihubungi' });
    }
});

app.post('/kelas/:id/finalisasi', zeroTrustMiddleware, async (req, res) => {
    try {
        const upstreamResponse = await fetch(
            `http://localhost:3001/kelas/${encodeURIComponent(req.params.id)}/finalisasi`,
            {
                method: 'POST',
                headers: {
                    Authorization: req.headers.authorization,
                    'x-gateway-secret': GATEWAY_SECRET,
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(req.body)
            }
        );
        const data = await upstreamResponse.json();

        return res.status(upstreamResponse.status).json(data);
    } catch (err) {
        console.error('[GATEWAY] Gagal menghubungi Service Nilai:', err.message);
        return res.status(502).json({ error: 'Service Nilai tidak dapat dihubungi' });
    }
});

// Forward manual ke Service Transkrip (Port 3002)
app.get('/transkrip/:nim', zeroTrustMiddleware, async (req, res) => {
    try {
        const upstreamResponse = await fetch(
            `http://localhost:3002/transkrip/${encodeURIComponent(req.params.nim)}`,
            {
                headers: {
                    Authorization: req.headers.authorization,
                    'x-gateway-secret': GATEWAY_SECRET
                }
            }
        );
        const data = await upstreamResponse.json();

        return res.status(upstreamResponse.status).json(data);
    } catch (err) {
        console.error('[GATEWAY] Gagal menghubungi Service Transkrip:', err.message);
        return res.status(502).json({ error: 'Service Transkrip tidak dapat dihubungi' });
    }
});

app.listen(3000, () => {
    console.log('API Gateway (PEP) berjalan di http://localhost:3000');
});