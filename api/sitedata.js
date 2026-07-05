// /api/sitedata.js
// Proxy baca/tulis siteData ke Firebase Realtime Database.
// index.html memanggil endpoint ini alih-alih connect langsung ke Firebase client SDK.
// Ini menyembunyikan struktur database dan menambah lapisan kontrol (rate limit, validasi).
//
// ENV VARS wajib di Vercel Dashboard:
//   FIREBASE_DATABASE_URL
//   FIREBASE_SERVICE_ACCOUNT_KEY   (JSON string dari Firebase service account, di-escape jadi satu baris)
//
// GET  /api/sitedata          -> baca seluruh siteData (public, read-only)
// POST /api/sitedata          -> tulis siteData (butuh header Authorization dari admin panel)

import { initializeApp, getApps, cert } from 'firebase-admin/app';
import { getDatabase } from 'firebase-admin/database';

function initFirebaseAdmin() {
  if (getApps().length) return;

  const serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT_KEY || '{}');

  initializeApp({
    credential: cert(serviceAccount),
    databaseURL: process.env.FIREBASE_DATABASE_URL,
  });
}

// Rate limit sederhana in-memory (reset tiap cold start Vercel — untuk rate limit
// yang lebih presisi lintas-instance, gunakan Vercel KV / Upstash Redis)
const rateLimitMap = new Map();
const RATE_LIMIT_WINDOW_MS = 10 * 1000; // 10 detik
const RATE_LIMIT_MAX = 20; // max 20 request per 10 detik per IP

function checkRateLimit(ip) {
  const now = Date.now();
  const entry = rateLimitMap.get(ip) || { count: 0, resetAt: now + RATE_LIMIT_WINDOW_MS };

  if (now > entry.resetAt) {
    entry.count = 0;
    entry.resetAt = now + RATE_LIMIT_WINDOW_MS;
  }

  entry.count += 1;
  rateLimitMap.set(ip, entry);

  return entry.count <= RATE_LIMIT_MAX;
}

export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');

  if (req.method === 'OPTIONS') return res.status(200).end();

  const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.socket?.remoteAddress || 'unknown';

  if (!checkRateLimit(ip)) {
    return res.status(429).json({ error: 'Terlalu banyak request. Coba lagi sebentar.' });
  }

  try {
    initFirebaseAdmin();
    const db = getDatabase();

    if (req.method === 'GET') {
      const snap = await db.ref('siteData').get();
      return res.status(200).json(snap.val() || {});
    }

    if (req.method === 'POST') {
      // Butuh auth token Firebase dari admin panel di header Authorization
      const authHeader = req.headers.authorization || '';
      const idToken = authHeader.replace('Bearer ', '');

      if (!idToken) {
        return res.status(401).json({ error: 'Unauthorized — token tidak ada' });
      }

      // Verifikasi token pakai Firebase Admin Auth
      const { getAuth } = await import('firebase-admin/auth');
      let decoded;
      try {
        decoded = await getAuth().verifyIdToken(idToken);
      } catch (e) {
        return res.status(401).json({ error: 'Token tidak valid' });
      }

      // Cek role admin/approved di DB
      const userSnap = await db.ref('users/' + decoded.uid).get();
      const userData = userSnap.val();
      const approved = userData?.status === 'approved' || userData?.status === 'sukses';

      if (!approved) {
        return res.status(403).json({ error: 'Akun belum disetujui' });
      }

      const { path, value } = req.body;
      if (!path) return res.status(400).json({ error: 'path wajib diisi' });

      await db.ref('siteData/' + path).set(value);
      return res.status(200).json({ success: true });
    }

    return res.status(405).json({ error: 'Method not allowed' });
  } catch (err) {
    console.error('sitedata API error:', err);
    return res.status(500).json({ error: err.message || 'Internal server error' });
  }
}
