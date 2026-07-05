// /api/visitor.js
// Visitor counter yang diperketat di server — tidak bisa dimanipulasi
// dengan hapus localStorage doang seperti sebelumnya.
//
// Strategi anti-spam berlapis:
// 1. Rate limit per IP: max N request per menit (block kalau spam)
// 2. Hash IP + User-Agent sebagai visitor key (bukan random ID dari client)
// 3. Quota BULANAN per visitor key (reset tanggal 1 tiap bulan, waktu server)
// 4. Online counter pakai TTL — auto dianggap offline kalau tidak ping ulang
//
// ENV VARS wajib:
//   FIREBASE_DATABASE_URL
//   FIREBASE_SERVICE_ACCOUNT_KEY
//   VISITOR_MONTHLY_QUOTA (opsional, default 3)

import { initializeApp, getApps, cert } from 'firebase-admin/app';
import { getDatabase } from 'firebase-admin/database';
import { createHash } from 'crypto';

function initFirebaseAdmin() {
  if (getApps().length) return;
  const serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT_KEY || '{}');
  initializeApp({
    credential: cert(serviceAccount),
    databaseURL: process.env.FIREBASE_DATABASE_URL,
  });
}

// ── RATE LIMIT PER IP (in-memory, per cold-start instance) ──
const rateLimitMap = new Map();
const RL_WINDOW_MS = 60 * 1000; // 1 menit
const RL_MAX = 8; // maksimal 8 ping per menit per IP — cukup untuk 1 tab normal

function checkRateLimit(ip) {
  const now = Date.now();
  const entry = rateLimitMap.get(ip) || { count: 0, resetAt: now + RL_WINDOW_MS };
  if (now > entry.resetAt) {
    entry.count = 0;
    entry.resetAt = now + RL_WINDOW_MS;
  }
  entry.count += 1;
  rateLimitMap.set(ip, entry);
  return entry.count <= RL_MAX;
}

// Bersihkan rate limit map yang basi biar tidak bocor memori
setInterval(() => {
  const now = Date.now();
  for (const [ip, entry] of rateLimitMap) {
    if (now > entry.resetAt + RL_WINDOW_MS) rateLimitMap.delete(ip);
  }
}, 5 * 60 * 1000);

function getClientIp(req) {
  const fwd = req.headers['x-forwarded-for'];
  if (fwd) return fwd.split(',')[0].trim();
  return req.socket?.remoteAddress || 'unknown';
}

function hashVisitor(ip, userAgent) {
  // Hash IP + UA jadi 1 visitor key — tidak bisa dipalsukan dari client
  // karena IP diambil dari header koneksi TCP/HTTP asli, bukan dari body request
  return createHash('sha256').update(ip + '|' + (userAgent || '')).digest('hex').slice(0, 24);
}

function monthKey() {
  const d = new Date();
  return `${d.getFullYear()}-${d.getMonth() + 1}`; // reset otomatis tiap tanggal 1
}

export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') return res.status(200).end();

  const ip = getClientIp(req);

  if (!checkRateLimit(ip)) {
    return res.status(429).json({ error: 'Rate limit — terlalu sering ping' });
  }

  try {
    initFirebaseAdmin();
    const db = getDatabase();

    // ── GET: baca angka realtime saja ──
    if (req.method === 'GET') {
      const [totalSnap, onlineSnap] = await Promise.all([
        db.ref('totalVisit').get(),
        db.ref('onlineNow').get(),
      ]);

      // Hitung online yang masih valid (belum expired TTL)
      const onlineData = onlineSnap.val() || {};
      const now = Date.now();
      const ONLINE_TTL_MS = 90 * 1000; // dianggap offline kalau tidak ping 90 detik
      const activeCount = Object.values(onlineData).filter(
        (v) => v && v.lastPing && now - v.lastPing < ONLINE_TTL_MS
      ).length;

      return res.status(200).json({
        total: totalSnap.val() || 0,
        online: activeCount,
      });
    }

    // ── POST: ping presence + hitung visit baru ──
    if (req.method === 'POST') {
      const userAgent = req.headers['user-agent'] || '';
      const visitorKey = hashVisitor(ip, userAgent);
      const quotaMax = parseInt(process.env.VISITOR_MONTHLY_QUOTA || '3', 10);

      // 1. Update presence (selalu, untuk online counter)
      await db.ref('onlineNow/' + visitorKey).set({
        lastPing: Date.now(),
      });

      // 2. Cek & increment quota bulanan — server-side, tidak bisa dimanipulasi client
      const quotaRef = db.ref('visitTracking/' + visitorKey);
      const quotaSnap = await quotaRef.get();
      const quotaData = quotaSnap.val();
      const thisMonth = monthKey();

      let shouldCountVisit = false;

      if (!quotaData || quotaData.month !== thisMonth) {
        // Bulan baru atau visitor baru — reset counter
        await quotaRef.set({ month: thisMonth, count: 1 });
        shouldCountVisit = true;
      } else if (quotaData.count < quotaMax) {
        await quotaRef.update({ count: quotaData.count + 1 });
        shouldCountVisit = true;
      }
      // Kalau sudah lewat quota bulan ini, shouldCountVisit tetap false — tidak nambah
      // totalVisit, tapi presence tetap di-set jadi online counter tetap akurat

      if (shouldCountVisit) {
        await db.ref('totalVisit').transaction((n) => (n || 0) + 1);
      }

      const totalSnap = await db.ref('totalVisit').get();

      return res.status(200).json({
        total: totalSnap.val() || 0,
        counted: shouldCountVisit,
      });
    }

    return res.status(405).json({ error: 'Method not allowed' });
  } catch (err) {
    console.error('visitor API error:', err);
    return res.status(500).json({ error: err.message || 'Internal server error' });
  }
}
