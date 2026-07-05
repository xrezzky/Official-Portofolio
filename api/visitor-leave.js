// /api/visitor-leave.js
// Dipanggil via navigator.sendBeacon saat tab ditutup — hapus presence
// segera, tidak perlu nunggu TTL expired.

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

function getClientIp(req) {
  const fwd = req.headers['x-forwarded-for'];
  if (fwd) return fwd.split(',')[0].trim();
  return req.socket?.remoteAddress || 'unknown';
}

function hashVisitor(ip, userAgent) {
  return createHash('sha256').update(ip + '|' + (userAgent || '')).digest('hex').slice(0, 24);
}

export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');

  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  try {
    initFirebaseAdmin();
    const db = getDatabase();

    const ip = getClientIp(req);
    const userAgent = req.headers['user-agent'] || '';
    const visitorKey = hashVisitor(ip, userAgent);

    await db.ref('onlineNow/' + visitorKey).remove();

    return res.status(200).json({ success: true });
  } catch (err) {
    console.error('visitor-leave error:', err);
    return res.status(500).json({ error: err.message });
  }
}
