'use strict';
const path = require('path');
const http = require('http');
const express = require('express');

const { Db } = require('./lib/db');
const { computeSerial } = require('./lib/license');
const {
  hashPassword, verifyPassword, randomToken,
  SessionStore, LoginThrottle, parseCookies
} = require('./lib/auth');

const PORT = process.env.PORT || 4100;
const COOKIE_NAME = 'ftc_session';

const db = new Db({ url: process.env.TURSO_DATABASE_URL, authToken: process.env.TURSO_AUTH_TOKEN });
const sessions = new SessionStore();
const loginThrottle = new LoginThrottle();

const app = express();
app.use(express.json());
app.use((req, res, next) => {
  req.cookies = parseCookies(req.headers.cookie);
  next();
});

async function currentUser(req) {
  const sess = sessions.get(req.cookies[COOKIE_NAME]);
  if (!sess) return null;
  return db.getUserById(sess.userId);
}

// ---- auth (public) ----
app.post('/api/login', async (req, res) => {
  const ip = req.ip;
  const { email, password } = req.body || {};
  if (loginThrottle.isLocked(ip)) {
    return res.status(429).json({ ok: false, error: 'Too many attempts. Try again in a few minutes.' });
  }
  const user = typeof email === 'string' ? await db.getUserByEmail(email) : null;
  const valid = user && typeof password === 'string' &&
    verifyPassword(password, user.password_salt, user.password_hash);

  await db.recordLogin({ email: (email || '').toLowerCase(), success: !!valid, ip, userAgent: req.headers['user-agent'] });

  if (!valid) {
    loginThrottle.recordFailure(ip);
    return res.status(401).json({ ok: false, error: 'Invalid email or password.' });
  }
  loginThrottle.recordSuccess(ip);
  const token = sessions.create(user.id);
  res.cookie(COOKIE_NAME, token, {
    httpOnly: true, sameSite: 'lax', maxAge: 30 * 24 * 60 * 60 * 1000, path: '/'
  });
  res.json({ ok: true, role: user.role });
});

app.post('/api/logout', (req, res) => {
  const token = req.cookies[COOKIE_NAME];
  if (token) sessions.destroy(token);
  res.clearCookie(COOKIE_NAME, { path: '/' });
  res.json({ ok: true });
});

app.get('/login', async (req, res) => {
  if (await currentUser(req)) return res.redirect('/');
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

// ---- station check-in (API key auth, not session-based) ----
app.post('/api/checkin', async (req, res) => {
  const { stationId, apiKey } = req.body || {};
  const station = typeof stationId === 'string' ? await db.getStationById(stationId) : null;
  const valid = station && typeof apiKey === 'string' &&
    verifyPassword(apiKey, station.api_key_salt, station.api_key_hash);
  if (!valid) return res.status(401).json({ ok: false, error: 'Invalid station credentials.' });

  await db.recordCheckin(station.id, req.ip);
  res.json({
    ok: true,
    subscriptionActive: !!station.subscription_active,
    stationName: station.name,
    message: station.subscription_active ? 'Subscription active.' : 'Subscription inactive - contact FuelTrack to renew.'
  });
});

// ---- everything below requires a session ----
app.use(async (req, res, next) => {
  const user = await currentUser(req);
  if (user) { req.user = user; return next(); }
  if (req.path.startsWith('/api/')) return res.status(401).json({ ok: false, error: 'Not authenticated.' });
  res.redirect('/login');
});

app.use(express.static(path.join(__dirname, 'public')));

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', req.user.role === 'admin' ? 'admin.html' : 'owner.html'));
});

app.get('/api/me', (req, res) => {
  res.json({ ok: true, email: req.user.email, role: req.user.role });
});

function requireAdmin(req, res, next) {
  if (req.user.role !== 'admin') return res.status(403).json({ ok: false, error: 'Admin only.' });
  next();
}

// ---- owner-facing: read-only view of own stations ----
app.get('/api/my/stations', async (req, res) => {
  const stations = await db.listStationsForOwner(req.user.id);
  res.json(stations.map((s) => ({
    id: s.id, name: s.name, address: s.address,
    subscriptionActive: !!s.subscription_active,
    lastCheckinAt: s.last_checkin_at
  })));
});

// ---- admin API ----
app.get('/api/admin/stations', requireAdmin, async (req, res) => {
  const stations = await db.listStations();
  res.json(stations.map((s) => ({
    id: s.id, name: s.name, address: s.address, ownerEmail: s.owner_email,
    subscriptionActive: !!s.subscription_active,
    hasLicense: !!s.license_key,
    createdAt: s.created_at, lastCheckinAt: s.last_checkin_at, lastCheckinIp: s.last_checkin_ip
  })));
});

app.post('/api/admin/stations', requireAdmin, async (req, res) => {
  const { name, address, ownerEmail } = req.body || {};
  if (!name || !name.trim()) return res.status(400).json({ ok: false, error: 'Station name is required.' });

  let ownerUserId = null;
  if (ownerEmail && ownerEmail.trim()) {
    const owner = await db.getUserByEmail(ownerEmail);
    if (!owner) return res.status(400).json({ ok: false, error: `No user with email ${ownerEmail} - create the user first.` });
    ownerUserId = owner.id;
  }

  const apiKey = randomToken(20);
  const { salt, hash } = hashPassword(apiKey);
  const station = await db.createStation({ name: name.trim(), ownerUserId, address, apiKeyHash: hash, apiKeySalt: salt });

  res.json({
    ok: true,
    station: { id: station.id, name: station.name },
    // Shown once - only the hash is stored. Put this in the station's config.json.
    apiKey
  });
});

app.post('/api/admin/stations/:id/subscription', requireAdmin, async (req, res) => {
  const station = await db.getStationById(req.params.id);
  if (!station) return res.status(404).json({ ok: false, error: 'No such station.' });
  await db.setSubscription(station.id, !!req.body.active);
  res.json({ ok: true });
});

app.post('/api/admin/stations/:id/license', requireAdmin, async (req, res) => {
  const station = await db.getStationById(req.params.id);
  if (!station) return res.status(404).json({ ok: false, error: 'No such station.' });
  const { mb, cpu } = req.body || {};
  if (!mb || !cpu) {
    return res.status(400).json({ ok: false, error: 'mb and cpu are required (from that machine\'s `npm run fingerprint`).' });
  }
  const licenseKey = computeSerial(mb, cpu);
  await db.setLicense(station.id, { mb, cpu, licenseKey });
  res.json({ ok: true, licenseKey });
});

app.get('/api/admin/users', requireAdmin, async (req, res) => {
  res.json(await db.listUsers());
});

app.post('/api/admin/users', requireAdmin, async (req, res) => {
  const { email, password, role } = req.body || {};
  if (!email || !/^\S+@\S+\.\S+$/.test(email)) return res.status(400).json({ ok: false, error: 'Valid email required.' });
  if (!password || password.length < 8) return res.status(400).json({ ok: false, error: 'Password must be at least 8 characters.' });
  if (await db.getUserByEmail(email)) return res.status(400).json({ ok: false, error: 'A user with that email already exists.' });

  const { salt, hash } = hashPassword(password);
  const user = await db.createUser({ email, passwordHash: hash, passwordSalt: salt, role: role === 'admin' ? 'admin' : 'owner' });
  res.json({ ok: true, user: { id: user.id, email: user.email, role: user.role } });
});

app.get('/api/admin/login-history', requireAdmin, async (req, res) => {
  res.json(await db.listLoginHistory(100));
});

const server = http.createServer(app);
db.init().then(() => {
  server.listen(PORT, () => {
    console.log(`FuelTrack central server running at http://localhost:${PORT}`);
  });
}).catch((e) => {
  console.error('Database init failed:', e.message);
  process.exit(1);
});
