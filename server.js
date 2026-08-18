'use strict';
const path = require('path');
const crypto = require('crypto');
const http = require('http');
const express = require('express');
const { WebSocketServer, WebSocket } = require('ws');

const { Db } = require('./lib/db');
const { computeSerial } = require('./lib/license');
const { LiveState } = require('./lib/liveState');
const { mintHandoffToken, publicKeyPem: ssoPublicKeyPem } = require('./lib/sso');
const {
  hashPassword, verifyPassword, randomToken,
  SessionStore, LoginThrottle, parseCookies
} = require('./lib/auth');

const PORT = process.env.PORT || 4100;
const BASE_URL = process.env.BASE_URL || `http://localhost:${PORT}`;

// Setup links must be openable by a real person, so they can't use BASE_URL's
// localhost fallback (that's the container's own address - unusable to anyone
// else, which is why links were coming out as http://localhost:8080/setup/...).
// Prefer an explicitly configured PUBLIC_BASE_URL or BASE_URL, otherwise derive
// it from the request the admin is actually making, honouring the proxy headers
// Railway/Cloudflare set.
function publicBaseUrl(req) {
  if (process.env.PUBLIC_BASE_URL) return process.env.PUBLIC_BASE_URL.replace(/\/+$/, '');
  if (process.env.BASE_URL) return process.env.BASE_URL.replace(/\/+$/, '');
  const proto = (req.headers['x-forwarded-proto'] || req.protocol || 'https').split(',')[0].trim();
  const host = (req.headers['x-forwarded-host'] || req.headers.host || '').split(',')[0].trim();
  if (!host) return BASE_URL;
  return `${proto}://${host}`;
}
const COOKIE_NAME = 'ftc_session';
const SETUP_TOKEN_TTL_MS = 24 * 60 * 60 * 1000;
const SETUP_CODE_TTL_MS = 30 * 24 * 60 * 60 * 1000; // 30 days - installs can happen well after the code was generated

// Same safe alphabet as lib/license.js's license keys - excludes 0/O/1/I/L so
// a code read aloud or handwritten on a batch sheet doesn't get mistyped.
const SETUP_CODE_ALPHABET = '23456789ABCDEFGHJKLMNPQRSTUVWXYZ';
function generateSetupCode() {
  let code = '';
  for (let i = 0; i < 8; i++) {
    if (i === 4) code += '-';
    code += SETUP_CODE_ALPHABET[crypto.randomInt(SETUP_CODE_ALPHABET.length)];
  }
  return code;
}

function newSetupToken() {
  return { setupToken: randomToken(24), setupTokenExpiresAt: new Date(Date.now() + SETUP_TOKEN_TTL_MS).toISOString() };
}

const db = new Db({ url: process.env.TURSO_DATABASE_URL, authToken: process.env.TURSO_AUTH_TOKEN });
const sessions = new SessionStore();
const loginThrottle = new LoginThrottle();
const liveState = new LiveState();

const app = express();
app.use(express.json());
app.use((req, res, next) => {
  req.cookies = parseCookies(req.headers.cookie);
  next();
});

// Admin-kind sessions map to the `users` table (this dashboard's own
// accounts). Station-user-kind sessions are only ever used transiently, to
// figure out where to redirect - they don't get access to anything here.
async function resolveAdmin(req) {
  const sess = sessions.get(req.cookies[COOKIE_NAME]);
  if (!sess || sess.kind !== 'admin') return null;
  return db.getUserById(sess.id);
}

// Station-user (owner/attendant) identity, scoped to exactly one station -
// used only by the /portal routes below, never mixed with req.user (admin).
async function resolveStationUser(req) {
  const sess = sessions.get(req.cookies[COOKIE_NAME]);
  if (!sess || sess.kind !== 'station_user') return null;
  const su = await db.getStationUserById(sess.id);
  if (!su) return null;
  const station = await db.getStationById(su.station_id);
  if (!station || !station.subscription_active) return null;
  return { user: su, station };
}

function normalizeStationAddress(raw) {
  const addr = raw.trim().replace(/\/+$/, '');
  if (/^https?:\/\//i.test(addr)) return addr;
  const isBareIp = /^\d{1,3}(\.\d{1,3}){3}(:\d+)?$/.test(addr);
  return (isBareIp ? 'http://' : 'https://') + addr;
}

// Where a just-authenticated (or returning) session should land. Admins go
// to the dashboard; station users go to their own station's address - or a
// clear error if that's not possible (station gone, no address on file, or
// the station's subscription is inactive). Station users get a one-time
// handoff token appended so they land there already logged in instead of
// re-entering their password a second time (see lib/sso.js).
async function resolveDestination(sess) {
  if (sess.kind === 'admin') return { ok: true, redirect: '/admin' };

  const su = await db.getStationUserById(sess.id);
  if (!su) return { ok: false, error: 'User not found.' };
  const station = await db.getStationById(su.station_id);
  if (!station) return { ok: false, error: 'User not found.' };
  if (!station.subscription_active) {
    return { ok: false, error: 'This station\'s subscription is inactive. Contact FuelTrack to restore access.' };
  }
  // Legacy stations still running their own web server (address on file)
  // keep the old external SSO handoff. Desktop-app stations have no address
  // to hand off to - they land on the central-hosted portal instead (see
  // the /portal routes below), authenticated with the same session cookie
  // since it's now the same origin.
  if (station.address && station.address.trim()) {
    const base = normalizeStationAddress(station.address);
    const token = mintHandoffToken({ username: su.username, stationId: station.id });
    return { ok: true, redirect: `${base}/api/sso/exchange?token=${encodeURIComponent(token)}` };
  }
  return { ok: true, redirect: '/portal' };
}

// ---- login gateway (public) ----
// Single entry point for everyone: central admins and station owners/
// attendants alike. Resolves which of the two account tables the given
// identifier belongs to, then either sends admins to /admin or looks up
// the right station and sends everyone else there.
app.get('/', async (req, res) => {
  const sess = sessions.get(req.cookies[COOKIE_NAME]);
  if (sess) {
    const dest = await resolveDestination(sess);
    if (dest.ok) return res.redirect(dest.redirect);
    sessions.destroy(req.cookies[COOKIE_NAME]); // stale/no-longer-valid - fall through to the login form
  }
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/login', (req, res) => res.redirect('/')); // old bookmarks/links

app.post('/api/login', async (req, res) => {
  const ip = req.ip;
  const { username, password } = req.body || {};
  if (loginThrottle.isLocked(ip)) {
    return res.status(429).json({ ok: false, error: 'Too many attempts. Try again in a few minutes.' });
  }
  const identifier = typeof username === 'string' ? username.trim() : '';
  const logId = identifier.toLowerCase();

  const adminUser = identifier ? await db.getUserByEmail(identifier) : null;
  const stationUser = (!adminUser && identifier) ? await db.getStationUserByUsername(identifier) : null;

  if (!adminUser && !stationUser) {
    await db.recordLogin({ email: logId, success: false, ip, userAgent: req.headers['user-agent'] });
    loginThrottle.recordFailure(ip);
    return res.status(404).json({ ok: false, error: 'No account found with that username.' });
  }

  const account = adminUser || stationUser;
  const valid = typeof password === 'string' &&
    verifyPassword(password, account.password_salt, account.password_hash);

  await db.recordLogin({ email: logId, success: valid, ip, userAgent: req.headers['user-agent'] });

  if (!valid) {
    loginThrottle.recordFailure(ip);
    return res.status(401).json({ ok: false, error: 'Invalid username or password.' });
  }
  loginThrottle.recordSuccess(ip);

  const sess = adminUser ? { kind: 'admin', id: adminUser.id } : { kind: 'station_user', id: stationUser.id };
  const dest = await resolveDestination(sess);
  if (!dest.ok) {
    // Authenticated fine, but there's nowhere to send them - don't hand out a session for a dead end.
    return res.status(409).json({ ok: false, error: dest.error });
  }

  const token = sessions.create(sess);
  res.cookie(COOKIE_NAME, token, {
    httpOnly: true, sameSite: 'lax', maxAge: 30 * 24 * 60 * 60 * 1000, path: '/'
  });
  res.json({ ok: true, redirect: dest.redirect });
});

app.post('/api/logout', (req, res) => {
  const token = req.cookies[COOKIE_NAME];
  if (token) sessions.destroy(token);
  res.clearCookie(COOKIE_NAME, { path: '/' });
  res.json({ ok: true });
});

// ---- station check-in (API key auth, not session-based) ----
app.post('/api/checkin', async (req, res) => {
  const { stationId, apiKey } = req.body || {};
  const station = typeof stationId === 'string' ? await db.getStationById(stationId) : null;
  const valid = station && typeof apiKey === 'string' &&
    verifyPassword(apiKey, station.api_key_salt, station.api_key_hash);
  if (!valid) return res.status(401).json({ ok: false, error: 'Invalid station credentials.' });

  await db.recordCheckin(station.id, req.ip);
  const stationUsers = await db.listStationUsersForSync(station.id);
  res.json({
    ok: true,
    subscriptionActive: !!station.subscription_active,
    stationName: station.name,
    message: station.subscription_active ? 'Subscription active.' : 'Subscription inactive - contact FuelTrack to renew.',
    // Synced down and cached locally so station-app login keeps working offline.
    stationUsers: stationUsers.map((u) => ({
      id: u.id, username: u.username, passwordHash: u.password_hash, passwordSalt: u.password_salt, role: u.role
    })),
    // Cached locally so the station can verify a gateway single-sign-on
    // handoff token with no round trip back here - see lib/sso.js.
    ssoPublicKey: ssoPublicKeyPem
  });
});

// ---- one-time station provisioning code (public - the code itself is the
// credential, single-use, and expires - see /api/admin/setup-codes below for
// how an admin generates a batch of these ahead of time). This is what lets
// an installer just type a short code into a brand-new install instead of
// looking up hardware IDs and hand-building sigma_123.lic / central_config.json. ----
app.post('/api/setup-code/redeem', async (req, res) => {
  const { code, mb, cpu } = req.body || {};
  if (!code || !mb || !cpu) {
    return res.status(400).json({ ok: false, error: 'code, mb, and cpu are required.' });
  }

  const normalizedCode = String(code).trim().toUpperCase();
  const row = await db.getSetupCode(normalizedCode);
  if (!row) return res.status(404).json({ ok: false, error: 'Invalid code.' });
  if (row.used_at) return res.status(410).json({ ok: false, error: 'This code has already been used.' });
  if (new Date(row.expires_at).getTime() < Date.now()) {
    return res.status(410).json({ ok: false, error: 'This code has expired - ask your admin for a new one.' });
  }

  const station = await db.getStationById(row.station_id);
  if (!station) return res.status(404).json({ ok: false, error: 'Station not found.' });

  // Deterministic, same algorithm the app itself uses - see lib/license.js.
  const licenseKey = computeSerial(mb, cpu);
  await db.setLicense(station.id, { mb, cpu, licenseKey });

  // A fresh API key, generated here and only here - this is the one and only
  // moment its plaintext ever exists. It goes straight into this response and
  // then into the app's central_config.json; no human ever sees or types it.
  const apiKey = randomToken(20);
  const { salt, hash } = hashPassword(apiKey);
  await db.setApiKey(station.id, { apiKeyHash: hash, apiKeySalt: salt });

  await db.markSetupCodeUsed(normalizedCode);

  res.json({
    ok: true,
    licenseKey,
    stationId: station.id,
    apiKey,
    centralUrl: publicBaseUrl(req),
    stationName: station.name
  });
});


// ---- one-time setup links (public - the token itself is the credential) ----
app.get('/setup/:token', async (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'setup.html'));
});

app.get('/api/setup/:token', async (req, res) => {
  const user = await db.getStationUserBySetupToken(req.params.token);
  if (!user || new Date(user.setup_token_expires_at) < new Date()) {
    return res.status(410).json({ ok: false, error: 'This setup link is invalid or has expired. Ask your admin for a new one.' });
  }
  const station = await db.getStationById(user.station_id);
  res.json({ ok: true, username: user.username, role: user.role, stationName: station ? station.name : null });
});

app.post('/api/setup/:token', async (req, res) => {
  const user = await db.getStationUserBySetupToken(req.params.token);
  if (!user || new Date(user.setup_token_expires_at) < new Date()) {
    return res.status(410).json({ ok: false, error: 'This setup link is invalid or has expired. Ask your admin for a new one.' });
  }
  const { password } = req.body || {};
  if (!password || password.length < 8) {
    return res.status(400).json({ ok: false, error: 'Password must be at least 8 characters.' });
  }
  const { salt, hash } = hashPassword(password);
  await db.completeStationUserSetup(user.id, { passwordHash: hash, passwordSalt: salt });
  res.json({ ok: true });
});

// Favicons, fonts, images, robots/sitemap and the APK download need to be reachable
// without signing in - the search-engine crawler certainly doesn't have a session.
app.use((req, res, next) => {
  if (req.path.startsWith('/icons/') || req.path.startsWith('/downloads/')
      || req.path.startsWith('/fonts/') || req.path.startsWith('/img/')
      || req.path === '/robots.txt' || req.path === '/sitemap.xml') {
    return express.static(path.join(__dirname, 'public'))(req, res, next);
  }
  next();
});

// ---- station portal (owner/attendant) ----
// Desktop-app stations have no web server of their own, so station users
// land here after login (see resolveDestination above) instead of being
// handed off externally. Every route re-derives the station from the
// session - nothing here ever trusts a client-supplied station id, so one
// station user can never see another station's data.
app.use(async (req, res, next) => {
  if (!req.path.startsWith('/portal') && !req.path.startsWith('/api/portal')) return next();

  const ctx = await resolveStationUser(req);
  if (!ctx) {
    if (req.path.startsWith('/api/')) return res.status(401).json({ ok: false, error: 'Not authenticated.' });
    return res.redirect('/');
  }
  req.stationUser = ctx.user;
  req.station = ctx.station;
  next();
});

app.get('/portal', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'portal.html'));
});

app.get('/api/portal/me', (req, res) => {
  res.json({ ok: true, username: req.stationUser.username, role: req.stationUser.role, stationName: req.station.name });
});

// Same connected-or-fall-back-to-last-known-state pattern as /api/admin/live,
// just scoped to this one station instead of every station.
app.get('/api/portal/live', async (req, res) => {
  const live = liveState.snapshot(req.station.id);
  let nozzles = live.nozzles;
  if (!nozzles.length) {
    const rows = await db.listNozzleState(req.station.id);
    nozzles = rows.map((r) => ({
      num: r.noz, status: r.status, product: r.product,
      rupees: r.rupees, litres: r.litres, rate: r.rate, totalMeter: r.total_meter
    }));
  }
  res.json({ connected: live.connected, lastEventAt: live.lastEventAt, nozzles });
});

// ?noz=03 filters to just that dispenser - the "select a particular
// dispenser" requirement. Omit it for the full station summary.
app.get('/api/portal/transactions', async (req, res) => {
  const limit = Math.min(parseInt(req.query.limit, 10) || 30, 200);
  const noz = typeof req.query.noz === 'string' && req.query.noz.trim() ? req.query.noz.trim() : null;
  res.json(await db.listStationTransactions(req.station.id, limit, noz));
});

// Remote rate-setting (#8). Owner-only, enforced HERE regardless of what the UI shows -
// req.stationUser.role is re-derived from the session on every request (see
// resolveStationUser), never trusted from anything the client sent. Responds as soon as
// the command is handed to the station's WebSocket - it does not wait for the station's
// rate_ack, which arrives separately and just updates the audit log (see the rate_ack
// case in wssStation above). No confirmation step by design (per product decision).
app.post('/api/portal/rate', async (req, res) => {
  if (req.stationUser.role !== 'owner') {
    return res.status(403).json({ ok: false, error: 'Only the station owner can change rates remotely.' });
  }

  const { noz, rate } = req.body || {};
  const rateNum = parseFloat(rate);
  if (!noz || !Number.isFinite(rateNum) || rateNum < 50) {
    return res.status(400).json({ ok: false, error: 'Enter a nozzle and a rate of at least Rs 50.' });
  }

  const ws = stationConnections.get(req.station.id);
  if (!ws || ws.readyState !== WebSocket.OPEN) {
    return res.status(409).json({ ok: false, error: 'This station is not currently connected.' });
  }

  const requestId = crypto.randomUUID();
  const newRateStr = rateNum.toFixed(2);

  const liveSnapshot = liveState.snapshot(req.station.id);
  const oldRate = liveSnapshot.nozzles.find((n) => n.num === noz)?.rate ?? null;

  try {
    await db.logRateChange({
      requestId, stationId: req.station.id, noz,
      oldRate, newRate: newRateStr, changedByUsername: req.stationUser.username
    });
  } catch (e) {
    console.error('[portal/rate] failed to write audit log:', e.message);
    // Still proceed - losing the audit row is not a reason to block the actual rate change.
  }

  ws.send(JSON.stringify({ type: 'set_rate', noz, rate: newRateStr, requestId }));
  res.json({ ok: true, requestId });
});

app.get('/api/portal/rate-history', async (req, res) => {
  if (req.stationUser.role !== 'owner') {
    return res.status(403).json({ ok: false, error: 'Only the station owner can view the rate change log.' });
  }
  res.json(await db.listRateChanges(req.station.id, 50));
});

// Cloud-side Detail/Summary records (#7) - mirrors the station app's own ReportPanel
// split, but reads from station_transactions in Turso instead of the station's local
// SQLite, and only covers sales sent since the uplink went live (no backfill, by
// deliberate choice).
function parsePortalFilters(body) {
  const products = Array.isArray(body.products) && body.products.length ? body.products : ['0', '1', '2', '3'];
  const nozzles = Array.isArray(body.nozzles) && body.nozzles.length
    ? body.nozzles
    : Array.from({ length: 24 }, (_, i) => String(i + 1).padStart(2, '0'));
  const dateStart = body.dateStart || new Date().toISOString().slice(0, 10);
  const dateEnd = body.dateEnd || new Date().toISOString().slice(0, 10);
  const hour = Number.isInteger(body.hour) ? body.hour : null;
  const minute = Number.isInteger(body.minute) ? body.minute : null;
  return { products, nozzles, dateStart, dateEnd, hour, minute };
}

app.post('/api/portal/records/detail', async (req, res) => {
  const filters = parsePortalFilters(req.body || {});
  res.json(await db.listRecordsDetail(req.station.id, filters));
});

app.post('/api/portal/records/summary', async (req, res) => {
  const filters = parsePortalFilters(req.body || {});
  res.json(await db.getRecordsSummary(req.station.id, filters));
});

app.post('/api/portal/logout', (req, res) => {
  const token = req.cookies[COOKIE_NAME];
  if (token) sessions.destroy(token);
  res.clearCookie(COOKIE_NAME, { path: '/' });
  res.json({ ok: true });
});

// ---- everything below requires an admin session ----
// (station-user sessions never reach here - they're resolved and sent
// straight to their station's own address at the login gateway above)
app.use(async (req, res, next) => {
  const user = await resolveAdmin(req);
  if (user) { req.user = user; return next(); }
  if (req.path.startsWith('/api/')) return res.status(401).json({ ok: false, error: 'Not authenticated.' });
  res.redirect('/');
});

app.use(express.static(path.join(__dirname, 'public')));

app.get('/admin', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin.html'));
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

// Generates 1-200 stations at once, each with its own one-time provisioning
// code - the batch-install case (e.g. 100 new laptops). Each station starts
// with a throwaway placeholder API key (never meant to work); the real one is
// generated fresh when the code is redeemed - see /api/setup-code/redeem.
app.post('/api/admin/setup-codes', requireAdmin, async (req, res) => {
  const { namePrefix, count } = req.body || {};
  const n = Math.min(Math.max(parseInt(count, 10) || 1, 1), 200);
  const prefix = (namePrefix && namePrefix.trim()) || 'New station';

  const results = [];
  for (let i = 0; i < n; i++) {
    const stationName = n === 1 ? prefix : `${prefix} ${i + 1}`;

    const placeholderKey = randomToken(20);
    const { salt, hash } = hashPassword(placeholderKey);
    const station = await db.createStation({ name: stationName, ownerUserId: null, address: null, apiKeyHash: hash, apiKeySalt: salt });

    const code = generateSetupCode();
    const expiresAt = new Date(Date.now() + SETUP_CODE_TTL_MS).toISOString();
    await db.createSetupCode({ code, stationId: station.id, expiresAt });

    results.push({ code, stationId: station.id, stationName });
  }

  res.json({ ok: true, codes: results });
});

app.get('/api/admin/setup-codes', requireAdmin, async (req, res) => {
  const rows = await db.listSetupCodes();
  res.json(rows.map((r) => ({
    code: r.code, stationId: r.station_id, stationName: r.station_name,
    createdAt: r.created_at, expiresAt: r.expires_at, usedAt: r.used_at
  })));
});

app.post('/api/admin/stations/:id/subscription', requireAdmin, async (req, res) => {
  const station = await db.getStationById(req.params.id);
  if (!station) return res.status(404).json({ ok: false, error: 'No such station.' });
  await db.setSubscription(station.id, !!req.body.active);
  res.json({ ok: true });
});

app.post('/api/admin/stations/:id/address', requireAdmin, async (req, res) => {
  const station = await db.getStationById(req.params.id);
  if (!station) return res.status(404).json({ ok: false, error: 'No such station.' });
  const { address } = req.body || {};
  await db.setAddress(station.id, typeof address === 'string' ? address.trim() : null);
  res.json({ ok: true });
});

app.delete('/api/admin/stations/:id', requireAdmin, async (req, res) => {
  const station = await db.getStationById(req.params.id);
  if (!station) return res.status(404).json({ ok: false, error: 'No such station.' });
  await db.deleteStation(station.id);
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

// ---- admin: live monitor ----
// Prefers the in-memory (ephemeral-included) snapshot for a station that's
// currently connected; falls back to Turso's durable snapshot (last real
// status change) for one that isn't - e.g. right after this server itself
// restarts, before any station has reconnected yet.
app.get('/api/admin/live', requireAdmin, async (req, res) => {
  const stations = await db.listStations();
  const result = [];
  for (const st of stations) {
    const live = liveState.snapshot(st.id);
    let nozzles = live.nozzles;
    if (!nozzles.length) {
      const rows = await db.listNozzleState(st.id);
      nozzles = rows.map((r) => ({
        num: r.noz, status: r.status, product: r.product,
        rupees: r.rupees, litres: r.litres, rate: r.rate, totalMeter: r.total_meter
      }));
    }
    result.push({
      stationId: st.id, stationName: st.name,
      connected: live.connected, lastEventAt: live.lastEventAt,
      nozzles
    });
  }
  res.json(result);
});

app.get('/api/admin/stations/:id/transactions', requireAdmin, async (req, res) => {
  const limit = Math.min(parseInt(req.query.limit, 10) || 20, 100);
  res.json(await db.listStationTransactions(req.params.id, limit));
});

// ---- admin: per-station login accounts (owner/attendant) ----
app.get('/api/admin/stations/:id/users', requireAdmin, async (req, res) => {
  const station = await db.getStationById(req.params.id);
  if (!station) return res.status(404).json({ ok: false, error: 'No such station.' });
  const users = await db.listStationUsers(station.id);
  res.json(users.map((u) => ({
    id: u.id, username: u.username, role: u.role,
    setupPending: !!u.setup_pending, createdAt: u.created_at
  })));
});

app.post('/api/admin/stations/:id/users', requireAdmin, async (req, res) => {
  const station = await db.getStationById(req.params.id);
  if (!station) return res.status(404).json({ ok: false, error: 'No such station.' });
  const { username, role } = req.body || {};
  if (!username || !username.trim()) return res.status(400).json({ ok: false, error: 'Username is required.' });
  const cleanRole = role === 'owner' ? 'owner' : 'attendant';

  let user;
  try {
    user = await db.createStationUser({
      stationId: station.id, username: username.trim(), role: cleanRole, ...newSetupToken()
    });
  } catch (e) {
    return res.status(400).json({ ok: false, error: `Username already exists - usernames must be unique across all stations.` });
  }
  res.json({ ok: true, user: { id: user.id, username: user.username, role: user.role }, setupUrl: `${publicBaseUrl(req)}/setup/${user.setup_token}` });
});

app.post('/api/admin/station-users/:userId/reset-password', requireAdmin, async (req, res) => {
  const user = await db.getStationUserById(req.params.userId);
  if (!user) return res.status(404).json({ ok: false, error: 'No such user.' });
  const token = newSetupToken();
  await db.setStationUserSetupToken(user.id, token);
  res.json({ ok: true, setupUrl: `${publicBaseUrl(req)}/setup/${token.setupToken}` });
});

const server = http.createServer(app);

// ---- station uplink: durable events + ephemeral live ticks ----
// Protocol (station -> central), matching lib/uplink.js in the station app:
//   -> {type:'auth', stationId, apiKey}            <- {type:'auth_ok'} | {type:'auth_fail', error}
//   -> {type:'event', id, kind:'nozzle'|'transaction', data, ts}   <- {type:'ack', id}
//   -> {type:'live', kind:'nozzle', data, ts}       (no ack, no persistence)
//   -> {type:'ping'}                                <- {type:'pong'}
const wssStation = new WebSocketServer({ server, path: '/ws/station', perMessageDeflate: false });

// stationId -> live WebSocket connection, so a remote command (e.g. a rate change from
// the portal) can be pushed down to the right station instead of only ever receiving.
const stationConnections = new Map();

wssStation.on('connection', (ws, req) => {
  console.log(`[ws/station] CONNECTION opened from ${req?.socket?.remoteAddress} url=${req?.url}`);
  let authed = false;
  let station = null;

  ws.on('error', (e) => console.log('[ws/station] socket ERROR:', e.message));
  ws.on('close', (code, reason) => console.log(`[ws/station] CLOSED code=${code} reason=${reason ? reason.toString() : ''}`));

  const send = (obj) => {
    if (ws.readyState === WebSocket.OPEN) {
      try { ws.send(JSON.stringify(obj)); } catch { /* connection is on its way out; 'close' will follow */ }
    }
  };

  // Send something back immediately, before waiting on the client's auth message.
  // A passive connection that sits silent after the 101 upgrade looks like a hung
  // backend to some edge proxies, which then kill it (observed as an instant 1006).
  send({ type: 'ready' });

  ws.on('message', async (raw) => {
    console.log(`[ws/station] message received, bytes=${raw.length}`);
    let msg;
    try { msg = JSON.parse(raw.toString()); } catch { return; }

    if (msg.type === 'auth') {
      let st = null;
      try {
        st = typeof msg.stationId === 'string' ? await db.getStationById(msg.stationId) : null;
      } catch (e) {
        console.log('[ws/station] getStationById ERROR:', e.message);
        send({ type: 'auth_fail', error: 'Server error.' });
        ws.close();
        return;
      }
      const valid = st && typeof msg.apiKey === 'string' &&
        verifyPassword(msg.apiKey, st.api_key_salt, st.api_key_hash);
      console.log(`[ws/station] auth attempt: stationId=${msg.stationId} valid=${valid}`);
      if (!valid) {
        send({ type: 'auth_fail', error: 'Invalid station credentials.' });
        ws.close();
        return;
      }
      station = st;
      authed = true;
      stationConnections.set(station.id, ws);
      liveState.setConnected(station.id, true);
      broadcastStatusChange(station.id, true);
      send({ type: 'auth_ok' });
      return;
    }

    if (!authed) return; // ignore everything until authenticated

    if (msg.type === 'ping') {
      send({ type: 'pong' });
      return;
    }

    if (msg.type === 'live' && msg.kind === 'nozzle' && msg.data) {
      liveState.updateNozzle(station.id, msg.data); // ephemeral - never touches Turso
      broadcastLiveUpdate(station.id, msg.data);
      return;
    }

    if (msg.type === 'event' && msg.id && msg.kind) {
      try {
        if (msg.kind === 'nozzle') {
          await db.upsertNozzleState(station.id, msg.id, msg.data);
          liveState.updateNozzle(station.id, msg.data);
          broadcastLiveUpdate(station.id, msg.data);
        } else if (msg.kind === 'transaction') {
          await db.insertStationTransaction(station.id, msg.id, msg.data);
        } else if (msg.kind === 'rate_change') {
          // Locally-triggered (station Update button) - already applied by the time we
          // hear about it, so log it as already-acked, same table as portal-triggered changes.
          await db.logRateChange({
            requestId: msg.id,
            stationId: station.id,
            noz: msg.data.noz,
            oldRate: msg.data.oldRate,
            newRate: msg.data.newRate,
            changedByUsername: '(station app)'
          });
          await db.markRateChangeResult(msg.id, true, 'Changed locally at the station.');
        } else {
          return; // unrecognized kind - drop silently, don't ack, don't crash
        }
      } catch (e) {
        console.error(`[ws/station] failed to process event ${msg.id}:`, e.message);
        return; // no ack - the station will retry after its own ack-timeout/reconnect
      }
      // event_id UNIQUE + INSERT OR IGNORE (transactions) and a blind
      // upsert keyed on (station, noz) (nozzle state) both make redelivery
      // safe, so acking here is correct whether this was the first
      // delivery or a resend of something already applied.
      send({ type: 'ack', id: msg.id });
      return;
    }

    if (msg.type === 'rate_ack' && msg.requestId) {
      // Fire-and-forget - the portal already got its immediate response when the
      // command was sent; this just updates the audit log with the real outcome.
      db.markRateChangeResult(msg.requestId, !!msg.ok, msg.message || null)
        .catch((e) => console.error('[ws/station] failed to record rate_ack:', e.message));
      return;
    }
  });

  ws.on('close', () => {
    if (station) {
      liveState.setConnected(station.id, false);
      broadcastStatusChange(station.id, false);
      if (stationConnections.get(station.id) === ws) stationConnections.delete(station.id);
    }
  });

  ws.on('error', () => { /* 'close' always follows */ });
});

// ---- browser-facing live push (#9: instant updates instead of 5s polling) ----
// Auth reuses the exact same session cookie the regular HTTP routes check - a WebSocket
// upgrade request still carries cookies, it just isn't run through Express's own cookie
// middleware, hence parseCookies here instead of req.cookies.
const wssBrowser = new WebSocketServer({ server, path: '/ws/live' });
const browserClients = new Map(); // ws -> { kind: 'admin' | 'station_user', stationId: string|null }

wssBrowser.on('connection', async (ws, req) => {
  console.log(`[ws/live] CONNECTION opened from ${req?.socket?.remoteAddress}`);
  const cookies = parseCookies(req.headers.cookie);
  const sess = sessions.get(cookies[COOKIE_NAME]);
  if (!sess) { console.log('[ws/live] no valid session cookie - closing'); ws.close(); return; }

  if (sess.kind === 'admin') {
    browserClients.set(ws, { kind: 'admin', stationId: null }); // admin sees every station
  } else if (sess.kind === 'station_user') {
    const su = await db.getStationUserById(sess.id);
    if (!su) { ws.close(); return; }
    browserClients.set(ws, { kind: 'station_user', stationId: su.station_id });
  } else {
    ws.close();
    return;
  }

  ws.on('close', () => browserClients.delete(ws));
  ws.on('error', () => { /* 'close' always follows */ });
});

// Called from wssStation's message handler above on every live tick and every durable
// nozzle-state event - deliberately NOT logged (console.log per packet would spam the
// server logs at several times a second per station, which is exactly what "don't show
// every packet on central" ruled out).
function broadcastLiveUpdate(stationId, nozzleData) {
  if (browserClients.size === 0) return;
  const payload = JSON.stringify({ type: 'live', stationId, data: nozzleData });
  for (const [client, info] of browserClients) {
    if (client.readyState !== WebSocket.OPEN) continue;
    if (info.kind === 'admin' || info.stationId === stationId) {
      try { client.send(payload); } catch { /* ignore - its own 'close' will clean it up */ }
    }
  }
}

// Separate from broadcastLiveUpdate: the Live/Offline indicator was only ever updated
// as a side effect of a nozzle-data message arriving, so an idle station (no fills
// happening right when someone loads the portal) could sit showing "Offline" even
// though it's genuinely connected - nothing ever told the browser otherwise. This
// broadcasts the connection state itself, independent of whether any data is flowing.
function broadcastStatusChange(stationId, connected) {
  if (browserClients.size === 0) return;
  const payload = JSON.stringify({ type: 'status', stationId, connected });
  for (const [client, info] of browserClients) {
    if (client.readyState !== WebSocket.OPEN) continue;
    if (info.kind === 'admin' || info.stationId === stationId) {
      try { client.send(payload); } catch { /* ignore - its own 'close' will clean it up */ }
    }
  }
}

db.init().then(() => {
  server.listen(PORT, '0.0.0.0', () => {
    console.log(`FuelTrack central server running at http://localhost:${PORT}`);
  });
}).catch((e) => {
  console.error('Database init failed:', e.message);
  process.exit(1);
});
