'use strict';
const path = require('path');
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
const COOKIE_NAME = 'ftc_session';
const SETUP_TOKEN_TTL_MS = 24 * 60 * 60 * 1000;

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

// Favicons and the APK download need to be reachable without signing in.
app.use((req, res, next) => {
  if (req.path.startsWith('/icons/') || req.path.startsWith('/downloads/')) {
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
  res.json({ ok: true, user: { id: user.id, username: user.username, role: user.role }, setupUrl: `${BASE_URL}/setup/${user.setup_token}` });
});

app.post('/api/admin/station-users/:userId/reset-password', requireAdmin, async (req, res) => {
  const user = await db.getStationUserById(req.params.userId);
  if (!user) return res.status(404).json({ ok: false, error: 'No such user.' });
  const token = newSetupToken();
  await db.setStationUserSetupToken(user.id, token);
  res.json({ ok: true, setupUrl: `${BASE_URL}/setup/${token.setupToken}` });
});

const server = http.createServer(app);

// ---- station uplink: durable events + ephemeral live ticks ----
// Protocol (station -> central), matching lib/uplink.js in the station app:
//   -> {type:'auth', stationId, apiKey}            <- {type:'auth_ok'} | {type:'auth_fail', error}
//   -> {type:'event', id, kind:'nozzle'|'transaction', data, ts}   <- {type:'ack', id}
//   -> {type:'live', kind:'nozzle', data, ts}       (no ack, no persistence)
//   -> {type:'ping'}                                <- {type:'pong'}
const wssStation = new WebSocketServer({ server, path: '/ws/station' });

wssStation.on('connection', (ws) => {
  let authed = false;
  let station = null;

  const send = (obj) => {
    if (ws.readyState === WebSocket.OPEN) {
      try { ws.send(JSON.stringify(obj)); } catch { /* connection is on its way out; 'close' will follow */ }
    }
  };

  ws.on('message', async (raw) => {
    let msg;
    try { msg = JSON.parse(raw.toString()); } catch { return; }

    if (msg.type === 'auth') {
      const st = typeof msg.stationId === 'string' ? await db.getStationById(msg.stationId) : null;
      const valid = st && typeof msg.apiKey === 'string' &&
        verifyPassword(msg.apiKey, st.api_key_salt, st.api_key_hash);
      if (!valid) {
        send({ type: 'auth_fail', error: 'Invalid station credentials.' });
        ws.close();
        return;
      }
      station = st;
      authed = true;
      liveState.setConnected(station.id, true);
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
      return;
    }

    if (msg.type === 'event' && msg.id && msg.kind) {
      try {
        if (msg.kind === 'nozzle') {
          await db.upsertNozzleState(station.id, msg.id, msg.data);
          liveState.updateNozzle(station.id, msg.data);
        } else if (msg.kind === 'transaction') {
          await db.insertStationTransaction(station.id, msg.id, msg.data);
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
  });

  ws.on('close', () => {
    if (station) liveState.setConnected(station.id, false);
  });

  ws.on('error', () => { /* 'close' always follows */ });
});

db.init().then(() => {
  server.listen(PORT, '0.0.0.0', () => {
    console.log(`FuelTrack central server running at http://localhost:${PORT}`);
  });
}).catch((e) => {
  console.error('Database init failed:', e.message);
  process.exit(1);
});
