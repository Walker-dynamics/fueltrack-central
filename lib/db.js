'use strict';
// Storage for the central server: users, the station registry, and login
// history. Uses Turso (hosted libSQL) in production - set TURSO_DATABASE_URL
// (and TURSO_AUTH_TOKEN for a remote database) - or falls back to a local
// file for dev/testing, since @libsql/client speaks the same API to both
// a `file:` URL and a `libsql://...` remote one.
const { createClient } = require('@libsql/client');
const crypto = require('crypto');

function isoNow() {
  return new Date().toISOString();
}

class Db {
  constructor({ url, authToken } = {}) {
    this.client = createClient({
      url: url || 'file:central.db',
      authToken: authToken || undefined
    });
  }

  async init() {
    await this.client.execute(`CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      password_salt TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'owner',
      created_at TEXT NOT NULL
    );`);
    await this.client.execute(`CREATE TABLE IF NOT EXISTS stations (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      owner_user_id INTEGER,
      address TEXT,
      api_key_hash TEXT NOT NULL,
      api_key_salt TEXT NOT NULL,
      subscription_active INTEGER NOT NULL DEFAULT 1,
      hardware_mb TEXT,
      hardware_cpu TEXT,
      license_key TEXT,
      created_at TEXT NOT NULL,
      last_checkin_at TEXT,
      last_checkin_ip TEXT,
      FOREIGN KEY (owner_user_id) REFERENCES users(id)
    );`);
    await this.client.execute(`CREATE TABLE IF NOT EXISTS login_history (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT NOT NULL,
      success INTEGER NOT NULL,
      ip TEXT,
      user_agent TEXT,
      created_at TEXT NOT NULL
    );`);
    // Station-app login accounts (owner/attendant) - distinct from the
    // `users` table above, which is for logging into THIS central
    // dashboard. A station_user logs into that one station's local
    // dashboard instead. password_hash/salt are NULL until the one-time
    // setup link (setup_token) has been used.
    await this.client.execute(`CREATE TABLE IF NOT EXISTS station_users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      station_id TEXT NOT NULL,
      username TEXT NOT NULL,
      password_hash TEXT,
      password_salt TEXT,
      role TEXT NOT NULL DEFAULT 'attendant',
      setup_token TEXT,
      setup_token_expires_at TEXT,
      created_at TEXT NOT NULL,
      UNIQUE(station_id, username),
      FOREIGN KEY (station_id) REFERENCES stations(id)
    );`);
    // The central login gateway (GET /) resolves a bare username to a
    // station without asking which one, so usernames must be globally
    // unique, not just per-station - the table-level UNIQUE above is kept
    // as-is (harmless, a subset of this) rather than risk a destructive
    // schema change on a table that already has real accounts in it.
    await this.client.execute(
      `CREATE UNIQUE INDEX IF NOT EXISTS idx_station_users_username ON station_users (username);`
    );
    // Durable "current state" snapshot per nozzle, upserted on every real
    // status-change event from a station (not on ephemeral live ticks - see
    // lib/liveState.js for those). A blind upsert-by-(station_id, noz) is
    // naturally idempotent, so redelivery of the same event needs no extra
    // dedup here - it just overwrites with the same values.
    await this.client.execute(`CREATE TABLE IF NOT EXISTS station_nozzle_state (
      station_id TEXT NOT NULL,
      noz TEXT NOT NULL,
      status TEXT,
      product TEXT,
      rupees REAL,
      litres REAL,
      rate REAL,
      total_meter REAL,
      event_id TEXT,
      updated_at TEXT NOT NULL,
      PRIMARY KEY (station_id, noz)
    );`);
    // Append-only, so unlike the snapshot above a redelivered event WOULD
    // double-count a sale if inserted blindly - event_id UNIQUE + INSERT OR
    // IGNORE makes it exactly-once regardless of how many times it's sent.
    await this.client.execute(`CREATE TABLE IF NOT EXISTS station_transactions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      event_id TEXT UNIQUE NOT NULL,
      station_id TEXT NOT NULL,
      noz TEXT, product TEXT, rup TEXT, ltr TEXT, rat TEXT, tltr TEXT,
      station_timestamp TEXT,
      received_at TEXT NOT NULL
    );`);
  }

  // ---- users ----
  async createUser({ email, passwordHash, passwordSalt, role = 'owner' }) {
    await this.client.execute({
      sql: `INSERT INTO users (email, password_hash, password_salt, role, created_at)
            VALUES (?, ?, ?, ?, ?)`,
      args: [email.toLowerCase(), passwordHash, passwordSalt, role, isoNow()]
    });
    return this.getUserByEmail(email);
  }

  async updateUserPassword(id, { passwordHash, passwordSalt, role }) {
    await this.client.execute({
      sql: 'UPDATE users SET password_hash = ?, password_salt = ?, role = ? WHERE id = ?',
      args: [passwordHash, passwordSalt, role, id]
    });
  }

  async getUserByEmail(email) {
    const res = await this.client.execute({
      sql: 'SELECT * FROM users WHERE email = ?',
      args: [email.toLowerCase()]
    });
    return res.rows[0] || null;
  }

  async getUserById(id) {
    const res = await this.client.execute({ sql: 'SELECT * FROM users WHERE id = ?', args: [id] });
    return res.rows[0] || null;
  }

  async listUsers() {
    const res = await this.client.execute('SELECT id, email, role, created_at FROM users ORDER BY created_at DESC');
    return res.rows;
  }

  // ---- stations ----
  async createStation({ name, ownerUserId, address, apiKeyHash, apiKeySalt }) {
    const id = 'st_' + crypto.randomBytes(6).toString('hex');
    await this.client.execute({
      sql: `INSERT INTO stations (id, name, owner_user_id, address, api_key_hash, api_key_salt, subscription_active, created_at)
            VALUES (?, ?, ?, ?, ?, ?, 1, ?)`,
      args: [id, name, ownerUserId || null, address || null, apiKeyHash, apiKeySalt, isoNow()]
    });
    return this.getStationById(id);
  }

  async getStationById(id) {
    const res = await this.client.execute({ sql: 'SELECT * FROM stations WHERE id = ?', args: [id] });
    return res.rows[0] || null;
  }

  async listStations() {
    const res = await this.client.execute(
      `SELECT s.*, u.email AS owner_email
       FROM stations s LEFT JOIN users u ON u.id = s.owner_user_id
       ORDER BY s.created_at DESC`
    );
    return res.rows;
  }

  async listStationsForOwner(ownerUserId) {
    const res = await this.client.execute({
      sql: 'SELECT * FROM stations WHERE owner_user_id = ? ORDER BY created_at DESC',
      args: [ownerUserId]
    });
    return res.rows;
  }

  async setSubscription(id, active) {
    await this.client.execute({
      sql: 'UPDATE stations SET subscription_active = ? WHERE id = ?',
      args: [active ? 1 : 0, id]
    });
  }

  async setLicense(id, { mb, cpu, licenseKey }) {
    await this.client.execute({
      sql: 'UPDATE stations SET hardware_mb = ?, hardware_cpu = ?, license_key = ? WHERE id = ?',
      args: [mb, cpu, licenseKey, id]
    });
  }

  async setAddress(id, address) {
    await this.client.execute({
      sql: 'UPDATE stations SET address = ? WHERE id = ?',
      args: [address || null, id]
    });
  }

  // Removes the station's login accounts first (no FK enforcement to rely
  // on here), then the station row itself. login_history is untouched -
  // it's keyed by email/username text, not a foreign key, so nothing to
  // orphan there.
  async deleteStation(id) {
    await this.client.execute({ sql: 'DELETE FROM station_users WHERE station_id = ?', args: [id] });
    await this.client.execute({ sql: 'DELETE FROM stations WHERE id = ?', args: [id] });
  }

  async recordCheckin(id, ip) {
    await this.client.execute({
      sql: 'UPDATE stations SET last_checkin_at = ?, last_checkin_ip = ? WHERE id = ?',
      args: [isoNow(), ip, id]
    });
  }

  // ---- login history ----
  async recordLogin({ email, success, ip, userAgent }) {
    await this.client.execute({
      sql: `INSERT INTO login_history (email, success, ip, user_agent, created_at)
            VALUES (?, ?, ?, ?, ?)`,
      args: [email, success ? 1 : 0, ip || null, userAgent || null, isoNow()]
    });
  }

  async listLoginHistory(limit = 50) {
    const res = await this.client.execute({
      sql: 'SELECT * FROM login_history ORDER BY id DESC LIMIT ?',
      args: [limit]
    });
    return res.rows;
  }

  // ---- station users (station-app login accounts) ----
  async createStationUser({ stationId, username, role, setupToken, setupTokenExpiresAt }) {
    const uname = username.toLowerCase();
    await this.client.execute({
      sql: `INSERT INTO station_users (station_id, username, role, setup_token, setup_token_expires_at, created_at)
            VALUES (?, ?, ?, ?, ?, ?)`,
      args: [stationId, uname, role, setupToken, setupTokenExpiresAt, isoNow()]
    });
    const res = await this.client.execute({
      sql: 'SELECT * FROM station_users WHERE station_id = ? AND username = ?',
      args: [stationId, uname]
    });
    return res.rows[0] || null;
  }

  async getStationUserById(id) {
    const res = await this.client.execute({ sql: 'SELECT * FROM station_users WHERE id = ?', args: [id] });
    return res.rows[0] || null;
  }

  // Global lookup (not scoped to a station) - what the central login
  // gateway uses to figure out which station a bare username belongs to.
  async getStationUserByUsername(username) {
    const res = await this.client.execute({
      sql: 'SELECT * FROM station_users WHERE username = ?',
      args: [username.toLowerCase()]
    });
    return res.rows[0] || null;
  }

  async getStationUserBySetupToken(token) {
    const res = await this.client.execute({ sql: 'SELECT * FROM station_users WHERE setup_token = ?', args: [token] });
    return res.rows[0] || null;
  }

  async listStationUsers(stationId) {
    const res = await this.client.execute({
      sql: `SELECT id, station_id, username, role, created_at,
                   (password_hash IS NULL) AS setup_pending
            FROM station_users WHERE station_id = ? ORDER BY created_at DESC`,
      args: [stationId]
    });
    return res.rows;
  }

  // Only users who've completed setup (have a usable password) - this is
  // what syncs down to the station app on check-in.
  async listStationUsersForSync(stationId) {
    const res = await this.client.execute({
      sql: `SELECT id, username, password_hash, password_salt, role
            FROM station_users WHERE station_id = ? AND password_hash IS NOT NULL`,
      args: [stationId]
    });
    return res.rows;
  }

  async setStationUserSetupToken(id, { setupToken, setupTokenExpiresAt }) {
    await this.client.execute({
      sql: 'UPDATE station_users SET setup_token = ?, setup_token_expires_at = ? WHERE id = ?',
      args: [setupToken, setupTokenExpiresAt, id]
    });
  }

  async completeStationUserSetup(id, { passwordHash, passwordSalt }) {
    await this.client.execute({
      sql: `UPDATE station_users SET password_hash = ?, password_salt = ?,
            setup_token = NULL, setup_token_expires_at = NULL WHERE id = ?`,
      args: [passwordHash, passwordSalt, id]
    });
  }

  // ---- live data uplink (durable side - see lib/liveState.js for the ephemeral side) ----
  async upsertNozzleState(stationId, eventId, state) {
    await this.client.execute({
      sql: `INSERT INTO station_nozzle_state
              (station_id, noz, status, product, rupees, litres, rate, total_meter, event_id, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(station_id, noz) DO UPDATE SET
              status = excluded.status, product = excluded.product,
              rupees = excluded.rupees, litres = excluded.litres, rate = excluded.rate,
              total_meter = excluded.total_meter, event_id = excluded.event_id,
              updated_at = excluded.updated_at`,
      args: [
        stationId, state.num, state.status || null, state.product || null,
        Number(state.rupees) || 0, Number(state.litres) || 0, Number(state.rate) || 0,
        Number(state.totalMeter) || 0, eventId, isoNow()
      ]
    });
  }

  async listNozzleState(stationId) {
    const res = await this.client.execute({
      sql: 'SELECT * FROM station_nozzle_state WHERE station_id = ? ORDER BY noz',
      args: [stationId]
    });
    return res.rows;
  }

  async insertStationTransaction(stationId, eventId, txn) {
    await this.client.execute({
      sql: `INSERT OR IGNORE INTO station_transactions
              (event_id, station_id, noz, product, rup, ltr, rat, tltr, station_timestamp, received_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      args: [eventId, stationId, txn.noz, txn.product, txn.rup, txn.ltr, txn.rat, txn.tltr, txn.timestamp || null, isoNow()]
    });
  }

  async listStationTransactions(stationId, limit = 20, noz = null) {
    const sql = noz
      ? 'SELECT * FROM station_transactions WHERE station_id = ? AND noz = ? ORDER BY id DESC LIMIT ?'
      : 'SELECT * FROM station_transactions WHERE station_id = ? ORDER BY id DESC LIMIT ?';
    const args = noz ? [stationId, noz, limit] : [stationId, limit];
    const res = await this.client.execute({ sql, args });
    return res.rows;
  }
}

module.exports = { Db };
