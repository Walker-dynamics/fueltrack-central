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
}

module.exports = { Db };
