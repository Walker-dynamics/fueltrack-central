'use strict';
// Password hashing + session/login-throttle primitives. Same scrypt-based
// approach as the station app's lib/auth.js, duplicated here deliberately -
// this is meant to be a fully separate deployable project.
const crypto = require('crypto');

const SCRYPT_KEYLEN = 64;
const SESSION_TTL_MS = 30 * 24 * 60 * 60 * 1000;
const MAX_LOGIN_ATTEMPTS = 5;
const LOGIN_WINDOW_MS = 15 * 60 * 1000;

function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(password, salt, SCRYPT_KEYLEN).toString('hex');
  return { salt, hash };
}

function verifyPassword(password, salt, hash) {
  if (!salt || !hash) return false;
  const candidate = crypto.scryptSync(password, salt, SCRYPT_KEYLEN);
  const expected = Buffer.from(hash, 'hex');
  if (candidate.length !== expected.length) return false;
  return crypto.timingSafeEqual(candidate, expected);
}

function randomToken(bytes = 32) {
  return crypto.randomBytes(bytes).toString('hex');
}

class SessionStore {
  constructor() {
    this.sessions = new Map(); // token -> { kind, id, expiresAt }
  }
  // payload identifies which table/row this session belongs to, e.g.
  // { kind: 'admin', id: <users.id> } or { kind: 'station_user', id: <station_users.id> }
  create(payload) {
    const token = randomToken();
    this.sessions.set(token, { ...payload, expiresAt: Date.now() + SESSION_TTL_MS });
    return token;
  }
  get(token) {
    if (!token) return null;
    const rec = this.sessions.get(token);
    if (!rec) return null;
    if (Date.now() > rec.expiresAt) { this.sessions.delete(token); return null; }
    rec.expiresAt = Date.now() + SESSION_TTL_MS;
    return rec;
  }
  destroy(token) {
    this.sessions.delete(token);
  }
}

class LoginThrottle {
  constructor() {
    this.attempts = new Map();
  }
  isLocked(key) {
    const rec = this.attempts.get(key);
    if (!rec) return false;
    if (Date.now() > rec.resetAt) { this.attempts.delete(key); return false; }
    return rec.count >= MAX_LOGIN_ATTEMPTS;
  }
  recordFailure(key) {
    const rec = this.attempts.get(key);
    if (!rec || Date.now() > rec.resetAt) {
      this.attempts.set(key, { count: 1, resetAt: Date.now() + LOGIN_WINDOW_MS });
    } else {
      rec.count += 1;
    }
  }
  recordSuccess(key) {
    this.attempts.delete(key);
  }
}

function parseCookies(header) {
  const out = {};
  if (!header) return out;
  for (const part of header.split(';')) {
    const idx = part.indexOf('=');
    if (idx === -1) continue;
    const k = part.slice(0, idx).trim();
    const v = part.slice(idx + 1).trim();
    if (k) out[k] = decodeURIComponent(v);
  }
  return out;
}

module.exports = {
  hashPassword, verifyPassword, randomToken,
  SessionStore, LoginThrottle, parseCookies
};
