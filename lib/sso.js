'use strict';
// Mints the one-time handoff token that lets a station_user land on their
// station's dashboard already logged in, instead of re-entering their
// password there. See fuelsight-web/lib/sso.js for the verifying half -
// this is deliberately the only place in the whole system that needs the
// private key; every station only ever needs the public half (see
// publicKeyPem below, synced down via /api/checkin).
const crypto = require('crypto');

const TOKEN_TTL_MS = 60 * 1000;

function loadOrGenerateSigningKeys() {
  const b64 = process.env.SSO_PRIVATE_KEY_B64;
  if (b64) {
    try {
      const pem = Buffer.from(b64, 'base64').toString('utf8');
      const privateKey = crypto.createPrivateKey(pem);
      return { privateKey, publicKey: crypto.createPublicKey(privateKey) };
    } catch (e) {
      console.warn(`[sso] SSO_PRIVATE_KEY_B64 is set but invalid (${e.message}) - generating an ephemeral signing key instead.`);
    }
  } else {
    console.warn('[sso] SSO_PRIVATE_KEY_B64 not set - generating an ephemeral signing key for this process. Station-side cached public keys will need to re-sync (next check-in) after every restart until this is set permanently.');
  }
  return crypto.generateKeyPairSync('ed25519');
}

const { privateKey, publicKey } = loadOrGenerateSigningKeys();
const publicKeyPem = publicKey.export({ type: 'spki', format: 'pem' });

function base64url(buf) {
  return buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

// One-time handoff token: proves to a station, with no round trip back
// here, that central just authenticated this exact station_user for this
// exact station, within the last minute.
function mintHandoffToken({ username, stationId }) {
  const payload = {
    sub: username,
    stationId,
    jti: crypto.randomBytes(16).toString('hex'),
    exp: Date.now() + TOKEN_TTL_MS
  };
  const payloadB64 = base64url(Buffer.from(JSON.stringify(payload)));
  const signature = crypto.sign(null, Buffer.from(payloadB64), privateKey);
  return `${payloadB64}.${base64url(signature)}`;
}

module.exports = { mintHandoffToken, publicKeyPem };
