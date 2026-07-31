'use strict';
// Same serial-derivation algorithm as the station app's lib/license.js -
// duplicated deliberately (separate deployable project). If that algorithm
// ever changes, this file MUST change identically or issued licenses won't
// match what stations compute locally.
const crypto = require('crypto');

const PERSONAL_KEY = 'STM2times';
const ALPHABET = '23456789ABCDEFGHJKLMNPQRSTUVWXYZ';

function serialFromHash(hash) {
  let key = '';
  for (let i = 0; i < 32; i++) {
    if (i > 0 && i % 8 === 0) key += '-';
    key += ALPHABET[(hash[i] + i) % ALPHABET.length];
  }
  return key;
}

function computeSerial(mb, cpu) {
  const raw = `MB:${mb};CPU:${cpu};KEY:${PERSONAL_KEY}`;
  return serialFromHash(crypto.createHash('sha256').update(raw, 'utf8').digest());
}

module.exports = { computeSerial };
