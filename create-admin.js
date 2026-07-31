'use strict';
// Bootstraps the first admin account (or promotes/resets an existing one).
// Usage: node create-admin.js <email> <password>
const { Db } = require('./lib/db');
const { hashPassword } = require('./lib/auth');

const [email, password] = process.argv.slice(2);
if (!email || !password) {
  console.error('Usage: node create-admin.js <email> <password>');
  process.exit(1);
}
if (password.length < 8) {
  console.error('Password must be at least 8 characters.');
  process.exit(1);
}

async function main() {
  const db = new Db({ url: process.env.TURSO_DATABASE_URL, authToken: process.env.TURSO_AUTH_TOKEN });
  await db.init();
  const { salt, hash } = hashPassword(password);
  const existing = await db.getUserByEmail(email);

  if (existing) {
    await db.updateUserPassword(existing.id, { passwordHash: hash, passwordSalt: salt, role: 'admin' });
    console.log(`Updated existing user ${email} -> admin, password reset.`);
  } else {
    await db.createUser({ email, passwordHash: hash, passwordSalt: salt, role: 'admin' });
    console.log(`Created admin user ${email}.`);
  }
}

main().catch((e) => { console.error(e); process.exit(1); });
