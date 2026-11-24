'use strict';
const crypto = require('node:crypto');
function hash(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  return 'scrypt$' + salt + '$' + crypto.scryptSync(password, salt, 64).toString('hex');
}
function verify(password, stored, legacySalt) {
  if (typeof password !== 'string' || typeof stored !== 'string') return false;
  let actual;
  if (stored.startsWith('scrypt$')) {
    const parts = stored.split('$');
    if (parts.length !== 3 || !/^[a-f0-9]{32}$/.test(parts[1]) || !/^[a-f0-9]{128}$/.test(parts[2])) return false;
    actual = crypto.scryptSync(password, parts[1], 64);
    return crypto.timingSafeEqual(actual, Buffer.from(parts[2], 'hex'));
  }
  if (typeof legacySalt !== 'string') return false;
  actual = crypto.createHash('sha512').update(password + legacySalt).digest('base64');
  const a = Buffer.from(actual), b = Buffer.from(stored);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}
module.exports = { hash, verify };
