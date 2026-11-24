'use strict';
const path = require('node:path');
const crypto = require('node:crypto');
const fs = require('node:fs');
const multer = require('multer');
const maxSize = 10 * 1024 * 1024;
const directory = path.join(__dirname, '..', 'var', 'uploads');
const parse = multer({ storage: multer.memoryStorage(), limits: { fileSize: maxSize + 1, files: 1, fields: 20, fieldSize: 8192, parts: 21 } }).single('userfile');
function validate(file) {
  if (!file) return true;
  const ext = path.extname(file.originalname).toLowerCase();
  const b = file.buffer;
  if (!Buffer.isBuffer(b) || !b.length || b.length > maxSize) return false;
  if (ext === '.png') return b.length >= 8 && b.subarray(0, 8).equals(Buffer.from('89504e470d0a1a0a', 'hex'));
  if (ext === '.jpg' || ext === '.jpeg') return b.length >= 3 && b[0] === 255 && b[1] === 216 && b[2] === 255;
  if (ext === '.pdf') return b.subarray(0, 5).toString('ascii') === '%PDF-';
  if (ext === '.txt') return !b.includes(0) && !b.toString('utf8').includes('\ufffd');
  return false;
}
function save(file) {
  if (!file) return null;
  if (!validate(file)) throw new Error('INVALID_FILE');
  const ext = path.extname(file.originalname).toLowerCase();
  const filename = crypto.randomBytes(24).toString('hex') + ext;
  const originalname = path.basename(file.originalname.replace(/\\/g, '/')).replace(/[\x00-\x1f\x7f]/g, '_').slice(0, 180);
  fs.mkdirSync(directory, {recursive: true, mode: 0o700});
  const target = path.join(directory, filename);
  const fd = fs.openSync(target, 'wx', 0o600);
  try {
    fs.writeFileSync(fd, file.buffer);
    fs.closeSync(fd);
  } catch (err) {
    try { fs.closeSync(fd); } catch (_) { /* already closed */ }
    try { fs.unlinkSync(target); } catch (_) { /* report original error */ }
    throw err;
  }
  return {filename, originalname};
}
function remove(filename) {
  if (typeof filename !== 'string' || !/^[a-f0-9]{48}\.(?:png|jpe?g|pdf|txt)$/.test(filename)) return;
  try { fs.unlinkSync(path.join(directory, filename)); } catch (e) { if (e.code !== 'ENOENT') throw e; }
}
module.exports = { parse, validate, save, remove, directory, maxSize };
