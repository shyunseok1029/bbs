'use strict';
const crypto = require('node:crypto');
function csrf(req, res, next) {
  if (!req.session.csrfToken) req.session.csrfToken = crypto.randomBytes(32).toString('hex');
  res.locals.csrfToken = req.session.csrfToken;
  if (/^(GET|HEAD|OPTIONS)$/.test(req.method)) return next();
  const token = (req.body && req.body._csrf) || req.get('x-csrf-token');
  if (typeof token !== 'string' || !/^[a-f0-9]{64}$/.test(token)) return res.status(403).send('요청을 확인할 수 없습니다.');
  if (!crypto.timingSafeEqual(Buffer.from(token), Buffer.from(req.session.csrfToken))) return res.status(403).send('요청을 확인할 수 없습니다.');
  next();
}
module.exports = csrf;
