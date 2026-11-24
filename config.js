'use strict';

// Values must be supplied through the environment; never log them.
var required = ['DB_USER', 'DB_PASSWORD', 'DB_CONNECT_STRING', 'SESSION_SECRET'];
var missing = required.filter(function(name) { return !process.env[name] || !process.env[name].trim(); });
if (missing.length) throw new Error('Missing required environment variables: ' + missing.join(', '));
module.exports = {
  db: { user: process.env.DB_USER, password: process.env.DB_PASSWORD, connectString: process.env.DB_CONNECT_STRING },
  sessionSecret: process.env.SESSION_SECRET
};
