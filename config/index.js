require('dotenv').config();
const path = require('path');

const sessionSecret = process.env.SESSION_SECRET || 'kero-forum-dev-secret-change-me';
if (sessionSecret.length < 32) {
  console.warn('WARNING: SESSION_SECRET should be at least 32 characters (birthday attack risk)');
}

module.exports = {
  port: parseInt(process.env.PORT, 10) || 3000,
  nodeEnv: process.env.NODE_ENV || 'development',
  sessionSecret,
  csrfSecret: process.env.CSRF_SECRET || 'kero-forum-csrf-change-me',
  trustProxy: process.env.TRUST_PROXY === '1' || process.env.TRUST_PROXY === 'true',
  dbPath: path.join(__dirname, '..', 'data', 'kero-forum.db'),
  siteName: 'Kero-Forum',
  allowedHosts: (process.env.ALLOWED_HOSTS || 'localhost:3000,127.0.0.1:3000,[::1]:3000')
    .split(',')
    .map((h) => h.trim())
    .filter(Boolean),
  roles: {
    USER: 'user',
    MOD: 'mod',
    ADMIN: 'admin',
    OWNER: 'owner'
  },
  roleHierarchy: {
    user: 0,
    mod: 1,
    admin: 2,
    owner: 3
  },
  owner: {
    username: process.env.OWNER_USERNAME || 'owner',
    email: process.env.OWNER_EMAIL || 'owner@kero-forum.local',
    password: process.env.OWNER_PASSWORD || 'KeroOwner2026!'
  },
  sessionFingerprintSalt: process.env.SESSION_FP_SALT || 'kero-forum-fp-salt-dev-change-me'
};
