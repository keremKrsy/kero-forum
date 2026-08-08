const fs = require('fs');
const path = require('path');
const config = require('../config');

const dataDir = path.dirname(config.dbPath);
const files = ['kero-forum.db', 'kero-forum.db-wal', 'kero-forum.db-shm', 'sessions.db', 'sessions.db-wal', 'sessions.db-shm'];

files.forEach((f) => {
  const p = path.join(dataDir, f);
  if (fs.existsSync(p)) fs.unlinkSync(p);
});

require('../database/init');
console.log('Kero-Forum database reset complete.');
console.log('Default owner:', config.owner.username);
console.log('Start server: npm start');
