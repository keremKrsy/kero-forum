require('dotenv').config();
const path = require('path');
const express = require('express');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);
const csrf = require('csurf');
const config = require('./config');
const { attachLocals } = require('./middleware/locals');
const {
  globalLimiter,
  burstLimiter,
  helmetMiddleware,
  hpp
} = require('./middleware/security');
const {
  hostGuard,
  pathGuard,
  methodGuard,
  malwareGuard,
  driveByGuard,
  inputShield,
  sessionFingerprint,
  sensitiveNoCache,
  insiderAudit,
  requestTimeout
} = require('./middleware/shield');
const { attachSiteLocals, maintenanceGuard, ipBanGuard } = require('./middleware/site');

require('./database/init');

const app = express();
app.disable('x-powered-by');

if (config.trustProxy) {
  app.set('trust proxy', 1);
}

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

app.use(requestTimeout(30000));
app.use(hostGuard);
app.use(pathGuard);
app.use(methodGuard);
app.use(malwareGuard);
app.use(helmetMiddleware());
app.use(hpp());
app.use(burstLimiter);
app.use(globalLimiter);
app.use(express.static(path.join(__dirname, 'public'), {
  maxAge: config.nodeEnv === 'production' ? '1d' : 0,
  dotfiles: 'deny'
}));
app.use(express.urlencoded({ extended: false, limit: '24kb' }));
app.use(express.json({ limit: '16kb', strict: true }));

app.use(session({
  store: new SQLiteStore({ db: 'sessions.db', dir: path.join(__dirname, 'data') }),
  secret: config.sessionSecret,
  name: 'kero.sid',
  resave: false,
  saveUninitialized: false,
  rolling: true,
  cookie: {
    httpOnly: true,
    secure: config.nodeEnv === 'production',
    sameSite: 'strict',
    maxAge: 7 * 24 * 60 * 60 * 1000,
    path: '/'
  }
}));

app.use(csrf());
app.use(driveByGuard);
app.use(sessionFingerprint);
app.use(sensitiveNoCache);
app.use(ipBanGuard);
app.use(attachSiteLocals);
app.use(attachLocals);
app.use(maintenanceGuard);
app.use(insiderAudit);
app.use(inputShield);

app.use('/', require('./routes/forum'));
app.use('/auth', require('./routes/auth'));
app.use('/admin', require('./routes/admin'));
app.use('/member', require('./routes/member'));
app.use('/u', require('./routes/profile'));
app.use('/settings', require('./routes/settings'));
app.use('/notifications', require('./routes/notifications'));

app.use((err, req, res, next) => {
  if (err.code === 'EBADCSRFTOKEN') {
    const forum = require('./models/forum');
    const { getClientIp } = require('./utils/sanitize');
    forum.logSecurityEvent({
      eventType: 'CSRF_VIOLATION',
      ip: getClientIp(req),
      userAgent: req.get('user-agent') || '',
      details: { path: req.originalUrl },
      blocked: true
    });
    return res.status(403).render('error', {
      title: 'CSRF Error',
      message: 'Session validation failed. Refresh the page and try again.',
      code: 403
    });
  }
  if (err.type === 'entity.too.large') {
    return res.status(413).render('error', {
      title: 'Request Too Large',
      message: 'DoS protection: request size limit exceeded.',
      code: 413
    });
  }
  console.error(err);
  res.status(500).render('error', {
    title: 'Server Error',
    message: 'An unexpected error occurred.',
    code: 500
  });
});

app.use((req, res) => {
  res.status(404).render('error', {
    title: '404',
    message: 'Page not found.',
    code: 404
  });
});

app.listen(config.port, () => {
  console.log(`\n  ╔══════════════════════════════════════╗`);
  console.log(`  ║         Kero-Forum v3.0.0            ║`);
  console.log(`  ║  http://localhost:${config.port}              ║`);
  console.log(`  ╚══════════════════════════════════════╝\n`);
});
