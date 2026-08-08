const helmet = require('helmet');
const hpp = require('hpp');
const rateLimit = require('express-rate-limit');
const forum = require('../models/forum');
const config = require('../config');

const globalLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: config.nodeEnv === 'production' ? 90 : 400,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => forum.getClientIp(req),
  handler: (req, res) => {
    forum.logSecurityEvent({
      eventType: 'DDOS_RATE_LIMIT',
      ip: forum.getClientIp(req),
      userAgent: req.get('user-agent') || '',
      details: { path: req.originalUrl },
      blocked: true
    });
    res.status(429).render('error', {
      title: 'Too Many Requests',
      message: 'Kero-Forum DDoS protection is active. Please wait.',
      code: 429
    });
  }
});

const burstLimiter = rateLimit({
  windowMs: 5 * 1000,
  max: config.nodeEnv === 'production' ? 25 : 80,
  keyGenerator: (req) => forum.getClientIp(req),
  handler: (req, res) => {
    forum.logSecurityEvent({
      eventType: 'DOS_BURST',
      ip: forum.getClientIp(req),
      userAgent: req.get('user-agent') || '',
      details: { path: req.originalUrl },
      blocked: true
    });
    res.status(429).render('error', {
      title: 'Burst Limit',
      message: 'DoS protection: you are sending requests too quickly.',
      code: 429
    });
  }
});

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 8,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => `${forum.getClientIp(req)}|${req.body?.username || ''}`,
  handler: (req, res) => {
    forum.logSecurityEvent({
      eventType: 'BRUTE_FORCE_RATE_LIMIT',
      ip: forum.getClientIp(req),
      userAgent: req.get('user-agent') || '',
      details: { path: req.originalUrl, username: req.body?.username },
      blocked: true
    });
    res.status(429).render('error', {
      title: 'Login Attempt Limit',
      message: 'Brute force protection: please wait 15 minutes.',
      code: 429
    });
  }
});

const adminLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 40,
  keyGenerator: (req) => `${forum.getClientIp(req)}|admin|${req.session?.user?.id || 'anon'}`,
  handler: (req, res) => {
    forum.logSecurityEvent({
      eventType: 'ADMIN_RATE_LIMIT',
      ip: forum.getClientIp(req),
      userAgent: req.get('user-agent') || '',
      details: { path: req.originalUrl },
      blocked: true
    });
    res.redirect('/admin/users?error=Too many actions, please wait a bit');
  }
});

const postLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 12,
  keyGenerator: (req) => `${forum.getClientIp(req)}|${req.session?.user?.id || 'anon'}`,
  handler: (req, res) => {
    res.status(429).render('error', {
      title: 'Rate Limit',
      message: 'You are submitting too quickly.',
      code: 429
    });
  }
});

function helmetMiddleware() {
  const isProd = config.nodeEnv === 'production';
  return helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        styleSrc: ["'self'", "'unsafe-inline'"],
        scriptSrc: ["'self'"],
        imgSrc: ["'self'", 'data:'],
        connectSrc: ["'self'"],
        fontSrc: ["'self'"],
        objectSrc: ["'none'"],
        frameSrc: ["'none'"],
        frameAncestors: ["'none'"],
        baseUri: ["'self'"],
        formAction: ["'self'"],
        upgradeInsecureRequests: isProd ? [] : null
      }
    },
    crossOriginEmbedderPolicy: false,
    crossOriginOpenerPolicy: { policy: 'same-origin' },
    crossOriginResourcePolicy: { policy: 'same-origin' },
    referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
    hsts: isProd ? { maxAge: 31536000, includeSubDomains: true, preload: true } : false,
    permittedCrossDomainPolicies: { permittedPolicies: 'none' },
    originAgentCluster: true
  });
}

function bruteForceCheck(req, res, next) {
  const ip = forum.getClientIp(req);
  const username = req.body?.username || '';
  const ipFails = forum.countFailedLogins(ip, 15);
  const userFails = username ? forum.countFailedLoginsForUser(username, 15) : 0;

  if (ipFails >= 8 || userFails >= 4) {
    forum.logSecurityEvent({
      eventType: 'BRUTE_FORCE_BLOCKED',
      ip,
      userAgent: req.get('user-agent') || '',
      details: { username, ipFails, userFails },
      blocked: true
    });
    return res.status(429).render('auth/login', {
      title: 'Login',
      error: 'Brute force protection is active. Please wait 15 minutes.',
      msg: null
    });
  }
  next();
}

module.exports = {
  globalLimiter,
  burstLimiter,
  authLimiter,
  adminLimiter,
  postLimiter,
  helmetMiddleware,
  hpp,
  bruteForceCheck
};
