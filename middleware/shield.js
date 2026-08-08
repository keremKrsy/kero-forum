const crypto = require('crypto');
const forum = require('../models/forum');
const config = require('../config');

const SQLI_PATTERNS = [
  /(\bUNION\b[\s\S]*\bSELECT\b)/i,
  /(\bSELECT\b[\s\S]*\bFROM\b)/i,
  /(\bINSERT\b[\s\S]*\bINTO\b)/i,
  /(\bUPDATE\b[\s\S]*\bSET\b)/i,
  /(\bDELETE\b[\s\S]*\bFROM\b)/i,
  /(\bDROP\b[\s\S]*\b(TABLE|DATABASE|INDEX)\b)/i,
  /(\bALTER\b[\s\S]*\bTABLE\b)/i,
  /(\bEXEC\b|\bEXECUTE\b|\bxp_)/i,
  /(\bOR\b\s+[\d'"]+\s*=\s*[\d'"]+)/i,
  /(\bAND\b\s+[\d'"]+\s*=\s*[\d'"]+)/i,
  /(';\s*--|'\s*OR\s+'1'\s*=\s*'1|"\s*OR\s+"1"\s*=\s*"1)/i,
  /(;\s*(DROP|DELETE|UPDATE|INSERT|SELECT))/i,
  /(0x[0-9a-f]{4,})/i,
  /(\bCHAR\s*\(\s*\d+)/i,
  /(\bCONCAT\s*\()/i,
  /(\bSLEEP\s*\(\s*\d+)/i,
  /(\bBENCHMARK\s*\()/i,
  /(\/\*[\s\S]*?\*\/)/,
  /(--[^\n]*)/,
  /(@@version|information_schema|sqlite_master)/i
];

const XSS_PATTERNS = [
  /(<script[\s\S]*?>)/i,
  /(javascript\s*:)/i,
  /(vbscript\s*:)/i,
  /(data\s*:\s*text\/html)/i,
  /(on\w+\s*=\s*['"])/i,
  /(<iframe|<object|<embed|<applet|<meta|<link|<base)/i,
  /(document\.(cookie|write|location))/i,
  /(window\.(location|open))/i,
  /(\beval\s*\()/i,
  /(expression\s*\()/i,
  /(<svg[\s\S]*?onload)/i
];

const WEB_ATTACK_PATTERNS = [
  /(\$\{[\s\S]*?\})/,
  /(\{\{[\s\S]*?\}\})/,
  /(<%[\s\S]*?%>)/,
  /(\.\.\/|\.\.\\)/,
  /(%2e%2e|%252e|%c0%ae)/i,
  /(\/etc\/passwd|\/proc\/self)/i,
  /(file:\/\/|gopher:\/\/|dict:\/\/)/i,
  /(<\?php|<\?=)/i,
  /(base64_decode\s*\()/i,
  /(cmd\.exe|powershell|\/bin\/sh|\/bin\/bash)/i
];

const SKIP_BODY = new Set(['content', 'description', 'bio', 'reason', 'signature']);

function logBlock(req, eventType, sample) {
  forum.logSecurityEvent({
    eventType,
    ip: forum.getClientIp(req),
    userAgent: req.get('user-agent') || '',
    details: { path: req.originalUrl, method: req.method, sample: String(sample || '').slice(0, 120) },
    blocked: true
  });
}

function scanValue(val) {
  if (val == null || typeof val !== 'string') return null;
  const s = val;
  for (const p of SQLI_PATTERNS) if (p.test(s)) return 'SQLI';
  for (const p of XSS_PATTERNS) if (p.test(s)) return 'XSS';
  for (const p of WEB_ATTACK_PATTERNS) if (p.test(s)) return 'WEB_ATTACK';
  return null;
}

function scanObject(obj, skipKeys) {
  if (!obj || typeof obj !== 'object') return null;
  for (const [key, val] of Object.entries(obj)) {
    if (skipKeys && skipKeys.has(key)) continue;
    if (typeof val === 'string') {
      const hit = scanValue(val);
      if (hit) return hit;
    }
  }
  return null;
}

function hostGuard(req, res, next) {
  const host = (req.headers.host || '').toLowerCase().split(':')[0];
  const fullHost = (req.headers.host || '').toLowerCase();
  const ok = config.allowedHosts.some((h) => {
    const hl = h.toLowerCase();
    return fullHost === hl || host === hl.split(':')[0];
  });
  if (!ok && config.nodeEnv === 'production') {
    logBlock(req, 'DNS_SPOOF_HOST');
    return res.status(400).render('error', {
      title: 'Invalid Host',
      message: 'The host header could not be verified.',
      code: 400
    });
  }
  next();
}

function pathGuard(req, res, next) {
  const raw = req.originalUrl || req.url;
  let decoded = raw;
  try {
    decoded = decodeURIComponent(raw);
    decoded = decodeURIComponent(decoded);
  } catch (_) {
    logBlock(req, 'URL_INTERPRETATION', raw);
    return res.status(400).render('error', {
      title: 'Invalid URL',
      message: 'URL interpretation attack was blocked.',
      code: 400
    });
  }
  if (/(\.\.|%2e%2e|%252e|\\x2e|\\\\|%5c|%00)/i.test(raw) || /(\.\.|%2e)/i.test(decoded)) {
    logBlock(req, 'URL_INTERPRETATION', raw);
    return res.status(400).render('error', {
      title: 'Invalid URL',
      message: 'URL interpretation attack was blocked.',
      code: 400
    });
  }
  if (raw.length > 2048) {
    logBlock(req, 'DOS_LONG_URL', raw.slice(0, 80));
    return res.status(414).render('error', {
      title: 'URL Too Long',
      message: 'Request rejected.',
      code: 414
    });
  }
  next();
}

function methodGuard(req, res, next) {
  if (!['GET', 'HEAD', 'POST'].includes(req.method)) {
    logBlock(req, 'WEB_ATTACK_METHOD');
    return res.status(405).render('error', {
      title: 'Forbidden Method',
      message: 'This HTTP method is not supported.',
      code: 405
    });
  }
  next();
}

function malwareGuard(req, res, next) {
  if (/\.(exe|bat|cmd|com|scr|pif|msi|dll|vbs|js\.download|php\d?)(\?|$)/i.test(req.path)) {
    logBlock(req, 'MALWARE_PATH');
    return res.status(403).render('error', {
      title: 'Blocked',
      message: 'Malicious file request was blocked.',
      code: 403
    });
  }
  next();
}

function driveByGuard(req, res, next) {
  const ref = req.get('referer') || '';
  if (ref && /^https?:\/\//i.test(ref)) {
    try {
      const refHost = new URL(ref).host.toLowerCase();
      const reqHost = (req.headers.host || '').toLowerCase();
      if (refHost && reqHost && refHost !== reqHost && req.method === 'POST') {
        const ok = config.allowedHosts.some((h) => refHost === h.toLowerCase().split(':')[0]);
        if (!ok && config.nodeEnv === 'production') {
          logBlock(req, 'DRIVE_BY_REFERER', ref);
        }
      }
    } catch (_) {}
  }
  next();
}

function inputShield(req, res, next) {
  const qHit = scanObject(req.query);
  if (qHit) {
    logBlock(req, qHit === 'SQLI' ? 'SQLI_QUERY' : qHit === 'XSS' ? 'XSS_QUERY' : 'WEB_ATTACK_QUERY', JSON.stringify(req.query));
    return res.status(400).render('error', {
      title: 'Invalid Request',
      message: 'Security filter blocked the request.',
      code: 400
    });
  }
  const pHit = scanObject(req.params);
  if (pHit) {
    logBlock(req, 'WEB_ATTACK_PARAM', JSON.stringify(req.params));
    return res.status(400).render('error', {
      title: 'Invalid Request',
      message: 'Security filter blocked the request.',
      code: 400
    });
  }
  const bHit = scanObject(req.body, SKIP_BODY);
  if (bHit) {
    logBlock(req, bHit === 'SQLI' ? 'SQLI_BODY' : bHit === 'XSS' ? 'XSS_BODY' : 'WEB_ATTACK_BODY', JSON.stringify(req.body));
    return res.status(400).render('error', {
      title: 'Invalid Request',
      message: 'Security filter blocked the request.',
      code: 400
    });
  }
  next();
}

function sessionFingerprint(req, res, next) {
  if (!req.session?.user) return next();
  const fp = crypto
    .createHmac('sha256', config.sessionFingerprintSalt)
    .update(`${forum.getClientIp(req)}|${req.get('user-agent') || ''}|${req.session.user.id}`)
    .digest('hex');
  if (req.session.fp && req.session.fp !== fp) {
    logBlock(req, 'SESSION_HIJACK');
    return req.session.destroy(() => {
      res.redirect('/auth/login?msg=Session security violation detected');
    });
  }
  req.session.fp = fp;
  next();
}

function sensitiveNoCache(req, res, next) {
  if (req.path.startsWith('/admin') || req.path.startsWith('/settings') || req.path.startsWith('/auth')) {
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, private');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '0');
  }
  next();
}

function insiderAudit(req, res, next) {
  if (req.session?.user && (req.path.startsWith('/admin') || req.path.startsWith('/settings'))) {
    const level = config.roleHierarchy[req.session.user.role] ?? 0;
    if (level >= config.roleHierarchy.admin && req.method === 'POST') {
      forum.logAudit({
        userId: req.session.user.id,
        action: 'INSIDER_POST',
        targetType: 'route',
        ip: forum.getClientIp(req),
        userAgent: req.get('user-agent') || '',
        details: { path: req.originalUrl },
        severity: level >= config.roleHierarchy.owner ? 'info' : 'warn'
      });
    }
  }
  next();
}

function requestTimeout(ms = 30000) {
  return (req, res, next) => {
    req.setTimeout(ms, () => {
      if (!res.headersSent) {
        logBlock(req, 'DOS_TIMEOUT');
        res.status(408).render('error', {
          title: 'Request Timeout',
          message: 'Request timed out.',
          code: 408
        });
      }
    });
    next();
  };
}

function makeFingerprint(req, userId) {
  return crypto
    .createHmac('sha256', config.sessionFingerprintSalt)
    .update(`${forum.getClientIp(req)}|${req.get('user-agent') || ''}|${userId}`)
    .digest('hex');
}

module.exports = {
  hostGuard,
  pathGuard,
  methodGuard,
  malwareGuard,
  driveByGuard,
  inputShield,
  sessionFingerprint,
  sensitiveNoCache,
  insiderAudit,
  requestTimeout,
  makeFingerprint,
  logBlock
};
