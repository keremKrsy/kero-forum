const config = require('../config');
const admin = require('../models/admin');
const forum = require('../models/forum');

function attachSiteLocals(req, res, next) {
  res.locals.siteAnnouncement = admin.getSiteSetting('site_announcement') || '';
  res.locals.maintenanceMode = admin.getSiteSetting('maintenance_mode') === '1';
  res.locals.registrationOpen = admin.getSiteSetting('registration_open') !== '0';
  next();
}

function isTruthyFlag(value) {
  if (value === undefined || value === null) return false;
  if (Array.isArray(value)) return value.some((v) => isTruthyFlag(v));
  const v = String(value).toLowerCase();
  return v === '1' || v === 'on' || v === 'true' || v === 'yes';
}

function getFreshUser(req) {
  if (!req.session?.user?.id) return null;
  const fresh = forum.getUserById(req.session.user.id);
  if (!fresh || fresh.is_banned) return null;
  return fresh;
}

function isStaffUser(req) {
  const fresh = getFreshUser(req);
  if (!fresh) return false;
  const userLevel = config.roleHierarchy[fresh.role] ?? 0;
  return userLevel >= config.roleHierarchy.admin;
}

function maintenanceGuard(req, res, next) {
  if (admin.getSiteSetting('maintenance_mode') !== '1') return next();

  const path = req.path || '';
  if (path.startsWith('/css') || path.startsWith('/js')) return next();

  if (path.startsWith('/auth/login') || path === '/auth/logout') return next();
  if (path.startsWith('/auth/register')) {
    const customMessage = admin.getSiteSetting('maintenance_message') || '';
    return res.status(503).render('maintenance', {
      title: 'Maintenance',
      message: customMessage || 'Kero-Forum is under maintenance. Please check back soon.',
      code: 503
    });
  }

  if (isStaffUser(req)) return next();

  const customMessage = admin.getSiteSetting('maintenance_message') || '';
  return res.status(503).render('maintenance', {
    title: 'Maintenance',
    message: customMessage || 'Kero-Forum is under maintenance. Please check back soon.',
    code: 503
  });
}

function ipBanGuard(req, res, next) {
  const ip = forum.getClientIp(req);
  if (admin.isIpBanned(ip)) {
    forum.logSecurityEvent({
      eventType: 'IP_BAN_BLOCK',
      ip,
      userAgent: req.get('user-agent') || '',
      details: { path: req.originalUrl },
      blocked: true
    });
    return res.status(403).render('error', {
      title: 'Access Denied',
      message: 'Your IP address is banned from this forum.',
      code: 403
    });
  }
  next();
}

module.exports = {
  attachSiteLocals,
  maintenanceGuard,
  ipBanGuard,
  isTruthyFlag,
  isStaffUser
};
