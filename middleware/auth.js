const config = require('../config');
const forum = require('../models/forum');

function audit(action, options = {}) {
  return (req, res, next) => {
    res.on('finish', () => {
      if (res.statusCode >= 400) return;
      try {
        forum.logAudit({
          userId: req.session?.user?.id || null,
          action,
          targetType: options.targetType || null,
          targetId: options.getTargetId ? options.getTargetId(req) : (req.params.id ? parseInt(req.params.id, 10) : null),
          ip: forum.getClientIp(req),
          userAgent: req.get('user-agent') || '',
          details: options.getDetails ? options.getDetails(req, res) : null,
          severity: options.severity || 'info'
        });
      } catch (_) {}
    });
    next();
  };
}

function requireAuth(req, res, next) {
  if (!req.session?.user) {
    req.session.returnTo = req.originalUrl;
    return res.redirect('/auth/login?msg=You must sign in');
  }
  if (req.session.user.is_banned) {
    req.session.destroy();
    return res.redirect('/auth/login?msg=Your account has been banned');
  }
  next();
}

function requireRole(minRole) {
  return (req, res, next) => {
    if (!req.session?.user) {
      return res.redirect('/auth/login');
    }
    const userLevel = config.roleHierarchy[req.session.user.role] ?? 0;
    const requiredLevel = config.roleHierarchy[minRole] ?? 0;
    if (userLevel < requiredLevel) {
      forum.logSecurityEvent({
        eventType: 'UNAUTHORIZED_ACCESS',
        ip: forum.getClientIp(req),
        userAgent: req.get('user-agent') || '',
        details: { path: req.originalUrl, role: req.session.user.role, required: minRole },
        blocked: true
      });
      return res.status(403).render('error', {
        title: 'Access Denied',
        message: 'You do not have permission to access this page.',
        code: 403
      });
    }
    next();
  };
}

const requireMod = requireRole('mod');
const requireAdmin = requireRole('admin');
const requireOwner = requireRole('owner');

module.exports = {
  audit,
  requireAuth,
  requireRole,
  requireMod,
  requireAdmin,
  requireOwner
};
