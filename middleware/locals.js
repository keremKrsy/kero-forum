const config = require('../config');

const forum = require('../models/forum');

function attachLocals(req, res, next) {
  res.locals.siteName = config.siteName;
  res.locals.user = req.session?.user || null;
  res.locals.currentPath = req.path;
  res.locals.csrfToken = req.csrfToken ? req.csrfToken() : '';
  res.locals.flash = req.session.flash || null;
  res.locals.unreadNotifications = 0;
  delete req.session.flash;

  if (req.session?.user) {
    const fresh = forum.getUserById(req.session.user.id);
    if (fresh) {
      req.session.user = {
        id: fresh.id,
        username: fresh.username,
        email: fresh.email,
        role: fresh.role,
        avatar_color: fresh.avatar_color,
        display_name: fresh.display_name,
        is_banned: fresh.is_banned
      };
      res.locals.user = req.session.user;
      res.locals.unreadNotifications = forum.getUnreadNotificationCount(fresh.id);
    }
  }

  res.locals.profileUrl = (username) => `/u/${username}`;

  res.locals.hasRole = (minRole) => {
    if (!req.session?.user) return false;
    const userLevel = config.roleHierarchy[req.session.user.role] ?? 0;
    const requiredLevel = config.roleHierarchy[minRole] ?? 0;
    return userLevel >= requiredLevel;
  };

  res.locals.roleBadge = (role) => {
    const map = {
      owner: 'Owner',
      admin: 'Admin',
      mod: 'Mod',
      user: 'Member'
    };
    return map[role] || role;
  };

  next();
}

function flash(type, message) {
  return (req, res, next) => {
    req.session.flash = { type, message };
    next();
  };
}

module.exports = { attachLocals, flash };
