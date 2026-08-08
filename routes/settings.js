const express = require('express');
const bcrypt = require('bcryptjs');
const { body, param, validationResult } = require('express-validator');
const router = express.Router();
const forum = require('../models/forum');
const { sanitizePlain, sanitizeRich } = require('../utils/sanitize');
const { requireAuth, audit } = require('../middleware/auth');
const { authLimiter } = require('../middleware/security');

const AVATAR_COLORS = ['#f5f0e8', '#d4c4a8', '#c45c5c', '#6b9e6b', '#5c8ec4', '#9b6bc4', '#c49b6b', '#e8d4f0'];

function syncSession(req) {
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
  }
}

function settingsData(req, activeTab) {
  return {
    title: 'Account Settings',
    activeTab,
    profile: forum.getUserById(req.session.user.id),
    avatarColors: AVATAR_COLORS,
    success: req.query.success || null,
    error: req.query.error || null
  };
}

router.get('/', requireAuth, (req, res) => res.redirect('/settings/profile'));

router.get('/profile', requireAuth, (req, res) => {
  res.render('profile/settings-profile', settingsData(req, 'profile'));
});

router.post('/profile',
  requireAuth,
  body('display_name').optional({ checkFalsy: true }).trim().isLength({ max: 50 }),
  body('bio').optional({ checkFalsy: true }).trim().isLength({ max: 500 }),
  body('signature').optional({ checkFalsy: true }).trim().isLength({ max: 300 }),
  body('location').optional({ checkFalsy: true }).trim().isLength({ max: 80 }),
  body('website').optional({ checkFalsy: true }).trim().isURL(),
  audit('PROFILE_UPDATE', { targetType: 'user' }),
  (req, res) => {
    if (!validationResult(req).isEmpty()) {
      return res.redirect('/settings/profile?error=Invalid profile information');
    }
    const avatarColor = AVATAR_COLORS.includes(req.body.avatar_color) ? req.body.avatar_color : '#f5f0e8';
    const bannerColor = /^#[0-9a-fA-F]{6}$/.test(req.body.banner_color || '') ? req.body.banner_color : '#1a1a1a';
    forum.updateUserProfile(req.session.user.id, {
      displayName: sanitizePlain(req.body.display_name || ''),
      bio: sanitizePlain(req.body.bio || ''),
      signature: sanitizeRich(req.body.signature || ''),
      location: sanitizePlain(req.body.location || ''),
      website: req.body.website ? sanitizePlain(req.body.website) : '',
      avatarColor,
      bannerColor
    });
    syncSession(req);
    res.redirect('/settings/profile?success=Profile updated');
  }
);

router.get('/username', requireAuth, (req, res) => {
  res.render('profile/settings-username', settingsData(req, 'username'));
});

router.post('/username',
  requireAuth,
  authLimiter,
  body('username').trim().isLength({ min: 3, max: 32 }).matches(/^[a-zA-Z0-9_]+$/),
  body('password').isLength({ min: 6, max: 128 }),
  audit('USERNAME_CHANGE', { targetType: 'user', severity: 'warn' }),
  (req, res) => {
    if (!validationResult(req).isEmpty()) {
      return res.redirect('/settings/username?error=Invalid username');
    }
    const username = sanitizePlain(req.body.username);
    const hash = forum.getUserPasswordHash(req.session.user.id);
    if (!bcrypt.compareSync(req.body.password, hash)) {
      return res.redirect('/settings/username?error=Current password is incorrect');
    }
    const existing = forum.getUserByUsername(username);
    if (existing && existing.id !== req.session.user.id) {
      return res.redirect('/settings/username?error=This username is already taken');
    }
    forum.updateUserUsername(req.session.user.id, username);
    syncSession(req);
    res.redirect('/settings/username?success=Username updated');
  }
);

router.get('/password', requireAuth, (req, res) => {
  res.render('profile/settings-password', settingsData(req, 'password'));
});

router.post('/password',
  requireAuth,
  authLimiter,
  body('current_password').isLength({ min: 6, max: 128 }),
  body('new_password').isLength({ min: 8, max: 128 }),
  body('confirm_password').custom((v, { req }) => v === req.body.new_password),
  audit('PASSWORD_CHANGE', { targetType: 'user', severity: 'critical' }),
  (req, res) => {
    if (!validationResult(req).isEmpty()) {
      return res.redirect('/settings/password?error=Password requirements are not met');
    }
    const hash = forum.getUserPasswordHash(req.session.user.id);
    if (!bcrypt.compareSync(req.body.current_password, hash)) {
      return res.redirect('/settings/password?error=Current password is incorrect');
    }
    forum.updateUserPassword(req.session.user.id, bcrypt.hashSync(req.body.new_password, 12));
    res.redirect('/settings/password?success=Password changed successfully');
  }
);

router.get('/account', requireAuth, (req, res) => {
  res.render('profile/settings-account', settingsData(req, 'account'));
});

router.post('/account',
  requireAuth,
  authLimiter,
  body('email').trim().isEmail().normalizeEmail(),
  body('password').isLength({ min: 6, max: 128 }),
  audit('EMAIL_CHANGE', { targetType: 'user', severity: 'warn' }),
  (req, res) => {
    if (!validationResult(req).isEmpty()) {
      return res.redirect('/settings/account?error=Invalid email address');
    }
    const hash = forum.getUserPasswordHash(req.session.user.id);
    if (!bcrypt.compareSync(req.body.password, hash)) {
      return res.redirect('/settings/account?error=Password is incorrect');
    }
    const email = sanitizePlain(req.body.email);
    const existing = forum.getUserByEmail(email);
    if (existing && existing.id !== req.session.user.id) {
      return res.redirect('/settings/account?error=This email is already in use');
    }
    forum.updateUserEmail(req.session.user.id, email);
    syncSession(req);
    res.redirect('/settings/account?success=Email updated');
  }
);

router.get('/privacy', requireAuth, (req, res) => {
  res.render('profile/settings-privacy', settingsData(req, 'privacy'));
});

router.post('/privacy',
  requireAuth,
  audit('PRIVACY_UPDATE', { targetType: 'user' }),
  (req, res) => {
    forum.updateUserPrivacy(req.session.user.id, {
      showEmail: req.body.show_email === 'on',
      notifyReplies: req.body.notify_replies === 'on',
      notifyMentions: req.body.notify_mentions === 'on',
      profilePublic: req.body.profile_public === 'on'
    });
    res.redirect('/settings/privacy?success=Privacy settings saved');
  }
);

router.get('/bookmarks', requireAuth, (req, res) => {
  res.render('profile/bookmarks', {
    title: 'Bookmarks',
    bookmarks: forum.getUserBookmarks(req.session.user.id),
    activeTab: 'bookmarks',
    profile: forum.getUserById(req.session.user.id),
    avatarColors: AVATAR_COLORS,
    success: null,
    error: null
  });
});

module.exports = router;
