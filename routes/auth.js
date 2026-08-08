const express = require('express');
const bcrypt = require('bcryptjs');
const { body, validationResult } = require('express-validator');
const router = express.Router();
const forum = require('../models/forum');
const admin = require('../models/admin');
const { sanitizePlain } = require('../utils/sanitize');
const { authLimiter, bruteForceCheck } = require('../middleware/security');
const { audit } = require('../middleware/auth');

router.get('/login', (req, res) => {
  if (req.session.user) return res.redirect('/');
  res.render('auth/login', { title: 'Sign In', error: null, msg: req.query.msg || null });
});

router.get('/register', (req, res) => {
  if (req.session.user) return res.redirect('/');
  if (admin.getSiteSetting('registration_open') === '0') {
    return res.render('auth/register', { title: 'Register', error: 'Registration is currently closed.' });
  }
  res.render('auth/register', { title: 'Register', error: null });
});

router.post('/login', authLimiter, bruteForceCheck,
  body('username').trim().isLength({ min: 3, max: 32 }).matches(/^[a-zA-Z0-9_]+$/),
  body('password').isLength({ min: 6, max: 128 }),
  (req, res) => {
    if (!validationResult(req).isEmpty()) {
      return res.render('auth/login', { title: 'Sign In', error: 'Invalid credentials.', msg: null });
    }
    const username = sanitizePlain(req.body.username);
    const ip = forum.getClientIp(req);
    const user = forum.getUserByUsername(username);
    if (!user || !bcrypt.compareSync(req.body.password, user.password_hash)) {
      forum.recordLoginAttempt(ip, username, false);
      return res.render('auth/login', { title: 'Sign In', error: 'Wrong username or password.', msg: null });
    }
    if (user.is_banned) {
      return res.render('auth/login', { title: 'Sign In', error: `Account banned: ${user.ban_reason || 'No reason given'}`, msg: null });
    }
    forum.recordLoginAttempt(ip, username, true);
    forum.updateUserLogin(user.id, ip);
    const { makeFingerprint } = require('../middleware/shield');
    const userData = { id: user.id, username: user.username, email: user.email, role: user.role, avatar_color: user.avatar_color, display_name: user.display_name, is_banned: user.is_banned };
    req.session.regenerate((err) => {
      if (err) return res.render('auth/login', { title: 'Sign In', error: 'Session error.', msg: null });
      req.session.user = userData;
      req.session.fp = makeFingerprint(req, user.id);
      forum.logAudit({ userId: user.id, action: 'USER_LOGIN', ip, userAgent: req.get('user-agent') || '', severity: 'info' });
      const returnTo = req.session.returnTo || '/';
      delete req.session.returnTo;
      res.redirect(returnTo);
    });
  }
);

router.post('/register', authLimiter,
  body('username').trim().isLength({ min: 3, max: 32 }).matches(/^[a-zA-Z0-9_]+$/),
  body('email').trim().isEmail().normalizeEmail(),
  body('password').isLength({ min: 8, max: 128 }),
  body('confirmPassword').custom((v, { req }) => v === req.body.password).withMessage('Passwords do not match'),
  audit('USER_REGISTER', { severity: 'info' }),
  (req, res) => {
    if (!validationResult(req).isEmpty()) {
      const errors = validationResult(req);
      return res.render('auth/register', { title: 'Register', error: errors.array()[0].msg });
    }
    const username = sanitizePlain(req.body.username);
    const email = sanitizePlain(req.body.email);
    if (admin.getSiteSetting('registration_open') === '0') {
      return res.render('auth/register', { title: 'Register', error: 'Registration is closed.' });
    }
    if (forum.getUserByUsername(username)) {
      return res.render('auth/register', { title: 'Register', error: 'Username taken.' });
    }
    if (forum.getUserByEmail(email)) {
      return res.render('auth/register', { title: 'Register', error: 'Email already registered.' });
    }
    if (admin.isEmailDomainBlocked(email)) {
      return res.render('auth/register', { title: 'Register', error: 'Email domain not allowed.' });
    }
    const user = forum.createUser({ username, email, passwordHash: bcrypt.hashSync(req.body.password, 12) });
    const { makeFingerprint } = require('../middleware/shield');
    req.session.regenerate((err) => {
      if (err) return res.render('auth/register', { title: 'Register', error: 'Session error.' });
      req.session.user = { id: user.id, username: user.username, email: user.email, role: user.role, avatar_color: user.avatar_color, is_banned: 0 };
      req.session.fp = makeFingerprint(req, user.id);
      res.redirect('/');
    });
  }
);

router.post('/logout', audit('USER_LOGOUT'), (req, res) => {
  req.session.destroy(() => res.redirect('/'));
});

module.exports = router;
