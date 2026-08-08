const express = require('express');
const fs = require('fs');
const os = require('os');
const { body, param, query, validationResult } = require('express-validator');
const router = express.Router();
const forum = require('../models/forum');
const admin = require('../models/admin');
const { sanitizePlain, sanitizeRich, slugify } = require('../utils/sanitize');
const { requireAdmin, requireMod, requireOwner, audit } = require('../middleware/auth');
const { adminLimiter } = require('../middleware/security');
const { isTruthyFlag } = require('../middleware/site');

router.use(requireMod);
router.use(adminLimiter);

admin.runAutoLockTopics();

router.get('/', requireAdmin, (req, res) => {
  res.render('admin/dashboard', {
    title: 'Admin Dashboard',
    stats: admin.getExtendedStats(),
    recentAudit: forum.getAuditLogs(12),
    recentSecurity: forum.getSecurityEvents(12),
    msg: req.query.msg || null,
    error: req.query.error || null
  });
});

router.get('/users', requireAdmin, (req, res) => {
  const q = sanitizePlain(req.query.q || '').trim();
  const users = q ? admin.searchUsers(q, 200) : forum.getAllUsers(200);
  res.render('admin/users', {
    title: 'Users',
    users,
    isOwner: req.session.user.role === 'owner',
    searchQuery: q,
    msg: req.query.msg || null,
    error: req.query.error || null
  });
});

router.post('/users/:id/role', requireAdmin, param('id').isInt({ min: 1 }), body('role').isIn(['user', 'mod', 'admin']), (req, res) => {
  if (!validationResult(req).isEmpty()) return res.redirect('/admin/users?error=Invalid role');
  const id = parseInt(req.params.id, 10);
  const newRole = req.body.role;
  const actor = req.session.user;
  const target = forum.getUserById(id);
  if (!target || target.role === 'owner') return res.redirect('/admin/users?error=Cannot change this user');
  if (target.id === actor.id) return res.redirect('/admin/users?error=Cannot change your own role here');
  if (newRole === 'admin' && actor.role !== 'owner') return res.redirect('/admin/users?error=Only Owner can assign Admin');
  if (target.role === 'admin' && actor.role !== 'owner') return res.redirect('/admin/users?error=Only Owner can modify Admin');
  forum.updateUserRole(id, newRole);
  forum.logAudit({ userId: actor.id, action: 'USER_ROLE_CHANGE', targetType: 'user', targetId: id, ip: forum.getClientIp(req), userAgent: req.get('user-agent') || '', details: { from: target.role, to: newRole }, severity: 'critical' });
  res.redirect(`/admin/users?msg=${encodeURIComponent(target.username + ' is now ' + newRole)}`);
});

router.post('/users/:id/ban', requireAdmin, param('id').isInt({ min: 1 }), body('reason').trim().isLength({ min: 3, max: 500 }), audit('USER_BAN', { targetType: 'user', severity: 'critical' }), (req, res) => {
  const target = forum.getUserById(parseInt(req.params.id, 10));
  if (!target || target.role === 'owner') return res.redirect('/admin/users?error=Cannot ban');
  if (target.role === 'admin' && req.session.user.role !== 'owner') return res.redirect('/admin/users?error=Cannot ban Admin');
  forum.banUser(target.id, sanitizePlain(req.body.reason));
  res.redirect('/admin/users?msg=User banned');
});

router.post('/users/:id/unban', requireAdmin, param('id').isInt({ min: 1 }), audit('USER_UNBAN', { targetType: 'user' }), (req, res) => {
  forum.unbanUser(parseInt(req.params.id, 10));
  res.redirect('/admin/users?msg=Ban removed');
});

router.post('/users/:id/note', requireAdmin, param('id').isInt({ min: 1 }), body('note').trim().isLength({ min: 3, max: 2000 }), (req, res) => {
  admin.createStaffNote({ userId: parseInt(req.params.id, 10), staffId: req.session.user.id, note: sanitizePlain(req.body.note) });
  res.redirect(`/admin/users?msg=Staff note added`);
});

router.get('/categories', requireAdmin, (req, res) => {
  res.render('admin/categories', {
    title: 'Categories',
    categories: forum.getAllCategories(),
    editId: req.query.edit ? parseInt(req.query.edit, 10) : null,
    msg: req.query.msg || null,
    error: req.query.error || null
  });
});

router.post('/categories', requireAdmin, body('name').trim().isLength({ min: 2, max: 80 }), body('description').trim().isLength({ max: 500 }), audit('CATEGORY_CREATE', { targetType: 'category' }), (req, res) => {
  if (!validationResult(req).isEmpty()) return res.redirect('/admin/categories?error=Invalid category');
  const name = sanitizePlain(req.body.name);
  forum.createCategory({ name, slug: slugify(name), description: sanitizePlain(req.body.description || ''), sortOrder: parseInt(req.body.sort_order || '0', 10) || 0 });
  res.redirect('/admin/categories?msg=Category created');
});

router.post('/categories/:id/edit', requireAdmin, param('id').isInt({ min: 1 }), body('name').trim().isLength({ min: 2, max: 80 }), audit('CATEGORY_UPDATE', { targetType: 'category' }), (req, res) => {
  if (!validationResult(req).isEmpty()) return res.redirect('/admin/categories?error=Invalid data');
  const id = parseInt(req.params.id, 10);
  admin.updateCategory(id, {
    name: sanitizePlain(req.body.name),
    slug: slugify(req.body.name),
    description: sanitizePlain(req.body.description || ''),
    isLocked: req.body.is_locked === 'on',
    slowModeSeconds: parseInt(req.body.slow_mode_seconds || '0', 10) || 0,
    minPostLength: parseInt(req.body.min_post_length || '2', 10) || 2,
    postPermission: req.body.post_permission === 'mod' ? 'mod' : 'all',
    sortOrder: parseInt(req.body.sort_order || '0', 10) || 0
  });
  res.redirect('/admin/categories?msg=Category updated');
});

router.post('/categories/reorder', requireAdmin, body('order').isArray({ min: 1 }), (req, res) => {
  const items = req.body.order.map((id, index) => ({ id: parseInt(id, 10), sortOrder: index }));
  admin.reorderCategories(items);
  res.redirect('/admin/categories?msg=Order saved');
});

router.post('/categories/:id/delete', requireAdmin, param('id').isInt({ min: 1 }), audit('CATEGORY_DELETE', { targetType: 'category', severity: 'warn' }), (req, res) => {
  admin.deleteCategory(parseInt(req.params.id, 10));
  res.redirect('/admin/categories?msg=Category deleted');
});

router.post('/categories/:id/purge', requireOwner, param('id').isInt({ min: 1 }), audit('CATEGORY_PURGE', { targetType: 'category', severity: 'critical' }), (req, res) => {
  const result = admin.massDeleteTopicsInCategory(parseInt(req.params.id, 10));
  res.redirect(`/admin/categories?msg=Deleted ${result.deletedTopics} topics`);
});

router.post('/posts/:id/edit', requireMod, param('id').isInt({ min: 1 }), body('content').trim().isLength({ min: 2, max: 10000 }), audit('POST_ADMIN_EDIT', { targetType: 'post' }), (req, res) => {
  const post = forum.getPostById(parseInt(req.params.id, 10));
  if (!post) return res.redirect('/admin?error=Post not found');
  forum.updatePost(post.id, sanitizeRich(admin.applyWordFilters(req.body.content)));
  res.redirect(`/topic/${post.topic_id}#post-${post.id}`);
});

router.get('/reports', requireAdmin, (req, res) => {
  res.render('admin/reports', { title: 'Reports', reports: admin.getPendingReports(200), msg: req.query.msg || null });
});

router.post('/reports/:id/resolve', requireAdmin, param('id').isInt({ min: 1 }), body('status').isIn(['resolved', 'dismissed']), (req, res) => {
  admin.resolveReport(parseInt(req.params.id, 10), { resolverId: req.session.user.id, status: req.body.status, resolutionNote: sanitizePlain(req.body.note || '') });
  res.redirect('/admin/reports?msg=Report updated');
});

router.get('/settings', requireOwner, (req, res) => {
  const settings = {};
  admin.getAllSettings().forEach((s) => { settings[s.key] = s.value; });
  res.render('admin/settings', { title: 'Site Settings', settings, msg: req.query.msg || null, error: req.query.error || null });
});

router.post('/settings', requireOwner, audit('SITE_SETTINGS', { severity: 'critical' }), (req, res) => {
  admin.setSiteSetting('maintenance_mode', isTruthyFlag(req.body.maintenance_mode) ? '1' : '0');
  admin.setSiteSetting('maintenance_message', sanitizePlain(req.body.maintenance_message || ''));
  admin.setSiteSetting('registration_open', isTruthyFlag(req.body.registration_open) ? '1' : '0');
  admin.setSiteSetting('site_announcement', sanitizePlain(req.body.site_announcement || ''));
  admin.setSiteSetting('auto_lock_days', String(parseInt(req.body.auto_lock_days || '0', 10) || 0));
  admin.setSiteSetting('blocked_email_domains', sanitizePlain(req.body.blocked_email_domains || ''));
  const enabled = isTruthyFlag(req.body.maintenance_mode);
  res.redirect(`/admin/settings?msg=Settings saved${enabled ? ' (Maintenance ON)' : ''}`);
});

router.get('/ip-bans', requireAdmin, (req, res) => {
  res.render('admin/ip-bans', { title: 'IP Bans', bans: admin.getIpBans(200), msg: req.query.msg || null });
});

router.post('/ip-bans', requireAdmin, body('ip_address').trim().isLength({ min: 7, max: 45 }), body('reason').trim().isLength({ min: 3, max: 500 }), (req, res) => {
  admin.createIpBan({ ipAddress: sanitizePlain(req.body.ip_address), reason: sanitizePlain(req.body.reason), bannedBy: req.session.user.id, expiresAt: req.body.expires_at || null });
  res.redirect('/admin/ip-bans?msg=IP banned');
});

router.post('/ip-bans/:id/delete', requireAdmin, param('id').isInt({ min: 1 }), (req, res) => {
  admin.deleteIpBan(parseInt(req.params.id, 10));
  res.redirect('/admin/ip-bans?msg=IP ban removed');
});

router.get('/filters', requireAdmin, (req, res) => {
  res.render('admin/filters', { title: 'Word Filters', filters: admin.getWordFilters(200), msg: req.query.msg || null });
});

router.post('/filters', requireAdmin, body('pattern').trim().isLength({ min: 1, max: 120 }), (req, res) => {
  admin.createWordFilter({ pattern: sanitizePlain(req.body.pattern), replacement: sanitizePlain(req.body.replacement || '***'), createdBy: req.session.user.id });
  res.redirect('/admin/filters?msg=Filter added');
});

router.post('/filters/:id/delete', requireAdmin, param('id').isInt({ min: 1 }), (req, res) => {
  admin.deleteWordFilter(parseInt(req.params.id, 10));
  res.redirect('/admin/filters?msg=Filter removed');
});

router.get('/sessions', requireOwner, (req, res) => {
  res.render('admin/sessions', { title: 'Active Sessions', sessions: admin.listSessions(200), msg: req.query.msg || null });
});

router.post('/sessions/:sid/revoke', requireOwner, param('sid').trim().isLength({ min: 10, max: 200 }), (req, res) => {
  admin.revokeSession(req.params.sid);
  res.redirect('/admin/sessions?msg=Session revoked');
});

router.get('/health', requireAdmin, (req, res) => {
  const cfg = require('../config');
  const stat = fs.existsSync(cfg.dbPath) ? fs.statSync(cfg.dbPath) : null;
  res.render('admin/health', {
    title: 'System Health',
    stats: admin.getExtendedStats(),
    uptime: process.uptime(),
    memory: process.memoryUsage(),
    dbSize: stat ? stat.size : 0,
    nodeVersion: process.version,
    platform: os.platform()
  });
});

router.get('/backup', requireOwner, (req, res) => {
  const path = admin.createDatabaseBackup();
  res.download(path, path.split(/[\\/]/).pop());
});

router.get('/export/audit', requireAdmin, (req, res) => {
  res.setHeader('Content-Type', 'text/csv');
  res.setHeader('Content-Disposition', 'attachment; filename="audit-log.csv"');
  res.send(admin.exportAuditCsv());
});

router.get('/export/security', requireAdmin, (req, res) => {
  res.setHeader('Content-Type', 'text/csv');
  res.setHeader('Content-Disposition', 'attachment; filename="security-events.csv"');
  res.send(admin.exportSecurityCsv());
});

router.get('/audit', requireAdmin, (req, res) => {
  res.render('admin/audit', { title: 'Audit Log', logs: forum.getAuditLogs(200) });
});

router.get('/security', requireAdmin, (req, res) => {
  res.render('admin/security', { title: 'Security Events', events: forum.getSecurityEvents(200) });
});

module.exports = router;
