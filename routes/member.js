const express = require('express');
const { body, param, validationResult } = require('express-validator');
const router = express.Router();
const db = require('../database/init');
const forum = require('../models/forum');
const admin = require('../models/admin');
const { requireAuth } = require('../middleware/auth');
const { sanitizePlain, sanitizeRich } = require('../utils/sanitize');

function redirectBack(req, res, fallback) {
  return res.redirect(req.get('referer') || fallback);
}

router.post('/post/:id/react', requireAuth, param('id').isInt({ min: 1 }), body('reaction').optional().trim(), (req, res) => {
  const postId = parseInt(req.params.id, 10);
  const post = forum.getPostById(postId);
  if (!post) return redirectBack(req, res, '/?error=Post not found');
  const reaction = sanitizePlain(req.body.reaction || 'like');
  db.prepare(`
    INSERT INTO post_reactions (user_id, post_id, reaction) VALUES (?, ?, ?)
    ON CONFLICT(user_id, post_id) DO UPDATE SET reaction = excluded.reaction
  `).run(req.session.user.id, postId, reaction);
  if (post.user_id !== req.session.user.id) admin.incrementReputation(post.user_id, 1);
  return redirectBack(req, res, `/topic/${post.topic_id}`);
});

router.post('/post/:id/edit', requireAuth, param('id').isInt({ min: 1 }), body('content').trim().isLength({ min: 2, max: 10000 }), (req, res) => {
  const postId = parseInt(req.params.id, 10);
  const row = db.prepare(`SELECT p.*, (strftime('%s','now')-strftime('%s',p.created_at)) AS age FROM posts p WHERE p.id = ?`).get(postId);
  if (!row || row.user_id !== req.session.user.id) return redirectBack(req, res, '/?error=Cannot edit');
  if (row.age > 1800) return redirectBack(req, res, '/?error=Edit window is 30 minutes');
  forum.updatePost(postId, sanitizeRich(admin.applyWordFilters(req.body.content)));
  return res.redirect(`/topic/${row.topic_id}#post-${postId}`);
});

router.post('/post/:id/delete-own', requireAuth, param('id').isInt({ min: 1 }), (req, res) => {
  const post = forum.getPostById(parseInt(req.params.id, 10));
  if (!post || post.user_id !== req.session.user.id) return redirectBack(req, res, '/?error=Cannot delete');
  forum.deletePost(post.id);
  return res.redirect(`/topic/${post.topic_id}`);
});

router.post('/report', requireAuth, body('targetType').isIn(['post','topic','user']), body('targetId').isInt({ min: 1 }), body('reason').trim().isLength({ min: 3, max: 500 }), (req, res) => {
  admin.createReport({ reporterId: req.session.user.id, targetType: req.body.targetType, targetId: parseInt(req.body.targetId, 10), reason: sanitizePlain(req.body.reason), details: req.body.details ? sanitizePlain(req.body.details) : null });
  return redirectBack(req, res, '/?msg=Report submitted');
});

router.post('/topic/:id/watch', requireAuth, param('id').isInt({ min: 1 }), (req, res) => {
  const topicId = parseInt(req.params.id, 10);
  if (!forum.getTopicById(topicId)) return redirectBack(req, res, '/?error=Topic not found');
  const exists = db.prepare('SELECT 1 FROM topic_watches WHERE user_id = ? AND topic_id = ?').get(req.session.user.id, topicId);
  if (exists) db.prepare('DELETE FROM topic_watches WHERE user_id = ? AND topic_id = ?').run(req.session.user.id, topicId);
  else db.prepare('INSERT INTO topic_watches (user_id, topic_id) VALUES (?, ?)').run(req.session.user.id, topicId);
  return redirectBack(req, res, `/topic/${topicId}`);
});

router.get('/activity', requireAuth, (req, res) => {
  const userId = req.session.user.id;
  const posts = forum.getUserPosts(userId, 20);
  const topics = forum.getUserTopics(userId, 20);
  res.render('member/activity', { title: 'My Activity', posts, topics });
});

router.get('/leaderboard', (req, res) => {
  const members = db.prepare(`
    SELECT u.username, u.display_name, u.role, u.avatar_color, u.reputation,
      (SELECT COUNT(*) FROM posts p WHERE p.user_id = u.id) AS post_count
    FROM users u WHERE u.is_banned = 0
    ORDER BY u.reputation DESC, post_count DESC LIMIT 50
  `).all();
  res.render('member/leaderboard', { title: 'Members', members });
});

router.get('/export-data', requireAuth, (req, res) => {
  const userId = req.session.user.id;
  const payload = { user: forum.getUserById(userId), topics: forum.getUserTopics(userId, 1000), exportedAt: new Date().toISOString() };
  res.setHeader('Content-Type', 'application/json');
  res.setHeader('Content-Disposition', `attachment; filename="kero-export-${userId}.json"`);
  res.send(JSON.stringify(payload, null, 2));
});

module.exports = router;
