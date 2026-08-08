const express = require('express');
const { body, param, validationResult } = require('express-validator');
const router = express.Router();
const db = require('../database/init');
const forum = require('../models/forum');
const { sanitizePlain, sanitizeRich, slugify } = require('../utils/sanitize');
const { requireAuth, requireMod, audit } = require('../middleware/auth');
const { postLimiter } = require('../middleware/security');
const config = require('../config');

router.get('/', (req, res) => {
  const categories = forum.getAllCategories();
  const recentTopics = forum.getRecentTopics(8);
  const stats = forum.getStats();
  const leaderboard = forum.getLeaderboard(5);
  res.render('forum/home', { title: 'Home', categories, recentTopics, stats, leaderboard });
});

router.get('/search', (req, res) => {
  const q = sanitizePlain(req.query.q || '').trim();
  let results = { topics: [], posts: [] };
  if (q.length >= 2) {
    results = forum.searchForum(q);
  }
  res.render('forum/search', { title: 'Search', query: q, results });
});

router.get('/category/:slug', param('slug').matches(/^[a-z0-9-]+$/), (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(404).render('error', { title: '404', message: 'Category not found.', code: 404 });

  const category = forum.getCategoryBySlug(req.params.slug);
  if (!category) return res.status(404).render('error', { title: '404', message: 'Category not found.', code: 404 });

  const topics = forum.getTopicsByCategory(category.id);
  res.render('forum/category', { title: category.name, category, topics });
});

router.get('/topic/:id', param('id').isInt({ min: 1 }), (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(404).render('error', { title: '404', message: 'Topic not found.', code: 404 });

  const topic = forum.getTopicById(parseInt(req.params.id, 10));
  if (!topic) return res.status(404).render('error', { title: '404', message: 'Topic not found.', code: 404 });

  forum.incrementTopicViews(topic.id);
  const posts = forum.getPostsByTopic(topic.id);
  const bookmarked = req.session.user ? forum.isBookmarked(req.session.user.id, topic.id) : false;
  const watched = req.session.user
    ? !!db.prepare('SELECT 1 FROM topic_watches WHERE user_id = ? AND topic_id = ?').get(req.session.user.id, topic.id)
    : false;
  const postLikesRows = db.prepare(`
    SELECT p.id AS post_id, COUNT(r.user_id) AS like_count
    FROM posts p
    LEFT JOIN post_reactions r ON r.post_id = p.id AND r.reaction = 'like'
    WHERE p.topic_id = ?
    GROUP BY p.id
  `).all(topic.id);
  const postLikes = {};
  postLikesRows.forEach((row) => {
    postLikes[row.post_id] = row.like_count;
  });
  res.render('forum/topic', { title: topic.title, topic, posts, bookmarked, watched, postLikes });
});

router.get('/category/:slug/new', requireAuth, param('slug').matches(/^[a-z0-9-]+$/), (req, res) => {
  const category = forum.getCategoryBySlug(req.params.slug);
  if (!category) return res.status(404).render('error', { title: '404', message: 'Category not found.', code: 404 });
  if (category.is_locked && !res.locals.hasRole('mod')) {
    return res.status(403).render('error', { title: 'Locked', message: 'This category is locked.', code: 403 });
  }
  res.render('forum/new-topic', { title: 'New Topic', category });
});

router.post('/category/:slug/new',
  requireAuth,
  postLimiter,
  param('slug').matches(/^[a-z0-9-]+$/),
  body('title').trim().isLength({ min: 3, max: 200 }),
  body('content').trim().isLength({ min: 10, max: 10000 }),
  audit('TOPIC_CREATE', { targetType: 'topic', getTargetId: (req, res) => res.locals.createdTopicId }),
  (req, res, next) => {
    const category = forum.getCategoryBySlug(req.params.slug);
    if (!category) return res.status(404).render('error', { title: '404', message: 'Category not found.', code: 404 });

    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.render('forum/new-topic', {
        title: 'New Topic',
        category,
        error: 'Title and content must be valid.'
      });
    }

    const title = sanitizePlain(req.body.title);
    const content = sanitizeRich(req.body.content);
    const slug = slugify(title) + '-' + Date.now();

    const topic = forum.createTopic({
      categoryId: category.id,
      userId: req.session.user.id,
      title,
      slug
    });
    res.locals.createdTopicId = topic.id;

    forum.createPost({ topicId: topic.id, userId: req.session.user.id, content });
    res.redirect(`/topic/${topic.id}`);
  }
);

router.post('/topic/:id/reply',
  requireAuth,
  postLimiter,
  param('id').isInt({ min: 1 }),
  body('content').trim().isLength({ min: 2, max: 10000 }),
  audit('POST_CREATE', { targetType: 'topic' }),
  (req, res) => {
    const topicId = parseInt(req.params.id, 10);
    const topic = forum.getTopicById(topicId);
    if (!topic) return res.status(404).render('error', { title: '404', message: 'Topic not found.', code: 404 });
    if (topic.is_locked && !res.locals.hasRole('mod')) {
      return res.status(403).render('error', { title: 'Locked', message: 'This topic is locked.', code: 403 });
    }

    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.redirect(`/topic/${topicId}?error=Invalid reply`);
    }

    const content = sanitizeRich(req.body.content);
    forum.createPost({ topicId, userId: req.session.user.id, content });

    const replier = req.session.user.username;
    forum.notifyTopicParticipants(
      topicId,
      req.session.user.id,
      `${replier} replied to "${topic.title}"`,
      `/topic/${topicId}`
    );

    res.redirect(`/topic/${topicId}#bottom`);
  }
);

router.post('/topic/:id/bookmark', requireAuth, param('id').isInt(), (req, res) => {
  const topicId = parseInt(req.params.id, 10);
  if (forum.isBookmarked(req.session.user.id, topicId)) {
    forum.removeBookmark(req.session.user.id, topicId);
  } else {
    forum.addBookmark(req.session.user.id, topicId);
  }
  res.redirect(`/topic/${topicId}`);
});

router.post('/topic/:id/pin', requireMod, param('id').isInt(), audit('TOPIC_PIN', { targetType: 'topic' }), (req, res) => {
  const id = parseInt(req.params.id, 10);
  const topic = forum.getTopicById(id);
  if (!topic) return res.status(404).render('error', { title: '404', message: 'Topic not found.', code: 404 });
  forum.toggleTopicPin(id, !topic.is_pinned);
  res.redirect(`/topic/${id}`);
});

router.post('/topic/:id/lock', requireMod, param('id').isInt(), audit('TOPIC_LOCK', { targetType: 'topic' }), (req, res) => {
  const id = parseInt(req.params.id, 10);
  const topic = forum.getTopicById(id);
  if (!topic) return res.status(404).render('error', { title: '404', message: 'Topic not found.', code: 404 });
  forum.toggleTopicLock(id, !topic.is_locked);
  res.redirect(`/topic/${id}`);
});

router.post('/topic/:id/delete', requireMod, param('id').isInt(), audit('TOPIC_DELETE', { targetType: 'topic', severity: 'warn' }), (req, res) => {
  const id = parseInt(req.params.id, 10);
  const topic = forum.getTopicById(id);
  if (!topic) return res.status(404).render('error', { title: '404', message: 'Topic not found.', code: 404 });
  forum.deleteTopic(id);
  res.redirect(`/category/${topic.category_slug}`);
});

router.post('/post/:id/delete', requireMod, param('id').isInt(), audit('POST_DELETE', { targetType: 'post', severity: 'warn' }), (req, res) => {
  const post = forum.getPostById(parseInt(req.params.id, 10));
  if (!post) return res.status(404).render('error', { title: '404', message: 'Post not found.', code: 404 });
  const topicId = post.topic_id;
  forum.deletePost(post.id);
  res.redirect(`/topic/${topicId}`);
});

module.exports = router;
