const db = require('../database/init');
const { getClientIp } = require('../utils/sanitize');

function getUserById(id) {
  return db.prepare(`
    SELECT id, username, email, role, avatar_color, banner_color, bio, display_name, signature,
           location, website, show_email, notify_replies, notify_mentions, profile_public, reputation,
           is_banned, ban_reason, last_login_at, last_ip, created_at, updated_at
    FROM users WHERE id = ?
  `).get(id);
}

function getUserPasswordHash(id) {
  return db.prepare('SELECT password_hash FROM users WHERE id = ?').get(id)?.password_hash;
}

function getPublicProfile(username) {
  return db.prepare(`
    SELECT id, username, role, avatar_color, bio, display_name, signature,
           location, website, show_email, email, profile_public, created_at, last_login_at
    FROM users WHERE username = ? COLLATE NOCASE AND is_banned = 0
  `).get(username);
}

function getUserStats(userId) {
  const topics = db.prepare('SELECT COUNT(*) as c FROM topics WHERE user_id = ?').get(userId).c;
  const posts = db.prepare('SELECT COUNT(*) as c FROM posts WHERE user_id = ?').get(userId).c;
  const views = db.prepare(`
    SELECT COALESCE(SUM(t.view_count), 0) as v FROM topics t WHERE t.user_id = ?
  `).get(userId).v;
  const bookmarks = db.prepare('SELECT COUNT(*) as c FROM bookmarks WHERE user_id = ?').get(userId).c;
  return { topics, posts, views, bookmarks };
}

function getUserTopics(userId, limit = 10) {
  return db.prepare(`
    SELECT t.*, c.name as category_name, c.slug as category_slug,
      (SELECT COUNT(*) FROM posts p WHERE p.topic_id = t.id) as reply_count
    FROM topics t
    JOIN categories c ON c.id = t.category_id
    WHERE t.user_id = ?
    ORDER BY t.created_at DESC LIMIT ?
  `).all(userId, limit);
}

function getUserPosts(userId, limit = 10) {
  return db.prepare(`
    SELECT p.*, t.title as topic_title, t.id as topic_id
    FROM posts p
    JOIN topics t ON t.id = p.topic_id
    WHERE p.user_id = ?
    ORDER BY p.created_at DESC LIMIT ?
  `).all(userId, limit);
}

function updateUserProfile(id, { displayName, bio, signature, location, website, avatarColor, bannerColor }) {
  db.prepare(`
    UPDATE users SET display_name = ?, bio = ?, signature = ?, location = ?,
      website = ?, avatar_color = ?, banner_color = ?, updated_at = datetime('now')
    WHERE id = ?
  `).run(displayName || '', bio || '', signature || '', location || '', website || '', avatarColor || '#f5f0e8', bannerColor || '#1a1a1a', id);
}

function updateUserUsername(id, username) {
  db.prepare("UPDATE users SET username = ?, updated_at = datetime('now') WHERE id = ?").run(username, id);
}

function updateUserEmail(id, email) {
  db.prepare("UPDATE users SET email = ?, updated_at = datetime('now') WHERE id = ?").run(email, id);
}

function updateUserPassword(id, passwordHash) {
  db.prepare("UPDATE users SET password_hash = ?, updated_at = datetime('now') WHERE id = ?").run(passwordHash, id);
}

function updateUserPrivacy(id, { showEmail, notifyReplies, notifyMentions, profilePublic }) {
  db.prepare(`
    UPDATE users SET show_email = ?, notify_replies = ?, notify_mentions = ?,
      profile_public = ?, updated_at = datetime('now')
    WHERE id = ?
  `).run(showEmail ? 1 : 0, notifyReplies ? 1 : 0, notifyMentions ? 1 : 0, profilePublic ? 1 : 0, id);
}

function searchForum(query, limit = 30) {
  const q = `%${query}%`;
  const topics = db.prepare(`
    SELECT t.id, t.title, t.created_at, u.username, c.name as category_name, c.slug as category_slug,
      'topic' as result_type
    FROM topics t
    JOIN users u ON u.id = t.user_id
    JOIN categories c ON c.id = t.category_id
    WHERE t.title LIKE ? OR t.slug LIKE ?
    ORDER BY t.updated_at DESC LIMIT ?
  `).all(q, q, limit);
  const posts = db.prepare(`
    SELECT p.id, p.content, p.created_at, t.id as topic_id, t.title as topic_title,
      u.username, 'post' as result_type
    FROM posts p
    JOIN topics t ON t.id = p.topic_id
    JOIN users u ON u.id = p.user_id
    WHERE p.content LIKE ?
    ORDER BY p.created_at DESC LIMIT ?
  `).all(q, limit);
  return { topics, posts };
}

function getLeaderboard(limit = 10) {
  return db.prepare(`
    SELECT u.id, u.username, u.role, u.avatar_color, u.display_name,
      (SELECT COUNT(*) FROM posts p WHERE p.user_id = u.id) as post_count,
      (SELECT COUNT(*) FROM topics t WHERE t.user_id = u.id) as topic_count
    FROM users u
    WHERE u.is_banned = 0
    ORDER BY post_count DESC, topic_count DESC
    LIMIT ?
  `).all(limit);
}

function addBookmark(userId, topicId) {
  db.prepare('INSERT OR IGNORE INTO bookmarks (user_id, topic_id) VALUES (?, ?)').run(userId, topicId);
}

function removeBookmark(userId, topicId) {
  db.prepare('DELETE FROM bookmarks WHERE user_id = ? AND topic_id = ?').run(userId, topicId);
}

function isBookmarked(userId, topicId) {
  return !!db.prepare('SELECT 1 FROM bookmarks WHERE user_id = ? AND topic_id = ?').get(userId, topicId);
}

function getUserBookmarks(userId, limit = 20) {
  return db.prepare(`
    SELECT t.*, u.username, c.name as category_name, c.slug as category_slug, b.created_at as bookmarked_at
    FROM bookmarks b
    JOIN topics t ON t.id = b.topic_id
    JOIN users u ON u.id = t.user_id
    JOIN categories c ON c.id = t.category_id
    WHERE b.user_id = ?
    ORDER BY b.created_at DESC LIMIT ?
  `).all(userId, limit);
}

function createNotification(userId, type, message, link) {
  const user = getUserById(userId);
  if (!user) return;
  if (type === 'reply' && !user.notify_replies) return;
  db.prepare(`
    INSERT INTO notifications (user_id, type, message, link) VALUES (?, ?, ?, ?)
  `).run(userId, type, message, link || null);
}

function getNotifications(userId, limit = 30) {
  return db.prepare(`
    SELECT * FROM notifications WHERE user_id = ? ORDER BY created_at DESC LIMIT ?
  `).all(userId, limit);
}

function getUnreadNotificationCount(userId) {
  return db.prepare('SELECT COUNT(*) as c FROM notifications WHERE user_id = ? AND is_read = 0').get(userId).c;
}

function markNotificationRead(id, userId) {
  db.prepare('UPDATE notifications SET is_read = 1 WHERE id = ? AND user_id = ?').run(id, userId);
}

function markAllNotificationsRead(userId) {
  db.prepare('UPDATE notifications SET is_read = 1 WHERE user_id = ?').run(userId);
}

function notifyTopicParticipants(topicId, excludeUserId, message, link) {
  const topic = getTopicById(topicId);
  if (!topic) return;
  const participants = db.prepare(`
    SELECT DISTINCT user_id FROM posts WHERE topic_id = ? AND user_id != ?
  `).all(topicId, excludeUserId);
  const notified = new Set();
  if (topic.user_id !== excludeUserId) {
    createNotification(topic.user_id, 'reply', message, link);
    notified.add(topic.user_id);
  }
  participants.forEach(p => {
    if (!notified.has(p.user_id)) {
      createNotification(p.user_id, 'reply', message, link);
      notified.add(p.user_id);
    }
  });
}

function getUserByUsername(username) {
  return db.prepare('SELECT * FROM users WHERE username = ? COLLATE NOCASE').get(username);
}

function getUserByEmail(email) {
  return db.prepare('SELECT * FROM users WHERE email = ? COLLATE NOCASE').get(email);
}

function createUser({ username, email, passwordHash, role = 'user' }) {
  const result = db.prepare(`
    INSERT INTO users (username, email, password_hash, role)
    VALUES (?, ?, ?, ?)
  `).run(username, email, passwordHash, role);
  return getUserById(result.lastInsertRowid);
}

function updateUserLogin(id, ip) {
  db.prepare(`
    UPDATE users SET last_login_at = datetime('now'), last_ip = ?, updated_at = datetime('now')
    WHERE id = ?
  `).run(ip, id);
}

function updateUserRole(id, role) {
  db.prepare("UPDATE users SET role = ?, updated_at = datetime('now') WHERE id = ?").run(role, id);
}

function banUser(id, reason) {
  db.prepare(`
    UPDATE users SET is_banned = 1, ban_reason = ?, updated_at = datetime('now') WHERE id = ?
  `).run(reason, id);
}

function unbanUser(id) {
  db.prepare(`
    UPDATE users SET is_banned = 0, ban_reason = NULL, updated_at = datetime('now') WHERE id = ?
  `).run(id);
}

function getAllCategories() {
  return db.prepare(`
    SELECT c.*,
      (SELECT COUNT(*) FROM topics t WHERE t.category_id = c.id) as topic_count,
      (SELECT MAX(p.created_at) FROM posts p
       JOIN topics t ON t.id = p.topic_id WHERE t.category_id = c.id) as last_activity
    FROM categories c
    ORDER BY c.sort_order ASC, c.name ASC
  `).all();
}

function getCategoryBySlug(slug) {
  return db.prepare('SELECT * FROM categories WHERE slug = ?').get(slug);
}

function getCategoryById(id) {
  return db.prepare('SELECT * FROM categories WHERE id = ?').get(id);
}

function createCategory({ name, slug, description, sortOrder = 0 }) {
  const result = db.prepare(`
    INSERT INTO categories (name, slug, description, sort_order) VALUES (?, ?, ?, ?)
  `).run(name, slug, description, sortOrder);
  return getCategoryById(result.lastInsertRowid);
}

function getTopicsByCategory(categoryId, limit = 50, offset = 0) {
  return db.prepare(`
    SELECT t.*, u.username, u.role as author_role,
      (SELECT COUNT(*) FROM posts p WHERE p.topic_id = t.id) as reply_count,
      (SELECT p.created_at FROM posts p WHERE p.topic_id = t.id ORDER BY p.created_at DESC LIMIT 1) as last_post_at,
      (SELECT u2.username FROM posts p2 JOIN users u2 ON u2.id = p2.user_id
       WHERE p2.topic_id = t.id ORDER BY p2.created_at DESC LIMIT 1) as last_poster
    FROM topics t
    JOIN users u ON u.id = t.user_id
    WHERE t.category_id = ?
    ORDER BY t.is_pinned DESC, t.updated_at DESC
    LIMIT ? OFFSET ?
  `).all(categoryId, limit, offset);
}

function getTopicById(id) {
  return db.prepare(`
    SELECT t.*, u.username, u.role as author_role, c.name as category_name, c.slug as category_slug
    FROM topics t
    JOIN users u ON u.id = t.user_id
    JOIN categories c ON c.id = t.category_id
    WHERE t.id = ?
  `).get(id);
}

function createTopic({ categoryId, userId, title, slug }) {
  const result = db.prepare(`
    INSERT INTO topics (category_id, user_id, title, slug) VALUES (?, ?, ?, ?)
  `).run(categoryId, userId, title, slug);
  return getTopicById(result.lastInsertRowid);
}

function incrementTopicViews(id) {
  db.prepare('UPDATE topics SET view_count = view_count + 1 WHERE id = ?').run(id);
}

function toggleTopicPin(id, pinned) {
  db.prepare('UPDATE topics SET is_pinned = ?, updated_at = datetime(\'now\') WHERE id = ?').run(pinned ? 1 : 0, id);
}

function toggleTopicLock(id, locked) {
  db.prepare('UPDATE topics SET is_locked = ?, updated_at = datetime(\'now\') WHERE id = ?').run(locked ? 1 : 0, id);
}

function deleteTopic(id) {
  db.prepare('DELETE FROM topics WHERE id = ?').run(id);
}

function getPostsByTopic(topicId) {
  return db.prepare(`
    SELECT p.*, u.username, u.role as author_role, u.avatar_color
    FROM posts p
    JOIN users u ON u.id = p.user_id
    WHERE p.topic_id = ?
    ORDER BY p.created_at ASC
  `).all(topicId);
}

function createPost({ topicId, userId, content }) {
  const result = db.prepare(`
    INSERT INTO posts (topic_id, user_id, content) VALUES (?, ?, ?)
  `).run(topicId, userId, content);
  db.prepare("UPDATE topics SET updated_at = datetime('now') WHERE id = ?").run(topicId);
  return db.prepare('SELECT * FROM posts WHERE id = ?').get(result.lastInsertRowid);
}

function updatePost(id, content) {
  db.prepare(`
    UPDATE posts SET content = ?, is_edited = 1, edited_at = datetime('now') WHERE id = ?
  `).run(content, id);
}

function deletePost(id) {
  db.prepare('DELETE FROM posts WHERE id = ?').run(id);
}

function getPostById(id) {
  return db.prepare('SELECT * FROM posts WHERE id = ?').get(id);
}

function getRecentTopics(limit = 10) {
  return db.prepare(`
    SELECT t.*, u.username, c.name as category_name, c.slug as category_slug
    FROM topics t
    JOIN users u ON u.id = t.user_id
    JOIN categories c ON c.id = t.category_id
    ORDER BY t.updated_at DESC LIMIT ?
  `).all(limit);
}

function getStats() {
  return {
    users: db.prepare('SELECT COUNT(*) as c FROM users').get().c,
    topics: db.prepare('SELECT COUNT(*) as c FROM topics').get().c,
    posts: db.prepare('SELECT COUNT(*) as c FROM posts').get().c,
    categories: db.prepare('SELECT COUNT(*) as c FROM categories').get().c,
    banned: db.prepare('SELECT COUNT(*) as c FROM users WHERE is_banned = 1').get().c
  };
}

function getAllUsers(limit = 100, offset = 0) {
  return db.prepare(`
    SELECT id, username, email, role, is_banned, last_login_at, last_ip, created_at
    FROM users ORDER BY created_at DESC LIMIT ? OFFSET ?
  `).all(limit, offset);
}

function logAudit({ userId, action, targetType, targetId, ip, userAgent, details, severity = 'info' }) {
  db.prepare(`
    INSERT INTO audit_logs (user_id, action, target_type, target_id, ip_address, user_agent, details, severity)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `).run(userId, action, targetType, targetId, ip, userAgent, details ? JSON.stringify(details) : null, severity);
}

function getAuditLogs(limit = 100, offset = 0) {
  return db.prepare(`
    SELECT a.*, u.username
    FROM audit_logs a
    LEFT JOIN users u ON u.id = a.user_id
    ORDER BY a.created_at DESC LIMIT ? OFFSET ?
  `).all(limit, offset).map(row => ({
    ...row,
    details: row.details ? JSON.parse(row.details) : null
  }));
}

function logSecurityEvent({ eventType, ip, userAgent, details, blocked = 0 }) {
  db.prepare(`
    INSERT INTO security_events (event_type, ip_address, user_agent, details, blocked)
    VALUES (?, ?, ?, ?, ?)
  `).run(eventType, ip, userAgent, details ? JSON.stringify(details) : null, blocked ? 1 : 0);
}

function getSecurityEvents(limit = 100, offset = 0) {
  return db.prepare(`
    SELECT * FROM security_events ORDER BY created_at DESC LIMIT ? OFFSET ?
  `).all(limit, offset).map(row => ({
    ...row,
    details: row.details ? JSON.parse(row.details) : null
  }));
}

function recordLoginAttempt(ip, username, success) {
  db.prepare(`
    INSERT INTO login_attempts (ip_address, username, success) VALUES (?, ?, ?)
  `).run(ip, username, success ? 1 : 0);
}

function countFailedLogins(ip, minutes = 15) {
  return db.prepare(`
    SELECT COUNT(*) as c FROM login_attempts
    WHERE ip_address = ? AND success = 0
    AND created_at > datetime('now', ?)
  `).get(ip, `-${minutes} minutes`).c;
}

function countFailedLoginsForUser(username, minutes = 15) {
  return db.prepare(`
    SELECT COUNT(*) as c FROM login_attempts
    WHERE username = ? COLLATE NOCASE AND success = 0
    AND created_at > datetime('now', ?)
  `).get(username, `-${minutes} minutes`).c;
}

module.exports = {
  getUserById,
  getUserByUsername,
  getUserByEmail,
  createUser,
  updateUserLogin,
  updateUserRole,
  banUser,
  unbanUser,
  getAllCategories,
  getCategoryBySlug,
  getCategoryById,
  createCategory,
  getTopicsByCategory,
  getTopicById,
  createTopic,
  incrementTopicViews,
  toggleTopicPin,
  toggleTopicLock,
  deleteTopic,
  getPostsByTopic,
  createPost,
  updatePost,
  deletePost,
  getPostById,
  getRecentTopics,
  getStats,
  getAllUsers,
  logAudit,
  getAuditLogs,
  logSecurityEvent,
  getSecurityEvents,
  recordLoginAttempt,
  countFailedLogins,
  countFailedLoginsForUser,
  getClientIp,
  getUserPasswordHash,
  getPublicProfile,
  getUserStats,
  getUserTopics,
  getUserPosts,
  updateUserProfile,
  updateUserUsername,
  updateUserEmail,
  updateUserPassword,
  updateUserPrivacy,
  searchForum,
  getLeaderboard,
  addBookmark,
  removeBookmark,
  isBookmarked,
  getUserBookmarks,
  createNotification,
  getNotifications,
  getUnreadNotificationCount,
  markNotificationRead,
  markAllNotificationsRead,
  notifyTopicParticipants
};
