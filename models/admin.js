const db = require('../database/init');
const config = require('../config');

const fs = require('fs');
const path = require('path');
const Database = require('better-sqlite3');

function getSiteSetting(key) {
  return db.prepare('SELECT value FROM site_settings WHERE key = ?').get(key)?.value || null;
}

function setSiteSetting(key, value) {
  db.prepare(`
    INSERT INTO site_settings (key, value, updated_at)
    VALUES (?, ?, datetime('now'))
    ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = datetime('now')
  `).run(key, String(value));
  return getSiteSetting(key);
}

function updateCategory(id, { name, slug, description, isLocked, slowModeSeconds, minPostLength, postPermission, sortOrder }) {
  const current = db.prepare('SELECT * FROM categories WHERE id = ?').get(id);
  if (!current) return null;
  db.prepare(`
    UPDATE categories
    SET name = ?, slug = ?, description = ?, is_locked = ?,
        slow_mode_seconds = ?, min_post_length = ?, post_permission = ?, sort_order = ?
    WHERE id = ?
  `).run(
    name == null ? current.name : name,
    slug == null ? current.slug : slug,
    description == null ? current.description : description,
    isLocked == null ? current.is_locked : (isLocked ? 1 : 0),
    slowModeSeconds == null ? current.slow_mode_seconds : slowModeSeconds,
    minPostLength == null ? current.min_post_length : minPostLength,
    postPermission == null ? current.post_permission : postPermission,
    sortOrder == null ? current.sort_order : sortOrder,
    id
  );
  return db.prepare('SELECT * FROM categories WHERE id = ?').get(id);
}

function deleteCategory(id) {
  return db.prepare('DELETE FROM categories WHERE id = ?').run(id);
}

function reorderCategories(items) {
  const tx = db.transaction((rows) => {
    const stmt = db.prepare('UPDATE categories SET sort_order = ? WHERE id = ?');
    rows.forEach((row) => stmt.run(row.sortOrder, row.id));
  });
  tx(items);
  return db.prepare('SELECT id, sort_order FROM categories ORDER BY sort_order ASC, id ASC').all();
}

function createReport({ reporterId, targetType, targetId, reason, details }) {
  const result = db.prepare(`
    INSERT INTO reports (reporter_id, target_type, target_id, reason, details)
    VALUES (?, ?, ?, ?, ?)
  `).run(reporterId, targetType, targetId, reason, details || null);
  return db.prepare('SELECT * FROM reports WHERE id = ?').get(result.lastInsertRowid);
}

function getPendingReports(limit = 100) {
  return db.prepare(`
    SELECT r.*, u.username AS reporter_username
    FROM reports r
    JOIN users u ON u.id = r.reporter_id
    WHERE r.status = 'pending'
    ORDER BY r.created_at DESC
    LIMIT ?
  `).all(limit);
}

function resolveReport(id, { resolverId, status = 'resolved', resolutionNote }) {
  db.prepare(`
    UPDATE reports
    SET status = ?, resolver_id = ?, resolution_note = ?, resolved_at = datetime('now')
    WHERE id = ?
  `).run(status, resolverId, resolutionNote || null, id);
  return db.prepare('SELECT * FROM reports WHERE id = ?').get(id);
}

function createIpBan({ ipAddress, reason, bannedBy, expiresAt }) {
  const result = db.prepare(`
    INSERT INTO ip_bans (ip_address, reason, banned_by, expires_at)
    VALUES (?, ?, ?, ?)
  `).run(ipAddress, reason, bannedBy || null, expiresAt || null);
  return db.prepare('SELECT * FROM ip_bans WHERE id = ?').get(result.lastInsertRowid);
}

function getIpBans(limit = 200) {
  return db.prepare(`
    SELECT b.*, u.username AS banned_by_username
    FROM ip_bans b
    LEFT JOIN users u ON u.id = b.banned_by
    ORDER BY b.created_at DESC
    LIMIT ?
  `).all(limit);
}

function updateIpBan(id, { reason, expiresAt, isActive }) {
  const current = db.prepare('SELECT * FROM ip_bans WHERE id = ?').get(id);
  if (!current) return null;
  db.prepare(`
    UPDATE ip_bans
    SET reason = ?, expires_at = ?, is_active = ?
    WHERE id = ?
  `).run(
    reason == null ? current.reason : reason,
    expiresAt == null ? current.expires_at : expiresAt,
    isActive == null ? current.is_active : (isActive ? 1 : 0),
    id
  );
  return db.prepare('SELECT * FROM ip_bans WHERE id = ?').get(id);
}

function deleteIpBan(id) {
  return db.prepare('DELETE FROM ip_bans WHERE id = ?').run(id);
}

function createWordFilter({ pattern, replacement = '', createdBy }) {
  const result = db.prepare(`
    INSERT INTO word_filters (pattern, replacement, created_by)
    VALUES (?, ?, ?)
  `).run(pattern, replacement, createdBy || null);
  return db.prepare('SELECT * FROM word_filters WHERE id = ?').get(result.lastInsertRowid);
}

function getWordFilters(limit = 200) {
  return db.prepare(`
    SELECT f.*, u.username AS created_by_username
    FROM word_filters f
    LEFT JOIN users u ON u.id = f.created_by
    ORDER BY f.created_at DESC
    LIMIT ?
  `).all(limit);
}

function updateWordFilter(id, { pattern, replacement, isActive }) {
  const current = db.prepare('SELECT * FROM word_filters WHERE id = ?').get(id);
  if (!current) return null;
  db.prepare(`
    UPDATE word_filters
    SET pattern = ?, replacement = ?, is_active = ?
    WHERE id = ?
  `).run(
    pattern == null ? current.pattern : pattern,
    replacement == null ? current.replacement : replacement,
    isActive == null ? current.is_active : (isActive ? 1 : 0),
    id
  );
  return db.prepare('SELECT * FROM word_filters WHERE id = ?').get(id);
}

function deleteWordFilter(id) {
  return db.prepare('DELETE FROM word_filters WHERE id = ?').run(id);
}

function createStaffNote({ userId, staffId, note }) {
  const result = db.prepare(`
    INSERT INTO staff_notes (user_id, staff_id, note)
    VALUES (?, ?, ?)
  `).run(userId, staffId, note);
  return db.prepare('SELECT * FROM staff_notes WHERE id = ?').get(result.lastInsertRowid);
}

function getStaffNotes(userId, limit = 100) {
  return db.prepare(`
    SELECT n.*, s.username AS staff_username
    FROM staff_notes n
    JOIN users s ON s.id = n.staff_id
    WHERE n.user_id = ?
    ORDER BY n.created_at DESC
    LIMIT ?
  `).all(userId, limit);
}

function updateStaffNote(id, { note }) {
  db.prepare(`
    UPDATE staff_notes
    SET note = ?, updated_at = datetime('now')
    WHERE id = ?
  `).run(note, id);
  return db.prepare('SELECT * FROM staff_notes WHERE id = ?').get(id);
}

function deleteStaffNote(id) {
  return db.prepare('DELETE FROM staff_notes WHERE id = ?').run(id);
}

function toCsv(rows, headers) {
  const escapeCell = (value) => {
    const stringValue = value == null ? '' : String(value);
    return `"${stringValue.replace(/"/g, '""')}"`;
  };
  const lines = [headers.map(escapeCell).join(',')];
  rows.forEach((row) => {
    lines.push(headers.map((header) => escapeCell(row[header])).join(','));
  });
  return `${lines.join('\n')}\n`;
}

function exportAuditCsv(limit = 5000) {
  const rows = db.prepare(`
    SELECT a.id, a.user_id, u.username, a.action, a.target_type, a.target_id,
           a.ip_address, a.user_agent, a.details, a.severity, a.created_at
    FROM audit_logs a
    LEFT JOIN users u ON u.id = a.user_id
    ORDER BY a.created_at DESC
    LIMIT ?
  `).all(limit);
  return toCsv(rows, [
    'id', 'user_id', 'username', 'action', 'target_type', 'target_id',
    'ip_address', 'user_agent', 'details', 'severity', 'created_at'
  ]);
}

function exportSecurityCsv(limit = 5000) {
  const rows = db.prepare(`
    SELECT id, event_type, ip_address, user_agent, details, blocked, created_at
    FROM security_events
    ORDER BY created_at DESC
    LIMIT ?
  `).all(limit);
  return toCsv(rows, ['id', 'event_type', 'ip_address', 'user_agent', 'details', 'blocked', 'created_at']);
}

function getBackupDbPath() {
  const dir = path.join(path.dirname(config.dbPath), 'backups');
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
  const stamp = new Date().toISOString().replace(/[:.]/g, '-');
  return path.join(dir, `kero-forum-${stamp}.db`);
}

function listSessions(limit = 500) {
  const sessionsDbPath = path.join(path.dirname(config.dbPath), 'sessions.db');
  if (!fs.existsSync(sessionsDbPath)) return [];
  const sessionsDb = new Database(sessionsDbPath, { readonly: true });
  try {
    const rows = sessionsDb.prepare(`
      SELECT sid, sess, expired
      FROM sessions
      ORDER BY expired DESC
      LIMIT ?
    `).all(limit);
    return rows.map((row) => {
      let parsed = {};
      try {
        parsed = JSON.parse(row.sess || '{}');
      } catch (_) {
        parsed = {};
      }
      return {
        sid: row.sid,
        expired: row.expired,
        user: parsed.user || null
      };
    });
  } finally {
    sessionsDb.close();
  }
}

function massDeleteTopicsInCategory(categoryId) {
  const result = db.prepare('DELETE FROM topics WHERE category_id = ?').run(categoryId);
  return { deletedTopics: result.changes };
}

function getExtendedStats() {
  return {
    users: db.prepare('SELECT COUNT(*) AS c FROM users').get().c,
    topics: db.prepare('SELECT COUNT(*) AS c FROM topics').get().c,
    posts: db.prepare('SELECT COUNT(*) AS c FROM posts').get().c,
    categories: db.prepare('SELECT COUNT(*) AS c FROM categories').get().c,
    pendingReports: db.prepare("SELECT COUNT(*) AS c FROM reports WHERE status = 'pending'").get().c,
    activeIpBans: db.prepare(`
      SELECT COUNT(*) AS c
      FROM ip_bans
      WHERE is_active = 1 AND (expires_at IS NULL OR expires_at > datetime('now'))
    `).get().c,
    activeWordFilters: db.prepare('SELECT COUNT(*) AS c FROM word_filters WHERE is_active = 1').get().c,
    staffNotes: db.prepare('SELECT COUNT(*) AS c FROM staff_notes').get().c,
    openSessions: listSessions(100000).length
  };
}

function searchUsers(query, limit = 50) {
  const q = `%${query}%`;
  return db.prepare(`
    SELECT id, username, email, role, is_banned, created_at, last_login_at, reputation
    FROM users
    WHERE username LIKE ? COLLATE NOCASE OR email LIKE ? COLLATE NOCASE
    ORDER BY username ASC
    LIMIT ?
  `).all(q, q, limit);
}

function revokeSession(sid) {
  const sessionsDbPath = path.join(path.dirname(config.dbPath), 'sessions.db');
  if (!fs.existsSync(sessionsDbPath)) return false;
  const sessionsDb = new Database(sessionsDbPath);
  try {
    sessionsDb.prepare('DELETE FROM sessions WHERE sid = ?').run(sid);
    return true;
  } finally {
    sessionsDb.close();
  }
}

function createDatabaseBackup() {
  const backupPath = getBackupDbPath();
  fs.copyFileSync(config.dbPath, backupPath);
  return backupPath;
}

function runAutoLockTopics() {
  const days = parseInt(getSiteSetting('auto_lock_days') || '0', 10);
  if (days <= 0) return 0;
  const result = db.prepare(`
    UPDATE topics SET is_locked = 1, updated_at = datetime('now')
    WHERE is_locked = 0 AND created_at < datetime('now', ?)
  `).run(`-${days} days`);
  return result.changes;
}

function applyWordFilters(text) {
  if (!text) return text;
  let output = text;
  const filters = db.prepare('SELECT pattern, replacement FROM word_filters WHERE is_active = 1').all();
  filters.forEach((f) => {
    try {
      const re = new RegExp(f.pattern, 'gi');
      output = output.replace(re, f.replacement);
    } catch (_) {}
  });
  return output;
}

function isIpBanned(ip) {
  const row = db.prepare(`
    SELECT 1 FROM ip_bans
    WHERE ip_address = ? AND is_active = 1
    AND (expires_at IS NULL OR expires_at > datetime('now'))
    LIMIT 1
  `).get(ip);
  return !!row;
}

function isEmailDomainBlocked(email) {
  const blocked = (getSiteSetting('blocked_email_domains') || '').split(',').map((s) => s.trim().toLowerCase()).filter(Boolean);
  if (!blocked.length) return false;
  const domain = String(email).split('@')[1]?.toLowerCase();
  return blocked.includes(domain);
}

function incrementReputation(userId, amount = 1) {
  db.prepare('UPDATE users SET reputation = reputation + ?, updated_at = datetime(\'now\') WHERE id = ?').run(amount, userId);
}

function getAllSettings() {
  return db.prepare('SELECT key, value, updated_at FROM site_settings ORDER BY key ASC').all();
}

module.exports = {
  getSiteSetting,
  setSiteSetting,
  updateCategory,
  deleteCategory,
  reorderCategories,
  createReport,
  getPendingReports,
  resolveReport,
  createIpBan,
  getIpBans,
  updateIpBan,
  deleteIpBan,
  createWordFilter,
  getWordFilters,
  updateWordFilter,
  deleteWordFilter,
  createStaffNote,
  getStaffNotes,
  updateStaffNote,
  deleteStaffNote,
  exportAuditCsv,
  exportSecurityCsv,
  getBackupDbPath,
  listSessions,
  massDeleteTopicsInCategory,
  getExtendedStats,
  searchUsers,
  revokeSession,
  createDatabaseBackup,
  runAutoLockTopics,
  applyWordFilters,
  isIpBanned,
  isEmailDomainBlocked,
  incrementReputation,
  getAllSettings
};
