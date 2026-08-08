const express = require('express');
const { param } = require('express-validator');
const router = express.Router();
const forum = require('../models/forum');
const { requireAuth } = require('../middleware/auth');

router.get('/', requireAuth, (req, res) => {
  const notifications = forum.getNotifications(req.session.user.id, 50);
  res.render('profile/notifications', { title: 'Bildirimler', notifications });
});

router.post('/read-all', requireAuth, (req, res) => {
  forum.markAllNotificationsRead(req.session.user.id);
  res.redirect('/notifications');
});

router.post('/:id/read', requireAuth, param('id').isInt(), (req, res) => {
  forum.markNotificationRead(parseInt(req.params.id, 10), req.session.user.id);
  const notif = forum.getNotifications(req.session.user.id, 1);
  res.redirect('/notifications');
});

module.exports = router;
