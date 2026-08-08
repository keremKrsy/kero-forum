const express = require('express');
const { param } = require('express-validator');
const router = express.Router();
const forum = require('../models/forum');

router.get('/:username', param('username').matches(/^[a-zA-Z0-9_]+$/), (req, res) => {
  const profile = forum.getPublicProfile(req.params.username);
  if (!profile) {
    return res.status(404).render('error', { title: '404', message: 'User not found.', code: 404 });
  }

  const isOwner = req.session?.user?.id === profile.id;
  if (!profile.profile_public && !isOwner && !res.locals.hasRole('mod')) {
    return res.status(403).render('error', { title: 'Private Profile', message: 'This profile is private.', code: 403 });
  }

  const stats = forum.getUserStats(profile.id);
  const topics = forum.getUserTopics(profile.id, 8);
  const posts = forum.getUserPosts(profile.id, 8);
  const isSelf = req.session?.user?.id === profile.id;

  res.render('profile/show', {
    title: profile.display_name || profile.username,
    profile,
    stats,
    topics,
    posts,
    isSelf
  });
});

module.exports = router;
