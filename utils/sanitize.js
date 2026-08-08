const sanitizeHtml = require('sanitize-html');
const config = require('../config');

const allowedTags = [
  'p', 'br', 'strong', 'em', 'u', 's', 'blockquote', 'code', 'pre',
  'ul', 'ol', 'li', 'a', 'h3', 'h4', 'span'
];

const sanitizeOptions = {
  allowedTags,
  allowedAttributes: {
    a: ['href', 'title', 'rel', 'target'],
    span: ['class']
  },
  allowedSchemes: ['http', 'https', 'mailto'],
  transformTags: {
    a: sanitizeHtml.simpleTransform('a', { rel: 'noopener noreferrer', target: '_blank' })
  }
};

function sanitizeInput(text, { allowHtml = false } = {}) {
  if (text == null) return '';
  const str = String(text).trim();
  if (!allowHtml) {
    return sanitizeHtml(str, { allowedTags: [], allowedAttributes: {} });
  }
  return sanitizeHtml(str, sanitizeOptions);
}

function sanitizePlain(text) {
  return sanitizeInput(text, { allowHtml: false });
}

function sanitizeRich(text) {
  return sanitizeInput(text, { allowHtml: true });
}

function escapeHtml(text) {
  return String(text)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function slugify(text) {
  return String(text)
    .toLowerCase()
    .trim()
    .replace(/[^\w\s-]/g, '')
    .replace(/[\s_-]+/g, '-')
    .replace(/^-+|-+$/g, '') || 'item';
}

function getClientIp(req) {
  if (config.trustProxy && req.headers['x-forwarded-for']) {
    return req.headers['x-forwarded-for'].split(',')[0].trim();
  }
  return req.ip || req.connection?.remoteAddress || 'unknown';
}

module.exports = {
  sanitizeInput,
  sanitizePlain,
  sanitizeRich,
  escapeHtml,
  slugify,
  getClientIp
};
