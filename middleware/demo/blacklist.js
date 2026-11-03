'use strict';
// JS copy of the first paper's sanitizeInput(), used only as a baseline
// middleware for the latency benchmark (it is the filter the ML model replaces).
// Kept identical to src/blacklist.py / the lab app's server.js.

function sanitizeInput(input) {
  if (typeof input !== 'string') return '';
  return input
    .replace(/'/g, '').replace(/"/g, '').replace(/;/g, '')
    .replace(/--/g, '').replace(/\/\*/g, '').replace(/\*\//g, '')
    .replace(/UNION/gi, '').replace(/SELECT/gi, '').replace(/INSERT/gi, '')
    .replace(/UPDATE/gi, '').replace(/DELETE/gi, '').replace(/DROP/gi, '')
    .replace(/OR/gi, '').replace(/AND/gi, '').replace(/xp_/gi, '')
    .replace(/EXEC/gi, '').trim();
}

// Express middleware that sanitizes every string field in place.
function sanitizeMiddleware(req, res, next) {
  for (const src of ['query', 'body', 'params']) {
    const obj = req[src];
    if (obj && typeof obj === 'object') {
      for (const k of Object.keys(obj)) {
        if (typeof obj[k] === 'string') obj[k] = sanitizeInput(obj[k]);
      }
    }
  }
  next();
}

module.exports = { sanitizeInput, sanitizeMiddleware };
