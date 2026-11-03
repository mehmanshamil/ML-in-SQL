'use strict';
// Express middleware: score every string value in req.query, req.body and
// req.params with the ML model and reject the request when any value's
// malicious probability crosses `threshold`.
//
// Logging never records the payload itself — only a SHA-1 hash and the score —
// so request contents (which may contain credentials) are not written to logs.

const crypto = require('crypto');
const { probaRaw, model } = require('./model');

function* stringValues(obj, prefix) {
  if (obj == null) return;
  if (typeof obj === 'string') {
    yield [prefix, obj];
    return;
  }
  if (Array.isArray(obj)) {
    for (let i = 0; i < obj.length; i++) yield* stringValues(obj[i], `${prefix}[${i}]`);
    return;
  }
  if (typeof obj === 'object') {
    for (const k of Object.keys(obj)) yield* stringValues(obj[k], prefix ? `${prefix}.${k}` : k);
  }
}

function sqliGuard(options = {}) {
  const threshold = options.threshold == null ? 0.5 : options.threshold;
  const sources = options.sources || ['query', 'body', 'params'];
  const m = options.model || model();
  const onBlock = options.onBlock || defaultLog;
  const scoreAll = Boolean(options.scoreAll); // keep scoring after the first hit (for analysis)

  return function (req, res, next) {
    let worst = { score: -1, field: null };
    for (const src of sources) {
      for (const [field, value] of stringValues(req[src], src)) {
        const score = probaRaw(value, m);
        if (score > worst.score) worst = { score, field, value };
        if (score >= threshold && !scoreAll) {
          return block(req, res, worst, threshold, onBlock);
        }
      }
    }
    if (worst.score >= threshold) return block(req, res, worst, threshold, onBlock);
    if (req) req.sqliMaxScore = worst.score;
    next();
  };
}

function block(req, res, worst, threshold, onBlock) {
  const hash = crypto.createHash('sha1').update(String(worst.value)).digest('hex').slice(0, 12);
  onBlock({ method: req.method, path: req.path, field: worst.field, score: worst.score, threshold, hash });
  res.status(403).json({ error: 'Request blocked by SQL injection filter' });
}

function defaultLog(info) {
  // payload-un özü deyil, yalnız hash və skor
  console.warn(`[sqliGuard] BLOCK ${info.method} ${info.path} field=${info.field} ` +
    `score=${info.score.toFixed(4)} >= ${info.threshold} sha1=${info.hash}`);
}

module.exports = { sqliGuard, stringValues };
