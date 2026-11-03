'use strict';
// Minimal copy of the first paper's WEAK (unsanitized) lab app, used to attach
// and benchmark sqliGuard. The original lab app is never modified. Endpoints use
// string-concatenated SQL on purpose (that is the vulnerability under test), but
// the connection is the SELECT-only sqli_ml_eval account, so nothing can be
// written or dropped.
//
// GUARD env selects the protection layer, so the same app serves every bench config:
//   GUARD=none   -> no filter (baseline)
//   GUARD=input  -> sanitizeInput() blacklist middleware
//   GUARD=ml     -> sqliGuard ML middleware
//   GUARD=both   -> ML then sanitizeInput

const express = require('express');
const mysql = require('mysql2/promise');
const { sqliGuard } = require('../src/sqliGuard');
const { sanitizeMiddleware } = require('./blacklist');

function readEnv() {
  const env = {};
  try {
    const fs = require('fs');
    const path = require('path');
    const text = fs.readFileSync(path.join(__dirname, '..', '..', '.env'), 'utf8');
    for (const line of text.split(/\r?\n/)) {
      const i = line.indexOf('=');
      if (i > 0 && !line.startsWith('#')) env[line.slice(0, i).trim()] = line.slice(i + 1).trim();
    }
  } catch (e) { /* .env optional */ }
  return env;
}

async function createApp(options = {}) {
  const guard = options.guard || process.env.GUARD || 'none';
  const threshold = options.threshold != null ? options.threshold
    : (process.env.THRESHOLD ? Number(process.env.THRESHOLD) : 0.5);
  const silent = options.silent || process.env.SILENT === '1';
  const env = readEnv();

  const pool = await mysql.createPool({
    host: 'localhost',
    user: env.MYSQL_EVAL_USER || 'sqli_eval',
    password: env.MYSQL_EVAL_PASSWORD || '',
    database: 'sqli_ml_eval',
    waitForConnections: true, connectionLimit: 10, queueLimit: 0,
    multipleStatements: false,
  });

  const app = express();
  app.use(express.urlencoded({ extended: false }));
  app.use(express.json());

  let blocked = 0;
  const onBlock = silent ? () => { blocked++; } : undefined;
  if (guard === 'ml' || guard === 'both') app.use(sqliGuard({ threshold, onBlock }));
  if (guard === 'input' || guard === 'both') app.use(sanitizeMiddleware);
  app.get('/__blocked', (req, res) => res.json({ blocked }));
  app.get('/health', (req, res) => res.json({ ok: true, guard, threshold }));

  // Vulnerable search (mirrors /products?search= in the weak lab app)
  app.get('/products', async (req, res) => {
    const search = req.query.search || '';
    try {
      const [rows] = await pool.query(`SELECT * FROM products WHERE name LIKE '%${search}%'`);
      res.json({ count: rows.length });
    } catch (e) {
      res.status(200).json({ count: 0, dberror: e.code });
    }
  });

  // Vulnerable login (mirrors /login in the weak lab app: auth bypass target)
  app.post('/login', async (req, res) => {
    const { email = '', password = '' } = req.body || {};
    try {
      const [rows] = await pool.query(
        `SELECT * FROM users WHERE email = '${email}' AND password = '${password}'`);
      if (rows.length > 0) return res.json({ ok: true, user: rows[0].username });
      res.status(401).json({ ok: false });
    } catch (e) {
      res.status(200).json({ ok: false, dberror: e.code });
    }
  });

  app._pool = pool;
  return app;
}

if (require.main === module) {
  const port = Number(process.env.PORT || 3100);
  createApp().then((app) => {
    const server = app.listen(port, () => console.log(`demo app listening on ${port} (GUARD=${process.env.GUARD || 'none'})`));
    const shut = () => app._pool.end().finally(() => server.close(() => process.exit(0)));
    process.on('SIGTERM', shut); process.on('SIGINT', shut);
  }).catch((e) => { console.error('startup failed:', e.message); process.exit(1); });
}

module.exports = { createApp };
