'use strict';
// Parity test: the pure-JS runtime must match the Python scikit-learn model.
// Every fixture row's |p_js - p_python| must stay below 1e-6.
// Fixtures are produced by scripts/export_model.py (same run that writes model.json).

const fs = require('fs');
const path = require('path');
const { probaRaw, model } = require('../src/model');

const TOL = 1e-6;
const fixture = path.join(__dirname, 'fixtures', 'parity.json');
const rows = JSON.parse(fs.readFileSync(fixture, 'utf8'));
const m = model();

let maxDiff = 0;
let worst = null;
let over = 0;
const t0 = Date.now();
for (const r of rows) {
  const d = Math.abs(probaRaw(r.q, m) - r.p);
  if (d > maxDiff) { maxDiff = d; worst = r.q; }
  if (d > TOL) over++;
}
const ms = Date.now() - t0;

console.log(`parity: ${rows.length} rows, max|Δ| = ${maxDiff.toExponential(3)}, over ${TOL} = ${over}`);
console.log(`throughput: ${(rows.length / (ms / 1000)).toFixed(0)} predictions/s`);
if (over > 0) {
  console.error(`FAIL: ${over} rows exceed ${TOL}. worst query: ${JSON.stringify(String(worst).slice(0, 100))}`);
  process.exit(1);
}
console.log('PASS');
