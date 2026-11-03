'use strict';
// Long-input / DoS test: scoring cost grows ~linearly with input length, so a
// large value is a cheap way to burn CPU. Measure per-call scoring time for
// 1 KB / 10 KB / 100 KB / 1 MB inputs, with and without the maxLength cap
// (default 4096). Reports mean/p95 ms per call over N repeats.

const fs = require('fs');
const path = require('path');
const { probaRaw, model } = require('../src/model');

const m = model();
const SIZES = [1024, 10 * 1024, 100 * 1024, 1024 * 1024];
const MAXLEN = 4096;
const REPEATS = 30;

// A realistic adversarial long value: repeated SQL-ish tokens, not just one char.
function makePayload(n) {
  const unit = "1' OR 1=1 UNION SELECT username,password FROM users-- ";
  let s = '';
  while (s.length < n) s += unit;
  return s.slice(0, n);
}

function timeCall(fn, repeats) {
  fn(); fn(); // warm
  const ts = [];
  for (let i = 0; i < repeats; i++) {
    const t0 = process.hrtime.bigint();
    fn();
    ts.push(Number(process.hrtime.bigint() - t0) / 1e6); // ms
  }
  ts.sort((a, b) => a - b);
  const mean = ts.reduce((a, b) => a + b, 0) / ts.length;
  return { mean, p95: ts[Math.floor(ts.length * 0.95)], max: ts[ts.length - 1] };
}

const rows = [];
for (const n of SIZES) {
  const payload = makePayload(n);
  const uncapped = timeCall(() => probaRaw(payload, m), REPEATS);
  const capped = timeCall(() => probaRaw(payload.slice(0, MAXLEN), m), REPEATS);
  rows.push({
    input_bytes: n,
    input_label: n < 1024 * 1024 ? `${n / 1024} KB` : '1 MB',
    no_limit_mean_ms: uncapped.mean.toFixed(3),
    no_limit_p95_ms: uncapped.p95.toFixed(3),
    no_limit_max_ms: uncapped.max.toFixed(3),
    maxlen4096_mean_ms: capped.mean.toFixed(3),
    maxlen4096_p95_ms: capped.p95.toFixed(3),
    speedup_x: (uncapped.mean / capped.mean).toFixed(1),
  });
  console.log(`${rows[rows.length - 1].input_label.padStart(6)}: no-limit ${uncapped.mean.toFixed(2)}ms (p95 ${uncapped.p95.toFixed(2)}), ` +
    `maxLength=4096 ${capped.mean.toFixed(3)}ms  (${(uncapped.mean / capped.mean).toFixed(0)}x faster)`);
}

const out = path.join(__dirname, '..', '..', 'results', 'middleware_dos.csv');
const header = Object.keys(rows[0]).join(',');
fs.writeFileSync(out, header + '\n' + rows.map((r) => Object.values(r).join(',')).join('\n') + '\n');
console.log(`\nwrote ${out}`);
