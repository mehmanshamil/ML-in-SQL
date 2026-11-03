const fs = require('fs');
const path = require('path');
const { probaRaw, model } = require('../src/model');
const rows = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));
const m = model();
let maxDiff = 0, worst = null, over = 0;
const t0 = Date.now();
for (const r of rows) {
  const d = Math.abs(probaRaw(r.q, m) - r.p);
  if (d > maxDiff) { maxDiff = d; worst = r.q; }
  if (d > 1e-6) over++;
}
const ms = Date.now() - t0;
console.log(`rows=${rows.length}  max|Δ|=${maxDiff.toExponential(3)}  over_1e-6=${over}`);
console.log(`worst: ${JSON.stringify((worst||'').slice(0,80))}`);
console.log(`throughput: ${(rows.length/(ms/1000)).toFixed(0)} pred/s`);
