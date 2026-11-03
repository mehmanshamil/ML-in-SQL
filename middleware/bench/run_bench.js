'use strict';
// Latency benchmark: compare four protection configs under clean traffic.
//   none  -> no filter
//   input -> sanitizeInput() blacklist middleware
//   ml    -> sqliGuard ML middleware
//   both  -> ML then sanitizeInput
// For each config: spawn the demo app, warm up, run autocannon (30s, 10 conns)
// three times, record p50/p95/p99 latency and req/s. Report mean and std.

const { spawn } = require('child_process');
const path = require('path');
const fs = require('fs');
const autocannon = require('autocannon');

const CONFIGS = ['none', 'input', 'ml', 'both'];
const DURATION = Number(process.env.BENCH_DURATION || 30);
const CONNECTIONS = Number(process.env.BENCH_CONNECTIONS || 10);
const REPEATS = Number(process.env.BENCH_REPEATS || 3);
const PORT = 3133;
const CLEAN_PATH = '/products?search=' + encodeURIComponent('wireless mouse');

function waitForHealth(port, timeoutMs = 20000) {
  const t0 = Date.now();
  return new Promise((resolve, reject) => {
    const tick = async () => {
      try {
        const r = await fetch(`http://localhost:${port}/health`);
        if (r.ok) return resolve();
      } catch (e) { /* not up yet */ }
      if (Date.now() - t0 > timeoutMs) return reject(new Error('server did not become healthy'));
      setTimeout(tick, 300);
    };
    tick();
  });
}

function startServer(guard) {
  const child = spawn(process.execPath, [path.join(__dirname, '..', 'demo', 'app.js')], {
    env: { ...process.env, GUARD: guard, PORT: String(PORT), SILENT: '1', THRESHOLD: '0.5' },
    stdio: ['ignore', 'ignore', 'inherit'],
  });
  return child;
}

function runAutocannon(duration) {
  return new Promise((resolve, reject) => {
    autocannon({
      url: `http://localhost:${PORT}${CLEAN_PATH}`,
      connections: CONNECTIONS, duration, timeout: 20,
    }, (err, result) => (err ? reject(err) : resolve(result)));
  });
}

function pct(latency, keys) {
  for (const k of keys) if (latency[k] != null) return latency[k];
  return NaN;
}

function stats(xs) {
  const n = xs.length;
  const mean = xs.reduce((a, b) => a + b, 0) / n;
  const sd = n > 1 ? Math.sqrt(xs.reduce((a, b) => a + (b - mean) ** 2, 0) / (n - 1)) : 0;
  return { mean, sd };
}

async function benchConfig(guard) {
  const server = startServer(guard);
  const runs = [];
  try {
    await waitForHealth(PORT);
    await runAutocannon(5); // warmup
    for (let i = 0; i < REPEATS; i++) {
      const r = await runAutocannon(DURATION);
      runs.push({
        p50: pct(r.latency, ['p50']),
        p95: pct(r.latency, ['p95', 'p97_5']),
        p99: pct(r.latency, ['p99']),
        rps: r.requests.average,
        non2xx: (r.non2xx || 0) + (r.errors || 0),
      });
      console.log(`  ${guard} run ${i + 1}: p50=${runs[i].p50}ms p95=${runs[i].p95}ms p99=${runs[i].p99}ms rps=${runs[i].rps.toFixed(0)}`);
    }
  } finally {
    server.kill('SIGTERM');
    await new Promise((r) => setTimeout(r, 1500));
  }
  return runs;
}

async function main() {
  console.log(`bench: ${DURATION}s x ${CONNECTIONS} conns x ${REPEATS} repeats, clean traffic (${CLEAN_PATH})`);
  const rows = [];
  for (const guard of CONFIGS) {
    const runs = await benchConfig(guard);
    const agg = {};
    for (const m of ['p50', 'p95', 'p99', 'rps']) {
      const s = stats(runs.map((r) => r[m]));
      agg[`${m}_mean`] = Number(s.mean.toFixed(3));
      agg[`${m}_std`] = Number(s.sd.toFixed(3));
    }
    rows.push({ config: guard, repeats: REPEATS, ...agg, non2xx_total: runs.reduce((a, r) => a + r.non2xx, 0) });
  }

  const header = Object.keys(rows[0]).join(',');
  const body = rows.map((r) => Object.values(r).join(',')).join('\n');
  const out = path.join(__dirname, '..', '..', 'results', 'middleware_latency.csv');
  fs.writeFileSync(out, header + '\n' + body + '\n');
  console.log('\n' + header + '\n' + body);
  console.log(`\nwrote ${out}`);
}

main().catch((e) => { console.error(e); process.exit(1); });
