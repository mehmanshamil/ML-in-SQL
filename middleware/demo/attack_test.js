'use strict';
// Send the first paper's three attack scenarios plus every obfuscation form that
// was MySQL-effective in step 4b through the running demo app over HTTP, and
// report how many the ML middleware blocks (HTTP 403). Payloads are placed in
// both the search context (GET /products?search=) and, for the auth-bypass
// canonical case, the login body.
//
// Usage: start the app with GUARD=ml (any threshold), then `node demo/attack_test.js`.

const fs = require('fs');
const path = require('path');

const PORT = Number(process.env.PORT || 3101);
const BASE = `http://localhost:${PORT}`;
const fixture = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'test', 'fixtures', 'attacks.json'), 'utf8'));

async function blockedViaSearch(text) {
  const res = await fetch(`${BASE}/products?search=${encodeURIComponent(text)}`);
  return res.status === 403;
}

async function blockedViaLogin(text) {
  const res = await fetch(`${BASE}/login`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email: text, password: 'x' }),
  });
  return res.status === 403;
}

async function main() {
  const rows = [];

  // 1) canonical paper attacks
  let canonBlocked = 0;
  for (const a of fixture.canonical) {
    const viaSearch = await blockedViaSearch(a.text);
    const viaLogin = await blockedViaLogin(a.text);
    const blocked = viaSearch || viaLogin;
    canonBlocked += blocked ? 1 : 0;
    console.log(`  [${blocked ? 'BLOCK' : 'PASS '}] ${a.variant}`);
  }
  console.log(`Canonical paper attacks blocked: ${canonBlocked}/${fixture.canonical.length}\n`);

  // 2) all MySQL-effective obfuscation forms from 4b
  const byVariant = new Map();
  let blockedForms = 0;
  const passedPayloads = new Set();
  const allPayloads = new Set();
  for (const a of fixture.effective_obfuscations) {
    const blocked = await blockedViaSearch(a.text);
    blockedForms += blocked ? 1 : 0;
    const v = byVariant.get(a.variant) || { n: 0, blocked: 0 };
    v.n++; v.blocked += blocked ? 1 : 0;
    byVariant.set(a.variant, v);
    allPayloads.add(a.payload_id);
    if (!blocked) passedPayloads.add(a.payload_id);
  }
  const n = fixture.effective_obfuscations.length;
  console.log(`Effective obfuscation forms blocked: ${blockedForms}/${n} (${(100 * blockedForms / n).toFixed(1)}%)`);
  console.log(`Unique effective payloads with >=1 form passing: ${passedPayloads.size}/${allPayloads.size}\n`);
  for (const [v, s] of [...byVariant.entries()].sort((a, b) => a[1].blocked / a[1].n - b[1].blocked / b[1].n)) {
    console.log(`  ${v.padEnd(24)} ${s.blocked}/${s.n} blocked`);
    rows.push({ variant: v, forms: s.n, blocked: s.blocked, blocked_pct: (100 * s.blocked / s.n).toFixed(1) });
  }

  const out = path.join(__dirname, '..', '..', 'results', 'middleware_attack_test.csv');
  const header = 'variant,forms,blocked,blocked_pct\n';
  const body = [
    `canonical_paper,${fixture.canonical.length},${canonBlocked},${(100 * canonBlocked / fixture.canonical.length).toFixed(1)}`,
    ...rows.map((r) => `${r.variant},${r.forms},${r.blocked},${r.blocked_pct}`),
  ].join('\n');
  fs.writeFileSync(out, header + body + '\n');
  console.log(`\nwrote ${out}`);
}

main().catch((e) => { console.error(e); process.exit(1); });
