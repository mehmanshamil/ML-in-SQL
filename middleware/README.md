# sqli-ml-guard

Pure-JavaScript SQL-injection detector as Express middleware. A character
n-gram TF-IDF + logistic-regression model (trained in scikit-learn, exported to
JSON) runs **inside Node.js** — no Python service and no network hop at request
time, so it installs and runs like any npm dependency.

> Research artifact for the accompanying paper. `private: true` — not published to npm.

## How it works

The model is the `lr_norm_aug_v2` pipeline from the study:

```
normalize(query)  ->  char n-gram TF-IDF (1–5, sublinear, L2)  ->  logistic regression  ->  P(malicious)
```

`normalize` canonicalizes a query before scoring (repeated URL-decode, comment
unwrapping, whitespace and punctuation folding, lowercase), which is what makes
the detector robust to obfuscation rather than to dataset formatting. All of it
is reimplemented in `src/normalize.js` and `src/model.js`; `src/model.json`
holds the vocabulary, IDF weights and LR coefficients.

## Usage

```js
const express = require('express');
const { sqliGuard } = require('./middleware'); // this package

const app = express();
app.use(express.json());
app.use(sqliGuard({ threshold: 0.5 }));        // 403 when any field scores >= threshold
```

`sqliGuard(options)`:

| option      | default                      | meaning                                               |
|-------------|------------------------------|-------------------------------------------------------|
| `threshold`       | `0.5`                       | block when a field's malicious probability ≥ this (selected on validation: max recall at FPR=0) |
| `sources`         | `['query','body','params']` | request parts to scan (all string values, recursively)|
| `maxLength`       | `4096`                      | cap per-field scoring cost (scoring is ~linear in length) |
| `maxLengthAction` | `'truncate'`                | `'truncate'` scores the first `maxLength` chars; `'block'` rejects over-length values outright |
| `onBlock`         | logs hash + score           | callback on a block; never receives the raw payload   |
| `model`           | bundled `model.json`        | a model loaded via `loadModel(path)`                  |

`maxLength` defends against a long-input DoS: scoring a 1 MB value takes ~1.2 s
uncapped but ~5 ms at `maxLength=4096` (251× faster, `bench/dos_test.js`).
`'truncate'` is the default because normalize + char n-grams are local — a
truncated injection keeps its malicious tokens at the start, so recall is
unchanged (no effective attack in the test set exceeds 422 chars) while cost is
bounded. `'block'` is strictly safer against evasion (no unscanned tail) but
rejects long benign inputs, so prefer it only where inputs are known to be short.

On a block it responds `403 {"error": "..."}` and logs only the method, path,
field, score and a SHA-1 hash of the value — never the payload itself.

## Parity with the Python model

`src/model.js` must equal the scikit-learn model bit for bit. `npm test` checks
every fixture query: `max |p_js − p_python| < 1e-6` (measured: 3.9e-7 over 2950
queries). Regenerate `model.json` and the fixtures from the trained model with:

```
python ../scripts/... # see scripts/export_model.py (run from the project root with its venv)
```

## Scripts

- `npm test` — JS/Python parity check (`test/parity.js`)
- `npm run demo` — start the vulnerable demo app (`GUARD=none|input|ml|both`, `PORT`, `THRESHOLD`)
- `npm run attack-test` — send the paper's attacks + all 4b-effective obfuscations over HTTP, count blocks
- `npm run bench` — autocannon latency comparison of the four configs

The demo app (`demo/app.js`) is a minimal copy of the first paper's **weak** lab
app (string-concatenated SQL) bound to the SELECT-only `sqli_ml_eval` database;
the original lab app is never modified. It needs the project `.env`
(`MYSQL_EVAL_USER` / `MYSQL_EVAL_PASSWORD`) and the DB from `sql/setup_eval_db.sql`.

## Note

The vulnerable endpoints exist only to exercise the middleware. This package is a
detector you put *in front of* code; it is not a substitute for parameterized
queries, which remain the correct fix for SQL injection.
