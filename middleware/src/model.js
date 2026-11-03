'use strict';
// Char n-gram TF-IDF + logistic regression, in pure JS, matching the scikit-learn
// pipeline in models/lr_norm_aug_v2.joblib (normalize -> TfidfVectorizer(analyzer=
// 'char', ngram_range=(1,5), sublinear_tf, norm='l2') -> LogisticRegression).
//
// logit = intercept + (1/||v||) * sum_t v_t * coef_t,  where
//   v_t = (1 + ln(count_t)) * idf_t           (sublinear tf-idf, raw count per n-gram)
//   ||v|| = sqrt(sum_t v_t^2)                  (L2 norm over n-grams present)
// Only n-grams in the vocabulary contribute; the rest are dropped, exactly as in
// transform(). The normalize step already collapses whitespace, so the char
// analyzer's own whitespace handling is a no-op and need not be replicated.

const fs = require('fs');
const path = require('path');
const { normalize } = require('./normalize');

function loadModel(file) {
  const raw = JSON.parse(fs.readFileSync(file || path.join(__dirname, 'model.json'), 'utf8'));
  return {
    cfg: raw.config,
    intercept: raw.intercept,
    vocab: raw.vocab, // ngram -> [idf, coef]
  };
}

let DEFAULT = null;
function model() {
  if (!DEFAULT) DEFAULT = loadModel();
  return DEFAULT;
}

// Logit for an already-normalized string.
function logitNormalized(text, m) {
  const { ngram_min, ngram_max } = m.cfg;
  const chars = Array.from(text); // code points, matching Python str indexing
  const L = chars.length;
  const counts = new Map();
  for (let n = ngram_min; n <= ngram_max && n <= L; n++) {
    for (let i = 0; i + n <= L; i++) {
      const g = chars.slice(i, i + n).join('');
      counts.set(g, (counts.get(g) || 0) + 1);
    }
  }
  let dot = 0;
  let sq = 0;
  for (const [g, c] of counts) {
    const entry = m.vocab[g];
    if (entry === undefined) continue;
    const v = (1 + Math.log(c)) * entry[0]; // sublinear tf * idf
    sq += v * v;
    dot += v * entry[1]; // * coef
  }
  if (sq === 0) return m.intercept;
  return m.intercept + dot / Math.sqrt(sq);
}

function probaRaw(rawText, m) {
  m = m || model();
  const logit = logitNormalized(normalize(rawText), m);
  return 1 / (1 + Math.exp(-logit));
}

module.exports = { loadModel, model, probaRaw, logitNormalized };
