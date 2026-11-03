'use strict';
// Pure-JS port of src/normalize.py::normalize(q, punct=true).
// Must match the Python output byte-for-byte so the JS detector equals the
// Python model. The two subtle points are replicated deliberately:
//   * Python urllib.parse.unquote: UTF-8 encode, split on '%', decode %XX byte
//     pairs, UTF-8 decode the result with U+FFFD replacement.
//   * Python re '\s' (Unicode): a wider set than JS '\s' (adds U+001C–U+001F,
//     U+0085; JS adds U+FEFF, which Python does not treat as \s).

// Python re \s, Unicode (str) — exact set.
const PY_WS = '\\t\\n\\x0b\\x0c\\r\\x1c\\x1d\\x1e\\x1f \\x85\\xa0\\u1680\\u2000-\\u200a\\u2028\\u2029\\u202f\\u205f\\u3000';
const WS_RE = new RegExp('[' + PY_WS + ']+', 'g');
const PUNCT_RE = new RegExp('[' + PY_WS + ']*([(),=])[' + PY_WS + ']*', 'g');
const VERSIONED_RE = /\/\*!\d*([\s\S]*?)\*\//g; // /*!50000X*/ -> " X "
const COMMENT_RE = /\/\*[\s\S]*?\*\//g;         // /* ... */   -> " "

const encoder = new TextEncoder();
const decoder = new TextDecoder('utf-8'); // fatal:false -> U+FFFD on bad bytes, like errors='replace'

function hexVal(c) {
  if (c >= 48 && c <= 57) return c - 48;        // 0-9
  if (c >= 65 && c <= 70) return c - 55;        // A-F
  if (c >= 97 && c <= 102) return c - 87;       // a-f
  return -1;
}

// Faithful port of urllib.parse.unquote(string, encoding='utf-8', errors='replace').
function unquoteOnce(str) {
  if (str.indexOf('%') === -1) return str;
  const bytes = encoder.encode(str);
  const out = [];
  let i = 0;
  while (i < bytes.length) {
    if (bytes[i] === 0x25) { // '%'
      const hi = i + 1 < bytes.length ? hexVal(bytes[i + 1]) : -1;
      const lo = i + 2 < bytes.length ? hexVal(bytes[i + 2]) : -1;
      if (hi >= 0 && lo >= 0) {
        out.push(hi * 16 + lo);
        i += 3;
        continue;
      }
    }
    out.push(bytes[i]);
    i += 1;
  }
  return decoder.decode(Uint8Array.from(out));
}

function urlDecode(str, maxRounds = 3) {
  for (let r = 0; r < maxRounds; r++) {
    const next = unquoteOnce(str);
    if (next === str) break;
    str = next;
  }
  return str;
}

function normalize(q, punct = true) {
  q = urlDecode(q);
  q = q.replace(VERSIONED_RE, ' $1 ');
  q = q.replace(COMMENT_RE, ' ');
  q = q.replace(WS_RE, ' ').replace(new RegExp('^[' + PY_WS + ']+|[' + PY_WS + ']+$', 'g'), '').toLowerCase();
  if (punct) q = q.replace(PUNCT_RE, '$1');
  return q;
}

module.exports = { normalize, unquoteOnce, urlDecode };
