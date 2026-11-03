"""Python port of the blacklist sanitizers from the first paper's lab app.

Source: Aztu-projects/meqale son/project-teqdimat/sql-injection - Copy (2)/server.js
(sanitizeInput, sanitizeSearch). The replace chain is kept in the same order.

JavaScript-equivalence details:
- ``/X/gi`` (no ``u`` flag) folds case for ASCII only, so patterns use
  ``re.IGNORECASE | re.ASCII`` (Python's default Unicode folding would also
  match e.g. U+017F "ſ" against "s").
- ``String.prototype.trim`` strips a different whitespace set than
  ``str.strip`` (JS strips U+FEFF; Python strips U+001C-U+001F and U+0085),
  so the JS set is spelled out.
"""

import re

_I = re.IGNORECASE | re.ASCII

# ECMAScript WhiteSpace + LineTerminator code points (used by trim()).
_JS_WS = "\t\n\x0b\x0c\r    -     　﻿"
_JS_TRIM_RE = re.compile(f"^[{_JS_WS}]+|[{_JS_WS}]+$")

_INPUT_CHAIN = [
    (r"'", 0), (r'"', 0), (r";", 0),
    (r"--", 0), (r"/\*", 0), (r"\*/", 0),
    (r"UNION", _I), (r"SELECT", _I), (r"INSERT", _I),
    (r"UPDATE", _I), (r"DELETE", _I), (r"DROP", _I),
    (r"OR", _I), (r"AND", _I), (r"xp_", _I),
    (r"EXEC", _I),
]
_SEARCH_CHAIN = [
    (r"'", 0), (r'"', 0), (r";", 0),
    (r"--", 0), (r"/\*", 0), (r"\*/", 0),
    (r"UNION", _I), (r"SELECT", _I), (r"INSERT", _I),
    (r"DROP", _I), (r"EXEC", _I),
]
_INPUT_RES = [re.compile(p, f) for p, f in _INPUT_CHAIN]
_SEARCH_RES = [re.compile(p, f) for p, f in _SEARCH_CHAIN]


def _js_trim(s):
    return _JS_TRIM_RE.sub("", s)


def _run(chain, value):
    if not isinstance(value, str):
        return ""
    for rx in chain:
        value = rx.sub("", value)
    return _js_trim(value)


def sanitize_input(value):
    """Port of sanitizeInput() — used for login/register fields."""
    return _run(_INPUT_RES, value)


def sanitize_search(value):
    """Port of sanitizeSearch() — used for /products?search=."""
    return _run(_SEARCH_RES, value)


def flags(value, sanitizer):
    """Blacklist as a detector: 1 if sanitization changes the input."""
    return int(sanitizer(value) != value)
