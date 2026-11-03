"""Query normalization used as a detector preprocessing defense.

``normalize`` maps many surface forms of the same payload to one canonical
form before TF-IDF, so the model cannot rely on formatting (whitespace style,
comments, encoding, case). ``human_format`` rewrites a query the way a person
would type it; it is used to test whether a model learned dataset formatting.
"""

import re
from urllib.parse import unquote

MAX_DECODE_ROUNDS = 3

_VERSIONED_RE = re.compile(r"/\*!\d*(.*?)\*/", re.S)
_COMMENT_RE = re.compile(r"/\*.*?\*/", re.S)
_WS_RE = re.compile(r"\s+")
_PUNCT_RE = re.compile(r"\s*([(),=])\s*")


def url_decode(q, max_rounds=MAX_DECODE_ROUNDS):
    """URL-decode repeatedly until the string stops changing (at most max_rounds)."""
    for _ in range(max_rounds):
        decoded = unquote(q)
        if decoded == q:
            break
        q = decoded
    return q


def human_format(q):
    """Collapse whitespace runs and drop spaces around ( ) = , — semantics unchanged."""
    q = _WS_RE.sub(" ", q).strip()
    return _PUNCT_RE.sub(r"\1", q)


def normalize(q, punct=True):
    """Canonical form: decode, unwrap/strip comments, unify whitespace, lowercase.

    1. repeated URL decode (max 3 rounds)
    2. MySQL versioned comments /*!50000X*/ -> " X "
    3. other /* ... */ comments -> " "
    4. every whitespace run (space, tab, LF, CR, VT, FF) -> one space
    5. lowercase
    6. (punct=True) remove spaces around ( ) = , so spacing style is not a feature
    """
    q = url_decode(q)
    q = _VERSIONED_RE.sub(r" \1 ", q)
    q = _COMMENT_RE.sub(" ", q)
    q = _WS_RE.sub(" ", q).strip().lower()
    if punct:
        q = _PUNCT_RE.sub(r"\1", q)
    return q


def normalize_no_punct(q):
    """normalize() without step 6 — the minimal variant, for ablation."""
    return normalize(q, punct=False)


def normalize_all(queries):
    """Batch form for sklearn FunctionTransformer (picklable, module-level)."""
    return [normalize(q) for q in queries]


def normalize_all_no_punct(queries):
    return [normalize(q, punct=False) for q in queries]
