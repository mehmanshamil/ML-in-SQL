"""SQL injection payload obfuscation techniques for detector robustness tests.

Each technique is a pure function ``f(query, rng) -> str``. Randomness comes only
from the ``rng`` argument (a ``random.Random``), so results are reproducible when
the caller seeds it (see ``rng_for``).

A technique that cannot change a query (e.g. no whitespace to replace) returns
it unchanged; callers drop those rows from that technique's test set.
"""

import random
import re
from urllib.parse import quote

SEED = 42

# Keywords targeted by the keyword-level techniques (case, versioned comments,
# split comments). Matched as whole words, case-insensitively.
KEYWORDS = [
    "SELECT", "UNION", "ALL", "FROM", "WHERE", "AND", "OR", "NOT", "NULL", "INSERT", "INTO",
    "VALUES", "UPDATE", "SET", "DELETE", "DROP", "TABLE", "CREATE", "EXEC", "DECLARE", "CAST",
    "CONVERT", "CHAR", "CONCAT", "SLEEP", "BENCHMARK", "WAITFOR", "DELAY", "IF", "CASE", "WHEN",
    "THEN", "ELSE", "END", "LIKE", "RLIKE", "ORDER", "BY", "GROUP", "HAVING", "LIMIT", "EXISTS",
    "INFORMATION_SCHEMA", "LOAD_FILE", "OUTFILE", "DUAL", "USER", "DATABASE", "VERSION",
    "EXTRACTVALUE", "UPDATEXML", "SUBSTRING", "ASCII",
]
_KW_RE = re.compile(
    r"(?<![A-Za-z0-9_])(" + "|".join(sorted(KEYWORDS, key=len, reverse=True)) + r")(?![A-Za-z0-9_])",
    re.IGNORECASE,
)
_WS_RE = re.compile(r"\s+")
# Quoted literal with "simple" content only. Payloads often have unbalanced
# quotes (``1' or 'a'='a``), so allowing spaces or operators inside would pair
# the wrong quotes and hex-encode SQL code instead of data.
_LITERAL_RE = re.compile(r"(['\"])([A-Za-z0-9_@.\-/:%~!$]+)\1")


def rng_for(technique, index, seed=SEED):
    """Deterministic RNG per (technique, row) so adding rows never shifts others."""
    return random.Random(f"{seed}:{technique}:{index}")


def random_case(q, rng):
    """UNION SELECT -> UnIoN SeLeCt (keywords only)."""
    def flip(m):
        word = m.group(0)
        out = "".join(c.upper() if rng.random() < 0.5 else c.lower() for c in word)
        if out == word:  # guarantee a visible change for this keyword
            out = out[0].swapcase() + out[1:]
        return out
    return _KW_RE.sub(flip, q)


def inline_comment_space(q, rng):
    """Every whitespace run -> /**/ (UNION/**/SELECT)."""
    return _WS_RE.sub("/**/", q)


def alt_whitespace(q, rng):
    """Every whitespace run -> one of tab, LF, CR, VT, FF (all whitespace to MySQL)."""
    return _WS_RE.sub(lambda m: rng.choice(["\t", "\n", "\r", "\x0b", "\x0c"]), q)


def alt_whitespace_url(q, rng):
    """Every whitespace run -> URL-encoded tab / LF / CR (%09, %0a, %0d)."""
    return _WS_RE.sub(lambda m: rng.choice(["%09", "%0a", "%0d"]), q)


def url_encode(q, rng):
    """Percent-encode every reserved character (letters and digits stay)."""
    return quote(q, safe="")


def double_url_encode(q, rng):
    """URL encoding applied twice (' -> %27 -> %2527)."""
    return quote(quote(q, safe=""), safe="")


def versioned_comment(q, rng):
    """MySQL executable comment: UNION -> /*!50000UNION*/."""
    return _KW_RE.sub(lambda m: f"/*!50000{m.group(0)}*/", q)


def logical_operator(q, rng):
    """OR -> ||, AND -> && (MySQL-specific operators)."""
    q = re.sub(r"(?<![A-Za-z0-9_])or(?![A-Za-z0-9_])", "||", q, flags=re.IGNORECASE)
    return re.sub(r"(?<![A-Za-z0-9_])and(?![A-Za-z0-9_])", "&&", q, flags=re.IGNORECASE)


def hex_strings(q, rng):
    """String literals -> hex: 'admin' -> 0x61646d696e."""
    return _LITERAL_RE.sub(lambda m: "0x" + m.group(2).encode("utf-8").hex(), q)


def keyword_split_comment(q, rng):
    """UNION -> UN/**/ION.

    SYNTACTICALLY INVALID in MySQL: a comment acts as a token separator, so
    UN/**/ION is parsed as two identifiers. Only meaningful as a detector test.
    """
    def split(m):
        w = m.group(0)
        if len(w) < 3:
            return w
        cut = len(w) // 2
        return f"{w[:cut]}/**/{w[cut:]}"
    return _KW_RE.sub(split, q)


TECHNIQUES = {
    "random_case": random_case,
    "inline_comment_space": inline_comment_space,
    "alt_whitespace": alt_whitespace,
    "alt_whitespace_url": alt_whitespace_url,
    "url_encode": url_encode,
    "double_url_encode": double_url_encode,
    "versioned_comment": versioned_comment,
    "logical_operator": logical_operator,
    "hex_strings": hex_strings,
    "keyword_split_comment": keyword_split_comment,
}

# Techniques whose output MySQL would no longer execute as the intended attack.
SYNTACTICALLY_INVALID = {"keyword_split_comment"}

# Combination rules: candidates are drawn from these slots, at most one per slot,
# and applied in this order (encoding must come last, whitespace after keyword
# rewrites so the keyword regex still sees word boundaries).
_COMBO_SLOTS = [
    ("operator", ["logical_operator"]),
    ("literal", ["hex_strings"]),
    ("case", ["random_case"]),
    ("keyword", ["versioned_comment"]),
    ("whitespace", ["inline_comment_space", "alt_whitespace"]),
    ("encoding", ["url_encode", "double_url_encode"]),
]


def combination(q, rng, exclude=()):
    """2-3 randomly chosen valid techniques applied together.

    Returns (obfuscated_query, [technique names]). keyword_split_comment is
    excluded so the combined payload stays executable. ``exclude`` removes
    techniques from the pool (used for leave-one-technique-out training).
    """
    slots = [opts for _, opts in _COMBO_SLOTS]
    slots = [[t for t in opts if t not in exclude] for opts in slots]
    slots = [opts for opts in slots if opts]
    k = rng.choice([2, 3])
    picked = rng.sample(range(len(slots)), k)
    chosen = [rng.choice(slots[i]) for i in sorted(picked)]
    for name in chosen:
        q = TECHNIQUES[name](q, rng)
    return q, chosen


def apply_technique(name, queries, seed=SEED):
    """Apply one technique (or "combination") to an iterable of queries.

    Returns a list of dicts: index, original, obfuscated, changed, techniques.
    """
    rows = []
    for i, q in enumerate(queries):
        rng = rng_for(name, i, seed)
        if name == "combination":
            out, used = combination(q, rng)
        else:
            out, used = TECHNIQUES[name](q, rng), [name]
        rows.append({"index": i, "original": q, "obfuscated": out,
                     "changed": out != q, "techniques": "+".join(used)})
    return rows
