"""Hand-written SQLi payload lists (notebook 14; also used by notebook 13).

Sources (pinned commits, sparse checkout into data/raw/external/handwritten/):
  - swisskyrepo/PayloadsAllTheThings, `SQL Injection/Intruder/*`   (MIT)
  - fuzzdb-project/fuzzdb, `attack/sql-injection/**/*.txt`        (BSD-3-Clause / CC BY 3.0)

Only the plain-text payload lists are used. The Markdown cheat sheets of
PayloadsAllTheThings mix payloads with prose and are not parsed.

Cleaning, in this order (every dropped line is kept with its reason):
  1. strip CR/LF; text after the first TAB is a description (cheat-sheet lines) -> cut;
     strip surrounding whitespace
  2. empty line                                   -> "empty"
  3. `# word ...` line                            -> "comment"
  4. fuzzer placeholders replaced by fixed values (PLACEHOLDERS)
  5. no SQL token (bare fuzz characters such as `'`, `%00`, `1*56`, single fuzz
     words such as `asc`, LDAP probes, or prose headings such as `Time-Based:`)
                                                  -> "no_sql_token"
  6. duplicate of an earlier kept line, compared on the model input
     (one URL decode = scenario A, the same as the middleware sees)  -> "duplicate"
Files are read in sorted order, PayloadsAllTheThings first, so a payload is
credited to the first file that contains it.
"""

import re
import subprocess
from pathlib import Path
from urllib.parse import unquote

import pandas as pd

from normalize import normalize

ROOT = Path(__file__).resolve().parent.parent
RAW_DIR = ROOT / "data" / "raw" / "external" / "handwritten"
PROCESSED = ROOT / "data" / "processed" / "14_handwritten_payloads.csv"

REPOS = {
    "PayloadsAllTheThings": {
        "url": "https://github.com/swisskyrepo/PayloadsAllTheThings.git",
        "commit": "08ea40e77db3f42ef8f20c65196f3936a19b6c86",
        "sparse": "SQL Injection",
        "glob": "SQL Injection/Intruder/*",
        "license": "MIT",
        "license_file": "LICENSE",
    },
    "fuzzdb": {
        "url": "https://github.com/fuzzdb-project/fuzzdb.git",
        "commit": "5656ab25dc6bb43bae32236fab775658a90d7380",
        "sparse": "attack/sql-injection",
        "glob": "attack/sql-injection/**/*.txt",
        "license": "BSD-3-Clause / CC BY 3.0",
        "license_file": "_copyright.txt",
    },
}

PLACEHOLDERS = {
    "__TIME__": "5",
    "<username>": "admin",
    "<filepath>": "/etc/passwd",
    "<attackerip>": "10.10.1.2",
    "<sharename>": "share",
    "<user-fieldname>": "username",
    "<pass-fieldname>": "password",
}

_COMMENT_RE = re.compile(r"^#\s*[A-Za-z]")
_SQL_WORDS = (
    r"select|union|insert|update|delete|drop|create|alter|truncate|exec|execute|declare|"
    r"waitfor|delay|sleep|pg_sleep|benchmark|or|and|xor|not|like|rlike|regexp|having|order|group|"
    r"where|from|into|outfile|dumpfile|load_file|limit|offset|null|true|false|if|case|when|then|"
    r"cast|convert|char|chr|concat|substring|substr|mid|ascii|ord|version|user|current_user|"
    r"session_user|system_user|database|schema|extractvalue|updatexml|desc|shutdown|grant|"
    r"randomblob|xp_\w+|sp_\w+|utl_\w+|dbms_\w+|information_schema|sysobjects|sysdatabases|load"
)
_SQL_TOKEN_RE = re.compile(rf"\b(?:{_SQL_WORDS})\b|@@\w+|\d(?:or|and)\d", re.I)
_INLINE_COMMENT_RE = re.compile(r"/\*.*?\*/")
_BARE_WORD_RE = re.compile(r"^\w+$")
_QUOTE_RE = re.compile(r"['\"`’‘“”]")
_SYNTAX_RE = re.compile(r"--|/\*|#|;|=|\|\|")


def has_sql_token(s):
    """A payload must contain a SQL keyword/function (also when split by inline
    comments, `uni/**/on`), or a quote together with SQL syntax (comment, `;`, `=`,
    `||`), e.g. `' --`. A single bare word (`select`, `asc`) is a fuzz word, not a payload."""
    if _BARE_WORD_RE.match(s):
        return False
    t = _INLINE_COMMENT_RE.sub("", s)
    return bool(_SQL_TOKEN_RE.search(s) or _SQL_TOKEN_RE.search(t)) or bool(_QUOTE_RE.search(s) and _SYNTAX_RE.search(s))


def fetch():
    """Sparse, depth-1 checkout of the pinned commits (skipped if present)."""
    for name, r in REPOS.items():
        d = RAW_DIR / name
        if (d / ".git").exists():
            continue
        d.mkdir(parents=True, exist_ok=True)
        for cmd in (["git", "init", "-q"], ["git", "remote", "add", "origin", r["url"]],
                    ["git", "sparse-checkout", "set", "--no-cone", r["sparse"], "/" + r["license_file"]],
                    ["git", "fetch", "-q", "--depth", "1", "--filter=blob:none", "origin", r["commit"]],
                    ["git", "checkout", "-q", "FETCH_HEAD"]):
            subprocess.run(cmd, cwd=d, check=True)


def checked_out_commit(name):
    return subprocess.run(["git", "rev-parse", "HEAD"], cwd=RAW_DIR / name, check=True,
                          capture_output=True, text=True).stdout.strip()


def source_files():
    files = []
    for name, r in REPOS.items():
        base = RAW_DIR / name
        for p in sorted(base.glob(r["glob"])):
            if p.is_file() and p.suffix.lower() != ".md":
                files.append((name, p.relative_to(base).as_posix(), p))
    return files


def _read_lines(path):
    raw = path.read_bytes()
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        text = raw.decode("latin-1")
    return text.splitlines()


def build():
    """Return (kept, dropped) DataFrames. kept.Query is the model input (scenario A)."""
    kept, dropped, seen = [], [], set()
    for repo, rel, path in source_files():
        for ln, line in enumerate(_read_lines(path), 1):
            raw = line
            s = line.split("\t", 1)[0].strip()
            row = {"repo": repo, "file": rel, "line": ln, "raw": raw}
            if not s:
                dropped.append({**row, "reason": "empty"}); continue
            if _COMMENT_RE.match(s):
                dropped.append({**row, "reason": "comment"}); continue
            for k, v in PLACEHOLDERS.items():
                s = s.replace(k, v)
            if not has_sql_token(unquote(s)):
                dropped.append({**row, "reason": "no_sql_token"}); continue
            q = unquote(s)
            if q in seen:
                dropped.append({**row, "reason": "duplicate"}); continue
            seen.add(q)
            kept.append({**row, "payload": s, "Query": q})
    return pd.DataFrame(kept), pd.DataFrame(dropped)


def load():
    """Saved payload set (written by notebook 14): Query, Label=1, source columns."""
    d = pd.read_csv(PROCESSED, keep_default_na=False, dtype={"Query": str, "payload": str})
    return d.assign(Label=1)


# --- independence keys ---------------------------------------------------------------

def ws_key(q):
    """Lowercase + collapse whitespace (= experiments.group_key, the HttpParams leakage key)."""
    return re.sub(r"\s+", " ", str(q).lower()).strip()


def norm_key(q):
    """Full defense normalisation (src/normalize.py)."""
    return normalize(str(q))


_STR_RE = re.compile(r"'[^']*'|\"[^\"]*\"")
_HEX_RE = re.compile(r"\b0x[0-9a-f]+\b")
_NUM_RE = re.compile(r"\b\d+\b")


def skeleton(q):
    """Template key: normalised, string literals -> 's', hex -> 0x, numbers -> 0.

    sqlmap fills its templates with random numbers (`and 6467=6467`) and random
    strings (`'avjk'`), so payloads from the same template share a skeleton.
    """
    s = normalize(str(q))
    s = _STR_RE.sub("'s'", s)
    s = _HEX_RE.sub("0x", s)
    return _NUM_RE.sub("0", s)


def leakage_free_norm(payloads, *seen_frames):
    """Drop payloads whose normalised form occurs in the given frames (train + val)."""
    seen = set(pd.concat([f.Query for f in seen_frames]).map(norm_key))
    return payloads[~payloads.Query.map(norm_key).isin(seen)].reset_index(drop=True)
