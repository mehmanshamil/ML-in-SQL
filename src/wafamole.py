"""WAF-A-MoLE dataset (Demetrio et al., SAC 2020; github.com/zangobot/wafamole_dataset).

The repository splits attacks.sql and sane.sql into chunks; they are concatenated
in order, byte for byte (`cat attacks.sql.* > attacks.sql`). The repository is
checked out with core.autocrlf=false: on Windows git would otherwise turn the LF
line ends (and the LFs inside payloads) into CRLF.

Splitting. The README recommends `sqlparse.split()`. On attacks.sql that does not
work: the generator inserts payloads into quoted SQL literals without escaping
(e.g. `VALUES ( "" OR 3299=LIKE(...)-- NmII", 'q' )`), sqlparse loses track of the
quotes and glues the following statements together - the whole 171 MB file comes
out as 3 262 "statements", one of them 171 MB long (`split_report()` reproduces
this). Every generated statement, however, starts on a new line with one of the
generator's four templates (SELECT `..`/SELECT *, INSERT INTO `tab`, UPDATE `tab`,
DELETE FROM `tab`) right after the `;` of the previous one. The file is therefore
first cut at `;\\n` followed by a template start; segments that do not start with a
template (only the DDL header of sane.sql) are split with `sqlparse.split()`.
Result: 1 004 669 attacks, 1 000 000 generated benign statements + the header.
The result is cached as a pickle next to the raw files (data/raw/, not tracked).
"""

import re
import subprocess
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parent.parent
RAW = ROOT / "data" / "raw" / "external" / "wafamole"
REPO_DIR = RAW / "repo"
URL = "https://github.com/zangobot/wafamole_dataset.git"
COMMIT = "3eb1cef05210be04e8c55d6b45e7e2d0933803ae"
CACHE = RAW / "wafamole_split.pkl"

TEMPLATE_START = r"(?:SELECT (?:`|\*)|INSERT INTO `tab`|UPDATE `tab`|DELETE FROM `tab`)"
_BOUNDARY = re.compile(rf"(?<=;)\n(?={TEMPLATE_START})")
_START = re.compile(TEMPLATE_START)


def fetch():
    if not (REPO_DIR / ".git").exists():
        subprocess.run(["git", "-c", "core.autocrlf=false", "clone", "-q", URL, str(REPO_DIR)], check=True)
    subprocess.run(["git", "config", "core.autocrlf", "false"], cwd=REPO_DIR, check=True)
    subprocess.run(["git", "checkout", "-q", COMMIT], cwd=REPO_DIR, check=True)


def concat(prefix):
    parts = sorted(REPO_DIR.glob(f"{prefix}.sql.*"), key=lambda p: int(p.suffix[1:]))
    raw = b"".join(p.read_bytes() for p in parts)
    assert b"\r\n" not in raw, "CRLF found: check out with core.autocrlf=false"
    return raw.decode("utf-8")


def split(text):
    import sqlparse

    out = []
    for seg in _BOUNDARY.split(text):
        if not seg.strip():
            continue
        if _START.match(seg):
            out.append(seg)
        else:
            out.extend(s for s in sqlparse.split(seg) if s.strip())
    return out


def split_report(prefix, n_bytes=None):
    """README method (sqlparse.split on the whole concatenated file) vs. split()."""
    import sqlparse

    text = concat(prefix)
    if n_bytes:
        text = text[:text.rfind(";\n", 0, n_bytes) + 1]
    sp = [s for s in sqlparse.split(text) if s.strip()]
    an = split(text)
    lens = pd.Series([len(s) for s in sp])
    return {"file": f"{prefix}.sql", "bytes": len(text.encode()), "sqlparse_statements": len(sp),
            "sqlparse_max_len": int(lens.max()), "sqlparse_over_2000_chars": int((lens > 2000).sum()),
            "sqlparse_share_of_bytes_in_over_2000": float(lens[lens > 2000].sum() / lens.sum()),
            "template_split_statements": len(an), "identical_statements": len(set(sp) & set(an))}


def load():
    """DataFrame Query, Label (1 = attacks.sql, 0 = sane.sql)."""
    if CACHE.exists():
        return pd.read_pickle(CACHE)
    frames = [pd.DataFrame({"Query": split(concat(prefix)), "Label": label})
              for prefix, label in (("attacks", 1), ("sane", 0))]
    df = pd.concat(frames, ignore_index=True)
    df.to_pickle(CACHE)
    return df
