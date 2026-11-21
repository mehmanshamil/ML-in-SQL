"""open-appsec WAF Comparison Project — legitimate traffic (notebook 15).

Source: github.com/openappsec/waf-comparison-project. The repository has no data
folder; config.py loads the legitimate set from LEGIT_URL (Apache 2.0). It holds
1 040 242 browser-recorded HTTP requests in 692 browser sessions (one JSON file
per session in legitimate.zip), each a list of {method, url, headers, data}. Only the legitimate set is used.

Our models score single parameter values, so every request is reduced to the
values the Express middleware (middleware/src/sqliGuard.js) would score:

  query  — the URL query string parsed like Express (`parse_qsl`, one decode,
           `+` -> space, blank values kept);
  body   — by Content-Type, as the body parsers would see it:
           application/json                  -> every string leaf (numbers, booleans and null are
                                                not strings and are skipped, as in stringValues())
           application/x-www-form-urlencoded -> `parse_qsl` values
           multipart/form-data               -> text fields (parts without a filename)
           anything else (text/plain, protobuf, binary beacons, CSP reports, ...) -> not parsed,
           as express.json()/express.urlencoded() leave req.body empty for them.
  Keys are not scored (the middleware scores values). Values longer than 4 096
  characters are truncated to 4 096, the middleware default (maxLength, 'truncate').

A request with no extracted value cannot be blocked by the middleware.
"""

import json
import re
import zipfile
from email.parser import BytesParser
from email.policy import HTTP
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit

import pandas as pd

ROOT = Path(__file__).resolve().parent.parent
RAW = ROOT / "data" / "raw" / "external" / "openappsec"
REPO_URL = "https://github.com/openappsec/waf-comparison-project"
REPO_COMMIT = "8ec8263eebba76816601f7c7052f8ffb83e31312"
LEGIT_URL = "https://downloads.openappsec.io/waf-comparison-project/legitimate.zip"
ZIP = RAW / "legitimate.zip"
ZIP_SIZE = 1_203_983_791
ZIP_SHA256 = "58faee18c54229759287a574f6f8cb1e3b951fa135e403ea9a679d2b18efd778"   # downloaded 2026-11-17
CACHE = RAW / "openappsec_values.pkl"
MAX_LEN = 4096


PART = 64 * 1024 * 1024


def fetch():
    """Download in 64 MB HTTP range requests (the server drops long connections),
    retry each part until it has the right size, then concatenate."""
    import subprocess

    if ZIP.exists() and ZIP.stat().st_size == ZIP_SIZE:
        import hashlib
        got = hashlib.sha256(ZIP.read_bytes()).hexdigest()
        if got != ZIP_SHA256:
            print(f"Xəbərdarlıq: legitimate.zip SHA-256 fərqlidir ({got}); dataset yenilənmiş ola bilər.")
        return
    parts_dir = RAW / "parts"
    parts_dir.mkdir(parents=True, exist_ok=True)
    parts = []
    for k, start in enumerate(range(0, ZIP_SIZE, PART)):
        end = min(start + PART, ZIP_SIZE) - 1
        p = parts_dir / f"part_{k:03d}"
        for _ in range(30):
            if p.exists() and p.stat().st_size == end - start + 1:
                break
            subprocess.run(["curl", "-s", "-L", "--max-time", "600", "-r", f"{start}-{end}", "-o", str(p), LEGIT_URL])
        assert p.stat().st_size == end - start + 1, (p, p.stat().st_size)
        parts.append(p)
    with open(ZIP, "wb") as out:
        for p in parts:
            out.write(p.read_bytes())
    assert ZIP.stat().st_size == ZIP_SIZE
    for p in parts:
        p.unlink()
    parts_dir.rmdir()


def _content_type(headers):
    for k, v in (headers or {}).items():
        if k.lower() == "content-type":
            return v.split(";")[0].strip().lower(), v
    return "", ""


def _json_strings(obj):
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, list):
        for x in obj:
            yield from _json_strings(x)
    elif isinstance(obj, dict):
        for x in obj.values():
            yield from _json_strings(x)


def _multipart_fields(body, full_ct):
    msg = BytesParser(policy=HTTP).parsebytes(
        f"Content-Type: {full_ct}\r\n\r\n".encode() + body.encode("utf-8", "surrogateescape"))
    if not msg.is_multipart():
        return
    for part in msg.iter_parts():
        if part.get_filename() is None:
            payload = part.get_payload(decode=True) or b""
            yield payload.decode("utf-8", "replace")


def extract(req):
    """Yield (source, value) pairs for one recorded request."""
    q = urlsplit(req.get("url", "")).query
    for _, v in parse_qsl(q, keep_blank_values=True):
        yield "query", v
    body = req.get("data") or ""
    if not body:
        return
    ct, full_ct = _content_type(req.get("headers"))
    if ct == "application/json":
        try:
            obj = json.loads(body)
        except ValueError:
            return
        for v in _json_strings(obj):
            yield "body_json", v
    elif ct == "application/x-www-form-urlencoded":
        for _, v in parse_qsl(body, keep_blank_values=True):
            yield "body_form", v
    elif ct == "multipart/form-data":
        try:
            for v in _multipart_fields(body, full_ct):
                yield "body_multipart", v
        except Exception:
            return


def iter_requests():
    with zipfile.ZipFile(ZIP) as z:
        for info in sorted(z.infolist(), key=lambda i: i.filename):
            if not info.filename.endswith(".json"):
                continue
            site = Path(info.filename).stem
            for i, req in enumerate(json.loads(z.read(info))):
                yield site, i, req


def load():
    """(requests, values): one row per request / per extracted value.

    requests: req_id, site, method, content_type, n_values
    values:   req_id, source, value (truncated to MAX_LEN), truncated
    """
    if CACHE.exists():
        return pd.read_pickle(CACHE)
    reqs, vals = [], []
    for rid, (site, i, req) in enumerate(iter_requests()):
        ct, _ = _content_type(req.get("headers"))
        n = 0
        for src, v in extract(req):
            vals.append((rid, src, v[:MAX_LEN], len(v) > MAX_LEN))
            n += 1
        reqs.append((rid, site, req.get("method", ""), ct, n))
    requests = pd.DataFrame(reqs, columns=["req_id", "site", "method", "content_type", "n_values"])
    values = pd.DataFrame(vals, columns=["req_id", "source", "value", "truncated"])
    pd.to_pickle((requests, values), CACHE)
    return requests, values


# --- reasons for false blocks ---------------------------------------------------------

_REASONS = [
    ("SQL açar sözü təbii mətndə/identifikatorda", re.compile(
        r"\b(select|union|insert|update|delete|drop|from|where|order|group|having|join|table|like|and|or|not|null|"
        r"sleep|exec|declare|cast|char|concat|limit)\b", re.I)),
    ("dırnaq / apostrof", re.compile(r"['\"`]")),
    ("şərh və ya ayırıcı simvol (--, #, /*, ;)", re.compile(r"--|#|/\*|;")),
    ("JSON / strukturlaşdırılmış mətn", re.compile(r"^\s*[\[{].*[\]}]\s*$", re.S)),
    ("URL / yol", re.compile(r"^(https?:)?//|^/[\w\-./%]+|%[0-9a-f]{2}", re.I)),
    ("token / base64 / hash", re.compile(r"^[A-Za-z0-9+/=_\-.]{20,}$")),
    ("bərabərlik / müqayisə (=, <, >)", re.compile(r"[=<>]")),
    ("mötərizə / funksiya çağırışına bənzər", re.compile(r"\w\s*\(")),
    ("rəqəm / qısa kod", re.compile(r"^[\w\-.:]{0,12}$")),
]


def reason(v):
    """First matching coarse category (the order above is the priority)."""
    for name, rx in _REASONS:
        if rx.search(v):
            return name
    return "digər"


def all_reasons(v):
    return [name for name, rx in _REASONS if rx.search(v)] or ["digər"]
