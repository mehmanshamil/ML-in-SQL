"""Shared experiment helpers for the multi-seed (12) and char-CNN (13) notebooks.

Every function reproduces the logic of notebooks 02_v2 / 03 / 04 / 05 with the
seed as a parameter, so seed 42 gives the same split, obfuscations and
augmentation as the original notebooks.
"""

import re
from pathlib import Path
from urllib.parse import unquote

import numpy as np
import pandas as pd
from sklearn.model_selection import GroupShuffleSplit

import obfuscation as obf

ROOT = Path(__file__).resolve().parent.parent
PROC = ROOT / "data" / "processed"

TECH_ORDER = list(obf.TECHNIQUES) + ["combination"]
VALID_TECHS = [t for t in TECH_ORDER if t not in obf.SYNTACTICALLY_INVALID]
SQL_STMT_RE = r"^\s*\(?\s*(?:select|insert|update|delete|create|drop|alter|with|exec|truncate|grant)\b"


def group_key(q):
    """Normalisation used for grouping (02_v2): lowercase, collapse whitespace."""
    return re.sub(r"\s+", " ", str(q).lower()).strip()


def load_clean():
    return pd.read_csv(PROC / "clean_v2.csv", keep_default_na=False, dtype={"Query": str, "Label": int})


def make_split(df, seed):
    """70/15/15 GroupShuffleSplit by normalised query, as in 02_v2."""
    df = df.copy()
    df["group_id"] = pd.factorize(df["Query"].map(group_key))[0]
    tr_idx, rest_idx = next(GroupShuffleSplit(n_splits=1, test_size=0.30, random_state=seed)
                            .split(df, df.Label, df.group_id))
    rest = df.iloc[rest_idx]
    va_idx, te_idx = next(GroupShuffleSplit(n_splits=1, test_size=0.50, random_state=seed)
                          .split(rest, rest.Label, rest.group_id))
    train = df.iloc[tr_idx].reset_index(drop=True)
    val = rest.iloc[va_idx].reset_index(drop=True)
    test = rest.iloc[te_idx].reset_index(drop=True)
    g = [set(p.group_id) for p in (train, val, test)]
    assert not (g[0] & g[1]) and not (g[0] & g[2]) and not (g[1] & g[2])
    return train, val, test


def obfuscate(queries, seed):
    """All techniques on the given malicious queries (03). Unchanged rows dropped.

    Returns a long frame: technique, obfuscated, input_A (one unquote), input_B (raw).
    """
    frames = []
    for tech in TECH_ORDER:
        r = pd.DataFrame(obf.apply_technique(tech, list(queries), seed=seed))
        r = r[r.changed]
        frames.append(pd.DataFrame({"technique": tech, "obfuscated": r.obfuscated.values}))
    out = pd.concat(frames, ignore_index=True)
    out["input_A"] = out.obfuscated.map(unquote)
    out["input_B"] = out.obfuscated
    return out


def augment(train_df, seed, exclude=()):
    """One obfuscated copy per malicious training query (04)."""
    pool = [t for t in TECH_ORDER if t not in exclude]
    mal = train_df[train_df.Label == 1].reset_index(drop=True)
    extra = []
    for i, q in enumerate(mal.Query):
        rng = obf.rng_for("augment", i, seed)
        tech = rng.choice(pool)
        if tech == "combination":
            new, _ = obf.combination(q, rng, exclude=exclude)
        else:
            new = obf.TECHNIQUES[tech](q, rng)
        if new != q:
            extra.append(new)
    aug = pd.concat([train_df[["Query", "Label"]], pd.DataFrame({"Query": extra, "Label": 1})],
                    ignore_index=True)
    return aug


def plain_benign_mask(test):
    """Benign rows that are not full SQL statements (05: "adi giriş")."""
    is_stmt = test.Query.str.contains(SQL_STMT_RE, case=False, regex=True)
    return ((test.Label == 0) & ~is_stmt).to_numpy()


def load_httpparams():
    hp = pd.read_csv(ROOT / "data" / "raw" / "external" / "httpparams" / "payload_full.csv")
    hp = hp[hp.attack_type.isin(["norm", "sqli"])].drop_duplicates("payload")
    return pd.DataFrame({"Query": hp.payload.astype(str).values,
                         "Label": (hp.attack_type == "sqli").astype(int).values})


def leakage_free(external, *seen_frames):
    seen = set(pd.concat([f.Query for f in seen_frames]).map(group_key))
    return external[~external.Query.map(group_key).isin(seen)].reset_index(drop=True)


def rates(y, p):
    y, p = np.asarray(y), np.asarray(p)
    tp = int(((p == 1) & (y == 1)).sum())
    fp = int(((p == 1) & (y == 0)).sum())
    fn = int(((p == 0) & (y == 1)).sum())
    tn = int(((p == 0) & (y == 0)).sum())
    recall = tp / (tp + fn) if tp + fn else np.nan
    fpr = fp / (fp + tn) if fp + tn else np.nan
    prec = tp / (tp + fp) if tp + fp else 0.0
    f1 = 2 * prec * recall / (prec + recall) if prec + recall else 0.0
    return {"recall": recall, "fpr": fpr, "precision": prec, "f1": f1}
