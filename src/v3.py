"""Combined dataset v3 (notebook 17): build, clean, split, train, evaluate.

Sources (every row: query, label, source):
  kaggle      Modified_SQL_Dataset, clean_v2 (all rows)
  httpparams  HttpParamsDataset, sqli + norm (all rows)
  wafamole    WAF-A-MoLE, 40 000 random statements per class (after dedup and
              removing statements present in both classes, as in notebook 16)
  openappsec  open-appsec legitimate set, 40 000 random unique non-empty parameter
              values extracted as in notebook 15 (label 0)
The hand-written payload lists of notebook 14 are test-only: every v3 row whose
normalized form equals a payload's normalized form is removed.

Everything is written to data/v3/, results/v3/, figures/v3/ and models/v3/;
earlier results are not touched.
"""

import re
import time
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import torch
from sklearn.metrics import roc_auc_score
from sklearn.model_selection import GroupShuffleSplit

import charcnn
import handwritten as hw
import obfuscation as obf
import openappsec as oa
import wafamole as wm
from detectors import makers, vectorizer
from experiments import load_clean, load_httpparams
from normalize import normalize

ROOT = Path(__file__).resolve().parent.parent
DATA, RES, FIG, MODELS = (ROOT / "data" / "v3", ROOT / "results" / "v3", ROOT / "figures" / "v3", ROOT / "models" / "v3")

SAMPLE_SEED = 42
N_WAFAMOLE_PER_CLASS = 40_000
N_OPENAPPSEC = 40_000
SOURCES = ["kaggle", "httpparams", "wafamole", "openappsec"]          # also the dedup priority
SOURCE_LABEL = {"kaggle": "Kaggle", "httpparams": "HttpParams", "wafamole": "WAF-A-MoLE", "openappsec": "open-appsec"}
SOURCE_INFO = {
    "kaggle": ("Modified_SQL_Dataset (sajid576)", "https://www.kaggle.com/datasets/sajid576/sql-injection-dataset"),
    "httpparams": ("HttpParamsDataset (Morzeux)", "https://github.com/Morzeux/HttpParamsDataset"),
    "wafamole": ("WAF-A-MoLE dataset (zangobot)", "https://github.com/zangobot/wafamole_dataset"),
    "openappsec": ("open-appsec WAF comparison, legitimate.zip", "https://github.com/openappsec/waf-comparison-project"),
}

# Hyperparameter grids (tuned on validation F1). Same grid for baseline and normalized
# input = the defense grids of notebooks 12/14 (GRID_DEF), to keep the larger data tractable.
GRID = {"LR": [1, 10, 100], "SVM": [0.1, 1, 10], "RF": [200], "NB": [0.001, 0.01, 0.1]}
CONFIGS = {"baza": None, "norm.": normalize}
MODEL_ORDER = [f"{m} {c}" for m in ("LR", "SVM", "RF", "NB", "CNN") for c in CONFIGS]


# --- 1. sources --------------------------------------------------------------------

def raw_sources():
    """Concatenated raw rows (Query, Label, source) before cross-source cleaning."""
    k = load_clean()[["Query", "Label"]].assign(source="kaggle")
    h = load_httpparams().assign(source="httpparams")

    w = wm.load().drop_duplicates()
    both = set(w.loc[w.Label == 0, "Query"]) & set(w.loc[w.Label == 1, "Query"])
    w = w[~w.Query.isin(both)]
    rng = np.random.RandomState(SAMPLE_SEED)
    w = pd.concat([w[w.Label == lab].sort_values("Query").sample(N_WAFAMOLE_PER_CLASS, random_state=rng)
                   for lab in (1, 0)]).assign(source="wafamole")

    _, values = oa.load()
    u = pd.Series(sorted(set(values.value)))
    u = u[u.str.strip() != ""]
    # drop values that cannot be written as UTF-8 (lone surrogates from binary junk)
    u = u[~u.str.contains("[\ud800-\udfff]", regex=True)]
    u = u.sample(N_OPENAPPSEC, random_state=np.random.RandomState(SAMPLE_SEED))
    o = pd.DataFrame({"Query": u.values, "Label": 0, "source": "openappsec"})

    df = pd.concat([k, h, w, o], ignore_index=True)
    df["Query"] = df.Query.astype(str)
    df["Label"] = df.Label.astype(int)
    return df


# --- 2. cleaning -------------------------------------------------------------------

def clean(raw):
    """Cross-source cleaning. Returns (clean_df with column nk, per-source report)."""
    df = raw.copy()
    rep = {s: {"ilkin": int((df.source == s).sum())} for s in SOURCES}

    def drop(mask, step):
        for s in SOURCES:
            rep[s][step] = int((mask & (df.source == s)).sum())
        return df[~mask].reset_index(drop=True)

    df = drop(df.Query.str.strip() == "", "boş")
    df = drop(df.duplicated(["source", "Query"]), "mənbə daxilində tam dublikat")
    df["nk"] = df.Query.map(normalize)
    n_labels = df.groupby("nk").Label.nunique()
    df = drop(df.nk.isin(n_labels[n_labels > 1].index), "iki sinifdə (normallaşdırılmış forma)")
    pay = set(hw.load().Query.map(normalize))
    df = drop(df.nk.isin(pay), "payload siyahıları ilə üst-üstə (14, yalnız test)")
    df["_prio"] = df.source.map(SOURCES.index)
    df = df.sort_values(["_prio"], kind="stable")
    df = drop(df.duplicated("Query"), "mənbələr arası tam dublikat")
    first_src = df.groupby("nk")._prio.transform("min")
    df = drop(df._prio > first_src, "mənbələr arası normallaşdırılmış dublikat")
    df = df.drop(columns="_prio").reset_index(drop=True)
    for s in SOURCES:
        d = df[df.source == s]
        rep[s].update({"yekun": len(d), "zərərli": int(d.Label.sum()), "təmiz": int((d.Label == 0).sum())})
    report = pd.DataFrame(rep).T
    report.loc["cəmi"] = report.sum()
    return df, report


# --- 3. split ----------------------------------------------------------------------

def split(df, seed):
    """Per-source group split 70/15/15 (group = normalized form), then concatenated."""
    parts = {"train": [], "val": [], "test": []}
    for s in SOURCES:
        d = df[df.source == s].reset_index(drop=True)
        g = pd.factorize(d.nk)[0]
        tr, rest = next(GroupShuffleSplit(n_splits=1, test_size=0.30, random_state=seed).split(d, d.Label, g))
        r = d.iloc[rest].reset_index(drop=True)
        va, te = next(GroupShuffleSplit(n_splits=1, test_size=0.50, random_state=seed).split(r, r.Label, g[rest]))
        parts["train"].append(d.iloc[tr])
        parts["val"].append(r.iloc[va])
        parts["test"].append(r.iloc[te])
    out = [pd.concat(parts[p], ignore_index=True) for p in ("train", "val", "test")]
    gs = [set(p.source + "\x00" + p.nk) for p in out]
    assert not (gs[0] & gs[1]) and not (gs[0] & gs[2]) and not (gs[1] & gs[2])
    return out


# --- 4. models ---------------------------------------------------------------------

class TfidfModel:
    def __init__(self, vec, clf, prep):
        self.vec, self.clf, self.prep = vec, clf, prep

    def _X(self, xs):
        xs = list(xs)
        return self.vec.transform([self.prep(x) for x in xs] if self.prep else xs)

    def predict_score(self, xs):
        X = self._X(xs)
        pred = self.clf.predict(X).astype(int)
        score = self.clf.decision_function(X) if hasattr(self.clf, "decision_function") and not hasattr(
            self.clf, "predict_proba") else self.clf.predict_proba(X)[:, 1]
        return pred, score


class CNNModel:
    def __init__(self, det):
        self.det = det

    def predict_score(self, xs):
        p = self.det.proba(list(xs))
        return (p >= 0.5).astype(int), p


def train_tfidf(cfg, seed, train, val, tag):
    """Four TF-IDF classifiers sharing one vectorizer; cached per (tag, cfg, seed)."""
    path = MODELS / f"tfidf_{tag}_{'base' if cfg == 'baza' else 'norm'}_{seed}.joblib"
    if path.exists():
        return joblib.load(path)
    prep = CONFIGS[cfg]
    xs = [prep(x) for x in train.Query] if prep else list(train.Query)
    vx_raw = [prep(x) for x in val.Query] if prep else list(val.Query)
    vec = vectorizer().fit(xs)
    Xtr, Xva = vec.transform(xs), vec.transform(vx_raw)
    y, yv = train.Label.to_numpy(), val.Label.to_numpy()
    out, info = {}, {}
    for name in ("LR", "SVM", "RF", "NB"):
        best = None
        for p in GRID[name]:
            t0 = time.perf_counter()
            clf = makers(seed)[name](p).fit(Xtr, y)
            pv = clf.predict(Xva)
            tp, fp, fn = ((pv == 1) & (yv == 1)).sum(), ((pv == 1) & (yv == 0)).sum(), ((pv == 0) & (yv == 1)).sum()
            f1 = 2 * tp / (2 * tp + fp + fn) if tp else 0.0
            print(f"    {tag} {cfg} {name} p={p} valF1={f1:.4f} ({time.perf_counter() - t0:.0f} s)", flush=True)
            if best is None or f1 > best[2]:
                best = (clf, p, f1)
        out[f"{name} {cfg}"] = TfidfModel(vec, best[0], prep)
        info[f"{name} {cfg}"] = {"param": best[1], "val_f1": best[2]}
    MODELS.mkdir(parents=True, exist_ok=True)
    joblib.dump((out, info), path)
    return out, info


def train_cnn(cfg, seed, train, val, tag, epochs):
    path = MODELS / f"cnn_{tag}_{'base' if cfg == 'baza' else 'norm'}_{seed}.pt"
    prep = str.lower if cfg == "baza" else normalize
    det = charcnn.CNNDetector(prep)
    if path.exists():
        ck = torch.load(path, weights_only=True)
        det.model = charcnn.CharCNN()
        det.model.load_state_dict(ck["state"])
        det.epochs, det.best_val_f1 = int(ck["epochs"]), float(ck["val_f1"])
    else:
        old, charcnn.EPOCHS = charcnn.EPOCHS, epochs
        try:
            t0 = time.perf_counter()
            det.fit(train, val, seed)
            print(f"    {tag} CNN {cfg} seed {seed}: epochs={det.epochs} valF1={det.best_val_f1:.4f} "
                  f"({time.perf_counter() - t0:.0f} s)", flush=True)
        finally:
            charcnn.EPOCHS = old
        MODELS.mkdir(parents=True, exist_ok=True)
        torch.save({"state": det.model.state_dict(), "epochs": det.epochs, "val_f1": det.best_val_f1}, path)
    return CNNModel(det), {"param": f"epochs={det.epochs}", "val_f1": det.best_val_f1}


def train_models(seed, train, val, tag, cnn=True, cnn_epochs=10):
    models, info = {}, {}
    for cfg in CONFIGS:
        m, i = train_tfidf(cfg, seed, train, val, tag)
        models.update(m)
        info.update(i)
    if cnn:
        for cfg in CONFIGS:
            models[f"CNN {cfg}"], info[f"CNN {cfg}"] = train_cnn(cfg, seed, train, val, tag, cnn_epochs)
    return models, info


# --- 5. evaluation -----------------------------------------------------------------

def alt_ws(queries, label, seed):
    """alt_whitespace on malicious rows only (attacker-side change); benign unchanged.
    Applied directly to the model input, as in notebook 14."""
    q = list(queries)
    out = [obf.alt_whitespace(x, obf.rng_for("alt_whitespace", i, seed)) if lab == 1 else x
           for i, (x, lab) in enumerate(zip(q, label))]
    return out


def metrics(y, pred, score):
    y, pred = np.asarray(y), np.asarray(pred)
    tp = int(((pred == 1) & (y == 1)).sum()); fp = int(((pred == 1) & (y == 0)).sum())
    fn = int(((pred == 0) & (y == 1)).sum()); tn = int(((pred == 0) & (y == 0)).sum())
    pos, neg = tp + fn, fp + tn
    prec = tp / (tp + fp) if tp + fp else np.nan
    rec = tp / pos if pos else np.nan
    return {"n": len(y), "n_malicious": pos, "n_benign": neg,
            "accuracy": (tp + tn) / len(y) if len(y) else np.nan,
            "precision": prec if pos and neg else np.nan,
            "recall": rec,
            "f1": 2 * tp / (2 * tp + fp + fn) if pos and neg and (2 * tp + fp + fn) else np.nan,
            "roc_auc": roc_auc_score(y, score) if pos and neg else np.nan,
            "fpr": fp / neg if neg else np.nan,
            "tp": tp, "fp": fp, "fn": fn, "tn": tn}


def evaluate(models, sets, seed, exp):
    """sets: {name: DataFrame(Query, Label)} -> long rows (normal and alt_whitespace input)."""
    rows = []
    for set_name, d in sets.items():
        variants = {"normal": list(d.Query), "alt_whitespace": alt_ws(d.Query, d.Label, seed)}
        for var, xs in variants.items():
            for mname, m in models.items():
                pred, score = m.predict_score(xs)
                rows.append({"experiment": exp, "seed": seed, "model": mname, "test": set_name, "input": var,
                             **metrics(d.Label, pred, score)})
    return rows


def evaluate_sliced(models, d, slices, seed, exp):
    """Predict once on d (normal and alt_whitespace), report metrics for every boolean slice."""
    rows = []
    y = d.Label.to_numpy()
    variants = {"normal": list(d.Query), "alt_whitespace": alt_ws(d.Query, d.Label, seed)}
    for var, xs in variants.items():
        for mname, m in models.items():
            pred, score = m.predict_score(xs)
            for set_name, mask in slices.items():
                mask = np.asarray(mask)
                rows.append({"experiment": exp, "seed": seed, "model": mname, "test": set_name, "input": var,
                             **metrics(y[mask], pred[mask], score[mask])})
    return rows


def cached_rows(key, fn):
    """Evaluation rows of one (experiment, seed) step, saved in models/v3/rows/ so an
    interrupted run resumes where it stopped instead of recomputing finished steps."""
    f = MODELS / "rows" / f"{key}.pkl"
    if f.exists():
        return pd.read_pickle(f)
    rows = fn()
    f.parent.mkdir(parents=True, exist_ok=True)
    pd.to_pickle(rows, f)
    return rows


# --- 6. artifact helpers -----------------------------------------------------------

ART = {
    "double_space": lambda q: q.str.contains("  ", regex=False),
    "newline": lambda q: q.str.contains(r"[\r\n]", regex=True),
    "comment": lambda q: q.str.contains(r"--|#|/\*", regex=True),
}
ART_LABEL = {"double_space": "İkiqat boşluq", "newline": "Sətir sonu (\\n, \\r)", "comment": "Şərh (--, #, /*)"}

_KW = re.compile(r"select|union|insert|update|delete|from|where|and|or|order|sleep|null|table|char|concat", re.I)


def ngram_category(g):
    if re.search(r"[\r\n]", g):
        return "sətir sonu"
    if "--" in g or "#" in g or "/*" in g or "*/" in g:
        return "şərh"
    if "  " in g:
        return "ikiqat boşluq"
    if g.strip() == "" or (g != g.strip() and len(g.strip()) <= 1):
        return "boşluq / tək simvol + boşluq"
    if re.fullmatch(r"[a-z]{1,2}", g) and not _KW.search(g):
        return "tək / iki hərf (təsadüfi literal?)"
    if _KW.search(g):
        return "SQL açar sözü (parça)"
    if re.fullmatch(r"[\d\s]+", g):
        return "rəqəm"
    return "durğu / digər"
