"""TF-IDF detectors with the same grids and tuning as notebook 12 (copied from it,
so notebook 14 trains exactly the models that 12 trains for a given seed)."""

import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import f1_score
from sklearn.naive_bayes import MultinomialNB
from sklearn.svm import LinearSVC

import libinj
from blacklist import flags, sanitize_input, sanitize_search

GRID_BASE = {"LR": [0.1, 1, 10, 100], "SVM": [0.01, 0.1, 1, 10], "RF": [(200, 1), (200, 2), (400, 1)],
             "NB": [0.001, 0.01, 0.1, 1.0]}
GRID_DEF = {"LR": [1, 10, 100], "SVM": [0.1, 1, 10], "RF": [200], "NB": [0.001, 0.01, 0.1]}


def vectorizer():
    return TfidfVectorizer(analyzer="char", ngram_range=(1, 5), lowercase=True,
                           sublinear_tf=True, min_df=2, dtype=np.float32)


def makers(seed):
    return {
        "LR": lambda p: LogisticRegression(C=p, max_iter=2000, random_state=seed),
        "SVM": lambda p: LinearSVC(C=p, random_state=seed),
        "RF": lambda p: (RandomForestClassifier(n_estimators=p[0], min_samples_leaf=p[1], n_jobs=-1, random_state=seed)
                         if isinstance(p, tuple) else RandomForestClassifier(n_estimators=p, n_jobs=-1, random_state=seed)),
        "NB": lambda p: MultinomialNB(alpha=p),
    }


class Fitted:
    """prep (optional) -> fitted vectorizer -> fitted classifier, predict on raw strings."""
    def __init__(self, vec, clf, prep=None):
        self.vec, self.clf, self.prep = vec, clf, prep

    def predict(self, xs):
        xs = list(xs)
        if self.prep:
            xs = [self.prep(x) for x in xs]
        return self.clf.predict(self.vec.transform(xs)).astype(int)


def fit_tuned(name, grid, seed, X, y, val, prep=None, vec=None):
    xs = [prep(x) for x in X] if prep else list(X)
    vec = vec or vectorizer().fit(xs)
    Xtr = vec.transform(xs)
    vx = vec.transform([prep(x) for x in val.Query] if prep else val.Query)
    best = None
    for p in grid:
        clf = makers(seed)[name](p).fit(Xtr, y)
        f1 = f1_score(val.Label, clf.predict(vx))
        if best is None or f1 > best[2]:
            best = (clf, p, f1)
    return Fitted(vec, best[0], prep), best[1], vec


def train_all(seed, train, val):
    """The six TF-IDF detectors of notebooks 12/14 for one split, cached in models/.

    Returns {name: Fitted}. Order and grids as in notebook 14 (seed 42–46 give the
    same models as 12 and 14).
    """
    import joblib
    from pathlib import Path

    from experiments import augment
    from normalize import normalize

    path = Path(__file__).resolve().parent.parent / "models" / f"tfidf_detectors_{seed}.joblib"
    if path.exists():
        return joblib.load(path)
    y = train.Label.to_numpy()
    out, vec = {}, None
    for name in ("LR", "SVM", "RF", "NB"):
        out[f"{name} baza"], _, vec = fit_tuned(name, GRID_BASE[name], seed, train.Query, y, val, vec=vec)
    out["LR + normallaşdırma"], _, _ = fit_tuned("LR", GRID_DEF["LR"], seed, train.Query, y, val, prep=normalize)
    aug = augment(train, seed)
    out["LR + norm. + augmentation"], _, _ = fit_tuned("LR", GRID_DEF["LR"], seed, aug.Query, aug.Label.to_numpy(),
                                                       val, prep=normalize)
    path.parent.mkdir(exist_ok=True)
    joblib.dump(out, path)
    return out


def vec_det(fn):
    return lambda xs: np.array([fn(x) for x in xs], dtype=int)


BL_INPUT = vec_det(lambda q: flags(q, sanitize_input))
BL_SEARCH = vec_det(lambda q: flags(q, sanitize_search))
LIBINJ = vec_det(libinj.is_sqli)
