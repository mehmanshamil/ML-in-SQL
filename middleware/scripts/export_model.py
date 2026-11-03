"""Export the trained scikit-learn pipeline to middleware/src/model.json.

Run from the project root with the project venv:
    venv/Scripts/python middleware/scripts/export_model.py

Emits the TF-IDF vocabulary (ngram -> [idf, coef]), the LR intercept and the
vectorizer config needed by the pure-JS runtime (src/model.js). Also writes a
parity fixture (test/fixtures/parity.json) with Python probabilities so the JS
port can be checked against this model.
"""

import json
import sys
from pathlib import Path

import joblib
import pandas as pd

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

MODEL = ROOT / "models" / "lr_norm_aug_v2.joblib"
OUT = ROOT / "middleware" / "src" / "model.json"
FIXTURE = ROOT / "middleware" / "test" / "fixtures" / "parity.json"


def main():
    m = joblib.load(MODEL)
    tf, clf = m.named_steps["tfidf"], m.named_steps["clf"]
    inv = {idx: ng for ng, idx in tf.vocabulary_.items()}
    idf, coef = tf.idf_, clf.coef_[0]
    vocab = {inv[i]: [float(idf[i]), float(coef[i])] for i in range(len(inv))}
    model = {
        "config": {"ngram_min": tf.ngram_range[0], "ngram_max": tf.ngram_range[1],
                   "lowercase": bool(tf.lowercase), "sublinear_tf": bool(tf.sublinear_tf), "norm": tf.norm},
        "intercept": float(clf.intercept_[0]),
        "vocab": vocab,
    }
    OUT.write_text(json.dumps(model, ensure_ascii=False), encoding="utf-8")
    print(f"wrote {OUT} ({OUT.stat().st_size} bytes, {len(vocab)} n-grams)")

    # Parity fixture: a mix of benign, malicious and obfuscated queries.
    test = pd.read_csv(ROOT / "data/processed/test_v2.csv", keep_default_na=False, dtype={"Query": str})
    obf = pd.read_csv(ROOT / "data/processed/obfuscated_test_v2.csv", keep_default_na=False)
    texts = pd.concat([
        test.sample(min(2000, len(test)), random_state=42)["Query"],
        obf[obf.scenario == "A"].sample(1000, random_state=42)["model_input"],
    ]).drop_duplicates().tolist()
    probs = m.predict_proba(texts)[:, 1]
    FIXTURE.parent.mkdir(parents=True, exist_ok=True)
    FIXTURE.write_text(json.dumps([{"q": t, "p": float(p)} for t, p in zip(texts, probs)], ensure_ascii=False),
                       encoding="utf-8")
    print(f"wrote {FIXTURE} ({len(texts)} rows)")


if __name__ == "__main__":
    main()
