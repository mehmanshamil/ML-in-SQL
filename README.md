# SQLi detectors, format artifacts and obfuscation

Code and data pipeline for the paper *"Robustness of ML-based SQL injection detectors to format artifacts and
obfuscation: an experimental analysis and a normalization-based defense"* (in Azerbaijani; English abstract).

**Main finding.** On the widely used Kaggle SQLi dataset, classical detectors reach F1 ≈ 0.997, but part of that
score comes from a formatting artifact: 95% of malicious queries carry sqlmap-style double spacing (`1  =  1`)
against 30% of benign ones. Replacing whitespace characters drops LR recall to ~78% and RF to ~33%. Canonicalizing
the input before the model (`src/normalize.py`) removes the effect; augmentation does not generalize to unseen
techniques. Results are checked on 5 group-aware splits, an external dataset (HttpParamsDataset), a char-CNN,
libinjection, the blacklist filter from the author's earlier paper, real MySQL execution, and a pure-JS Express
middleware.

> Notebooks and comments are in Azerbaijani; file and column names are in English.

## Reproducing

Requirements: Python 3.13, Node.js ≥ 20, (optional) MySQL 8.0 for notebooks 05–06.

```bash
python -m venv venv
venv\Scripts\activate                     # Linux/macOS: source venv/bin/activate
pip install -r requirements.txt
pip install torch==2.15.0 --index-url https://download.pytorch.org/whl/cpu   # notebook 13 only
python tools/build_libinjection.py        # notebooks 11, 12: builds libinjection 4.0.1 with zig cc
```

Data:

| File | Source | How to get it |
|---|---|---|
| `data/raw/Modified_SQL_Dataset.csv` | Kaggle `sajid576/sql-injection-dataset` | download manually (columns `Query`, `Label`) |
| `data/raw/external/httpparams/payload_full.csv` | GitHub `Morzeux/HttpParamsDataset` | notebook 10 downloads it, SHA-256 checked |
| `data/raw/external/sqliv3/*.csv` | Kaggle `syedsaqlainhussain/sql-injection-dataset` v5 | notebook 10 downloads it via `kagglehub`, SHA-256 checked |

`data/raw/`, `models/`, `third_party/` and the large MySQL run logs are not tracked; every notebook regenerates
what the next one needs. Run the notebooks **in numeric order** (from `notebooks/` or the repo root):

```bash
jupyter nbconvert --to notebook --execute --inplace notebooks/01_data_analysis.ipynb   # etc.
```

Random seed is always 42 (notebooks 12 and 13 use seeds 42–46). Figures are saved as 300 dpi PNG to `figures/`,
tables as CSV to `results/`.

### MySQL execution test (notebooks 05, 06, 09)

Creates an isolated database `sqli_ml_eval` and a **SELECT-only** user, so injected `DROP`/`INSERT`/`INTO OUTFILE`
fail with a privilege error. Run `sql/setup_eval_db.sql` as root, then create `.env` in the repo root:

```
MYSQL_EVAL_USER=sqli_eval
MYSQL_EVAL_PASSWORD=...
```

Notebooks 09, 11 and 12 read the saved `data/processed/06_mysql_effectiveness.csv` and do not need MySQL.

### Middleware (`middleware/`)

Pure-JavaScript port of the final model as Express middleware; see `middleware/README.md`.

```bash
cd middleware && npm install
python scripts/export_model.py   # models/lr_norm_aug_v2.joblib -> src/model.json
npm test                         # Python/JS parity
npm run attack-test              # live HTTP attack test
npm run bench                    # latency (autocannon)
node bench/dos_test.js           # input length vs processing time
```

## What produces what

Paper tables and figures (the multi-seed versions in notebook 12 report the same quantities as mean ± std
over 5 splits):

| Paper | Content | Notebook / script | Output |
|---|---|---|---|
| Table 1 | Obfuscation techniques | `src/obfuscation.py`, 03 | `results/03_examples.csv` |
| Table 2 | Baseline models | 02_v2 (seed 42), 12 | `baseline_results_v2.csv`, `12_T2_baseline_mean_std.csv` |
| Table 3 | Recall per technique, raw traffic (B) | 03, 12 | `obfuscation_recall_table_B.csv`, `12_T3_obf_B_mean_std.csv` |
| Table 4 | LR defenses, scenario A (normalization, augmentation LOTO) | 04, 12 | `04_defense_table_A.csv`, `12_T4_defense_A_mean_std.csv` |
| Table 5 | Blacklist vs libinjection vs ML (+ MySQL bypass) | 05, 06, 09, 11, 12 | `11_detector_comparison.csv`, `09_bypass_full_set.csv`, `12_T5_detectors_mean_std.csv` |
| Table 6 | Input length vs processing time (DoS) | `middleware/bench/dos_test.js` | `middleware_dos.csv` |
| Table 7 | Middleware latency | `middleware/bench/run_bench.js`, 09 | `middleware_latency.csv` |
| Cross-dataset | HttpParamsDataset, dataset overlap, independence | 10, 12 | `10_*.csv`, `12_HTTPPARAMS_mean_std.csv` |
| char-CNN | Does a neural model learn the artifact too? | 13 | `13_char_cnn_mean_std.csv`, `13_cnn_vs_lr.csv` |
| Fig. 1 | LR defenses, scenario A | 04 | `figures/04_defense_recall_A.png` |
| Paper figures | Pipeline, FPR–recall, HttpParams | 14 | `figures/paper/*.png` |

All notebooks:

| # | Notebook | Purpose |
|---|---|---|
| 01 | `01_data_analysis` | Dataset analysis, cleaning → `clean.csv` |
| 02 | `02_baseline_models`, `02_baseline_models_v2` | Excel-artifact removal → `clean_v2.csv`; group-aware 70/15/15 split; TF-IDF + LR/SVM/RF/NB |
| 03 | `03_obfuscation_eval` | 11 obfuscation techniques on test malicious queries; threat scenarios A (decoded once) / B (raw) |
| 04 | `04_robustness_defenses` | Format-artifact test, normalization, augmentation with leave-one-technique-out |
| 05 | `05_blacklist_vs_ml` | Python port of the earlier paper's blacklist (50/50 Node.js parity), MySQL pilot (300 payloads) |
| 06 | `06_mysql_full_eval` | MySQL execution of all 1 745 malicious test payloads in 10 contexts |
| 07 | `07_middleware_threshold` | Threshold / ROC for the middleware model |
| 08 | `08_threshold_and_failure` | Threshold selected on validation; failure attribution |
| 09 | `09_reconciliation_bootstrap` | Payload-count reconciliation, cluster-bootstrap CIs, final tables |
| 10 | `10_cross_dataset` | External datasets: overlap, HttpParamsDataset test, independence analysis |
| 11 | `11_libinjection` | libinjection 4.0.1 on the same test sets |
| 12 | `12_multiseed` | All main tables over seeds 42–46 (mean ± std) + seed-42 reproduction check |
| 13 | `13_char_cnn` | Byte-level CNN (PyTorch, CPU), baseline vs normalization |
| 14 | `14_paper_figures` | Figures for the paper → `figures/paper/` |

## Layout

```
src/            normalize.py, obfuscation.py, blacklist.py, libinj.py (ctypes), experiments.py (shared helpers)
tools/          build_libinjection.py
notebooks/      01–14, run in order
data/processed/ cleaned data, splits, obfuscated test set, MySQL effectiveness
results/        CSV tables
figures/        300 dpi PNG; figures/paper/ = figures used in the paper
middleware/     Express middleware (pure JS) with parity test, attack test and benchmarks
sql/            MySQL setup for the execution test
```

## libinjection

The official C library (`libinjection/libinjection`, tag v4.0.1, tarball SHA-256 pinned in
`tools/build_libinjection.py`) is compiled from source with `zig cc` from the `ziglang` pip package and called through
`ctypes` (`src/libinj.py`). This avoids depending on unmaintained Python bindings, which have no Windows/Python 3.13
wheels. It is the same `libinjection_sqli()` that ModSecurity exposes as `@detectSQLi`; CRS transformations are not
applied, so it sees the same input as the other detectors.

## License and data

The middleware package is MIT (`middleware/package.json`); a license for the rest of the repository will be added
before it is made public. The datasets belong to their authors and are not redistributed here.
