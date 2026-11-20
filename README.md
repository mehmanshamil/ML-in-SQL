# SQLi detectors, format artifacts and obfuscation

Code and data pipeline for the paper *"Robustness of ML-based SQL injection detectors to format artifacts and
obfuscation: an experimental analysis and a normalization-based defense"* (in Azerbaijani; English abstract).

**Main finding.** On the widely used Kaggle SQLi dataset, classical detectors reach F1 ≈ 0.997, but part of that
score comes from a formatting artifact: 95% of malicious queries carry sqlmap-style double spacing (`1  =  1`)
against 30% of benign ones. Replacing whitespace characters drops LR recall to ~78% and RF to ~33%. Canonicalizing
the input before the model (`src/normalize.py`) removes the effect; augmentation does not generalize to unseen
techniques. Results are checked on 5 group-aware splits, an external dataset (HttpParamsDataset), hand-written
payload lists (PayloadsAllTheThings, fuzzdb), real benign web traffic (open-appsec), the WAF-A-MoLE dataset, a char-CNN,
libinjection, the blacklist filter from the author's earlier paper, real MySQL execution, and a pure-JS Express
middleware.

> Notebooks and comments are in Azerbaijani; file and column names are in English.

## Reproducing

Requirements: Python 3.13, Node.js ≥ 20, (optional) MySQL 8.0 for notebooks 05–06.

```bash
python -m venv venv
venv\Scripts\activate                     # Linux/macOS: source venv/bin/activate
pip install -r requirements.txt
pip install torch==2.15.0 --index-url https://download.pytorch.org/whl/cpu   # notebooks 13, 15, 16
python tools/build_libinjection.py        # notebooks 11, 12: builds libinjection 4.0.1 with zig cc
```

Data:

| File | Source | How to get it |
|---|---|---|
| `data/raw/Modified_SQL_Dataset.csv` | Kaggle `sajid576/sql-injection-dataset` | download manually (columns `Query`, `Label`) |
| `data/raw/external/httpparams/payload_full.csv` | GitHub `Morzeux/HttpParamsDataset` | notebook 10 downloads it, SHA-256 checked |
| `data/raw/external/sqliv3/*.csv` | Kaggle `syedsaqlainhussain/sql-injection-dataset` v5 | notebook 10 downloads it via `kagglehub`, SHA-256 checked |
| `data/raw/external/openappsec/legitimate.zip` | open-appsec WAF Comparison Project, legitimate set (URL in the project's `config.py`; the repository itself has no data folder) | notebook 15 downloads it in 64 MB range requests, size and SHA-256 checked (`src/openappsec.py`) |
| `data/raw/external/wafamole/repo/` | GitHub `zangobot/wafamole_dataset` | notebook 16 clones the pinned commit with `core.autocrlf=false` (`src/wafamole.py`) |
| `data/raw/external/handwritten/` | GitHub `swisskyrepo/PayloadsAllTheThings` (`SQL Injection/Intruder/*`) and `fuzzdb-project/fuzzdb` (`attack/sql-injection/**/*.txt`) | notebook 14 does a sparse checkout of pinned commits (`src/handwritten.py`); the cleaned list is `data/processed/14_handwritten_payloads.csv` |

`data/raw/`, `models/`, `third_party/` and the large MySQL run logs are not tracked; every notebook regenerates
what the next one needs. Run the notebooks **in numeric order** (from `notebooks/` or the repo root):

```bash
jupyter nbconvert --to notebook --execute --inplace notebooks/01_data_analysis.ipynb   # etc.
```

Random seed is always 42 (notebooks 12–15 use seeds 42–46). Figures are saved as 300 dpi PNG to `figures/`,
tables as CSV to `results/`.

### MySQL execution test (notebooks 05, 06, 09)

Creates an isolated database `sqli_ml_eval` and a **SELECT-only** user, so injected `DROP`/`INSERT`/`INTO OUTFILE`
fail with a privilege error. Run `sql/setup_eval_db.sql` as root, then create `.env` in the repo root:

```
MYSQL_EVAL_USER=sqli_eval
MYSQL_EVAL_PASSWORD=...
```

Notebooks 09, 11 and 12 read the saved `data/processed/06_mysql_effectiveness.csv` and do not need MySQL.

### open-appsec legitimate traffic (notebook 15)

The legitimate set of the open-appsec WAF Comparison Project (Apache 2.0; 1 040 242 browser-recorded requests from 185
sites, one JSON file per site with `method`, `url`, `headers`, `data`). Only this set is used; the malicious set is not.
Our models score single parameter values, so each request is reduced to the values the Express middleware
(`middleware/src/sqliGuard.js`) would score:

- **query string**: parsed like Express (`urllib.parse.parse_qsl`, one percent-decode, `+` → space, blank values kept);
- **body**, by `Content-Type`: `application/json` → every string leaf (numbers, booleans and `null` are not strings and are
  skipped, as in `stringValues()`); `application/x-www-form-urlencoded` → `parse_qsl` values; `multipart/form-data` → text
  fields (parts without a filename). Other bodies (text/plain, protobuf, binary beacons, CSP reports, …) are not parsed,
  as `express.json()` / `express.urlencoded()` leave `req.body` empty for them;
- keys are not scored; values longer than 4 096 characters are truncated (middleware default).

This gives 9 520 543 values (833 477 unique) in 657 160 requests. Detectors run on the unique values; a request counts
as blocked when any of its values is blocked. The server drops long connections, so `src/openappsec.py` downloads the zip
in 64 MB HTTP range requests and checks size and SHA-256.

### WAF-A-MoLE (notebook 16)

The chunks are concatenated byte for byte as the dataset README says (`cat attacks.sql.* > attacks.sql`), with git's CRLF
conversion disabled because payloads contain LF. The README's `sqlparse.split()` does **not** split `attacks.sql`
correctly: the generator puts payloads into quoted literals without escaping, and sqlparse glues the following statements
together (the first 20 MB come out as 3 262 "statements", one of them 18.9 MB; see `results/16_split_report.csv`).
`src/wafamole.py` therefore cuts the file where one of the generator's four templates starts (``SELECT `…``/`SELECT *`,
``INSERT INTO `tab` ``, ``UPDATE `tab` ``, ``DELETE FROM `tab` ``, right after `;\n`) and splits the remaining segment
(the DDL header of `sane.sql`) with `sqlparse.split()`: 1 004 669 attacks, 1 000 209 benign statements.

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
| Hand-written payloads | PayloadsAllTheThings + fuzzdb: independence, recall of all detectors, alt. whitespace; FPR on HttpParams benign | 14 | `14_*.csv`, `figures/paper/14_handwritten_recall.png` |
| Real benign traffic | open-appsec legitimate requests: value- and request-level FPR of all detectors, top false blocks | 15 | `15_*.csv`, `figures/paper/15_openappsec_fpr.png` |
| WAF-A-MoLE | Artifact statistics, our models on 20k + 20k, LR trained on WAF-A-MoLE | 16 | `16_*.csv`, `figures/paper/16_wafamole.png` |
| char-CNN | Does a neural model learn the artifact too? | 13 (after 14) | `13_char_cnn_table.csv`, `13_char_cnn_mean_std.csv`, `13_cnn_vs_lr.csv`, `figures/paper/13_char_cnn_artifact.png` |
| Fig. 1 | LR defenses, scenario A | 04 | `figures/04_defense_recall_A.png` |

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
| 13 | `13_char_cnn` | Byte-level CNN (PyTorch, CPU), baseline vs normalization; needs the payload list from 14 |
| 14 | `14_handwritten_payloads` | Hand-written payload lists (PayloadsAllTheThings, fuzzdb): cleaning, independence, all detectors over seeds 42–46 |
| 15 | `15_openappsec_benign` | open-appsec real benign traffic: parameter values extracted like the middleware; FPR per value and per request, seeds 42–46 |
| 16 | `16_wafamole` | WAF-A-MoLE dataset: split, artifact statistics, transfer in both directions |

## Layout

```
src/            normalize.py, obfuscation.py, blacklist.py, libinj.py (ctypes), experiments.py (shared helpers),
                detectors.py (TF-IDF models of notebook 12, cached), charcnn.py (CNN of notebook 13, cached),
                handwritten.py (payload lists, 13/14), openappsec.py (15), wafamole.py (16)
tools/          build_libinjection.py
notebooks/      01–16, run in order (except: 14 before 13)
data/processed/ cleaned data, splits, obfuscated test set, MySQL effectiveness
results/        CSV tables
figures/        300 dpi PNG; figures/paper/ = figures of notebooks 13–16 used in the paper
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

Exception: `data/processed/14_handwritten_payloads.csv` contains cleaned lines from two payload collections,
redistributed under their licenses:

| Source | Commit | License |
|---|---|---|
| [swisskyrepo/PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings), `SQL Injection/Intruder/` | `08ea40e` | MIT, Copyright (c) 2019 Swissky |
| [fuzzdb-project/fuzzdb](https://github.com/fuzzdb-project/fuzzdb), `attack/sql-injection/` | `5656ab2` | BSD 3-Clause and CC BY 3.0, Copyright (c) 2010-2019 Adam Muntner (see `_copyright.txt` in the repository) |

Several PayloadsAllTheThings Intruder files are themselves copies of fuzzdb lists (`FUZZDB_*`, `payloads-sql-blind-*`).

Not redistributed: the open-appsec legitimate set (Apache 2.0, per the project README) and the WAF-A-MoLE dataset
(no license file in the repository; cite Demetrio et al., *WAF-A-MoLE: Evading Web Application Firewalls through
Adversarial Machine Learning*, ACM SAC 2020). Notebooks 15 and 16 download them.
