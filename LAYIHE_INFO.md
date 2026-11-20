# Layihə haqqında məlumat (SQLi ML məqaləsi)

> Son yenilənmə: 2026-11-20 (tam review: fayllar, notebook çıxışları, `results/` CSV-ləri, keşlənmiş modellər yoxlanılıb).
> Bu fayl layihənin bütün hissələrini bir yerdə toplayır: mövzu, məlumat, kod, eksperimentlər, nəticələr,
> qəbul olunmuş qərarlar və açıq qalan işlər. Ətraflı nəticələr: `coursework/summary.md`, reproduksiya: `README.md`.

---

## 1. Mövzu və əsas tapıntı

**Məqalə:** *"ML əsaslı SQL injection detektorlarının format artefaktlarına və obfuskasiyaya qarşı dayanıqlığı:
eksperimental analiz və normallaşdırmaya əsaslanan müdafiə"* (Azərbaycan dilində, ingiliscə xülasə ilə).

**Əsas tapıntı.** Geniş istifadə olunan Kaggle SQLi datasetində klassik modellər F1 ≈ 0.997 göstərir, amma bunun bir hissəsi
**format artefaktıdır**: zərərli sorğuların 95%-ində sqlmap-ə xas ikiqat boşluq (`1  =  1`) var, təmizlərdə 30%.
LR-in ən güclü siqnalı boşluq n-gram-larıdır. Boşluq simvollarını dəyişmək (tab, LF və s.) LR recall-unu ~78%-ə, RF-i ~33%-ə salır.
Girişi modeldən əvvəl kanonik formaya salmaq (`src/normalize.py`) effekti aradan qaldırır; augmentation görmədiyi texnikaya ümumiləşmir.

**Yeni təsdiqlər (13, 14, 16):**
- Neyron şəbəkə (char-CNN) artefakta TF-IDF modellərindən **daha çox** söykənir (insan formatında F1 99.7 → 57.4, HttpParams recall 41.9);
  eyni normallaşdırma onu da tam düzəldir — müdafiə arxitekturadan asılı deyil.
- Əl ilə yazılmış (sqlmap olmayan) payload-larda da eyni şəkil: baza modellər alt. whitespace ilə düşür, normallaşdırılmış LR ~95% sabit qalır.
- WAF-A-MoLE datasetində ikiqat boşluq yoxdur, amma **öz format artefaktları** var (yalnız hücumlarda sətir sonu və şərh; təmiz sinifdə
  təsadüfi hərf literalları); orada öyrədilmiş baza LR də alt. whitespace ilə düşür.

**Təhdid modeli.** Ssenari A = middleware (Express bir dəfə URL decode edir, real ssenari); ssenari B = xam trafik.

---

## 2. Məlumat mənbələri

| # | Dataset | Mənbə | Rolu | Lisenziya / qeyd |
|---|---|---|---|---|
| 1 | Modified_SQL_Dataset | Kaggle `sajid576/sql-injection-dataset` | **Əsas dataset** — bütün modellər burada öyrədilir. v1 (`clean.csv`) və v2 (`clean_v2.csv`, Excel pozuntuları çıxarılıb, 30 255 sorğu: 11 370 zərərli / 18 885 təmiz) | Paylanmır |
| 2 | HttpParamsDataset | GitHub `Morzeux/HttpParamsDataset` | **Xarici test** (sqli + norm, 30 156 sorğu: 10 852 / 19 304). İkiqat boşluq artefaktı yoxdur. Train/val ilə üst-üstə düşənlər çıxarılır | Paylanmır |
| 3 | SQLiV3 / sqliv2 | Kaggle `syedsaqlainhussain/sql-injection-dataset` v5 | Yalnız üst-üstə düşmə analizi — bizim datasetlə 98.4–99.9% eynidir, müstəqil test deyil | Paylanmır |
| 4 | Əl ilə yazılmış payload-lar | `swisskyrepo/PayloadsAllTheThings` (`SQL Injection/Intruder/`, commit `08ea40e`) + `fuzzdb-project/fuzzdb` (`attack/sql-injection/`, commit `5656ab2`) | Notebook 14: sqlmap formatında olmayan insan payload-ları. Təmizlənmiş siyahı `data/processed/14_handwritten_payloads.csv` | MIT; BSD-3 / CC BY 3.0 — lisenziyalar README-də, siyahı repoda paylanır |
| 5 | open-appsec legitimate | `openappsec/waf-comparison-project` → `legitimate.zip` (1.2 GB, SHA-256 `58faee18…`, 2026-11-17 yüklənib) | Notebook 15: real saytların təmiz HTTP trafiki (**692 JSON qeyd faylı**, 1 040 242 sorğu) — FPR | Apache 2.0, paylanmır. ⚠ "185 sayt" rəqəmi yoxlanmalıdır (bax §8) |
| 6 | WAF-A-MoLE | `zangobot/wafamole_dataset` (commit `3eb1cef`) | Notebook 16: başqa açıq dataset — artefakt yoxlaması, köçürmə, əks istiqamət | Repoda lisenziya faylı yoxdur — paylanmır, yalnız istinad (Demetrio et al., SAC 2020) |

`data/raw/` git-də izlənmir; notebook-lar faylları özləri yükləyir və SHA-256 / sabit commit ilə yoxlayır.
Lokal keşlər: `data/raw/external/openappsec/openappsec_values.pkl` (480 MB, çıxarılmış dəyərlər),
`data/raw/external/wafamole/wafamole_split.pkl` (267 MB, bölünmüş sorğular).

---

## 3. Kod strukturu

| Yol | Nə edir |
|---|---|
| `src/normalize.py` | Müdafiə: decode ×3, şərhlər, whitespace, lowercase, `( ) = ,` ətrafı boşluqlar; `human_format` |
| `src/obfuscation.py` | 11 obfuskasiya texnikası + kombinasiya (deterministik RNG) |
| `src/blacklist.py` | Birinci məqalənin qara siyahı filtrinin (`sanitizeInput` / `sanitizeSearch`) Python portu, Node.js ilə 50/50 eyni |
| `src/libinj.py` | libinjection 4.0.1 (rəsmi C kitabxanası, `zig cc` ilə qurulur, ctypes) |
| `src/experiments.py` | Ümumi köməkçilər: qrup əsaslı bölgü, obfuskasiya, augmentation, HttpParams, metriklər |
| `src/detectors.py` | Notebook 12-nin TF-IDF modelləri/gridləri; `train_all(seed)` — 6 model, `models/tfidf_detectors_<seed>.joblib`-də keşlənir (42–46 hazırdır) |
| `src/charcnn.py` | Notebook 13-ün char-CNN-i; `get_cnn(cfg, seed)` — `models/charcnn_<base\|norm>_<seed>.pt`-də keşlənir |
| `src/handwritten.py` | Payload siyahılarının yüklənməsi, təmizlənməsi, müstəqillik açarları (skelet və s.) |
| `src/openappsec.py` | open-appsec yüklənməsi (64 MB Range hissələri), HTTP sorğularından parametr dəyərlərinin çıxarılması, yanlış bloklama səbəb qrupları (`reason`) |
| `src/wafamole.py` | WAF-A-MoLE birləşdirmə və şablon sərhədləri ilə bölmə |
| `tools/build_libinjection.py` | libinjection 4.0.1 tarball-ı (SHA-256 sabit) `zig cc` ilə qurur |
| `middleware/` | Son modelin saf JavaScript portu (Express middleware), parity testi, hücum testi, benchmark |
| `notebooks/01–16` | Eksperimentlər (aşağıda) |
| `results/` | CSV cədvəllər; `figures/` — 300 dpi PNG; `figures/paper/` — notebook 13–16-nın qrafikləri |

**Qaydalar:** seed həmişə 42 (çox-seed eksperimentlərində — 12, 13, 14, 15 — 42–46); qrafiklər 300 dpi PNG; cədvəllər CSV; kod təkrarlana bilən.
Python 3.13 venv, PyTorch 2.15.0 CPU (TensorFlow yox); `requirements.txt`-ə `sqlparse==0.6.1` əlavə olunub (16 üçün).

---

## 4. Notebook-lar və vəziyyət

| # | Notebook | Nə edir | Vəziyyət |
|---|---|---|---|
| 01 | `01_data_analysis` | Dataset analizi, təmizləmə → `clean.csv` | ✅ |
| 02 | `02_baseline_models(_v2)` | Excel pozuntuları → `clean_v2.csv`; qrup əsaslı 70/15/15 bölgü; TF-IDF + LR/SVM/RF/NB | ✅ |
| 03 | `03_obfuscation_eval` | 11 texnika, ssenari A/B, itən n-gram analizi | ✅ |
| 04 | `04_robustness_defenses` | Artefakt testi ("insan formatı"), normallaşdırma, augmentation (LOTO) | ✅ |
| 05 | `05_blacklist_vs_ml` | Qara siyahı portu, ML ilə müqayisə, MySQL pilot (300 payload) | ✅ |
| 06 | `06_mysql_full_eval` | 1 745 zərərli payload-ın 10 kontekstdə MySQL-də icrası | ✅ |
| 07 | `07_middleware_threshold` | Middleware üçün hədd / ROC | ✅ |
| 08 | `08_threshold_and_failure` | Validation-da hədd seçimi, səhvlərin səbəbləri | ✅ |
| 09 | `09_reconciliation_bootstrap` | Payload saylarının uzlaşdırılması, cluster-bootstrap CI | ✅ |
| 10 | `10_cross_dataset` | Xarici datasetlər, HttpParams testi, müstəqillik, əks istiqamət | ✅ |
| 11 | `11_libinjection` | libinjection 4.0.1 eyni test dəstlərində | ✅ |
| 12 | `12_multiseed` | Bütün əsas cədvəllər seed 42–46 (orta ± std) | ✅ |
| 13 | `13_char_cnn` | Bayt səviyyəli CNN: baza vs normallaşdırma, 5 seed; Kaggle, insan formatı, obfuskasiya, HttpParams, payload siyahıları | ✅ (2026-11-17 17:09, 7/7 hüceyrə, xətasız) |
| 14 | `14_handwritten_payloads` | PayloadsAllTheThings + fuzzdb, bütün detektorlar, 5 seed | ✅ |
| 15 | `15_openappsec_benign` | open-appsec təmiz trafiki: dəyər və sorğu səviyyəsində FPR, 11 detektor, 5 seed; top-20 yanlış bloklama, səbəb qrupları, sayt üzrə FPR | ❌ **icra olunmayıb** (0/9 hüceyrə, `results/15_*` yoxdur) |
| 16 | `16_wafamole` | WAF-A-MoLE: artefakt statistikası, 20k+20k nümunədə bizim modellər, WAF-A-MoLE-də öyrədilmiş LR | ✅ (2026-11-17 16:41, 9/9 hüceyrə, xətasız) |

İcra ardıcıllığı: 01 → 12, sonra **14 → 13 → 15 → 16** (13 payload siyahısını 14-dən götürür). 16 15-dən asılı deyil (artıq bitib).

**15-in vəziyyəti.** Notebook-da heç bir çıxış yoxdur; işləyən proses yoxdur. Görünür, `nbconvert --inplace` ilə işə salınıb
və yarımçıq kəsilib (nbconvert çıxışı yalnız sonda yazır). Hazır olanlar: dəyər keşi (`openappsec_values.pkl`),
TF-IDF modelləri (5 seed), CNN modellərinin 9/10-u — **`charcnn_norm_46.pt` çatışmır**, növbəti icrada öyrədiləcək.

---

## 5. Əsas nəticələr

### 5.1. Baza modellər (5 seed, %, orta ± std)

| | LR | SVM | RF | NB |
|---|---|---|---|---|
| F1 (test) | 99.68 ± 0.05 | 99.71 ± 0.05 | 99.57 ± 0.10 | 93.72 ± 0.17 |
| F1 ("insan formatı") | 95.91 ± 1.05 | 96.21 ± 0.54 | 92.77 ± 1.08 | 93.59 ± 0.14 |
| Ən pis texnika, ssenari A, baza | 63.71 ± 21.97 | 75.55 ± 4.79 | 4.53 ± 2.98 | 98.16 ± 0.12 |
| Ən pis texnika, normallaşdırma ilə | 99.56 ± 0.20 | 99.60 ± 0.15 | 98.96 ± 0.11 | 99.28 ± 0.08 |

LR müdafiələri (ssenari A, recall): `alt_whitespace` baza 76.25 → normallaşdırma 99.76 → augmentation (LOTO) 86.49.

### 5.2. Detektorların müqayisəsi (seed 42)

| Detektor | Recall | FPR (Kaggle) | Ən pis texnika (A) |
|---|---|---|---|
| Qara siyahı (`sanitizeInput`) | 0.976 | 0.649 | `double_url_encode` 91.4% |
| Qara siyahı (`sanitizeSearch`) | 0.950 | 0.599 | `double_url_encode` 71.3% |
| libinjection 4.0.1 | 0.905 | 0.388 | `double_url_encode` 0.0% |
| LR baza | 0.996 | 0.001 | `alt_whitespace` 77.8% |
| LR + normallaşdırma (+ aug.) | 0.995 | 0.001 | `url_encode` 99.8% |

### 5.3. HttpParams (xarici test)
LR baza recall 96.91 ± 0.75 → LR + normallaşdırma 99.98 ± 0.01; qara siyahının (`sanitizeInput`) FPR-i 8.56%.
HttpParams zərərli sorğularının 78% sqlmap şablonlarıdır — test format artefaktını birbaşa yoxlayır.

### 5.4. Notebook 14 — əl ilə yazılmış payload-lar ✅
- 2 133 sətir → **1 427 unikal payload** (580 dublikat, 111 SQL tokensiz fuzz sətri, 11 şərh, 4 boş).
  PayloadsAllTheThings-in bir çox faylı fuzzdb-nin surətidir, fuzzdb yalnız 141 yeni payload verir.
- Müstəqillik: ikiqat boşluq **0.3%** (bizim test 94.5%); train ilə normallaşdırılmış üst-üstə düşmə 7.5%; sqlmap skeleti 11.5%.
  Hər seed-də train+val ilə üst-üstə düşənlər çıxarılır (126–134), ~1 297 payload qalır.
- Recall (5 seed, orta): LR baza 92.8 → alt. whitespace ilə 81.8; RF baza 84.8 → **35.6**; LR + normallaşdırma 95.1 / 95.2;
  qara siyahı (Input) 98.1 (amma FPR 8.56%); libinjection 58.3; CNN baza 58.5 → 32.4; CNN + norm. 95.1 / 95.3.
  FPR HttpParams-ın təmiz sinfində hesablanır.
- Ən yaxşı LR-in seed 42-də buraxdığı 48 payload-dan 34-ü tam SQL operatorudur (`select current_user;`) —
  Kaggle-da təmiz sinif tam SQL sorğularıdır, model "tam operator = təmiz" öyrənib.
- Seed 42–46 HttpParams FPR-i notebook 12 ilə tam eynidir (fərq 0.0).

### 5.5. Middleware (Node.js)
Gecikmə p50 2.3 → 3.3 ms; ötürmə 3 423 → 2 648 req/s; 1 MB giriş limitsiz 1 225 ms, `maxLength = 4096` ilə 4.9 ms.

### 5.6. Notebook 13 — char-CNN ✅ (5 seed, %, orta ± std)

| Göstərici | CNN baza | CNN + norm. | LR baza (12) | LR + norm. (12) |
|---|---|---|---|---|
| F1, Kaggle test | 99.67 ± 0.08 | 99.65 ± 0.08 | 99.68 ± 0.05 | 99.63 ± 0.09 |
| F1, insan formatı | **57.35 ± 7.16** | 99.65 ± 0.08 | 95.91 ± 1.05 | 99.63 ± 0.09 |
| Recall, alt. whitespace (A) | **25.19 ± 11.50** | 99.73 ± 0.05 | 76.25 ± 4.82 | 99.76 ± 0.11 |
| Recall, kombinasiya (A) | 71.97 ± 2.80 | 99.70 ± 0.12 | 93.36 ± 4.76 | 99.71 ± 0.12 |
| Recall, HttpParams | **41.92 ± 9.17** | 99.98 ± 0.00 | 96.91 ± 0.75 | 99.98 ± 0.01 |
| Recall, HttpParams + alt. whitespace | 16.95 ± 5.67 | 100.00 ± 0.00 | — | — |
| Recall, əl ilə yazılmış | 58.49 ± 3.83 | 95.10 ± 1.20 | 92.79 ± 2.29 | 95.10 ± 0.67 |

- Baza CNN-in HttpParams-da buraxdığı payload-lar (orta 6 108) sqlmap boşluq formatına salındıqda **99.96%**-i tutulur —
  CNN-in əsas siqnalı formatdır.
- Epoxa 9.8 ± 0.4 (maks. 10), val F1 0.996–0.998. Qrafik: `figures/paper/13_char_cnn_artifact.png`.

### 5.7. Notebook 16 — WAF-A-MoLE ✅
- Bölmə: 1 004 669 hücum (745 593 unikal), 1 000 209 təmiz (923 425 unikal); 8 353 sorğu hər iki sinifdə → çıxarılıb;
  yekun 737 240 / 915 072. Bizim datasetlə üst-üstə düşmə 0.0%.
- Artefaktlar: ikiqat boşluq hücum 3.5% / təmiz 0.0%; **sətir sonu 28.6% / 0%; şərh 58.9% / 0%**; təmiz literallar təsadüfi hərflərdir
  (WAF-A-MoLE LR-in ən güclü "təmiz" n-gram-ları `j`, `z`, `q`).
- Bizim modellər (seed 42, 20k + 20k), recall / FPR %: LR baza 90.8 / 21.3; RF baza 70.1 → alt. ws. **19.5**; CNN baza 46.5 → alt. ws. **2.3**;
  LR + norm. 95.9 / 26.5; CNN + norm. 95.5 / 40.0; qara siyahı 100 / **100**; libinjection 78.1 / 45.1.
- Əks test (WAF-A-MoLE-də öyrədilmiş LR, C = 10 / 100): öz testində recall 99.9; Kaggle-da 82.8 → alt. ws. **56.8**,
  HttpParams-da 95.1 → **76.9**; LR + norm. variantı sabit (91.5 / 94.1), amma Kaggle-da FPR 58%.
- Şərh: təmiz sinfin tərifi datasetlər arasında köçmür (FPR hər iki istiqamətdə 21–58%). Qrafik: `figures/paper/16_wafamole.png`.

### 5.8. Notebook 15 — open-appsec ⏳ (yalnız dəyər çıxarılması hazırdır, FPR hesablanmayıb)
Keşdən yoxlanılıb: 1 040 242 sorğu, 692 fayl, 657 160 sorğuda ən azı bir dəyər, 9 520 543 dəyər (833 477 unikal),
6 968 dəyər 4 096 simvoldan uzun olduğu üçün kəsilib.

---

## 6. Qəbul olunmuş qərarlar və sapmalar (məqalədə qeyd olunmalı)

1. **Payload siyahıları (14):** yalnız düz mətn siyahıları (PayloadsAllTheThings-in Markdown fırıldaq vərəqləri istifadə olunmur).
   SQL tokeni olmayan sətirlər (tək `'`, `%00`, tək sözlər `asc`, LDAP probları, başlıqlar) çıxarılır; fuzzer yer tutucuları
   (`__TIME__`, `<username>` …) sabit dəyərlə əvəz olunur; giriş = bir dəfə URL decode (ssenari A).
   Sızma testdən **normallaşdırılmış** formada çıxarılır (HttpParams-dakından sərt).
2. **open-appsec (15):** repoda tapşırıqda deyilən `Data` qovluğu **yoxdur**; təmiz dəst `config.py`-dəki `legitimate.zip`-dən yüklənir.
   Server uzun bağlantıları kəsir — fayl 64 MB-lıq Range hissələri ilə yüklənir, CRC və SHA-256 yoxlanılır.
   Parametr dəyərləri middleware-in məntiqi ilə çıxarılır: URL query + body (`application/json` sətir yarpaqları,
   `x-www-form-urlencoded`, `multipart` mətn sahələri); digər body növləri oxunmur; 4 096 simvol limiti.
   Nəticə: 9 520 543 dəyər (833 477 unikal), 657 160 sorğuda ən azı bir dəyər.
3. **WAF-A-MoLE (16):** README-dəki `sqlparse.split()` hücum faylında **işləmir** — generator payload-ları dırnaqları escape etmədən
   literal içinə qoyur, sqlparse sonrakı sorğuları yapışdırır: faylın **ilk 20 MB-ı** 3 262 "statement" verir, ən uzunu **18.9 MB**,
   baytların 96.8%-i 2 000 simvoldan uzun "statement"-lərdədir (sqlparse yavaş olduğundan müqayisə yalnız ilk 20 MB-da aparılıb;
   `16_split_report.csv`). Ona görə fayl generatorun dörd şablonunun başlanğıcında kəsilir, qalan hissə (təmiz faylın DDL başlığı)
   sqlparse ilə bölünür → 1 004 669 hücum (745 593 unikal), 1 000 209 təmiz (923 425 unikal). Bu məqaləyə ayrıca tapıntı kimi yazıla bilər.
   Windows-da git CRLF çevirməsi söndürülüb (`core.autocrlf=false`), çünki payload-ların içində LF var.
4. **CNN modelləri** 15/16 üçün `src/charcnn.py` ilə yenidən öyrədilir (13 ilə eyni kod və seed, deterministik).
   **Yoxlanılıb (2026-11-20):** 9 keşlənmiş modelin hamısında epoxa sayı və val F1 `13_char_cnn_raw.csv` ilə tam eynidir
   (fərq < 1e-9). `charcnn_norm_46.pt` hələ yoxdur.
5. **13-ün icra müddəti:** bəzi CNN təlimləri anormal uzun çəkib (seed 43 norm. 13 431 s, digərləri 281–3 649 s) — kompüter yuxusu
   və paralel icra (15-in CNN təlimi və 16 eyni vaxtda) səbəbindən. Təlim deterministik olduğundan nəticələrə təsir etmir (4-cü bəndə bax).

---

## 7. Açıq qalan işlər

- [ ] **Notebook 15-i icra etmək** (yeganə qalan hesablama). `charcnn_norm_46` öyrədiləcək; 833 477 unikal dəyər × 11 detektor × 5 seed —
      bir neçə saat. Kompüter yuxu rejiminə keçməməlidir; başqa ağır iş paralel işlədilməməlidir.
- [ ] "185 sayt" rəqəmini mənbədən yoxlamaq (bax §8) və README / notebook 15 / summary-də düzəltmək
- [ ] `coursework/summary.md` §9.1-ə 15-in nəticələri: cədvəl + 3 cümləlik şərh; §6-da 15-in statusu
- [x] `coursework/summary.md` — Section 14–13 və 16 yazılıb
- [x] README: 15/16 məlumat mənbələri, çıxarma üsulu, lisenziyalar yazılıb
- [ ] Commit (push yox — istifadəçinin göstərişi). Commit edilməmiş: 4 dəyişdirilmiş fayl + 30-dan çox yeni fayl
      (`src/` 5 modul, notebook 14–16, `results/13_*`, `14_*`, `16_*`, `figures/paper/`, `data/processed/14_handwritten_payloads.csv`, bu fayl)

---

## 8. Review qeydləri (2026-11-20)

**Yoxlanılıb və uyğundur:** §5.1–5.5-in bütün rəqəmləri mənbə CSV-lərlə (`12_*`, `11_detector_comparison`, `14_*`, `middleware_*`);
13 və 16-nın cədvəlləri summary.md ilə; WAF-A-MoLE sayları; open-appsec dəyər sayları; CNN keşi ↔ notebook 13.

**Köhnə versiyadakı səhvlər (bu faylda düzəldilib):**
- 13 və 16 "⏳ işləyir" kimi göstərilirdi — hər ikisi 2026-11-17-də bitib; 15 isə "CNN-i gözləyir" yox, ümumiyyətlə icra olunmayıb.
- WAF-A-MoLE: "171 MB-lıq fayl 3 262 statement olur, biri 171 MB" — səhv idi; 3 262 yalnız ilk 20 MB-dandır, ən uzunu 18.9 MB.
- Açıq işlərdə summary §14–13 və README 15/16 hələ edilməmiş kimi göstərilirdi — hər ikisi artıq yazılıb.

**Digər sənədlərdə düzəldilən kiçik səhvlər:**
- `coursework/summary.md` §5.1: SVM-in "normallaşdırma ilə ən pis texnika" xanası "—" idi → 99.60 ± 0.15 (`12_NORM_all_mean_std.csv`).
- `README.md`: torch "notebook 13 only" yazılmışdı — 15 və 16 da `src/charcnn.py`-ni import edir → "notebooks 13, 15, 16";
  seed qeydi "12 and 13" → "12–15".

**Həll olunmamış (istifadəçinin qərarı lazımdır):**
- ⚠ **"185 sayt"**: `legitimate.zip`-də 692 JSON faylı var (məs. `browsing_2024_airbnb`, `browsing_2024_airbnb_al` — eyni saytın
  müxtəlif sessiyaları); suffix-lər (`_al`, `_hl`, `_ni`) atılanda ~649 ad qalır. 185 rəqəminin lokal mənbəyi yoxdur
  (`repo/` qovluğu boşdur). README, notebook 15-in giriş mətni və bu fayl 185 deyir; notebook 15-in özü isə "saytlar (fayllar)" = 692 çıxaracaq.
  Məqaləyə yazmazdan əvvəl open-appsec mənbəsindən yoxlanmalı, ya da "692 brauzer sessiyası" kimi yazılmalıdır.

---

## 9. Reproduksiya (qısa)

```bash
python -m venv venv && venv\Scripts\activate
pip install -r requirements.txt
pip install torch==2.15.0 --index-url https://download.pytorch.org/whl/cpu   # 13, 15, 16
python tools/build_libinjection.py
jupyter nbconvert --to notebook --execute --inplace notebooks/01_data_analysis.ipynb   # ... 01–12, 14, 13, 15, 16
```
MySQL testi (05–06) üçün `sql/setup_eval_db.sql` və `.env` lazımdır; ətraflı — `README.md`.
