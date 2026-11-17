# Sərbəst iş: ML əsaslı SQL injection detektorlarının dayanıqlığı — xülasə

**Fənn:** Tədqiqat analitikası
**Mövzu:** ML əsaslı SQLi detektorlarının obfuskasiya olunmuş payload-lara qarşı dayanıqlığı və qara siyahı filtri ilə müqayisəsi.

Bütün rəqəmlər layihənin `results/` qovluğundakı CSV-lərdən götürülüb. Bu xülasə üçün yeni hesablama aparılmayıb.
Random seed həmişə 42-dir. Çox seed-li təkrarda 42–46 seed-ləri istifadə olunub.

**Əsas tapıntı.** Kaggle datasetində klassik modellər F1 ≈ 0.997 göstərir. Lakin bu nəticənin bir hissəsi format
artefaktından gəlir: zərərli sorğuların **94.9%**-ində sqlmap üslubunda ikiqat boşluq var (`1  =  1`), təmiz sorğularda
isə bu pay **29.8%**-dir. Boşluq simvollarını başqa whitespace ilə əvəz etmək LR-in recall-unu ~76%-ə, RF-inkini ~27%-ə
endirir. Modeldən əvvəl girişin normallaşdırılması (`src/normalize.py`) bu təsiri aradan qaldırır.

---

## 1. EDA (kəşfiyyat analizi)

**Dataset:** Kaggle *SQL Injection Dataset* (sajid576), `Modified_SQL_Dataset.csv`. Sütunlar: `Query`, `Label` (1 = zərərli).

| Mərhələ | Sətir | Təmiz (0) | Zərərli (1) | Zərərli % |
|---|---|---|---|---|
| Xam | 30 919 | 19 537 | 11 382 | 36.81 |
| Təmizlənmiş (`clean.csv`) | 30 902 | 19 527 | 11 375 | 36.81 |
| v2 (`clean_v2.csv`, Excel pozuntuları çıxarılıb) | 30 255 | 18 885 | 11 370 | 37.58 |

- **Dublikatlar:** 12 tam dublikat sətir var. 2 unikal sorğu fərqli label ilə təkrarlanır (ziddiyyətli, 10 sətir).
  Normallaşdırmadan sonra 102 dublikat sətir qalır.
- **Excel pozuntuları (v2):** 643 sorğu elmi notasiyaya çevrilib (642 təmiz, 1 zərərli). 4 sorğu `rəqəm%` formasındadır
  (hamısı zərərli). Bunlar çıxarılıb.
- **Uzunluq (simvol):** təmiz sorğularda median 35, orta 39.9, maks. 5 370. Zərərli sorğularda median 85, orta 118.6,
  maks. 456. Təkcə uzunluğa əsaslanan LR F1 = 0.65 verir. Deməli, uzunluq tək başına kifayət deyil.
- **Açar sözlər** (zərərli % / təmiz %): `OR` 30.0 / 1.9, `AND` 42.5 / 6.5, `UNION` 19.5 / 2.9,
  `CASE/WHEN/THEN` ≈14 / 0.1, `SLEEP` 7.7 / 0.1, `CHR` 6.7 / 0.0.
  `SELECT` və `FROM` hər iki sinifdə çox rast gəlinir: təmiz sinif də SQL sorğularından ibarətdir.
- **Simvollar** (zərərli % / təmiz %): `)` 82.3 / 23.0, `=` 81.0 / 14.3, `--` 34.9 / 0.01, `#` 17.7 / 0.04,
  `||` 15.7 / 0.01, `0x` 10.8 / 0.01.
- **Format artefaktı** (zərərli % / təmiz %):

  | Naxış | Zərərli % | Təmiz % |
  |---|---|---|
  | İkiqat boşluq (2+ ardıcıl) | 94.91 | 29.81 |
  | Mötərizə ətrafında 2+ boşluq | 86.71 | 1.01 |
  | `=` ətrafında boşluq | 81.06 | 14.78 |
  | Ümumiyyətlə boşluq | 99.24 | 69.93 |

- **Bölgü (v2):** normallaşdırılmış sorğu qrupuna görə 70/15/15 bölünüb, eyni qrup iki dəstə düşmür.
  Train 21 181, val 4 535, test 4 539 sətirdir (test-də 1 745 zərərli).

## 2. `figures/` qovluğundakı qrafiklər

| Fayl | İzah |
|---|---|
| `01_class_balance_raw.png` | Təmizlənmədən əvvəl sinif balansı: 19 537 təmiz və 11 382 zərərli sorğu. |
| `01_class_balance_clean.png` | Dublikat və boş sətirlər çıxarıldıqdan sonra sinif balansı. Nisbət dəyişmir (63/37). |
| `01_query_length_hist.png` | Sinif üzrə sorğu uzunluğunun histoqramı, xətti və log şkalada. Zərərli sorğular xeyli uzundur. |
| `01_top20_keywords.png` | Zərərli sorğularda ən çox rast gəlinən 20 SQL açar sözü, təmiz siniflə yan-yana. |
| `01_top20_symbols.png` | Zərərli sorğularda ən çox rast gəlinən 20 simvol və ardıcıllıq (`)`, `=`, `--`, `#`, `0x`…), təmiz siniflə müqayisədə. |
| `02_roc_curves.png` | v1 datasetində 4 model və "yalnız uzunluq" baza xətti üçün ROC əyriləri. |
| `02_confusion_matrix_best.png` | v1 datasetində ən yaxşı modelin test dəstindəki confusion matrix-i. |
| `02_v2_roc_curves.png` | v2 datasetində (Excel pozuntuları çıxarılıb) eyni ROC müqayisəsi. Bütün TF-IDF modellərində AUC ≥ 0.998-dir. |
| `02_v2_confusion_matrix_lr.png` | v2-də Logistic Regression-un confusion matrix-i: 7 FN, 3 FP. |
| `03_obfuscation_recall_A.png` | 11 obfuskasiya texnikası üzrə model recall-u, ssenari A (middleware, giriş bir dəfə decode olunur). |
| `03_obfuscation_recall_B.png` | Eyni müqayisə ssenari B üçün (xam trafik, decode yoxdur). |
| `03_ngram_loss_top3.png` | Obfuskasiyadan sonra LR üçün ən çox "itən" zərərli n-gram-lar. Bunların əsasını boşluq n-gram-ları təşkil edir. |
| `04_defense_recall_A.png` | LR üçün müdafiə konfiqurasiyaları (baza, normallaşdırma, augmentation, ikisi birlikdə): texnikalar üzrə recall və F1. |
| `05_blacklist_vs_ml.png` | Birinci məqalənin qara siyahı filtri (`sanitizeInput`/`sanitizeSearch`) ML detektorları ilə müqayisədə: recall və FPR. |
| `06_attack_types_and_bypass.png` | Solda: MySQL-də real işləyən payload-ların hücum növləri. Sağda: detektordan keçən effektiv hücumların payı (95% Wilson CI). |
| `07_threshold_roc.png` | ML middleware modeli üçün recall–FPR əyrisi və seçilmiş hədd nöqtələri. |
| `07_middleware_latency.png` | Express middleware-in gecikməsi (p50/p95/p99) və ötürmə qabiliyyəti (req/s). 4 konfiqurasiya müqayisə olunur. |
| `10_cross_dataset_recall.png` | Bizim test dəsti, xarici HttpParams və HttpParams + alt. whitespace üzrə recall. Normallaşdırma olmadan RF 38.7%-ə düşür. |

## 3. Modellərin əsas nəticəsi (v2, seed 42, test dəsti)

Xüsusiyyətlər: simvol TF-IDF (1–5-gram).

| Model | Recall | FPR | F1 | ROC-AUC |
|---|---|---|---|---|
| Logistic Regression (əsas model) | 0.9960 | 0.0011 | 0.9971 | 0.9991 |
| Linear SVM | 0.9960 | 0.0007 | 0.9974 | 0.9993 |
| Random Forest | 0.9931 | 0.0007 | 0.9960 | 0.9999 |
| Multinomial NB | 0.9891 | 0.0773 | 0.9363 | 0.9986 |
| Yalnız uzunluq (LR) | 0.5828 | 0.1288 | 0.6515 | 0.8116 |

## 4. HttpParamsDataset (xarici dataset) nəticələri

**Datasetin seçilməsi.** Ədəbiyyatdakı digər Kaggle datasetləri (SQLiV3, sqliv2) bizim datasetin zərərli sinfi ilə
98.4–99.9% üst-üstə düşür. Ona görə müstəqil test sayıla bilməzlər. HttpParamsDataset (GitHub Morzeux) isə ayrıca
toplanıb və onda ikiqat boşluq artefaktı yoxdur.

**Ölçü:**
- `sqli` + `norm` sinifləri: 30 156 sorğu (10 852 zərərli, 19 304 təmiz). Hamısı unikaldır.
- Bizim train/val dəstləri ilə üst-üstə düşənlər çıxarıldıqdan sonra test dəstində **23 720 sorğu** qalır
  (**10 531 zərərli, 13 189 təmiz**).
- Datasetdəki digər hücum növləri (xss 532, path-traversal 290, cmdi 89) istifadə olunmayıb.

**İkiqat boşluq yoxlaması:**

| Dataset | Sinif | İkiqat boşluq % | `=` ətrafında boşluq % | Mötərizə içində boşluq % | Median uzunluq |
|---|---|---|---|---|---|
| Modified_SQL_Dataset | zərərli | 94.9 | 81.1 | 86.9 | 85.5 |
| Modified_SQL_Dataset | təmiz | 29.8 | 14.8 | 24.4 | 37 |
| HttpParamsDataset | zərərli | **0.0** | 0.0 | 0.0 | 75 |
| HttpParamsDataset | təmiz | **0.0** | 0.0 | 0.0 | 9 |

HttpParams-da ikiqat boşluq artefaktı yoxdur. Buna baxmayaraq, onun zərərli sorğularının **78.4%**-i rəqəm və
whitespace nəzərə alınmadıqda bizim datasetdəki eyni sqlmap şablonlarıdır. Deməli, bu test yeni hücum növlərinə
ümumiləşməni ölçmür. O, eyni hücumların başqa formatda tanınmasını ölçür. Bu da format artefaktı hipotezinin
birbaşa yoxlamasıdır.

**Əsas cədvəl** (bizim datasetdə öyrədilib, HttpParams-da test olunub; seed 42):

| Model | Recall (bizim test) | Recall (HttpParams) | FPR (HttpParams) | F1 (HttpParams) | FN |
|---|---|---|---|---|---|
| LR baza | 0.9960 | 0.9725 | 0.0003 | 0.9858 | 290 |
| SVM baza | 0.9960 | 0.9718 | 0.0002 | 0.9856 | 297 |
| RF baza | 0.9931 | 0.9504 | 0.0002 | 0.9745 | 522 |
| NB baza | 0.9891 | 0.9904 | 0.2941 | 0.8398 | 101 |
| LR + normallaşdırma | 0.9948 | **0.9998** | 0.0003 | 0.9997 | 2 |
| LR + norm. + augmentation | 0.9937 | **0.9998** | 0.0003 | 0.9997 | 2 |
| Qara siyahı (`sanitizeInput`) | — | 0.9949 | **0.0868** | 0.9459 | 54 |
| Qara siyahı (`sanitizeSearch`) | — | 0.9639 | 0.0023 | 0.9802 | 380 |

- **Artefakt yoxlaması:** baza LR HttpParams-da 290 payload-ı qaçırır. Həmin payload-lar sqlmap boşluq formatına
  salındıqda onların **99.3%**-i tutulur.
- **Obfuskasiya (ssenari A):** `alt_whitespace` texnikasında LR baza 83.4%, RF baza 38.7% recall verir.
  `double_url_encode`-da RF 12.0%-dir. Normallaşdırılmış LR bütün texnikalarda 100% tutur.
- **Əks istiqamət:** HttpParams-da öyrədilmiş LR bizim test dəstində yüksək recall verir (0.986), amma FPR **0.52**-dir.
  Səbəb budur ki, bizim təmiz sinif SQL sorğularıdır, HttpParams-ın təmiz sinfi isə qısa form dəyərləridir.
- **5 seed üzrə** (orta ± std, %): HttpParams recall LR baza 96.91 ± 0.75, LR + normallaşdırma 99.98 ± 0.01,
  libinjection 96.80 ± 0.01. Qara siyahının (`sanitizeInput`) FPR-i 8.56 ± 0.09-dur.

## 5. Əlavə eksperimentlər: nə bitib, nə bitməyib

### 5.1. Beş seed (notebook 12) — **bitib**

Bütün əsas cədvəllər 42–46 seed-lərində təkrarlanıb. Hər seed üçün qrup əsaslı bölgü yenidən qurulur.
Seed 42 nəticələri orijinal notebook-larla üst-üstə düşür: fərq ≤ 0.0006 (`12_seed42_reproduction_check.csv`).

| Göstərici (%, orta ± std) | LR | SVM | RF | NB |
|---|---|---|---|---|
| F1 (test) | 99.68 ± 0.05 | 99.71 ± 0.05 | 99.57 ± 0.10 | 93.72 ± 0.17 |
| F1 ("insan formatı" test) | 95.91 ± 1.05 | 96.21 ± 0.54 | 92.77 ± 1.08 | 93.59 ± 0.14 |
| Ən pis texnikada recall, ssenari A, baza | 63.71 ± 21.97 | 75.55 ± 4.79 | 4.53 ± 2.98 | 98.16 ± 0.12 |
| Ən pis texnikada recall, ssenari A, normallaşdırma ilə | 99.56 ± 0.20 | — | 98.96 ± 0.11 | 99.28 ± 0.08 |

LR üçün müdafiə nəticələri (ssenari A, recall %):

| Texnika | Baza | Normallaşdırma | Augmentation (LOTO) |
|---|---|---|---|
| `alt_whitespace` | 76.25 ± 4.82 | 99.76 ± 0.11 | 86.49 ± 3.39 |
| `double_url_encode` | 71.52 ± 28.91 | 99.70 ± 0.16 | 99.85 ± 0.11 |
| `combination` | 93.36 ± 4.76 | 99.71 ± 0.12 | 99.93 ± 0.08 |

Nəticə belədir. Normallaşdırma seed-dən asılı olmayaraq artefaktı aradan qaldırır. Augmentation isə model görmədiyi
texnikaya, məsələn `alt_whitespace`-ə, tam ümumiləşmir. Baza LR-in `double_url_encode` nəticəsi seed-ə çox
həssasdır (30.9–98.4%).

### 5.2. libinjection 4.0.1 (notebook 11) — **bitib**

Test dəsti eynidir, seed 42:

| Detektor | Recall | FPR | F1 | Ən pis texnika (A) | MySQL-də işləyib keçən hücumlar |
|---|---|---|---|---|---|
| Qara siyahı (`sanitizeInput`) | 0.976 | 0.649 | 0.648 | `double_url_encode` 91.4% | 3.0% (20 unikal) |
| Qara siyahı (`sanitizeSearch`) | 0.950 | 0.599 | 0.653 | `double_url_encode` 71.3% | 12.3% (22 unikal) |
| libinjection 4.0.1 | 0.905 | 0.388 | 0.717 | `double_url_encode` **0.0%** | 0.2% (2 unikal) |
| LR baza | 0.996 | 0.001 | 0.997 | `alt_whitespace` 77.8% | 4.6% (23 unikal) |
| LR + normallaşdırma | 0.995 | 0.001 | 0.996 | `url_encode` 99.8% | 0.1% (1 unikal) |
| LR + norm. + augmentation | 0.994 | 0.001 | 0.996 | `url_encode` 99.7% | 0.1% (1 unikal) |

Son sütun MySQL-də real işləyən 996 effektiv hücum formasından detektordan keçənlərin payıdır.

- libinjection-un bizim test dəstindəki FPR-i yüksəkdir (0.388). Bunun səbəbi təmiz sinfin özünün SQL sorğusu
  olmasıdır. Adi giriş dəyərlərində (`fpr_plain_input`) və HttpParams-da libinjection-un FPR-i 0-dır.
- `keyword_split_comment` texnikasında libinjection 9.8% recall verir. Lakin bu texnika MySQL-də işləmir.

### 5.3. Simvol səviyyəli CNN (notebook 13) — **bitməyib**

`notebooks/13_char_cnn.ipynb` yazılıb (PyTorch, CPU, 5 seed, baza və normallaşdırma), amma hələ icra olunmayıb:
0/7 kod hücrəsi işə salınıb. `results/13_*` və `figures/13_char_cnn_artifact.png` faylları yoxdur. Ona görə
CNN nəticəsi bu xülasəyə daxil edilməyib.

## 6. Notebook-ların siyahısı

| # | Notebook | Nə edir | Vəziyyət |
|---|---|---|---|
| 01 | `01_data_analysis` | Dataset analizi (balans, uzunluq, açar sözlər, simvollar, dublikatlar), təmizləmə → `clean.csv` | icra olunub |
| 02 | `02_baseline_models` | v1-də qrup əsaslı 70/15/15 bölgü. TF-IDF + LR/SVM/RF/NB və "yalnız uzunluq" baza xətti | icra olunub |
| 02 | `02_baseline_models_v2` | Excel pozuntularının çıxarılması → `clean_v2.csv`, eyni modellər v2-də | icra olunub |
| 03 | `03_obfuscation_eval` | Test dəstinin zərərli sorğularına 11 obfuskasiya texnikası. Ssenari A (bir dəfə decode) və B (xam trafik), itən n-gram analizi | icra olunub |
| 04 | `04_robustness_defenses` | Format artefaktı testi, normallaşdırma, augmentation (leave-one-technique-out) | icra olunub |
| 05 | `05_blacklist_vs_ml` | Qara siyahı filtrinin Python portu (Node.js ilə 50/50 eynilik), ML ilə müqayisə, MySQL pilot testi (300 payload) | icra olunub |
| 06 | `06_mysql_full_eval` | 1 745 zərərli test payload-ının 10 SQL kontekstində MySQL-də real icrası | icra olunub |
| 07 | `07_middleware_threshold` | Middleware modeli üçün hədd seçimi və recall–FPR əyrisi | icra olunub |
| 08 | `08_threshold_and_failure` | Həddin validation dəstində seçilməsi (0.5), səhvlərin səbəb üzrə bölgüsü | icra olunub |
| 09 | `09_reconciliation_bootstrap` | Payload saylarının uzlaşdırılması, cluster-bootstrap etibar intervalları, yekun cədvəllər, gecikmə qrafiki | icra olunub |
| 10 | `10_cross_dataset` | Xarici datasetlər: üst-üstə düşmə, HttpParams testi, müstəqillik analizi, əks istiqamət | icra olunub |
| 11 | `11_libinjection` | libinjection 4.0.1 eyni test dəstlərində | icra olunub |
| 12 | `12_multiseed` | Bütün əsas cədvəllər 42–46 seed-lərində (orta ± std) və seed 42 üçün yoxlama | icra olunub |
| 13 | `13_char_cnn` | Bayt səviyyəli CNN: neyron model də artefaktı öyrənirmi? | **icra olunmayıb** |

Notebook-lardan kənar yalnız middleware ölçmələri aparılıb (`middleware/`, Node.js):

- **Gecikmə:** p50 2.3 ms (middleware yoxdur) → 3.3 ms (ML middleware).
- **Ötürmə qabiliyyəti:** 3 423 → 2 648 req/s.
- **Uzun giriş (DoS):** 1 MB giriş limitsiz halda 1 225 ms çəkir, `maxLength = 4096` ilə 4.9 ms.

## 7. `coursework/figures/` qovluğuna seçilmiş qrafiklər

| # | Fayl | Bölmə | Niyə seçilib |
|---|---|---|---|
| 1 | `01_query_length_hist.png` | EDA | Siniflər arasında uzunluq fərqini göstərir. |
| 2 | `01_top20_symbols.png` | EDA | Ən ayırd edici simvolları göstərir (`--`, `#`, `0x`, `\|\|`). |
| 3 | `02_v2_roc_curves.png` | Model | Əsas modellərin ROC əyriləri, "yalnız uzunluq" baza xətti ilə birlikdə. |
| 4 | `03_obfuscation_recall_A.png` | Model | Obfuskasiya altında recall-un düşməsini göstərir. |
| 5 | `03_ngram_loss_top3.png` | Model | Recall-un niyə düşdüyünü izah edir: model boşluq n-gram-larına söykənir. |
| 6 | `04_defense_recall_A.png` | Nəticə | Normallaşdırma və augmentation müdafiələrinin müqayisəsi. |
| 7 | `05_blacklist_vs_ml.png` | Nəticə | Qara siyahı filtri ML detektorları ilə müqayisədə. |
| 8 | `10_cross_dataset_recall.png` | Nəticə | Xarici datasetdə yoxlama: artefakt hipotezinin təsdiqi. |
