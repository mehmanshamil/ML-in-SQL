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
| Ən pis texnikada recall, ssenari A, normallaşdırma ilə | 99.56 ± 0.20 | 99.60 ± 0.15 | 98.96 ± 0.11 | 99.28 ± 0.08 |

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

### 5.3. Simvol səviyyəli CNN (notebook 13) — **bitib**

Nəticələr 8-ci bölmədədir (Section 14–13).

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
| 13 | `13_char_cnn` | Bayt səviyyəli CNN: neyron model də artefaktı öyrənirmi? (14-dən sonra işə salınır) | icra olunub |
| 14 | `14_handwritten_payloads` | PayloadsAllTheThings + fuzzdb payload siyahıları, bütün detektorlar, 5 seed | icra olunub |
| 15 | `15_openappsec_benign` | open-appsec real təmiz trafiki: dəyər və sorğu səviyyəsində FPR, 5 seed | icra olunub |
| 17 | `17_combined_v3` | Böyüdülmüş v3 dataseti (Kaggle + HttpParams + WAF-A-MoLE + open-appsec), 5 model × 2 konfiqurasiya × 5 seed, LODO, payload testi | icra olunub (bax `summary_v3.md`) |
| 16 | `16_wafamole` | WAF-A-MoLE: artefakt statistikası, köçürmə, əks istiqamət | icra olunub |

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

## 8. Section 14–13: əl ilə yazılmış payload-lar və char-CNN

### 8.1. Əl ilə yazılmış payload siyahıları (notebook 14)

**Məlumat.** `swisskyrepo/PayloadsAllTheThings` (`SQL Injection/Intruder/`, MIT) və `fuzzdb-project/fuzzdb`
(`attack/sql-injection/`, BSD-3 / CC BY 3.0), sabit commit-lər. 42 fayl, 2 133 sətir → boş (4), şərh (11), SQL tokeni
olmayan fuzz sətirləri (111) və dublikatlar (580) çıxarıldıqdan sonra **1 427 unikal payload**
(fayl üzrə saylar: `results/14_payload_sources.csv`). Model girişi = bir dəfə URL decode (ssenari A).
FPR üçün siyahılarda təmiz sinif olmadığından **HttpParams-ın təmiz sinfi** (train+val ilə üst-üstə düşənlər çıxarılıb) istifadə olunur.

**Müstəqillik** (seed 42 train ilə):

| Dəst | n | Tam üst-üstə düşmə % | Normallaşdırılmış üst-üstə düşmə % | İkiqat boşluq % | sqlmap skeleti train-də % | Median uzunluq |
|---|---|---|---|---|---|---|
| Əl ilə yazılmış (hamısı) | 1 427 | 1.8 | 7.5 | **0.3** | 11.5 | 39 |
| Bizim test, zərərli | 1 745 | 0.0 | 0.1 | 94.5 | 28.7 | 84 |
| HttpParams, zərərli | 10 852 | 2.4 | 55.3 | 0.0 | 63.4 | 75 |

Train+val ilə normallaşdırılmış formada üst-üstə düşənlər hər seed-də testdən çıxarılır (126–134), ~1 297 payload qalır.

**Recall və FPR** (%, orta ± std, 5 seed):

| Detektor | Recall | Recall, skeleti yeni | Recall, alt. whitespace (A) | FPR (HttpParams təmiz) |
|---|---|---|---|---|
| LR baza | 92.79 ± 2.29 | 92.59 ± 2.37 | 81.83 ± 2.66 | 0.02 ± 0.01 |
| SVM baza | 93.62 ± 1.52 | 93.39 ± 1.55 | 83.65 ± 2.46 | 0.03 ± 0.02 |
| RF baza | 84.77 ± 1.45 | 84.33 ± 1.46 | **35.59 ± 10.00** | 0.01 ± 0.00 |
| NB baza | 91.24 ± 0.33 | 91.21 ± 0.37 | 91.04 ± 0.39 | 29.28 ± 0.25 |
| LR + normallaşdırma | 95.10 ± 0.67 | 95.02 ± 0.72 | 95.20 ± 0.69 | 0.02 ± 0.01 |
| LR + norm. + augmentation | 95.16 ± 1.20 | 95.07 ± 1.26 | 95.26 ± 1.27 | 0.02 ± 0.01 |
| Qara siyahı (`sanitizeInput`) | 98.06 ± 0.03 | 98.02 ± 0.07 | 98.87 ± 0.00 | 8.56 ± 0.09 |
| Qara siyahı (`sanitizeSearch`) | 89.18 ± 0.14 | 89.00 ± 0.13 | 89.84 ± 0.13 | 0.24 ± 0.01 |
| libinjection 4.0.1 | 58.29 ± 0.14 | 57.44 ± 0.15 | 57.10 ± 0.11 | 0.00 ± 0.00 |
| CNN baza (13) | 58.49 ± 3.83 | 57.43 ± 3.85 | 32.36 ± 8.17 | 0.02 ± 0.01 |
| CNN + normallaşdırma (13) | 95.10 ± 1.20 | 94.97 ± 1.26 | 95.30 ± 1.20 | 0.03 ± 0.01 |

Seed 42–46 üçün HttpParams FPR-i notebook 12 ilə eynidir (fərq 0.0, `14_reproduction_check.csv`).
Qrafik: `figures/paper/14_handwritten_recall.png`.

**Şərh.** sqlmap formatında olmayan, insan tərəfindən yazılmış payload-larda baza modellər artıq daha zəifdir və alternativ
whitespace onları yenə salır (RF 84.8% → 35.6%), normallaşdırılmış LR isə bu dəstdə də sabit qalır (95.1% / 95.2%). Ən yaxşı
LR-in buraxdığı payload-ların əksəriyyəti (seed 42-də 48-dən 34-ü) tam SQL operatorlarıdır (`select current_user;`), çünki
Kaggle-da təmiz sinif tam SQL sorğularıdır — bu, datasetin ikinci, semantik məhdudiyyətidir. Qara siyahı recall-da öndədir,
amma real form dəyərlərində 8.6% FPR ilə; libinjection isə FPR-i sıfır saxlayaraq bu payload-ların yalnız 58%-ini tanıyır.

### 8.2. Simvol səviyyəli CNN (notebook 13)

Bayt embedding (32) → üç paralel Conv1d (kernel 3/5/7, 64 filtr) → global max-pool → dropout 0.3; Adam, maksimum 10 epoxa,
validation F1-ə görə ən yaxşı epoxa; 5 seed. **Baza** = yalnız kiçik hərf, **normallaşdırma** = `src/normalize.py`.

| Göstərici (%, orta ± std) | CNN baza | CNN + normallaşdırma | LR baza (12) | LR + norm. (12) |
|---|---|---|---|---|
| F1, Kaggle test | 99.67 ± 0.08 | 99.65 ± 0.08 | 99.68 ± 0.05 | 99.63 ± 0.09 |
| FPR, Kaggle test | 0.03 ± 0.03 | 0.04 ± 0.05 | 0.04 ± 0.04 | 0.06 ± 0.05 |
| F1, insan formatı | **57.35 ± 7.16** | 99.65 ± 0.08 | 95.91 ± 1.05 | 99.63 ± 0.09 |
| Recall, alt. whitespace (A) | **25.19 ± 11.50** | 99.73 ± 0.05 | 76.25 ± 4.82 | 99.76 ± 0.11 |
| Recall, inline şərh (A) | 60.73 ± 29.97 | 99.73 ± 0.05 | — | — |
| Recall, `double_url_encode` (A) | 59.14 ± 13.66 | 99.68 ± 0.06 | — | — |
| Recall, kombinasiya (A) | 71.97 ± 2.80 | 99.70 ± 0.12 | 93.36 ± 4.76 | 99.71 ± 0.12 |
| Recall, HttpParams | **41.92 ± 9.17** | 99.98 ± 0.00 | 96.91 ± 0.75 | 99.98 ± 0.01 |
| FPR, HttpParams | 0.02 ± 0.01 | 0.03 ± 0.01 | — | — |
| Recall, HttpParams + alt. whitespace | 16.95 ± 5.67 | 100.00 ± 0.00 | — | — |
| Recall, əl ilə yazılmış payload-lar | 58.49 ± 3.83 | 95.10 ± 1.20 | 92.79 ± 2.29 | 95.10 ± 0.67 |
| Recall, əl ilə yazılmış + alt. whitespace | 32.36 ± 8.17 | 95.30 ± 1.20 | 81.83 ± 2.66 | 95.20 ± 0.69 |

Baza CNN-in HttpParams-da buraxdığı payload-lar (orta 6 108) sqlmap boşluq formatına salındıqda **99.96%**-i tutulur.
Qrafik: `figures/paper/13_char_cnn_artifact.png`.

**Şərh.** Neyron şəbəkə artefaktdan qorunmur, əksinə ona TF-IDF modellərindən daha çox söykənir: Kaggle testində F1 99.7%
olan baza CNN "insan formatı"nda 57%-ə, HttpParams-da recall 42%-ə, alternativ whitespace ilə 25%-ə düşür. HttpParams-da
buraxılan payload-ların 99.96%-i yalnız sqlmap boşluqları əlavə olunanda tutulduğundan, CNN-in öyrəndiyi əsas siqnalın format
olduğu birbaşa görünür. Eyni normallaşdırma CNN-də də problemi tam aradan qaldırır və onu normallaşdırılmış LR ilə eyni
səviyyəyə gətirir — müdafiə model arxitekturasından asılı deyil.

## 9. Section 15–16: real təmiz trafik və WAF-A-MoLE

### 9.1. open-appsec real təmiz trafiki (notebook 15)

**Məlumat.** 692 brauzer sessiyasında (`legitimate.zip`, hər sessiya bir JSON faylı) 1 040 242 HTTP sorğusu var; onlardan 9 520 543 parametr dəyəri, o cümlədən **833 477 unikal dəyər** çıxarılıb. Bütün unikal dəyərlər yoxlanılıb, nümunə götürülməyib; iş vaxtı ≈4 saat olub.

| Detektor | Unikal dəyər FPR, % | Sorğu FPR, % |
|---|---|---|
| LR baza | 0.87 ± 0.13 | 16.96 ± 8.80 |
| SVM baza | 0.99 ± 0.19 | 14.29 ± 8.53 |
| RF baza | 0.35 ± 0.01 | 34.53 ± 5.32 |
| LR + norm. + augmentation (yerləşdirilən) | 1.24 ± 0.17 | 22.32 ± 7.39 |
| CNN baza / + norm. | 0.76 / 2.73 | 27.50 / 25.19 |
| Qara siyahı (sanitizeSearch) | 7.00 | 20.30 |
| libinjection 4.0.1 | **0.08** | **0.57** |

Unikal dəyərlərdə FPR ≈1%-dir, amma sorğu səviyyəsində 14–35%-ə qalxır. Səbəb tez-tez təkrarlanan qısa dəyərlərdir: `0` tək başına 394 min dəfə rast gəlinir və yerləşdirilən model onun 118 min halını bloklayır; `c`, `-1`, `{}` də siyahının başındadır. Tam cədvəllər, top-20 yanlış blok, səbəb qrupları və sessiyalar üzrə bölgü üçün bax: `summary_v3.md`, bölmə 9.

### 9.2. WAF-A-MoLE (notebook 16)

**Məlumat və bölmə.** `zangobot/wafamole_dataset` (Demetrio et al., SAC 2020; repoda lisenziya faylı yoxdur — paylanmır).
Parçalar README-dəki kimi birləşdirilib. README-nin `sqlparse.split()` üsulu hücum faylında **işləmir**: generator
payload-ları dırnaqları escape etmədən literal içinə qoyur və sqlparse sonrakı sorğuları yapışdırır (faylın ilk 20 MB-ı
3 262 "statement" verir, biri 18.9 MB; baytların 96.8%-i 2 000 simvoldan uzun "statement"-lərdədir). Ona görə fayl generatorun
dörd şablonunun (`SELECT`, ``INSERT INTO `tab` ``, ``UPDATE `tab` ``, ``DELETE FROM `tab` ``) başlanğıcında kəsilib,
yalnız təmiz faylın DDL başlığı sqlparse ilə bölünüb (`src/wafamole.py`, `16_split_report.csv`).
Nəticə: 1 004 669 hücum (745 593 unikal), 1 000 209 təmiz (923 425 unikal); 8 353 sorğu hər iki sinifdə olduğu üçün çıxarılıb.

**Artefakt statistikası** (10-cu notebook-un cədvəli ilə eyni format):

| Dataset | Sinif | n | İkiqat boşluq % | `=` ətrafında boşluq % | Mötərizə içində boşluq % | Böyük hərf % | Median uzunluq | Bizimlə üst-üstə düşmə % (normallaşdırılmış) |
|---|---|---|---|---|---|---|---|---|
| Modified_SQL_Dataset | zərərli | 11 370 | 94.9 | 81.1 | 86.9 | 2.0 | 85.5 | — |
| Modified_SQL_Dataset | təmiz | 18 885 | 29.8 | 14.8 | 24.4 | 61.3 | 37 | — |
| HttpParamsDataset | zərərli | 10 852 | 0.0 | 0.0 | 0.0 | 0.0 | 75 | 79.1 |
| HttpParamsDataset | təmiz | 19 304 | 0.0 | 0.0 | 0.0 | 0.0 | 9 | 37.3 |
| WAF-A-MoLE | zərərli | 737 240 | 3.5 | 52.8 | 22.4 | 100.0 | 174 | 0.0 |
| WAF-A-MoLE | təmiz | 915 072 | 0.0 | 47.4 | 22.7 | 100.0 | 70 | 0.0 |

WAF-A-MoLE-də ikiqat boşluq artefaktı demək olar ki, yoxdur, amma siniflər başqa formatda fərqlənir: hücumların 28.6%-ində
sətir sonu, 58.9%-ində şərh (`--`, `#`, `/*`) var, təmizlərdə 0%; təmiz sorğulardakı sətir literalları təsadüfi hərflərdən
ibarətdir (`'nrgbrgef'`) — WAF-A-MoLE-də öyrədilmiş LR-in ən güclü "təmiz" n-gram-ları tək hərflərdir (`j`, `z`, `q`).

**Bizim modellər WAF-A-MoLE-də** (20 000 hücum + 20 000 təmiz, seed 42; alternativ whitespace hər iki sinfə tətbiq olunur), %:

| Detektor | Recall | FPR | Recall, alt. whitespace | FPR, alt. whitespace |
|---|---|---|---|---|
| LR baza | 90.83 | 21.31 | 86.56 | 10.03 |
| SVM baza | 88.81 | 11.89 | 79.09 | 1.97 |
| RF baza | 70.12 | 18.84 | **19.50** | 0.00 |
| NB baza | 80.55 | 21.62 | 77.58 | 35.63 |
| LR + normallaşdırma | 95.95 | 26.55 | 95.95 | 26.55 |
| LR + norm. + augmentation | 95.24 | 21.72 | 95.24 | 21.72 |
| CNN baza | 46.50 | 3.73 | **2.34** | 0.00 |
| CNN + normallaşdırma | 95.51 | 39.95 | 95.51 | 39.95 |
| Qara siyahı (`sanitizeInput` / `sanitizeSearch`) | 100.00 | 100.00 | 100.00 | 100.00 |
| libinjection 4.0.1 | 78.12 | 45.06 | 77.90 | 45.06 |

**Əks test: baza LR WAF-A-MoLE-də öyrədilir** (nümunədən kənar 20k + 20k train, 5k + 5k val), %:

| Test dəsti | LR baza: recall | LR baza: FPR | LR baza: recall, alt. whitespace | LR + norm.: recall | LR + norm.: FPR | LR + norm.: recall, alt. whitespace |
|---|---|---|---|---|---|---|
| WAF-A-MoLE nümunə | 99.87 | 0.30 | 97.19 | 99.67 | 0.39 | 99.67 |
| Kaggle test | 82.81 | 36.65 | **56.81** | 90.89 | 58.05 | 91.46 |
| HttpParams | 95.10 | 0.02 | **76.85** | 93.63 | 3.40 | 94.13 |
| Əl ilə yazılmış payload-lar | 92.15 | — | **79.77** | 96.92 | — | 97.65 |

Qrafik: `figures/paper/16_wafamole.png`.

**Şərh.** WAF-A-MoLE-də sqlmap-ə xas ikiqat boşluq yoxdur, amma onun da öz format artefaktları var (yalnız hücumlarda sətir sonu
və şərh, təmiz sinifdə təsadüfi hərf literalları), və orada öyrədilmiş baza LR eyni zəifliyi göstərir: öz testində 99.9% recall
verən model alternativ whitespace ilə Kaggle-da 82.8% → 56.8%, HttpParams-da 95.1% → 76.9% düşür, normallaşdırılmış variant isə
sabit qalır. Bizim baza modellərimiz bu tam SQL sorğularına zəif köçür — xüsusilə CNN baza (46.5%, alt. whitespace ilə 2.3%) və
RF baza (70.1% → 19.5%) — normallaşdırılmış modellər recall-u ~95%-ə qaldırır. Lakin FPR hər iki istiqamətdə yüksəkdir
(21–40%), çünki iki datasetin təmiz sinifləri tam fərqli paylanmadır; bu, "təmiz" sinfin tərifinin datasetlər arasında
köçürülə bilmədiyini göstərir və qara siyahı burada hər sorğunu bloklayır.
