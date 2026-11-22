# Böyüdülmüş dataset (v3): birləşdirilmiş məlumat, modellər və real təmiz trafik

Bu sənəd müəllimin "dataseti böyüt" tələbinə cavabdır. İki hissədən ibarətdir:

- **Notebook 15**: əvvəlki (v2) modellərin open-appsec-in real brauzer trafikində yanlış bloklama dərəcəsi (FPR).
- **Notebook 17**: dörd mənbədən yığılmış yeni v3 dataseti, onun təmizlənməsi, EDA, beş model × iki konfiqurasiya × beş seed və üç test ssenarisi.

v3-ün bütün nəticələri yalnız yeni qovluqlardadır: `data/v3/`, `results/v3/`, `figures/v3/`. Köhnə nəticələrə toxunulmayıb.

Tarix: 2026-11-21. Bütün metriklər, başqa cür deyilməyibsə, beş seed (42–46) üzrə **orta ± standart sapma** şəklində və faizlə verilir (ROC-AUC istisna).

---

## 1. Datasetlər

| Ad | Link | Ölçü (xam) | Sinif sayı (zərərli / təmiz) | Lisenziya | v3-də rolu |
|---|---|---|---|---|---|
| Modified_SQL_Dataset (sajid576) | https://www.kaggle.com/datasets/sajid576/sql-injection-dataset | 30 255 sətir (notebook 01 təmizləməsindən sonra) | 11 370 / 18 885 | Kaggle-da göstərilməyib (Unknown) | train/val/test, hamısı |
| HttpParamsDataset (Morzeux) | https://github.com/Morzeux/HttpParamsDataset | 30 156 sətir (`sqli` + `norm`) | 10 852 / 19 304 | MIT | train/val/test, hamısı |
| WAF-A-MoLE dataset (zangobot) | https://github.com/zangobot/wafamole_dataset | 2 004 878 sətir, 1 669 018 unikal | 1 004 669 / 1 000 209 | Lisenziya faylı yoxdur | train/val/test, hər sinifdən 40 000 təsadüfi sətir (seed 42) |
| open-appsec WAF comparison, `legitimate.zip` | https://github.com/openappsec/waf-comparison-project | 1 040 242 HTTP sorğusu, 692 brauzer sessiyası, 833 477 unikal dəyər | 0 / hamısı | Apache-2.0 | train/val/test, 40 000 təsadüfi unikal dəyər (seed 42), hamısı təmiz |
| Payload siyahıları (notebook 14): PayloadsAllTheThings + fuzzdb | https://github.com/swisskyrepo/PayloadsAllTheThings, https://github.com/fuzzdb-project/fuzzdb | 1 427 unikal payload | 1 427 / 0 | MIT; BSD-3 / CC BY 3.0 | **yalnız test**, train-ə düşmür |

**Qeydlər:**

- **open-appsec dəyərləri.** open-appsec-dən nümunə götürülməzdən əvvəl UTF-8-də yazıla bilməyən (tək "surrogate" simvolları olan) dəyərlər çıxarılıb. Belə dəyər 1 idi, binar zibil idi.
- **Paylaşma.** Kaggle və WAF-A-MoLE lisenziyası olmadığı üçün `data/v3/` repoya daxil edilmir. Fayllar notebook 17 ilə yenidən yaradılır.

## 2. Təmizləmə

Hər sətirdə üç sütun var: `query`, `label`, `source`. Təmizləmə addımları cədvəldəki sıra ilə tətbiq olunur. "Normallaşdırılmış forma" `normalize()` funksiyasının nəticəsidir: 3 dəfə decode, şərhlərin silinməsi, boşluqların vahidləşdirilməsi, kiçik hərf.

Mənbələr arası dublikatlarda prioritet belədir: Kaggle → HttpParams → WAF-A-MoLE → open-appsec. Dublikat sətir prioriteti yüksək olan mənbədə qalır.

| Mənbə | İlkin | Boş | Mənbə daxilində tam dublikat | Hər iki sinifdə (norm. forma) | Payload siyahıları ilə üst-üstə | Mənbələr arası tam dublikat | Mənbələr arası norm. dublikat | **Yekun** | Zərərli | Təmiz |
|---|---|---|---|---|---|---|---|---|---|---|
| Kaggle | 30 255 | 0 | 0 | 5 | 163 | 0 | 0 | **30 087** | 11 203 | 18 884 |
| HttpParams | 30 156 | 0 | 0 | 1 | 5 | 7 592 | 8 189 | **14 369** | 2 271 | 12 098 |
| WAF-A-MoLE | 80 000 | 0 | 0 | 0 | 0 | 0 | 0 | **80 000** | 40 000 | 40 000 |
| open-appsec | 40 000 | 0 | 0 | 4 | 0 | 66 | 6 | **39 924** | 0 | 39 924 |
| **Cəmi** | 180 411 | 0 | 0 | 10 | 168 | 7 658 | 8 195 | **164 380** | 53 474 | 110 906 |

Mənbə: `results/v3/17_cleaning_report.csv`.

**Əsas müşahidə:** HttpParams-ın yarıdan çoxu (15 785 sətir, 52.3%) Kaggle-da artıq var. Normallaşdırmadan sonra bu sətirlər eynidir və çıxarılıb, ona görə HttpParams-ın zərərli sinfi 10 852-dən 2 271-ə düşüb. WAF-A-MoLE başqa mənbələrlə üst-üstə düşmür (0%).

**Bölmə.** Hər mənbə ayrıca qrup əsaslı 70/15/15 nisbətində bölünür, sonra hissələr birləşdirilir. Qrup normallaşdırılmış formadır, ona görə eyni normallaşdırılmış sorğu iki hissəyə düşə bilməz; bunu kod `assert` ilə yoxlayır.

Seed 42 üçün test hissəsi 24 664 sətirdir (8 087 zərərli):

| Mənbə | Test sətri | Zərərli |
|---|---|---|
| Kaggle | 4 518 | 1 712 |
| HttpParams | 2 156 | 335 |
| WAF-A-MoLE | 12 000 | 6 040 |
| open-appsec | 5 990 | 0 |

Bütün seed-lər: `results/v3/17_split_report.csv`.

## 3. EDA

**(a) Mənbə × sinif** — `figures/v3/17a_source_class_counts.png`, `results/v3/17_eda_counts.csv`

| Mənbə | Zərərli | Təmiz | Cəmi | Zərərli % |
|---|---|---|---|---|
| Kaggle | 11 203 | 18 884 | 30 087 | 37.2 |
| HttpParams | 2 271 | 12 098 | 14 369 | 15.8 |
| WAF-A-MoLE | 40 000 | 40 000 | 80 000 | 50.0 |
| open-appsec | 0 | 39 924 | 39 924 | 0.0 |
| **Cəmi** | 53 474 | 110 906 | 164 380 | 32.5 |

**(b) Uzunluq** — `figures/v3/17b_query_length_boxplot.png`, `results/v3/17_eda_length.csv`

Median uzunluqlar, simvol:

| Mənbə | Zərərli | Təmiz |
|---|---|---|
| Kaggle | 87 | 37 |
| HttpParams | 85 | 9 |
| WAF-A-MoLE | 174 | 70 |
| open-appsec | — | 23 |

Hər mənbədə zərərli sorğular təmizlərdən 2–9 dəfə uzundur. Ən böyük fərq HttpParams-dadır (85-ə qarşı 9). Deməli, uzunluq tək başına güclü, amma süni bir siqnaldır.

**(c) Format artefaktları** — `figures/v3/17c_format_artifacts.png`, `results/v3/17_eda_format_artifacts.csv`

Sətirlərin neçə faizində artefakt var:

| Mənbə | Sinif | İkiqat boşluq | Sətir sonu | Şərh |
|---|---|---|---|---|
| Kaggle | zərərli | **95.2** | 0.0 | 52.2 |
| Kaggle | təmiz | 29.8 | 0.0 | 0.04 |
| HttpParams | zərərli | 0.0 | 0.0 | 66.4 |
| HttpParams | təmiz | 0.0 | 0.0 | 0.0 |
| WAF-A-MoLE | zərərli | 3.3 | **28.5** | 59.1 |
| WAF-A-MoLE | təmiz | 0.0 | 0.0 | 0.0 |
| open-appsec | təmiz | 0.44 | 0.35 | 1.12 |

Şərh (`--`, `#`, `/*`) üç mənbədə praktik olaraq yalnız zərərli sinifdə görünür. Kaggle-da ikiqat boşluq, WAF-A-MoLE-da isə sətir sonu da sinfi göstərir. Bu, modelin hücumun mənasını yox, formatı öyrənə biləcəyini göstərir. Bunu 8-ci bölmə yoxlayır.

**(d) Mənbələr arası üst-üstə düşmə** — `figures/v3/17d_source_overlap_heatmap.png`, `results/v3/17_eda_overlap_pct.csv`

Normallaşdırılmış formada, mənbələr arası dublikatlar çıxarılmazdan əvvəl ölçülüb:

- Kaggle ↔ HttpParams: 52.3%
- open-appsec ↔ Kaggle və HttpParams: 0.1–0.2%
- WAF-A-MoLE ↔ hamısı: 0%

## 4. Modellər və protokol

- **Modellər:** Logistic Regression, Linear SVM, Random Forest (200 ağac), Multinomial Naive Bayes — hamısı TF-IDF char 1–5 n-gram ilə. Bir də bayt səviyyəli char-CNN.
- **Konfiqurasiyalar:**
  - **baza**: xam sorğu;
  - **norm.**: `normalize()` funksiyasından keçmiş sorğu.
- **Hiperparametrlər:** validation F1 ilə seçilir, grid `C`/`alpha` ∈ {3 dəyər}. CNN 5 epoch öyrədilir. Seçimlər: `results/v3/17_model_selection.csv`.
- **Seed-lər:** 42–46. Hər seed üçün bölmə də, model də yenidən qurulur.
- **alt. whitespace:** yalnız zərərli sətirlərdə boşluq alternativ ayırıcılarla (`/**/`, `%09`, `%0a` …) əvəz olunur. Təmiz sətirlər dəyişmir, buna görə FPR iki girişdə eynidir.
- **İş vaxtı:** notebook 17 təxminən 9.7 saat işləyib (4 nüvəli CPU).

## 5. Test A: birləşdirilmiş test və hər mənbənin öz test hissəsi

### 5.1. Birləşdirilmiş test (24 664 sətir/seed)

Mənbə: `results/v3/17_A_combined_table.csv`. Normal giriş:

| Model | Accuracy | Precision | Recall | F1 | ROC-AUC | FPR |
|---|---|---|---|---|---|---|
| LR baza | 99.76 ± 0.04 | 99.70 ± 0.07 | 99.56 ± 0.13 | 99.63 ± 0.06 | 0.9996 ± 0.0002 | 0.14 ± 0.04 |
| LR norm. | 99.81 ± 0.02 | 99.71 ± 0.04 | 99.70 ± 0.07 | 99.71 ± 0.03 | 0.9997 ± 0.0002 | 0.14 ± 0.02 |
| SVM baza | 99.86 ± 0.02 | 99.73 ± 0.04 | 99.85 ± 0.03 | 99.79 ± 0.03 | 0.9998 ± 0.0001 | 0.13 ± 0.02 |
| SVM norm. | 99.86 ± 0.01 | 99.73 ± 0.04 | 99.84 ± 0.02 | 99.79 ± 0.02 | 0.9998 ± 0.0001 | 0.13 ± 0.02 |
| RF baza | 99.74 ± 0.02 | 99.58 ± 0.08 | 99.63 ± 0.03 | 99.60 ± 0.04 | 0.9998 ± 0.0001 | 0.21 ± 0.04 |
| RF norm. | 99.74 ± 0.03 | 99.57 ± 0.07 | 99.64 ± 0.09 | 99.60 ± 0.05 | 0.9998 ± 0.0001 | 0.21 ± 0.03 |
| NB baza | 99.80 ± 0.02 | 99.55 ± 0.07 | 99.84 ± 0.04 | 99.70 ± 0.04 | 0.9999 ± 0.0001 | 0.22 ± 0.03 |
| NB norm. | 99.82 ± 0.01 | 99.63 ± 0.03 | 99.83 ± 0.03 | 99.73 ± 0.01 | 0.9999 ± 0.0001 | 0.18 ± 0.02 |
| **CNN baza** | 99.87 ± 0.02 | 99.75 ± 0.02 | 99.86 ± 0.04 | **99.80 ± 0.03** | 0.9999 ± 0.0001 | 0.12 ± 0.01 |
| CNN norm. | 99.87 ± 0.02 | 99.75 ± 0.03 | 99.84 ± 0.06 | 99.79 ± 0.03 | 0.9999 ± 0.0001 | 0.12 ± 0.01 |

Alternativ whitespace ilə (`results/v3/17_A_combined_alt_ws_table.csv`):

- norm. modellərin nəticələri normal girişlə **eynidir**;
- baza modellərin recall və F1-i düşür. FPR dəyişmir, çünki təmiz sətirlərə toxunulmur:

| Model | Accuracy | Precision | Recall | F1 | ROC-AUC | FPR |
|---|---|---|---|---|---|---|
| LR baza | 96.23 ± 1.39 | 99.67 ± 0.07 | 88.77 ± 4.25 | 93.86 ± 2.41 | 0.9985 ± 0.0007 | 0.14 ± 0.04 |
| LR norm. | 99.81 ± 0.02 | 99.71 ± 0.04 | 99.70 ± 0.07 | 99.71 ± 0.03 | 0.9997 ± 0.0002 | 0.14 ± 0.02 |
| SVM baza | 97.55 ± 0.30 | 99.71 ± 0.05 | 92.75 ± 0.87 | 96.10 ± 0.47 | 0.9994 ± 0.0001 | 0.13 ± 0.02 |
| SVM norm. | 99.86 ± 0.01 | 99.73 ± 0.04 | 99.84 ± 0.02 | 99.79 ± 0.02 | 0.9998 ± 0.0001 | 0.13 ± 0.02 |
| RF baza | 91.91 ± 0.55 | 99.44 ± 0.10 | 75.60 ± 1.85 | 85.89 ± 1.20 | 0.9983 ± 0.0003 | 0.21 ± 0.04 |
| RF norm. | 99.74 ± 0.03 | 99.57 ± 0.07 | 99.64 ± 0.09 | 99.60 ± 0.05 | 0.9998 ± 0.0001 | 0.21 ± 0.03 |
| NB baza | 98.25 ± 0.09 | 99.53 ± 0.08 | 95.08 ± 0.26 | 97.25 ± 0.14 | 0.9991 ± 0.0001 | 0.22 ± 0.03 |
| NB norm. | 99.82 ± 0.01 | 99.63 ± 0.03 | 99.83 ± 0.03 | 99.73 ± 0.01 | 0.9999 ± 0.0001 | 0.18 ± 0.02 |
| CNN baza | 98.80 ± 0.44 | 99.74 ± 0.02 | 96.56 ± 1.36 | 98.12 ± 0.70 | 0.9996 ± 0.0001 | 0.12 ± 0.01 |
| CNN norm. | 99.87 ± 0.02 | 99.75 ± 0.03 | 99.84 ± 0.06 | 99.79 ± 0.03 | 0.9999 ± 0.0001 | 0.12 ± 0.01 |

Hər mənbə və LODO üçün altı metrikin hamısı (normal və alt. whitespace): `results/v3/17_A_per_source_mean_std.csv`, `results/v3/17_B_lodo_mean_std.csv`.

**Ən yaxşı model** (orta F1): CNN baza. Confusion matrix (seed 42): `figures/v3/17_confusion_matrix_best.png`, `results/v3/17_confusion_matrix_best_seed42.csv`.

| | Normal giriş | Alt. whitespace |
|---|---|---|
| TN | 16 558 | 16 558 |
| FP | 19 | 19 |
| FN | 12 | 410 |
| TP | 8 075 | 7 677 |

**Şərh.**

1. Birləşdirilmiş testdə bütün on model F1 = 99.6–99.8% və FPR = 0.12–0.22% göstərir, modellər arasındakı fərq standart sapma ilə müqayisə ediləcək qədər kiçikdir.
2. Normallaşdırma normal girişdə nəticəni demək olar dəyişmir. Alternativ whitespace-də isə baza modellərin recall-u 3–24 faiz bəndi düşür, norm. modellər eyni qalır; norm. modellərdə bu, konstruksiyadan irəli gəlir, çünki `normalize()` boşluqları vahidləşdirir.
3. Ən yaxşı baza model (CNN) belə alt. whitespace-də 410 hücumu buraxır, ona görə yerləşdirmə üçün normallaşdırma şərtdir.

### 5.2. Hər mənbənin öz test hissəsi

Mənbə: `results/v3/17_A_per_source_table.csv`. Normal girişdə F1 / FPR:

| Model | Kaggle F1 | Kaggle FPR | HttpParams F1 | HttpParams FPR | WAF-A-MoLE F1 | WAF-A-MoLE FPR | open-appsec FPR |
|---|---|---|---|---|---|---|---|
| LR baza | 99.44 ± 0.18 | 0.04 ± 0.03 | 100.00 ± 0.00 | 0.00 ± 0.00 | 99.67 ± 0.07 | 0.37 ± 0.09 | 0.02 ± 0.02 |
| LR norm. | 99.45 ± 0.10 | 0.06 ± 0.05 | 99.97 ± 0.07 | 0.01 ± 0.02 | 99.77 ± 0.03 | 0.34 ± 0.07 | 0.02 ± 0.02 |
| SVM baza | 99.66 ± 0.11 | 0.01 ± 0.03 | 100.00 ± 0.00 | 0.00 ± 0.00 | 99.82 ± 0.03 | 0.34 ± 0.05 | 0.01 ± 0.01 |
| SVM norm. | 99.62 ± 0.06 | 0.02 ± 0.03 | 100.00 ± 0.00 | 0.00 ± 0.00 | 99.83 ± 0.03 | 0.34 ± 0.05 | 0.01 ± 0.01 |
| RF baza | 99.44 ± 0.12 | 0.00 ± 0.00 | 100.00 ± 0.00 | 0.00 ± 0.00 | 99.63 ± 0.04 | 0.57 ± 0.11 | 0.01 ± 0.01 |
| RF norm. | 99.47 ± 0.18 | 0.00 ± 0.00 | 100.00 ± 0.00 | 0.00 ± 0.00 | 99.63 ± 0.05 | 0.57 ± 0.10 | 0.01 ± 0.01 |
| NB baza | 99.39 ± 0.16 | 0.32 ± 0.18 | 99.81 ± 0.26 | 0.07 ± 0.09 | 99.84 ± 0.02 | 0.30 ± 0.04 | 0.13 ± 0.04 |
| NB norm. | 99.46 ± 0.06 | 0.18 ± 0.02 | 99.88 ± 0.13 | 0.04 ± 0.05 | 99.84 ± 0.03 | 0.31 ± 0.05 | 0.10 ± 0.04 |
| CNN baza | 99.66 ± 0.13 | 0.02 ± 0.03 | 100.00 ± 0.00 | 0.00 ± 0.00 | 99.86 ± 0.01 | 0.28 ± 0.01 | 0.04 ± 0.03 |
| CNN norm. | 99.62 ± 0.11 | 0.00 ± 0.00 | 100.00 ± 0.00 | 0.00 ± 0.00 | 99.85 ± 0.02 | 0.29 ± 0.03 | 0.04 ± 0.02 |

Alt. whitespace-də recall (baza / norm.):

| Model | Kaggle | HttpParams | WAF-A-MoLE |
|---|---|---|---|
| LR | 71.84 ± 10.46 / 99.00 | 98.80 / 100.00 | 92.95 / 99.88 |
| SVM | 70.70 ± 2.50 / 99.29 | 99.70 / 100.00 | 98.52 / 99.99 |
| RF | **23.30 ± 2.81** / 98.94 | 96.21 / 100.00 | 89.06 / 99.82 |
| NB | 78.82 ± 1.00 / 99.23 | 100.00 / 100.00 | 99.34 / 99.99 |
| CNN | 91.94 ± 3.27 / 99.25 | 99.70 / 100.00 | 97.68 / 99.99 |

**Şərh.**

1. Mənbə daxilində bütün modellər 99.4–100% F1 göstərir. HttpParams-ın 100%-i ən asan hissədir: onun təmiz sorğuları çox qısadır, median 9 simvol.
2. FPR ən yüksək WAF-A-MoLE-dadır: 0.28–0.57%, Kaggle və open-appsec-də isə əksər modellərdə 0.00–0.06%. Səbəb odur ki, oradakı təmiz sətirlər də SQL sorğularıdır, sadəcə zərərsizdir.
3. Alt. whitespace ən çox Kaggle baza modellərinə zərbə vurur, RF baza recall-u 23%-ə düşür. Bu, EDA (c)-dəki nəticəni təsdiqləyir: Kaggle-ın zərərli sətirlərinin 95%-ində ikiqat boşluq var və baza modellər buna söykənir.

## 6. Test B: leave-one-dataset-out (LODO)

Sütundakı mənbə train və val-dan tam çıxarılır, model qalan üç mənbədə öyrədilir və **həmin mənbənin bütün sətirlərində** test olunur.

- TF-IDF modelləri 5 seed ilə yoxlanılıb.
- CNN vaxt səbəbi ilə yalnız seed 42 ilə yoxlanılıb, ona görə std yoxdur.
- open-appsec-də zərərli sinif olmadığı üçün orada yalnız FPR var.

Mənbələr: `results/v3/17_B_lodo_table.csv`, `figures/v3/17_lodo_heatmap.png`.

| Model | Kaggle Recall | Kaggle FPR | Kaggle F1 | HttpParams Recall | HttpParams FPR | WAF-A-MoLE Recall | WAF-A-MoLE FPR | WAF-A-MoLE F1 | open-appsec FPR |
|---|---|---|---|---|---|---|---|---|---|
| LR baza | 80.68 ± 1.81 | 18.16 ± 12.50 | 76.89 ± 6.13 | 99.89 ± 0.02 | 0.00 ± 0.01 | 88.59 ± 2.47 | 10.77 ± 5.85 | 88.92 ± 2.70 | 0.24 ± 0.03 |
| LR norm. | 86.47 ± 2.57 | 20.65 ± 15.41 | 78.99 ± 8.76 | 99.88 ± 0.06 | 0.00 ± 0.00 | 95.49 ± 0.47 | 14.53 ± 3.37 | 90.95 ± 1.30 | 0.27 ± 0.02 |
| SVM baza | 82.01 ± 2.21 | 6.23 ± 0.86 | 85.19 ± 0.76 | 99.91 ± 0.00 | 0.00 ± 0.00 | 93.41 ± 1.30 | 18.84 ± 6.90 | 88.09 ± 2.18 | 0.39 ± 0.02 |
| SVM norm. | 93.91 ± 0.58 | 5.67 ± 0.61 | 92.31 ± 0.19 | 99.91 ± 0.00 | 0.01 ± 0.00 | 95.33 ± 0.86 | 16.43 ± 6.05 | 90.09 ± 2.07 | 0.35 ± 0.01 |
| RF baza | 68.39 ± 0.86 | 10.79 ± 1.71 | 73.32 ± 1.10 | 98.06 ± 0.31 | 0.00 ± 0.00 | 78.40 ± 1.74 | 4.78 ± 1.36 | 85.59 ± 0.82 | 0.27 ± 0.03 |
| RF norm. | 78.82 ± 2.56 | 10.78 ± 1.74 | 80.02 ± 2.63 | 99.91 ± 0.00 | 0.00 ± 0.00 | 83.90 ± 0.50 | 3.06 ± 0.84 | 89.75 ± 0.26 | 0.35 ± 0.08 |
| NB baza | 91.52 ± 0.20 | 4.01 ± 0.08 | 92.31 ± 0.11 | 99.91 ± 0.00 | 0.08 ± 0.01 | 86.81 ± 3.01 | 2.37 ± 2.62 | 91.76 ± 0.66 | 1.59 ± 0.02 |
| NB norm. | **99.13 ± 0.05** | 7.30 ± 0.05 | **93.77 ± 0.05** | 99.91 ± 0.00 | 0.07 ± 0.01 | 87.00 ± 2.80 | 1.35 ± 1.39 | 92.37 ± 0.97 | 1.21 ± 0.02 |
| CNN baza (seed 42) | 75.35 | 7.35 | 80.27 | 98.86 | 0.00 | 62.05 | 0.27 | 76.45 | 0.86 |
| CNN norm. (seed 42) | 96.25 | 14.23 | 87.40 | 99.91 | 0.00 | 88.58 | 1.25 | **93.32** | 0.38 |

Alt. whitespace-də recall (baza → norm.):

| Model | Kaggle | WAF-A-MoLE |
|---|---|---|
| LR | 59.4 → 86.5 | 60.2 → 95.5 |
| SVM | 49.3 → 93.9 | 90.7 → 95.3 |
| RF | **3.5** → 78.8 | 35.6 → 83.9 |
| NB | 69.1 → 99.1 | 76.0 → 87.0 |
| CNN | 80.7 → 96.3 | 25.9 → 88.6 |

Bütün sütunlar 17_B cədvəlindədir.

**Şərh.**

1. Mənbə train-dən çıxarılanda nəticə kəskin pisləşir. Kaggle-da F1 73–94%, FPR 4–21%; WAF-A-MoLE-da F1 76–93%, FPR 0.3–19% olur. Mənbə daxilindəki 99.4–100%-lik nəticə başqa paylanmaya keçmir.
2. Normallaşdırma LODO-da da ən etibarlı yaxşılaşmadır. Kaggle-da SVM recall-u 82-dən 94%-ə, CNN recall-u 75-dən 96%-ə qalxır. Alt. whitespace-də baza RF Kaggle hücumlarının yalnız 3.5%-ini tapır, norm. RF isə 78.8%-ini.
3. HttpParams-ın 99.9%-lik recall-u əsl ümumiləşdirmə sayılmamalıdır. Onun hücumlarının çoxu Kaggle ilə eyni mənbədən gəlir: dublikatlar çıxarılsa da, yaxın variantlar qalır. open-appsec-in FPR-i isə mənbə daxilindəki 0.01–0.13%-dən LODO-da 0.24–1.59%-ə qalxır.

## 7. Test C: payload siyahıları (yalnız test)

- **Test dəsti:** notebook 14-ün 1 427 unikal payload-ı. Normallaşdırılmış formada v3-də olan hər sətir əvvəlcədən çıxarılıb (168 sətir, bax: 2-ci bölmə).
- **FPR:** open-appsec-in test hissəsində ölçülür (≈5 990 sətir).

Mənbə: `results/v3/17_C_payload_table.csv`.

| Model | Recall | Recall, alt. whitespace | FPR (open-appsec test) |
|---|---|---|---|
| LR baza | 86.63 ± 1.71 | 77.62 ± 5.20 | 0.02 ± 0.02 |
| LR norm. | 91.17 ± 1.08 | 91.17 ± 1.08 | 0.02 ± 0.02 |
| SVM baza | 89.39 ± 0.61 | 72.71 ± 1.75 | 0.01 ± 0.01 |
| SVM norm. | 91.17 ± 0.61 | 91.17 ± 0.61 | 0.01 ± 0.01 |
| RF baza | 88.35 ± 3.35 | 38.32 ± 4.64 | 0.01 ± 0.01 |
| RF norm. | **91.49 ± 0.15** | **91.49 ± 0.15** | 0.01 ± 0.01 |
| NB baza | 90.95 ± 2.03 | 84.88 ± 2.12 | 0.13 ± 0.04 |
| NB norm. | 87.90 ± 2.12 | 87.90 ± 2.12 | 0.10 ± 0.04 |
| CNN baza | 90.74 ± 0.63 | 76.12 ± 2.45 | 0.04 ± 0.03 |
| CNN norm. | 89.96 ± 1.76 | 89.96 ± 1.76 | 0.04 ± 0.02 |

**Şərh.**

1. Train-də olmayan əl ilə yazılmış payload-larda recall 86.6–91.5%-dir. Bu, birləşdirilmiş testdəki 99.6–99.9%-dən təxminən 8–13 faiz bəndi aşağıdır, yəni payload-ların təxminən hər 10-dan biri buraxılır.
2. Normallaşdırma LR, SVM və RF-də recall-u 2–5 faiz bəndi artırır. Alt. whitespace-də isə fərqi 13–53 faiz bəndinə çatdırır, ən çox RF-də: 38.3-ə qarşı 91.5.
3. open-appsec-in real təmiz dəyərlərində FPR çox aşağıdır (0.01–0.13%). Bunun səbəbi v3-ün train hissəsinə open-appsec-in öz dəyərlərinin daxil edilməsidir. Notebook 15-də bu trafiki görməyən v2 modelləri 0.35–2.7% FPR verirdi (bax: 9-cu bölmə).

## 8. Artefakt yoxlaması: LR baza modelinin top-20 n-gram-ı

Ölçülən: seed 42 modelinin ən böyük müsbət (zərərli) və mənfi (təmiz) əmsallı 20 n-gram-ı.

Mənbələr: `results/v3/17_lr_base_top20_ngrams.csv`, `figures/v3/17_lr_base_top_ngrams.png`.

- **Zərərli tərəfdə 20 n-gram-dan 9-u format n-gram-ıdır:**
  - 2-si **şərh** n-gram-ıdır: `--` (7-ci yer, əmsal 7.29) və `#` (14-cü yer, 5.00);
  - 7-si boşluqla bitişik qısa parçalardır: `) `, tək boşluq `' '`, `' "`, `"' "`, `" '"`, `' a'`, `'1 '`.
  - Qalan yerləri dırnaq və mötərizə tutur: `'"'`, `)`, `"'"`, `=`, `','`, `(`, `))`. SQL açar sözündən yalnız `or ` var, 17-ci yerdə.
- **Təmiz tərəfdə 20 n-gram-dan 8-i format n-gram-ıdır:**
  - 7-si **tək təsadüfi hərfdir**: `t`, `m`, `f`, `i`, `g`, `j`, `o`;
  - 1-i boşluq n-gram-ıdır: `' -'`.
  - Qalanları rəqəm və `limit -1` parçalarıdır: `' -1'`, `'-1'`, `'mit -'`, `'2;'`, `'4'`, `'0'`.
- **Sətir sonu n-gram-ı top-20-də yoxdur,** halbuki WAF-A-MoLE-un zərərli sətirlərinin 28.5%-ində sətir sonu var.

**Açıq qeyd:** top-20-də şərh n-gram-ları (`--`, `#`) və təsadüfi tək hərf n-gram-ları **var**, sətir sonu n-gram-ı **yoxdur**.

**Şərh.**

1. Baza LR modeli SQL açar sözlərinə az söykənir. Onun ən güclü siqnalları dırnaq, mötərizə, şərh simvolları və boşluq ilə bitişik parçalardır. Bunlar EDA (c)-dəki format fərqləri ilə üst-üstə düşür, məsələn şərh demək olar yalnız zərərli sinifdə var.
2. Təmiz sinfin tək hərfli n-gram-ları (`t`, `m`, `f` …) qısa, mətn kimi dəyərlərin (HttpParams və open-appsec, median 9–23 simvol) izidir. Yəni model "qısa, sadə hərfli dəyər təmizdir" qaydasını öyrənib.
3. Bu, 5.2 və 6-cı bölmələrdəki alt. whitespace düşüşünü izah edir. Normallaşdırma şərhləri silir və boşluqları vahidləşdirir, ona görə norm. modellər bu artefaktlara daha az həssasdır.

## 9. Notebook 15: open-appsec real təmiz trafiki (v2 modelləri)

**Məlumat.**

- 692 brauzer sessiyasında (open-appsec `legitimate.zip`, hər sessiya bir JSON faylı) 1 040 242 HTTP sorğusu var.
- Bu sorğulardan 657 160-ında ən azı bir parametr dəyəri var: query, JSON body, form və ya multipart.
- Cəmi 9 520 543 dəyər var, onlardan **833 477-si unikaldır**; median uzunluq 23 simvoldur.
- 4096 simvoldan uzun 6 968 dəyər kəsilib (`maxLength`).
- Mənbə: `results/15_extraction_summary.csv`.

**Həcm.**

- **Bütün 833 477 unikal dəyər** 11 detektorla, öyrədilmiş modellərdə isə 5 seed ilə yoxlanılıb.
- 200 000-lik nümunəyə ehtiyac olmayıb: ölçülmüş iş vaxtı təxminən 4 saat idi, bu da 6 saatlıq limitdən azdır.
- `charcnn_norm_46` bu iş zamanı öyrədilib.
- Modellər v2-nin (Kaggle) modelləridir və bu trafiki heç vaxt görməyiblər.

**Metriklər:**

- **unikal dəyər FPR:** bloklanan unikal dəyərlərin payı;
- **çəkili dəyər FPR:** təkrarlarla birlikdə bloklanan dəyər payı;
- **sorğu FPR:** ən azı bir dəyəri bloklanan sorğuların payı; burada yalnız dəyəri olan sorğular sayılır, cədvəldəki "bütün sorğular" sütunu isə 1 040 242 sorğunun hamısına bölünür.

Mənbə: `results/15_fpr_table.csv`, qrafik `figures/paper/15_openappsec_fpr.png`.

| Detektor | Unikal dəyər FPR | Çəkili dəyər FPR | Sorğu FPR | Sorğu FPR (bütün sorğular) |
|---|---|---|---|---|
| LR baza | 0.87 ± 0.13 | 3.82 ± 2.52 | 16.96 ± 8.80 | 10.71 ± 5.56 |
| SVM baza | 0.99 ± 0.19 | 3.01 ± 2.47 | 14.29 ± 8.53 | 9.03 ± 5.39 |
| RF baza | 0.35 ± 0.01 | 9.85 ± 3.14 | 34.53 ± 5.32 | 21.81 ± 3.36 |
| NB baza | 37.71 ± 0.64 | 33.53 ± 0.39 | 73.04 ± 0.54 | 46.14 ± 0.34 |
| LR + normallaşdırma | 1.00 ± 0.27 | 5.58 ± 3.31 | 22.72 ± 9.46 | 14.35 ± 5.97 |
| **LR + norm. + augmentation** (yerləşdirilən) | 1.24 ± 0.17 | 4.89 ± 1.97 | 22.32 ± 7.39 | 14.10 ± 4.67 |
| CNN baza | 0.76 ± 0.46 | 5.79 ± 1.51 | 27.50 ± 5.81 | 17.37 ± 3.67 |
| CNN + normallaşdırma | 2.73 ± 0.70 | 5.22 ± 1.90 | 25.19 ± 7.06 | 15.91 ± 4.46 |
| Qara siyahı (sanitizeInput) | 14.07 | 8.63 | 35.39 | 22.36 |
| Qara siyahı (sanitizeSearch) | 7.00 | 2.84 | 20.30 | 12.82 |
| **libinjection 4.0.1** | **0.08** | **0.04** | **0.57** | **0.36** |

**Top-20 yanlış blok** — yerləşdirilən model, seed 42, `results/15_top20_false_blocks_lr_norm_aug_seed42.csv`; baza LR üçün `…_lr_base_seed42.csv`

| Dəyər | Bloklanan sorğu | Rast gəlinmə |
|---|---|---|
| `0` | 117 976 | 393 986 |
| `c` | 8 584 | 10 315 |
| `-1` | 5 121 | 13 216 |
| `{}` | 3 602 | 8 682 |
| `10000` | 3 287 | 3 289 |
| `1---` | 2 798 | 2 800 |
| `/` | 2 620 | 5 301 |
| `-` | 2 225 | 3 414 |
| `0,0` | 2 063 | 4 241 |
| `-5` | 1 254 | 1 255 |
| `0.9,1.0,8,0` | 978 | 978 |
| `1-0-40` | 919 | 919 |
| `ue` | 898 | 1 223 |
| `000` | 828 | 830 |
| `v` | 812 | 829 |
| `90,0` | 807 | 828 |
| `user` | 751 | 953 |
| `C` | 648 | 10 260 |
| `1.2,1,6,0` | 648 | 648 |
| `G1--` | 627 | 627 |

**Səbəb qrupları** — seed 42, `results/15_fp_reasons_seed42.csv`. Bloklanan sorğuların böyük əksəriyyəti **"rəqəm / qısa kod"** qrupundadır, ən çox `0`, `-1` və tək hərflər:

| Detektor | "Rəqəm / qısa kod" qrupunda bloklanan sorğu |
|---|---|
| LR baza | 158 425 |
| Yerləşdirilən model | 164 672 |
| RF baza | 312 922 |
| CNN baza | 272 528 |

Qara siyahılarda əsas səbəblər fərqlidir: dırnaq/apostrof, URL/yol və təbii mətndəki SQL açar sözləri. libinjection yanlış bloklarının çoxu şərh və ayırıcı simvol qrupundadır (3 121 sorğu), məsələn `1---` kimi dəyərlər.

**Sessiyalar üzrə** — seed 42, `results/15_fpr_by_site_seed42.csv`. 1%-dən çox yanlış blok olan sessiya sayı (692-dən):

| Detektor | Sessiya sayı | Median sessiya FPR |
|---|---|---|
| LR baza | 642 | 23.9% |
| SVM baza | 573 | 5.3% |
| Yerləşdirilən model | 643 | 25.2% |
| libinjection | 48 | 0% |

**Şərh.**

1. v2 modelləri unikal dəyərlərdə aşağı FPR (≈1%) göstərir, amma sorğu səviyyəsində bu 14–35%-ə qalxır. Səbəb tez-tez təkrarlanan qısa dəyərlərdir: `0` tək başına 394 min dəfə rast gəlinir.
2. Yanlış blokların əsas səbəbi qısa rəqəm və hərf dəyərləridir. Kaggle-ın təmiz sinfində bu cür dəyərlər azdır, ona görə model onları "qeyri-adi" hesab edir; bu, 8-ci bölmədəki artefakt nəticəsi ilə uyğundur.
3. libinjection eyni trafikdə 0.57% sorğu FPR verir. Ona görə real yerləşdirmədə ML modeli ya bu cür trafiklə öyrədilməli, ya libinjection ilə birlikdə və ya parametr konteksti ilə işləməlidir. v3-ə open-appsec dəyərlərinin əlavə edilməsi məhz buna görədir və 7-ci bölmədə FPR-i 0.01–0.13%-ə endirib.

## 10. Qrafiklərin siyahısı (`figures/v3/`, 300 dpi)

| Fayl | Məzmun |
|---|---|
| `17a_source_class_counts.png` | Mənbə × sinif sayları (üfüqi sütun) |
| `17b_query_length_boxplot.png` | Mənbə və sinif üzrə uzunluq, log oxu, medianlarla |
| `17c_format_artifacts.png` | İkiqat boşluq / sətir sonu / şərh, mənbə × sinif % (qruplaşdırılmış sütun) |
| `17d_source_overlap_heatmap.png` | Mənbələr arası üst-üstə düşmə |
| `17_models_combined_test.png` | Modellər, birləşdirilmiş test, baza və norm. |
| `17_confusion_matrix_best.png` | Ən yaxşı model (CNN baza), normal və alt. whitespace |
| `17_lodo_heatmap.png` | LODO: recall, alt. whitespace recall, FPR |
| `17_lr_base_top_ngrams.png` | LR baza top-20 n-gram |

Notebook 15-in qrafiki: `figures/paper/15_openappsec_fpr.png`.

## 11. Yenidən yaratmaq

```bash
jupyter nbconvert --to notebook --execute --inplace --ExecutePreprocessor.timeout=-1 notebooks/15_openappsec_benign.ipynb
jupyter nbconvert --to notebook --execute --inplace --ExecutePreprocessor.timeout=-1 notebooks/17_combined_v3.ipynb
```

Hər iki notebook bərpa olunandır, yəni yarımçıq qalsa bitmiş işi təkrarlamır:

- 15 proqnozları `models/15_preds/`-də saxlayır;
- 17 modelləri `models/v3/`-də, qiymətləndirmə sətirlərini `models/v3/rows/`-da saxlayır.
