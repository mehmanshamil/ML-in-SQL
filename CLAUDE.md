# SQLi ML Paper

Bu, elmi məqalə üçün tədqiqat layihəsidir.

**Mövzu:** ML əsaslı SQL injection detektorlarının obfuskasiya olunmuş payload-lara qarşı dayanıqlığı və qayda əsaslı (qara siyahı) filtrlə müqayisəsi.

## Plan
1. Dataset analizi və təmizlənməsi
2. Klassik ML və dərin öyrənmə modelləri
3. Obfuskasiya olunmuş test dəsti
4. Qara siyahı filtri ilə müqayisə
5. Node.js/Express middleware və gecikmə ölçümü

## Qaydalar
- Random seed həmişə `42`.
- Qrafiklər `figures/` qovluğuna 300 dpi PNG kimi saxlanılır.
- Nəticə cədvəlləri `results/` qovluğuna CSV kimi saxlanılır.
- Kod təkrarlana bilən olmalıdır.

## Struktur
- `data/raw/Modified_SQL_Dataset.csv` — Kaggle SQL Injection Dataset (sajid576), sütunlar: `Query`, `Label` (1 = zərərli, 0 = təmiz).
- `data/processed/clean.csv` — dublikatsız, boş sətirsiz dataset (`notebooks/01_data_analysis.ipynb` yaradır).
- `notebooks/` — Jupyter notebook-lar, nömrəli ardıcıllıqla.
- `data/processed/{train,val,test}.csv` — normallaşdırılmış sorğu qrupuna görə bölgü (`notebooks/02_baseline_models.ipynb`); eyni qrup iki dəstə düşmür.
- `models/` — saxlanılan modellər (git-də izlənmir).
- Python mühiti: `venv/` (`venv\Scripts\activate`). Dərin öyrənmə üçün PyTorch (TensorFlow yox — Python 3.13).

## Birinci məqalənin qara siyahı filtri (4-cü mərhələ üçün)
Orijinal kod: `C:\Users\Mehman\OneDrive\Desktop\Aztu-projects\meqale son\project-teqdimat\sql-injection - Copy (2)\server.js`
— `sanitizeInput()` və `sanitizeSearch()`. Python-a eyni məntiqlə (eyni regex ardıcıllığı) köçürülməlidir.

Versiya təsdiqləndi (2026-11-03): birinci məqalənin Şəkil 8–10-u bu kodla üst-üstə düşür.
- `sql-injection/` = zəif versiya, `sql-injection - Copy/` = Prepared Statements, `sql-injection - Copy (2)/` = Input Validation.
- Login/register: `isValidEmail()` + `sanitizeInput()` (OR/AND söz sərhədsiz silinir → `password` → `passwd`).
- Axtarış (`/products?search=`): yalnız `sanitizeSearch()` (OR/AND/UPDATE/DELETE silinmir) + 100 simvol limiti.
  Şəkil 9 (UNION) və Şəkil 10 (EXTRACTVALUE) bu funksiyanın nəticəsidir.

## Modellər
- **Əsas model: Logistic Regression** (ehtimal çıxışı verir → middleware-də hədd tənzimlənir). Linear SVM ikinci əsas model kimi müqayisədə qalır; RF və NB də cədvəllərdə.
- Əsas dataset: `clean_v2.csv` (Excel pozuntuları çıxarılıb). Məqalədə həm v1 (`clean.csv`), həm v2 nəticələri göstərilir.
- Obfuskasiya: `src/obfuscation.py`, yalnız test dəstinin zərərli sorğularına tətbiq olunur.
- Təhdid modeli: **ssenari A** = middleware (Express bir dəfə decode edir → `unquote`), real ssenari; **ssenari B** = xam trafik.
  `mysql_valid`: yes / conditional (`double_url_encode` — yalnız ikiqat decode edən tətbiqdə) / no (`keyword_split_comment`).
- Əsas tapıntı: dataset artefaktı — zərərli sorğuların 95%-ində ikiqat boşluq (sqlmap formatı), təmizlərdə 30%; LR-in ən güclü siqnalı boşluq n-gram-larıdır.
- Müdafiə: `src/normalize.py::normalize` (decode ×3, şərhlər, whitespace, lowercase, `( ) = ,` ətrafı boşluqlar) + augmentation (LOTO ilə yoxlanılır).
- Middleware üçün model: `models/lr_norm_aug_v2.joblib` (normalize + augmentation + LR; `src/` import yolunda olmalıdır).
