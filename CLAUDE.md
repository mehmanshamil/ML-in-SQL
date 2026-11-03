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
