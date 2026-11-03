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
- Python mühiti: `venv/` (`venv\Scripts\activate`).
