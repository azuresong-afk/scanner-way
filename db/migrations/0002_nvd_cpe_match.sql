-- Справочник уязвимых конфигураций NVD для цепочки «сервис+версия -> CPE -> CVE».
-- reference_nvd_cve.cpe[] хранит только строки критериев, а для сопоставления
-- нужны диапазоны версий (versionStart*/versionEnd*) из cpeMatch.
-- PostgreSQL 16. Таблица соответствует scanner/feeds/store.py (nvd_cpe_match).

CREATE TABLE IF NOT EXISTS reference_nvd_cpe_match (
    id                 BIGSERIAL PRIMARY KEY,
    cve_id             TEXT NOT NULL REFERENCES reference_nvd_cve(cve_id) ON DELETE CASCADE,
    criteria           TEXT NOT NULL,          -- cpe:2.3:a:vendor:product:version:...
    vendor             TEXT NOT NULL,
    product            TEXT NOT NULL,
    version            TEXT,                   -- '*' = любая (тогда смотрим диапазон)
    "update"           TEXT,
    version_start_incl TEXT,
    version_start_excl TEXT,
    version_end_incl   TEXT,
    version_end_excl   TEXT
);
CREATE INDEX IF NOT EXISTS ix_reference_nvd_cpe_match_product ON reference_nvd_cpe_match(product);
CREATE INDEX IF NOT EXISTS ix_reference_nvd_cpe_match_cve_id ON reference_nvd_cpe_match(cve_id);
