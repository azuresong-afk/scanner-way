-- Scanner — начальная схема БД (референс). В проде управляется Alembic.
-- PostgreSQL 16.

-- ========== RBAC ==========
CREATE TABLE IF NOT EXISTS users (
    id            BIGSERIAL PRIMARY KEY,
    username      TEXT UNIQUE NOT NULL,
    display_name  TEXT,
    password_hash TEXT NOT NULL,
    is_active     BOOLEAN NOT NULL DEFAULT TRUE,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS roles (
    id    BIGSERIAL PRIMARY KEY,
    name  TEXT UNIQUE NOT NULL          -- admin | operator | auditor
);

CREATE TABLE IF NOT EXISTS permissions (
    id    BIGSERIAL PRIMARY KEY,
    name  TEXT UNIQUE NOT NULL          -- run_scan | manage_allowlist | cred_audit | view_report | ...
);

CREATE TABLE IF NOT EXISTS user_roles (
    user_id BIGINT REFERENCES users(id) ON DELETE CASCADE,
    role_id BIGINT REFERENCES roles(id) ON DELETE CASCADE,
    PRIMARY KEY (user_id, role_id)
);

CREATE TABLE IF NOT EXISTS role_permissions (
    role_id       BIGINT REFERENCES roles(id) ON DELETE CASCADE,
    permission_id BIGINT REFERENCES permissions(id) ON DELETE CASCADE,
    PRIMARY KEY (role_id, permission_id)
);

-- ========== Engagement (договор) + allowlist ==========
CREATE TABLE IF NOT EXISTS engagements (
    id          BIGSERIAL PRIMARY KEY,
    name        TEXT NOT NULL,
    client      TEXT,
    contract_ref TEXT,
    created_by  BIGINT REFERENCES users(id),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Разрешённые к сканированию цели (жёсткий allowlist-гейт)
CREATE TABLE IF NOT EXISTS targets_allowlist (
    id            BIGSERIAL PRIMARY KEY,
    engagement_id BIGINT NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
    cidr          CIDR NOT NULL,
    note          TEXT,
    added_by      BIGINT REFERENCES users(id),
    added_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_allowlist_engagement ON targets_allowlist(engagement_id);

-- ========== Прогоны ==========
CREATE TABLE IF NOT EXISTS scan_runs (
    id            BIGSERIAL PRIMARY KEY,
    engagement_id BIGINT NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
    started_by    BIGINT REFERENCES users(id),
    modules       TEXT[] NOT NULL,         -- {discovery,vuln,config_audit,cred_audit}
    rate_profile  TEXT NOT NULL DEFAULT 'gentle',
    status        TEXT NOT NULL DEFAULT 'pending',  -- pending|running|done|failed|stopped
    started_at    TIMESTAMPTZ,
    finished_at   TIMESTAMPTZ,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_runs_engagement ON scan_runs(engagement_id);

CREATE TABLE IF NOT EXISTS host_results (
    id          BIGSERIAL PRIMARY KEY,
    scan_run_id BIGINT NOT NULL REFERENCES scan_runs(id) ON DELETE CASCADE,
    host        INET NOT NULL,
    state       TEXT,                      -- up|down
    os_guess    TEXT,
    os_accuracy INT
);
CREATE INDEX IF NOT EXISTS idx_host_run ON host_results(scan_run_id);

CREATE TABLE IF NOT EXISTS service_results (
    id          BIGSERIAL PRIMARY KEY,
    host_id     BIGINT NOT NULL REFERENCES host_results(id) ON DELETE CASCADE,
    port        INT NOT NULL,
    protocol    TEXT NOT NULL,             -- tcp|udp
    service     TEXT,
    product     TEXT,
    version     TEXT,
    cpe         TEXT
);
CREATE INDEX IF NOT EXISTS idx_service_host ON service_results(host_id);

-- ========== Находки (ядро отчётов и сравнения) ==========
CREATE TABLE IF NOT EXISTS findings (
    id             BIGSERIAL PRIMARY KEY,
    engagement_id  BIGINT NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
    scan_run_id    BIGINT NOT NULL REFERENCES scan_runs(id) ON DELETE CASCADE,
    module         TEXT NOT NULL,          -- discovery|vuln|config|cred
    finding_type   TEXT NOT NULL,          -- vuln|config|cred|info
    host           INET NOT NULL,
    port           INT,
    vuln_id        TEXT,                   -- CVE-… или BDU:…
    cve_ids        TEXT[] DEFAULT '{}',
    bdu_ids        TEXT[] DEFAULT '{}',
    title          TEXT NOT NULL,
    severity       TEXT NOT NULL DEFAULT 'info',
    cvss           NUMERIC(4,1),
    evidence       TEXT,
    status         TEXT NOT NULL DEFAULT 'open',  -- open|fixed|new|regression
    dedup_key      TEXT NOT NULL,          -- hash(host+port+vuln_id+module)
    detected_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_findings_run ON findings(scan_run_id);
CREATE INDEX IF NOT EXISTS idx_findings_dedup ON findings(engagement_id, dedup_key);

-- ========== Справочники уязвимостей ==========
CREATE TABLE IF NOT EXISTS reference_nvd_cve (
    cve_id      TEXT PRIMARY KEY,
    cvss_v3     NUMERIC(4,1),
    cvss_vector TEXT,
    severity    TEXT,
    cpe         TEXT[] DEFAULT '{}',
    summary     TEXT,
    refs        TEXT[] DEFAULT '{}',
    updated_at  TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS reference_bdu_entry (
    bdu_id            TEXT PRIMARY KEY,        -- BDU:YYYY-NNNNN
    title             TEXT,
    description       TEXT,
    vendor            TEXT,                    -- Вендор ПО
    software          TEXT,                    -- Название ПО
    versions          TEXT,                    -- Версия ПО (строкой, как в выгрузке)
    software_type     TEXT,                    -- Тип ПО
    vuln_class        TEXT,                    -- Класс уязвимости
    cvss2_vector      TEXT,                    -- CVSS 2.0 (вектор)
    cvss3             TEXT,                    -- CVSS 3.0
    cvss4             TEXT,                    -- CVSS 4.0
    cvss_score        NUMERIC(4,1),            -- базовая оценка из "Уровень опасности"
    severity_text     TEXT,                    -- "Уровень опасности уязвимости" (как есть)
    exploit_available TEXT,                    -- Наличие эксплойта
    status            TEXT,                    -- Статус уязвимости
    cwe               TEXT,                    -- Тип ошибки CWE
    cve_ids           TEXT[] DEFAULT '{}',     -- извлечено из "Идентификаторы других систем"
    other_ids         TEXT,                    -- исходная строка идентификаторов
    remediation       TEXT,                    -- Возможные меры по устранению
    refs              TEXT,                    -- Ссылки на источники
    detection_date    TEXT,
    published_at      TEXT,
    updated_at        TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_bdu_cve ON reference_bdu_entry USING GIN (cve_ids);

-- ========== Аудит действий (append-only) ==========
CREATE TABLE IF NOT EXISTS audit_log (
    id          BIGSERIAL PRIMARY KEY,
    ts          TIMESTAMPTZ NOT NULL DEFAULT now(),
    subject     TEXT NOT NULL,             -- пользователь или 'scanner'
    action      TEXT NOT NULL,             -- scan_target|auth_attempt|export|deny|...
    target      TEXT,
    result      TEXT,
    details     JSONB
);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(ts);
