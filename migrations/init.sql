-- ============================================================
-- CTIR — Central Threat Intelligence Repository
-- Schema Initialisation
-- ============================================================

CREATE DATABASE IF NOT EXISTS ctir_db CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE ctir_db;

-- ── IOC Types ────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS ioc_types (
    id          TINYINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    name        VARCHAR(50)  NOT NULL UNIQUE,  -- ip, domain, url, hash_md5, hash_sha1, hash_sha256, email, filename
    description VARCHAR(255)
) ENGINE=InnoDB;

INSERT IGNORE INTO ioc_types (name, description) VALUES
    ('ip',          'IPv4 or IPv6 address'),
    ('domain',      'Fully-qualified domain name'),
    ('url',         'Uniform Resource Locator'),
    ('hash_md5',    'MD5 file hash'),
    ('hash_sha1',   'SHA-1 file hash'),
    ('hash_sha256', 'SHA-256 file hash'),
    ('email',       'Email address'),
    ('filename',    'Malicious filename'),
    ('other',       'Uncategorised IOC type');

-- ── Feeds ────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS feeds (
    id          SMALLINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    name        VARCHAR(100) NOT NULL UNIQUE,
    provider    VARCHAR(100) NOT NULL,
    feed_url    VARCHAR(512),
    auth_type   ENUM('none','api_key','oauth','taxii') DEFAULT 'none',
    is_active   BOOLEAN NOT NULL DEFAULT TRUE,
    created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB;

INSERT IGNORE INTO feeds (name, provider, feed_url, auth_type) VALUES
    ('ThreatFox', 'abuse.ch', 'https://threatfox-api.abuse.ch/api/v1/', 'api_key');

-- ── IOCs ─────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS iocs (
    id              BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    ioc_value       VARCHAR(2048) NOT NULL,
    ioc_type_id     TINYINT UNSIGNED NOT NULL,
    ioc_hash        CHAR(64) NOT NULL UNIQUE,  -- SHA-256(type+':'+value) for dedup

    -- Threat metadata
    malware_family  VARCHAR(128),
    threat_type     VARCHAR(128),
    confidence      TINYINT UNSIGNED NOT NULL DEFAULT 50  COMMENT '0-100',
    severity        ENUM('critical','high','medium','low','info') NOT NULL DEFAULT 'medium',
    tags            JSON,

    -- Source tracking
    primary_feed_id SMALLINT UNSIGNED NOT NULL,
    source_ioc_id   VARCHAR(128),              -- upstream ID (e.g. ThreatFox ioc_id)
    source_count    SMALLINT UNSIGNED NOT NULL DEFAULT 1,
    merged_sources  JSON,                      -- [{feed_id, source_ioc_id, first_seen}]

    -- Validity
    first_seen_at   DATETIME NOT NULL,
    last_seen_at    DATETIME NOT NULL,
    expires_at      DATETIME,
    is_active       BOOLEAN NOT NULL DEFAULT TRUE,

    -- Audit
    created_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,

    FOREIGN KEY (ioc_type_id)     REFERENCES ioc_types(id),
    FOREIGN KEY (primary_feed_id) REFERENCES feeds(id),
    INDEX idx_ioc_value      (ioc_value(255)),
    INDEX idx_ioc_type       (ioc_type_id),
    INDEX idx_severity       (severity),
    INDEX idx_malware_family (malware_family),
    INDEX idx_last_seen      (last_seen_at),
    INDEX idx_is_active      (is_active),
    FULLTEXT INDEX ft_ioc_value (ioc_value)
) ENGINE=InnoDB;

-- ── Ingestion Jobs ───────────────────────────────────────────
CREATE TABLE IF NOT EXISTS ingestion_jobs (
    id              BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    feed_id         SMALLINT UNSIGNED NOT NULL,
    triggered_by    ENUM('scheduler','manual') NOT NULL DEFAULT 'scheduler',
    status          ENUM('running','success','partial','failed') NOT NULL DEFAULT 'running',

    -- Metrics
    records_fetched INT UNSIGNED NOT NULL DEFAULT 0,
    records_parsed  INT UNSIGNED NOT NULL DEFAULT 0,
    records_valid   INT UNSIGNED NOT NULL DEFAULT 0,
    records_invalid INT UNSIGNED NOT NULL DEFAULT 0,
    records_new     INT UNSIGNED NOT NULL DEFAULT 0,
    records_updated INT UNSIGNED NOT NULL DEFAULT 0,
    records_dupes   INT UNSIGNED NOT NULL DEFAULT 0,

    -- Timing
    started_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    finished_at     DATETIME,
    latency_ms      INT UNSIGNED,

    error_message   TEXT,

    FOREIGN KEY (feed_id) REFERENCES feeds(id),
    INDEX idx_feed_status (feed_id, status),
    INDEX idx_started_at  (started_at)
) ENGINE=InnoDB;

-- ── Parse Errors ─────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS parse_errors (
    id          BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    job_id      BIGINT UNSIGNED NOT NULL,
    raw_data    JSON,
    error_type  VARCHAR(128),
    error_msg   TEXT,
    created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (job_id) REFERENCES ingestion_jobs(id) ON DELETE CASCADE,
    INDEX idx_job_id (job_id)
) ENGINE=InnoDB;