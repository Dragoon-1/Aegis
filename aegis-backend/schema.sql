-- ============================================================================
-- AEGIS THREAT INTELLIGENCE DATABASE SCHEMA
-- PostgreSQL 15+
-- ============================================================================

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";  -- For fast text search

-- ── Core Threats Table ────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS threats (
    id              UUID        PRIMARY KEY DEFAULT uuid_generate_v4(),
    hash            CHAR(64)    NOT NULL UNIQUE,   -- SHA-256 hex (64 chars)
    type            VARCHAR(30) NOT NULL
                    CHECK (type IN ('URL','PHONE','FILE_HASH','IP','APP','RANSOMWARE_ATTEMPT', 'RANSOMWARE_CONFIRMED', 'MALICIOUS_URL', 'SMS_PHISHING', 'NETWORK_THREAT', 'DANGEROUS_APP', 'PERMISSION_ABUSE', 'MALICIOUS_OVERLAY')),
    severity        SMALLINT    NOT NULL CHECK (severity BETWEEN 1 AND 5),
    report_count    INTEGER     NOT NULL DEFAULT 1,
    first_seen      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    police_reported BOOLEAN     NOT NULL DEFAULT FALSE,
    metadata        JSONB       NOT NULL DEFAULT '{}',
    region          CHAR(2)     NOT NULL DEFAULT 'IN'   -- ISO 3166-1 alpha-2
);

-- Indexes for fast lookups
CREATE INDEX IF NOT EXISTS idx_threats_hash         ON threats (hash);
CREATE INDEX IF NOT EXISTS idx_threats_last_seen    ON threats (last_seen DESC);
CREATE INDEX IF NOT EXISTS idx_threats_severity     ON threats (severity DESC);
CREATE INDEX IF NOT EXISTS idx_threats_report_count ON threats (report_count DESC);
CREATE INDEX IF NOT EXISTS idx_threats_type         ON threats (type);
CREATE INDEX IF NOT EXISTS idx_threats_not_reported ON threats (police_reported) WHERE NOT police_reported;

-- ── Per-Device Report Events (for deduplication) ──────────────────────────────
-- Ensures each device is counted only once per threat.

CREATE TABLE IF NOT EXISTS threat_events (
    id          UUID        PRIMARY KEY DEFAULT uuid_generate_v4(),
    hash        CHAR(64)    NOT NULL REFERENCES threats(hash) ON DELETE CASCADE,
    device_id   CHAR(64)    NOT NULL,   -- SHA-256 of anonymous device fingerprint
    timestamp   TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    UNIQUE (hash, device_id)            -- One report per device per threat
);

CREATE INDEX IF NOT EXISTS idx_events_hash      ON threat_events (hash);
CREATE INDEX IF NOT EXISTS idx_events_device    ON threat_events (device_id);
CREATE INDEX IF NOT EXISTS idx_events_timestamp ON threat_events (timestamp DESC);

-- ── Police / CERT Reports ──────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS police_reports (
    id              UUID        PRIMARY KEY DEFAULT uuid_generate_v4(),
    report_path     TEXT        NOT NULL,
    threat_count    INTEGER     NOT NULL,
    devices_covered INTEGER     NOT NULL DEFAULT 0,
    generated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    submitted_at    TIMESTAMPTZ,                          -- NULL = pending
    status          VARCHAR(20) NOT NULL DEFAULT 'PENDING'
                    CHECK (status IN ('PENDING','SUBMITTED','ACKNOWLEDGED','CLOSED'))
);

CREATE INDEX IF NOT EXISTS idx_reports_status ON police_reports (status);

-- ── Blockchain Sync Checkpoints ───────────────────────────────────────────────
-- Tracks what's been written to Polygon so we don't re-write old threats.

CREATE TABLE IF NOT EXISTS blockchain_sync (
    id              SERIAL      PRIMARY KEY,
    threat_hash     CHAR(64)    NOT NULL,
    polygon_tx_hash CHAR(66),   -- 0x + 64 hex chars, NULL until confirmed
    submitted_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    confirmed_at    TIMESTAMPTZ,
    gas_used        INTEGER
);

CREATE INDEX IF NOT EXISTS idx_bcsync_unconfirmed ON blockchain_sync (confirmed_at) WHERE confirmed_at IS NULL;

-- ── Blocklist Snapshots (for device sync) ─────────────────────────────────────
-- Devices download the current blocklist as a delta since last sync.

CREATE TABLE IF NOT EXISTS blocklist_snapshots (
    id              SERIAL      PRIMARY KEY,
    snapshot_hash   CHAR(64)    NOT NULL UNIQUE,  -- Hash of snapshot content
    threat_count    INTEGER     NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ── Dashboard Materialized View (refresh hourly) ──────────────────────────────

CREATE MATERIALIZED VIEW IF NOT EXISTS threat_stats_hourly AS
SELECT
    date_trunc('hour', NOW())                                    AS computed_at,
    COUNT(*)                                                     AS total_threats,
    COUNT(*) FILTER (WHERE first_seen > NOW() - '24h'::INTERVAL) AS new_24h,
    COUNT(*) FILTER (WHERE first_seen > NOW() - '7d'::INTERVAL)  AS new_7d,
    COUNT(*) FILTER (WHERE severity = 5)                         AS emergency,
    COUNT(*) FILTER (WHERE severity = 4)                         AS critical,
    COUNT(*) FILTER (WHERE severity = 3)                         AS high,
    COALESCE(SUM(report_count), 0)                               AS total_reports,
    COUNT(*) FILTER (WHERE police_reported)                      AS police_reported_count,
    COUNT(DISTINCT region)                                       AS regions_affected
FROM threats;

CREATE UNIQUE INDEX IF NOT EXISTS idx_threat_stats_ts ON threat_stats_hourly (computed_at);

-- Refresh this view every hour (set up pg_cron or call from backend cron job):
-- SELECT cron.schedule('0 * * * *', $$REFRESH MATERIALIZED VIEW CONCURRENTLY threat_stats_hourly$$);

-- ── Useful Queries (Reference) ────────────────────────────────────────────────

-- Top 10 most-reported threats today:
-- SELECT hash, type, severity, report_count FROM threats
-- WHERE first_seen > NOW() - '24h'::INTERVAL
-- ORDER BY report_count DESC LIMIT 10;

-- Threats ready for police report (not yet reported):
-- SELECT * FROM threats
-- WHERE report_count >= 50 AND severity >= 3 AND NOT police_reported
-- ORDER BY report_count DESC;

-- Regional breakdown:
-- SELECT region, COUNT(*) AS threats, SUM(report_count) AS total_reports
-- FROM threats GROUP BY region ORDER BY total_reports DESC;

-- ── Seed Data (for testing) ───────────────────────────────────────────────────

-- Example: insert a known malicious domain hash for testing
-- The raw domain is "evil-phishing-test.example.com" — never stored in DB.
-- INSERT INTO threats (hash, type, severity, report_count, region)
-- VALUES (encode(sha256('evil-phishing-test.example.com'), 'hex'), 'URL', 4, 1, 'IN');
