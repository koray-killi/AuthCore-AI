CREATE TABLE anomaly_reports (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    batch_start_id  UUID NOT NULL,
    batch_end_id    UUID NOT NULL,
    severity        TEXT NOT NULL CHECK (severity IN ('low', 'medium', 'high', 'critical')),
    anomaly_type    TEXT NOT NULL,
    description     TEXT NOT NULL,
    affected_users  UUID[] NOT NULL DEFAULT '{}',
    raw_response    JSONB NOT NULL DEFAULT '{}',
    model_version   TEXT NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_anomaly_reports_severity ON anomaly_reports (severity);
CREATE INDEX idx_anomaly_reports_created_at ON anomaly_reports (created_at);
