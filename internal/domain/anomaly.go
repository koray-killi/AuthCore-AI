package domain

import (
	"time"

	"github.com/google/uuid"
)

// AnomalyReport represents a detected security anomaly from AI analysis.
// This table, like audit_logs, is append-only.
type AnomalyReport struct {
	ID            uuid.UUID
	BatchStartID  uuid.UUID
	BatchEndID    uuid.UUID
	Severity      string // low, medium, high, critical
	AnomalyType   string
	Description   string
	AffectedUsers []uuid.UUID
	RawResponse   map[string]interface{}
	ModelVersion  string
	CreatedAt     time.Time
}
