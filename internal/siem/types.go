package siem

import (
	"time"

	"github.com/google/uuid"
)

// SanitizedLog is an audit log entry with PII removed.
// This type exists to make it a compile-time error to accidentally send
// raw domain.AuditLog (which contains real IPs and emails) to the Claude API.
type SanitizedLog struct {
	ID        uuid.UUID              `json:"id"`
	UserID    *uuid.UUID             `json:"user_id,omitempty"`
	Action    string                 `json:"action"`
	MaskedIP  string                 `json:"masked_ip"`
	UserAgent string                 `json:"user_agent"`
	Metadata  map[string]interface{} `json:"metadata"`
	CreatedAt time.Time              `json:"created_at"`
}

// AnalysisResult represents Claude's anomaly analysis response.
type AnalysisResult struct {
	Anomalies     []Anomaly     `json:"anomalies"`
	BatchMetadata BatchMetadata `json:"batch_metadata"`
}

// Anomaly is a single detected anomaly.
type Anomaly struct {
	AnomalyType       string                 `json:"anomaly_type"`
	Severity          string                 `json:"severity"` // low, medium, high, critical
	Description       string                 `json:"description"`
	AffectedUsers     []uuid.UUID            `json:"affected_users"`
	Evidence          map[string]interface{} `json:"evidence"`
	RecommendedAction string                 `json:"recommended_action"`
}

// BatchMetadata contains information about the analysis batch.
type BatchMetadata struct {
	LogsAnalyzed       int       `json:"logs_analyzed"`
	TimeRangeFrom      time.Time `json:"time_range_from"`
	TimeRangeTo        time.Time `json:"time_range_to"`
	Model              string    `json:"model"`
	AnalysisDurationMs int64     `json:"analysis_duration_ms"`
}
