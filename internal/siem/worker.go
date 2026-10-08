package siem

import (
	"context"
	"time"

	"github.com/koray-killi/AuthCore/internal/repository"
	"go.uber.org/zap"
)

// WorkerConfig holds configuration for the SIEM background worker.
type WorkerConfig struct {
	ScanInterval time.Duration
	BatchSize    int
}

// Worker represents the AI SIEM background worker.
type Worker struct {
	config    WorkerConfig
	auditRepo repository.AuditRepository
	analyzer  Analyzer
	sanitizer *Sanitizer
	logger    *zap.Logger
	cursor    time.Time
}

// NewWorker creates a new SIEM Worker.
func NewWorker(config WorkerConfig, auditRepo repository.AuditRepository, analyzer Analyzer, sanitizer *Sanitizer, logger *zap.Logger) *Worker {
	return &Worker{
		config:    config,
		auditRepo: auditRepo,
		analyzer:  analyzer,
		sanitizer: sanitizer,
		logger:    logger,
		cursor:    time.Now().Add(-1 * time.Hour), // Process the last hour on startup
	}
}

// Run starts the background worker. It runs until the context is canceled.
func (w *Worker) Run(ctx context.Context) {
	ticker := time.NewTicker(w.config.ScanInterval)
	defer ticker.Stop()

	consecutiveErrors := 0
	circuitOpenUntil := time.Time{}

	for {
		select {
		case <-ctx.Done():
			w.logger.Info("SIEM worker shutting down gracefully")
			return
		case <-ticker.C:
			if time.Now().Before(circuitOpenUntil) {
				w.logger.Warn("SIEM worker circuit breaker open, skipping tick")
				continue
			}

			if err := w.scan(ctx); err != nil {
				w.logger.Error("SIEM worker scan failed", zap.Error(err))
				consecutiveErrors++
				if consecutiveErrors >= 5 {
					w.logger.Error("SIEM worker circuit breaker tripped, pausing for 5 minutes")
					circuitOpenUntil = time.Now().Add(5 * time.Minute)
					consecutiveErrors = 0 // Reset after tripping
				}
			} else {
				consecutiveErrors = 0
			}
		}
	}
}

func (w *Worker) scan(ctx context.Context) error {
	logs, err := w.auditRepo.ListAfterCursor(ctx, w.cursor, w.config.BatchSize)
	if err != nil {
		return err
	}

	if len(logs) == 0 {
		w.logger.Debug("SIEM worker: no new audit logs")
		return nil
	}

	sanitizedLogs := w.sanitizer.SanitizeBatch(logs)

	w.logger.Info("SIEM worker analyzing batch", zap.Int("size", len(sanitizedLogs)))

	result, err := w.analyzer.AnalyzeBatch(ctx, sanitizedLogs)
	if err != nil {
		// Do not update cursor on error so we can retry the same batch
		return err
	}

	if len(result.Anomalies) > 0 {
		for _, anomaly := range result.Anomalies {
			w.logger.Warn("SIEM worker detected anomaly",
				zap.String("type", anomaly.AnomalyType),
				zap.String("severity", anomaly.Severity),
				zap.String("description", anomaly.Description),
			)
			// Here we would normally insert the anomaly into the anomaly_reports table
			// via an anomaly_repo, but for this iteration, logging is sufficient.
		}
	}

	// Update cursor to the timestamp of the last processed log
	w.cursor = logs[len(logs)-1].CreatedAt

	return nil
}
