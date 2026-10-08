package siem

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"go.uber.org/zap"
)

// Analyzer is the interface for the AI analysis backend.
// This abstraction allows swapping Claude for a mock in tests
// or a different LLM provider in the future.
type Analyzer interface {
	AnalyzeBatch(ctx context.Context, logs []SanitizedLog) (*AnalysisResult, error)
}

// ClaudeClient implements the Analyzer interface for Anthropic's Claude API.
type ClaudeClient struct {
	apiKey     string
	baseURL    string
	httpClient *http.Client
	logger     *zap.Logger
}

// NewClaudeClient creates a new ClaudeClient.
func NewClaudeClient(apiKey, baseURL string, logger *zap.Logger) *ClaudeClient {
	return &ClaudeClient{
		apiKey:  apiKey,
		baseURL: baseURL,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		logger: logger,
	}
}

type anthropicRequest struct {
	Model       string    `json:"model"`
	MaxTokens   int       `json:"max_tokens"`
	Temperature float64   `json:"temperature"`
	System      string    `json:"system"`
	Messages    []message `json:"messages"`
}

type message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type anthropicResponse struct {
	Content []struct {
		Text string `json:"text"`
	} `json:"content"`
	Error struct {
		Type    string `json:"type"`
		Message string `json:"message"`
	} `json:"error"`
}

// AnalyzeBatch sends sanitized logs to Claude for anomaly detection.
func (c *ClaudeClient) AnalyzeBatch(ctx context.Context, logs []SanitizedLog) (*AnalysisResult, error) {
	if len(logs) == 0 {
		return &AnalysisResult{}, nil
	}

	logsJSON, err := json.Marshal(logs)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal logs: %w", err)
	}

	reqBody := anthropicRequest{
		Model:       "claude-3-5-sonnet-20241022",
		MaxTokens:   4096,
		Temperature: 0,
		System:      SystemPrompt,
		Messages: []message{
			{
				Role:    "user",
				Content: string(logsJSON),
			},
		},
	}

	reqBytes, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	var lastErr error
	backoff := []time.Duration{1 * time.Second, 2 * time.Second, 4 * time.Second}

	for i := 0; i <= len(backoff); i++ {
		req, err := http.NewRequestWithContext(ctx, "POST", c.baseURL+"/v1/messages", bytes.NewReader(reqBytes))
		if err != nil {
			return nil, fmt.Errorf("failed to create request: %w", err)
		}

		req.Header.Set("x-api-key", c.apiKey)
		req.Header.Set("anthropic-version", "2023-06-01")
		req.Header.Set("content-type", "application/json")

		start := time.Now()
		resp, err := c.httpClient.Do(req)
		if err != nil {
			lastErr = fmt.Errorf("http request failed: %w", err)
			c.logger.Warn("Claude API request failed", zap.Error(err), zap.Int("attempt", i+1))
			time.Sleep(backoff[i%len(backoff)])
			continue
		}

		bodyBytes, err := io.ReadAll(resp.Body)
		resp.Body.Close()

		if resp.StatusCode == http.StatusTooManyRequests {
			c.logger.Warn("Claude API rate limited", zap.Int("attempt", i+1))
			if i < len(backoff) {
				time.Sleep(backoff[i])
				continue
			}
			return nil, fmt.Errorf("rate limit exceeded after retries")
		}

		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("api error (status %d): %s", resp.StatusCode, string(bodyBytes))
		}

		var apiResp anthropicResponse
		if err := json.Unmarshal(bodyBytes, &apiResp); err != nil {
			return nil, fmt.Errorf("failed to unmarshal api response: %w", err)
		}

		if len(apiResp.Content) == 0 {
			return nil, fmt.Errorf("empty response from claude")
		}

		var result AnalysisResult
		if err := json.Unmarshal([]byte(apiResp.Content[0].Text), &result); err != nil {
			return nil, fmt.Errorf("failed to parse json from claude text: %w, text: %s", err, apiResp.Content[0].Text)
		}

		result.BatchMetadata.AnalysisDurationMs = time.Since(start).Milliseconds()
		result.BatchMetadata.Model = "claude-3-5-sonnet-20241022"
		result.BatchMetadata.LogsAnalyzed = len(logs)
		if len(logs) > 0 {
			result.BatchMetadata.TimeRangeFrom = logs[0].CreatedAt
			result.BatchMetadata.TimeRangeTo = logs[len(logs)-1].CreatedAt
		}

		return &result, nil
	}

	return nil, fmt.Errorf("max retries exceeded, last error: %w", lastErr)
}
