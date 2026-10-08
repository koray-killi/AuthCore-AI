package siem

import (
	"fmt"
	"net"
	"strings"

	"github.com/koray-killi/AuthCore/internal/domain"
)

// Sanitizer masks PII fields in audit logs before they are sent to external APIs.
type Sanitizer struct{}

// NewSanitizer creates a new Sanitizer.
func NewSanitizer() *Sanitizer {
	return &Sanitizer{}
}

// SanitizeBatch converts a slice of raw audit logs to sanitized logs
// with PII removed. This is the mandatory gateway between the database
// and the Claude API — raw logs must never bypass this step.
func (s *Sanitizer) SanitizeBatch(logs []domain.AuditLog) []SanitizedLog {
	result := make([]SanitizedLog, len(logs))
	for i, log := range logs {
		result[i] = SanitizedLog{
			ID:        log.ID,
			UserID:    log.UserID,
			Action:    log.Action,
			MaskedIP:  maskIP(log.IP),
			UserAgent: log.UserAgent,
			Metadata:  sanitizeMetadata(log.Metadata),
			CreatedAt: log.CreatedAt,
		}
	}
	return result
}

// maskIP replaces the last two octets of an IPv4 address with "xxx"
// and the last 64 bits of an IPv6 address with "xxxx".
// If the input is not a valid IP, it returns "xxx.xxx.xxx.xxx".
func maskIP(raw string) string {
	ip := net.ParseIP(strings.TrimSpace(raw))
	if ip == nil {
		return "xxx.xxx.xxx.xxx"
	}

	if ip4 := ip.To4(); ip4 != nil {
		return fmt.Sprintf("%d.%d.xxx.xxx", ip4[0], ip4[1])
	}

	// IPv6: mask the last 64 bits (interface identifier)
	return fmt.Sprintf("%x:%x:%x:%x:xxxx:xxxx:xxxx:xxxx",
		uint16(ip[0])<<8|uint16(ip[1]),
		uint16(ip[2])<<8|uint16(ip[3]),
		uint16(ip[4])<<8|uint16(ip[5]),
		uint16(ip[6])<<8|uint16(ip[7]),
	)
}

// maskEmail masks the middle characters of the local part and domain.
// "koray@gmail.com" → "k***y@g***l.com"
// If the input is not a valid email format, it returns "***@***.***".
func maskEmail(email string) string {
	parts := strings.SplitN(email, "@", 2)
	if len(parts) != 2 {
		return "***@***.***"
	}

	local := parts[0]
	domainParts := strings.SplitN(parts[1], ".", 2)
	if len(domainParts) != 2 {
		return "***@***.***"
	}

	maskedLocal := maskMiddle(local)
	maskedDomain := maskMiddle(domainParts[0])

	return fmt.Sprintf("%s@%s.%s", maskedLocal, maskedDomain, domainParts[1])
}

// maskMiddle keeps the first and last character of a string, replacing the rest with "***".
func maskMiddle(s string) string {
	if len(s) <= 1 {
		return "***"
	}
	if len(s) == 2 {
		return string(s[0]) + "***" + string(s[1])
	}
	return string(s[0]) + "***" + string(s[len(s)-1])
}

// sanitizeMetadata masks known PII fields within the metadata map.
func sanitizeMetadata(meta map[string]interface{}) map[string]interface{} {
	if meta == nil {
		return map[string]interface{}{}
	}

	sanitized := make(map[string]interface{}, len(meta))
	for k, v := range meta {
		switch strings.ToLower(k) {
		case "email", "e-mail", "mail":
			if s, ok := v.(string); ok {
				sanitized[k] = maskEmail(s)
			} else {
				sanitized[k] = "***"
			}
		case "ip", "ip_address", "remote_ip":
			if s, ok := v.(string); ok {
				sanitized[k] = maskIP(s)
			} else {
				sanitized[k] = "xxx.xxx.xxx.xxx"
			}
		default:
			sanitized[k] = v
		}
	}
	return sanitized
}
