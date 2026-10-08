package siem

import (
	"reflect"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/koray-killi/AuthCore/internal/domain"
)

func TestMaskIP_IPv4(t *testing.T) {
	result := maskIP("192.168.1.42")
	expected := "192.168.xxx.xxx"
	if result != expected {
		t.Errorf("expected %s, got %s", expected, result)
	}
}

func TestMaskIP_IPv6(t *testing.T) {
	result := maskIP("2001:0db8:85a3:0000:0000:8a2e:0370:7334")
	expected := "2001:db8:85a3:0:xxxx:xxxx:xxxx:xxxx"
	if result != expected {
		t.Errorf("expected %s, got %s", expected, result)
	}
}

func TestMaskIP_Invalid(t *testing.T) {
	result := maskIP("not-an-ip")
	expected := "xxx.xxx.xxx.xxx"
	if result != expected {
		t.Errorf("expected %s, got %s", expected, result)
	}
}

func TestMaskEmail_Standard(t *testing.T) {
	result := maskEmail("koray@gmail.com")
	expected := "k***y@g***l.com"
	if result != expected {
		t.Errorf("expected %s, got %s", expected, result)
	}
}

func TestMaskEmail_Short(t *testing.T) {
	result := maskEmail("ab@cd.com")
	expected := "a***b@c***d.com"
	if result != expected {
		t.Errorf("expected %s, got %s", expected, result)
	}
}

func TestMaskEmail_Invalid(t *testing.T) {
	result := maskEmail("not-an-email")
	expected := "***@***.***"
	if result != expected {
		t.Errorf("expected %s, got %s", expected, result)
	}
}

func TestSanitizeBatch_PreservesCounts(t *testing.T) {
	s := NewSanitizer()
	logs := []domain.AuditLog{
		{ID: uuid.New(), IP: "127.0.0.1", CreatedAt: time.Now()},
		{ID: uuid.New(), IP: "10.0.0.1", CreatedAt: time.Now()},
	}
	result := s.SanitizeBatch(logs)
	if len(result) != len(logs) {
		t.Errorf("expected %d logs, got %d", len(logs), len(result))
	}
}

func TestSanitizeMetadata_MasksEmailField(t *testing.T) {
	meta := map[string]interface{}{
		"email": "test@example.com",
		"other": "value",
	}
	result := sanitizeMetadata(meta)
	if result["email"] != "t***t@e***e.com" {
		t.Errorf("email not masked correctly, got %v", result["email"])
	}
	if result["other"] != "value" {
		t.Errorf("other field mutated, got %v", result["other"])
	}
}

func TestSanitizeMetadata_PreservesNonPII(t *testing.T) {
	meta := map[string]interface{}{
		"browser": "Chrome",
		"version": 123,
	}
	result := sanitizeMetadata(meta)
	if !reflect.DeepEqual(meta, result) {
		t.Errorf("expected %v, got %v", meta, result)
	}
}
