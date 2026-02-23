// Tests for the crowdsec package covering decision parsing, protocol
// detection, duration parsing, and stream construction.
package crowdsec

import (
	"testing"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/models"

	"github.com/jmrplens/cs-routeros-bouncer/internal/config"
)

// strPtr returns a pointer to the given string. It is a test helper for
// constructing models.Decision structs that use pointer fields.
func strPtr(s string) *string { return &s }

// TestDetectProtoIPv4 verifies that IPv4 addresses are correctly identified
// as protocol "ip" regardless of CIDR notation.
func TestDetectProtoIPv4(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"192.168.1.1", "ip"},
		{"10.0.0.0/8", "ip"},
		{"255.255.255.255", "ip"},
		{"0.0.0.0/0", "ip"},
	}
	for _, tt := range tests {
		if got := DetectProto(tt.input); got != tt.want {
			t.Errorf("DetectProto(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

// TestDetectProtoIPv6 verifies that IPv6 addresses are correctly identified
// as protocol "ipv6" in various notations.
func TestDetectProtoIPv6(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"2001:db8::1", "ipv6"},
		{"::1", "ipv6"},
		{"fe80::/10", "ipv6"},
		{"2001:db8::/32", "ipv6"},
	}
	for _, tt := range tests {
		if got := DetectProto(tt.input); got != tt.want {
			t.Errorf("DetectProto(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

// TestDetectProtoEmpty verifies that an empty value falls back to the default
// protocol "ip".
func TestDetectProtoEmpty(t *testing.T) {
	if got := DetectProto(""); got != "ip" {
		t.Errorf("DetectProto(\"\") = %q, want \"ip\"", got)
	}
}

// TestDetectProtoHostname verifies that a bare hostname (no colons, no dots
// forming a valid IP) falls back to the default protocol "ip".
func TestDetectProtoHostname(t *testing.T) {
	if got := DetectProto("hostname"); got != "ip" {
		t.Errorf("DetectProto(\"hostname\") = %q, want \"ip\"", got)
	}
}

// TestParseDurationSeconds verifies that durations expressed as bare seconds
// (CrowdSec format) are correctly parsed.
func TestParseDurationSeconds(t *testing.T) {
	d, err := ParseDuration("45s")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if d != 45*time.Second {
		t.Errorf("expected 45s, got %v", d)
	}
}

// TestParseDurationHoursAndMinutes verifies that composite duration strings
// are correctly parsed.
func TestParseDurationHoursAndMinutes(t *testing.T) {
	d, err := ParseDuration("2h30m")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if d != 2*time.Hour+30*time.Minute {
		t.Errorf("expected 2h30m, got %v", d)
	}
}

// TestParseDurationCrowdSecFormat verifies that the CrowdSec-specific duration
// format (e.g. "4h0m0s" or "2h30m15.123s") is handled.
func TestParseDurationCrowdSecFormat(t *testing.T) {
	d, err := ParseDuration("4h0m0s")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if d != 4*time.Hour {
		t.Errorf("expected 4h, got %v", d)
	}
}

// TestParseDecisionValid verifies that a fully populated CrowdSec models.Decision
// is correctly converted to the internal Decision type.
func TestParseDecisionValid(t *testing.T) {
	d := parseDecision(&models.Decision{
		Duration: strPtr("4h"),
		Origin:   strPtr("crowdsec"),
		Scenario: strPtr("ssh-bf"),
		Scope:    strPtr("Ip"),
		Value:    strPtr("1.2.3.4"),
		Type:     strPtr("ban"),
	})

	if d == nil {
		t.Fatal("expected non-nil decision")
	}
	if d.Value != "1.2.3.4" {
		t.Errorf("expected value '1.2.3.4', got '%s'", d.Value)
	}
	if d.Origin != "crowdsec" {
		t.Errorf("expected origin 'crowdsec', got '%s'", d.Origin)
	}
	if d.Scenario != "ssh-bf" {
		t.Errorf("expected scenario 'ssh-bf', got '%s'", d.Scenario)
	}
	if d.Proto != "ip" {
		t.Errorf("expected proto 'ip', got '%s'", d.Proto)
	}
}

// TestParseDecisionIPv6 verifies that an IPv6 decision is correctly detected.
func TestParseDecisionIPv6(t *testing.T) {
	d := parseDecision(&models.Decision{
		Duration: strPtr("1h"),
		Scope:    strPtr("Ip"),
		Value:    strPtr("2001:db8::1"),
		Type:     strPtr("ban"),
	})

	if d == nil {
		t.Fatal("expected non-nil decision")
	}
	if d.Proto != "ipv6" {
		t.Errorf("expected proto 'ipv6', got '%s'", d.Proto)
	}
}

// TestParseDecisionNilFields verifies that a decision with nil optional fields
// does not panic and produces sensible zero values.
func TestParseDecisionNilFields(t *testing.T) {
	d := parseDecision(&models.Decision{
		Duration: strPtr("1h"),
		Scope:    strPtr("Ip"),
		Value:    strPtr("10.0.0.1"),
		Type:     strPtr("ban"),
		Origin:   nil,
		Scenario: nil,
	})

	if d == nil {
		t.Fatal("expected non-nil decision")
	}
	if d.Origin != "" {
		t.Errorf("expected empty origin, got '%s'", d.Origin)
	}
	if d.Scenario != "" {
		t.Errorf("expected empty scenario, got '%s'", d.Scenario)
	}
}

// TestParseDecisionNilValue verifies that a decision with nil Value returns nil.
func TestParseDecisionNilValue(t *testing.T) {
	d := parseDecision(&models.Decision{
		Duration: strPtr("1h"),
		Scope:    strPtr("Ip"),
		Value:    nil,
		Type:     strPtr("ban"),
	})
	if d != nil {
		t.Error("expected nil decision for nil Value")
	}
}

// TestParseDecisionNilType verifies that a decision with nil Type returns nil.
func TestParseDecisionNilType(t *testing.T) {
	d := parseDecision(&models.Decision{
		Duration: strPtr("1h"),
		Scope:    strPtr("Ip"),
		Value:    strPtr("10.0.0.1"),
		Type:     nil,
	})
	if d != nil {
		t.Error("expected nil decision for nil Type")
	}
}

// TestParseDecisionNonBanType verifies that non-ban decision types (e.g.
// "captcha") are filtered out and return nil.
func TestParseDecisionNonBanType(t *testing.T) {
	d := parseDecision(&models.Decision{
		Duration: strPtr("1h"),
		Scope:    strPtr("Ip"),
		Value:    strPtr("10.0.0.1"),
		Type:     strPtr("captcha"),
	})
	if d != nil {
		t.Error("expected nil decision for non-ban type")
	}
}

// TestNewStreamCreatesInstance verifies that NewStream returns a non-nil
// Stream instance with the correct configuration.
func TestNewStreamCreatesInstance(t *testing.T) {
	cfg := config.CrowdSecConfig{
		APIURL:          "http://localhost:8080/",
		APIKey:          "test-key",
		UpdateFrequency: 10 * time.Second,
	}
	s := NewStream(cfg, "test")
	if s == nil {
		t.Fatal("expected non-nil stream")
	}
}

// TestNewStreamWithOrigins verifies that origins are correctly passed to the
// Stream instance.
func TestNewStreamWithOrigins(t *testing.T) {
	cfg := config.CrowdSecConfig{
		APIURL:          "http://localhost:8080/",
		APIKey:          "test-key",
		UpdateFrequency: 10 * time.Second,
		Origins:         []string{"crowdsec", "cscli"},
	}
	s := NewStream(cfg, "test")
	if s == nil {
		t.Fatal("expected non-nil stream")
	}
}

// TestIsRangeIPv4 verifies that IPv4 CIDR ranges are detected and bare IPs
// are not.
func TestIsRangeIPv4(t *testing.T) {
	if !IsRange("192.168.0.0/24") {
		t.Error("expected 192.168.0.0/24 to be a range")
	}
	if IsRange("192.168.0.1") {
		t.Error("expected 192.168.0.1 not to be a range")
	}
}

// TestIsRangeIPv6 verifies that IPv6 CIDR ranges are detected and bare
// IPv6 addresses are not.
func TestIsRangeIPv6(t *testing.T) {
	if !IsRange("2001:db8::/32") {
		t.Error("expected 2001:db8::/32 to be a range")
	}
	if IsRange("2001:db8::1") {
		t.Error("expected 2001:db8::1 not to be a range")
	}
}

// --- ParseDuration edge cases ---

// TestParseDurationFractionalSeconds verifies that CrowdSec fractional
// second durations (e.g., "3599.123456789s") are correctly parsed.
func TestParseDurationFractionalSeconds(t *testing.T) {
	d, err := ParseDuration("3599.5s")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	expected := 3599*time.Second + 500*time.Millisecond
	if d != expected {
		t.Errorf("expected %v, got %v", expected, d)
	}
}

// TestParseDurationPlainNumber verifies that a plain number without "s"
// suffix is treated as seconds via the fallback path.
func TestParseDurationPlainNumber(t *testing.T) {
	d, err := ParseDuration("3600s")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if d != time.Hour {
		t.Errorf("expected 1h, got %v", d)
	}
}

// TestParseDurationEmpty verifies that an empty string returns an error.
func TestParseDurationEmpty(t *testing.T) {
	_, err := ParseDuration("")
	if err == nil {
		t.Error("expected error for empty duration string")
	}
}

// TestParseDurationInvalid verifies that a non-numeric string returns an error.
func TestParseDurationInvalid(t *testing.T) {
	_, err := ParseDuration("not-a-duration")
	if err == nil {
		t.Error("expected error for invalid duration string")
	}
}

// TestParseDurationZero verifies that "0s" parses to zero duration.
func TestParseDurationZero(t *testing.T) {
	d, err := ParseDuration("0s")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if d != 0 {
		t.Errorf("expected 0, got %v", d)
	}
}

// TestParseDurationComplex verifies a complex duration with all components.
func TestParseDurationComplex(t *testing.T) {
	d, err := ParseDuration("1h30m45s")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	expected := time.Hour + 30*time.Minute + 45*time.Second
	if d != expected {
		t.Errorf("expected %v, got %v", expected, d)
	}
}

// --- parseDecision additional edge cases ---

// TestParseDecisionWithRange verifies that a CIDR range decision is
// correctly marked as IsRange.
func TestParseDecisionWithRange(t *testing.T) {
	d := parseDecision(&models.Decision{
		Duration: strPtr("2h"),
		Scope:    strPtr("Range"),
		Value:    strPtr("10.0.0.0/8"),
		Type:     strPtr("ban"),
	})
	if d == nil {
		t.Fatal("expected non-nil decision")
	}
	if !d.IsRange {
		t.Error("expected IsRange=true for CIDR range")
	}
	if d.Proto != "ip" {
		t.Errorf("expected proto 'ip', got %q", d.Proto)
	}
}

// TestParseDecisionIPv6Range verifies IPv6 CIDR range detection.
func TestParseDecisionIPv6Range(t *testing.T) {
	d := parseDecision(&models.Decision{
		Duration: strPtr("1h"),
		Scope:    strPtr("Range"),
		Value:    strPtr("2001:db8::/32"),
		Type:     strPtr("ban"),
	})
	if d == nil {
		t.Fatal("expected non-nil decision")
	}
	if !d.IsRange {
		t.Error("expected IsRange=true for IPv6 CIDR")
	}
	if d.Proto != "ipv6" {
		t.Errorf("expected proto 'ipv6', got %q", d.Proto)
	}
}

// TestParseDecisionBadDurationFallback verifies that an unparseable duration
// falls back to 4 hours.
func TestParseDecisionBadDurationFallback(t *testing.T) {
	d := parseDecision(&models.Decision{
		Duration: strPtr("invalid-duration"),
		Scope:    strPtr("Ip"),
		Value:    strPtr("1.2.3.4"),
		Type:     strPtr("ban"),
	})
	if d == nil {
		t.Fatal("expected non-nil decision")
	}
	if d.Duration != 4*time.Hour {
		t.Errorf("expected 4h fallback duration, got %v", d.Duration)
	}
}

// TestParseDecisionNilDuration verifies that a nil duration gives zero duration.
func TestParseDecisionNilDuration(t *testing.T) {
	d := parseDecision(&models.Decision{
		Duration: nil,
		Scope:    strPtr("Ip"),
		Value:    strPtr("10.0.0.1"),
		Type:     strPtr("ban"),
	})
	if d == nil {
		t.Fatal("expected non-nil decision")
	}
	if d.Duration != 0 {
		t.Errorf("expected zero duration for nil Duration, got %v", d.Duration)
	}
}

// TestParseDecisionCaseInsensitiveBan verifies that "BAN", "Ban" etc. are accepted.
func TestParseDecisionCaseInsensitiveBan(t *testing.T) {
	tests := []string{"ban", "Ban", "BAN", "bAn"}
	for _, banType := range tests {
		d := parseDecision(&models.Decision{
			Duration: strPtr("1h"),
			Value:    strPtr("1.2.3.4"),
			Type:     strPtr(banType),
		})
		if d == nil {
			t.Errorf("expected non-nil decision for type %q", banType)
		}
	}
}
