package crowdsec

import (
	"testing"

	"github.com/crowdsecurity/crowdsec/pkg/models"

	"github.com/jmrplens/cs-routeros-bouncer/internal/config"
)

// A decision the bouncer must act on has to survive parseDecision; one it must
// ignore has to be dropped. Both directions matter: the previous behavior
// hardcoded "ban", so a custom type was silently discarded whatever the
// operator configured.
func TestParseDecisionHonoursConfiguredTypes(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		configure []string
		decision  string
		want      bool
	}{
		{"default set accepts ban", nil, "ban", true},
		{"default set rejects captcha", nil, "captcha", false},
		{"default set rejects a custom type", nil, "blocklist", false},
		{"explicit ban accepts ban", []string{"ban"}, "ban", true},
		{"custom type is accepted when configured", []string{"ban", "blocklist"}, "blocklist", true},
		{"ban still accepted alongside a custom type", []string{"ban", "blocklist"}, "ban", true},
		{"a type outside the set is rejected", []string{"ban", "blocklist"}, "captcha", false},
		{"comparison is case-insensitive", []string{"ban"}, "BAN", true},
		{"configured value is trimmed and lowered", []string{"  BlockList  "}, "blocklist", true},
		{"blank entries do not widen the set", []string{"ban", "  "}, "captcha", false},
		{"an all-blank list falls back to the default", []string{" ", ""}, "ban", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			enforced := enforcedDecisionTypes(config.CrowdSecConfig{
				SupportedDecisionTypes: tc.configure,
			})
			duration := "4h"
			got := parseDecision(&models.Decision{
				Value:    new("192.0.2.1"),
				Type:     new(tc.decision),
				Duration: &duration,
			}, enforced)
			if (got != nil) != tc.want {
				t.Fatalf("type %q with set %v: parsed=%v, want parsed=%v",
					tc.decision, tc.configure, got != nil, tc.want)
			}
		})
	}
}

// The server-side filter is an optimisation that only holds for the default
// set: the Local API matches `type` exactly, so a wider set must be fetched in
// full and filtered here. Getting this backwards would silently drop every
// custom-type decision on the reconciliation path while the live stream kept
// working — the hardest kind of bug to notice.
func TestOnlyDefaultDecisionType(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		configure []string
		want      bool
	}{
		{"unset is the default set", nil, true},
		{"explicit ban is the default set", []string{"ban"}, true},
		{"case does not change it", []string{"BAN"}, true},
		{"a second type widens it", []string{"ban", "blocklist"}, false},
		{"a single custom type is not the default", []string{"blocklist"}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := onlyDefaultDecisionType(enforcedDecisionTypes(config.CrowdSecConfig{
				SupportedDecisionTypes: tc.configure,
			}))
			if got != tc.want {
				t.Fatalf("set %v: onlyDefault=%v, want %v", tc.configure, got, tc.want)
			}
		})
	}
}

// defaultEnforcedTypes is the set an unconfigured bouncer uses. Shared with the
// older tests, which predate the setting and assert the default behavior.
func defaultEnforcedTypes() map[string]struct{} {
	return enforcedDecisionTypes(config.CrowdSecConfig{})
}
