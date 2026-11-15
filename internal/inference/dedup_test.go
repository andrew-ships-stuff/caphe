package inference

import (
	"strings"
	"testing"
)

func dedupAllowed() map[string]bool {
	return map[string]bool{"r1": true, "r2": true, "r3": true}
}

func TestValidateDedupSuggestions(t *testing.T) {
	cases := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{"valid", `{"merges":[{"group_id":"r1","duplicate_of":"r2","rationale":"same dependency line"}],"confidence":"hypothesis"}`, false},
		{"empty", `{"merges":[],"confidence":"hypothesis"}`, false},
		{"unknown field", `{"merges":[],"confidence":"hypothesis","extra":1}`, true},
		{"trailing json", `{"merges":[],"confidence":"hypothesis"}{}`, true},
		{"fabricated group", `{"merges":[{"group_id":"r9","duplicate_of":"r2","rationale":"x"}],"confidence":"hypothesis"}`, true},
		{"self merge", `{"merges":[{"group_id":"r1","duplicate_of":"r1","rationale":"x"}],"confidence":"hypothesis"}`, true},
		{"non hypothesis confidence", `{"merges":[{"group_id":"r1","duplicate_of":"r2","rationale":"x"}],"confidence":"confirmed"}`, true},
		{"missing rationale", `{"merges":[{"group_id":"r1","duplicate_of":"r2","rationale":"  "}],"confidence":"hypothesis"}`, true},
		{"oversized rationale", `{"merges":[{"group_id":"r1","duplicate_of":"r2","rationale":"` + strings.Repeat("x", 501) + `"}],"confidence":"hypothesis"}`, true},
		{"duplicate pair", `{"merges":[{"group_id":"r1","duplicate_of":"r2","rationale":"x"},{"group_id":"r1","duplicate_of":"r2","rationale":"y"}],"confidence":"hypothesis"}`, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ValidateDedupSuggestions([]byte(tc.input), dedupAllowed())
			if (err != nil) != tc.wantErr {
				t.Fatalf("err=%v wantErr=%v", err, tc.wantErr)
			}
		})
	}
}

func TestValidateDedupSuggestionsCaps(t *testing.T) {
	var builder strings.Builder
	builder.WriteString(`{"merges":[`)
	for i := 0; i < 11; i++ {
		if i > 0 {
			builder.WriteString(",")
		}
		builder.WriteString(`{"group_id":"r1","duplicate_of":"r2","rationale":"pair `)
		builder.WriteString(string(rune('a' + i)))
		builder.WriteString(`"}`)
	}
	builder.WriteString(`],"confidence":"hypothesis"}`)
	if _, err := ValidateDedupSuggestions([]byte(builder.String()), dedupAllowed()); err == nil {
		t.Fatal("expected cap rejection for 11 merges")
	}
}
