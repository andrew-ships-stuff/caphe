package adapters

import (
	"encoding/json"
	"testing"
)

func TestPackageInstancesHaveDistinctIdentities(t *testing.T) {
	for _, tool := range []string{"scanner.grype", "scanner.osv"} {
		t.Run(tool, func(t *testing.T) {
			property := "artifact"
			if tool == "scanner.osv" {
				property = "package"
			}
			first := newFinding(tool, "CVE-2026-1234", "same advisory", "high", "go.mod", 0, map[string]any{property: map[string]any{"name": "a", "version": "1"}})
			second := newFinding(tool, "CVE-2026-1234", "same advisory", "high", "go.mod", 0, map[string]any{property: map[string]any{"name": "b", "version": "1"}})
			if first.ID == second.ID {
				t.Fatal("distinct packages collided")
			}
			data, _ := json.Marshal(first.Properties)
			var props map[string]any
			_ = json.Unmarshal(data, &props)
			if first.ID != newFinding(tool, "CVE-2026-1234", "changed explanation", "high", "go.mod", 0, props).ID {
				t.Fatal("identity is unstable")
			}
		})
	}
}

func TestRejectMalformedScannerDocuments(t *testing.T) {
	for _, tc := range []struct{ tool, raw string }{
		{"scanner.grype", `{}`}, {"scanner.grype", `{"matches":{}}`}, {"scanner.grype", `{"matches":[{}]}`},
		{"scanner.opengrep", `{"results":[],"errors":[{"message":"rules failed"}]}`},
		{"scanner.gitleaks", `{}`}, {"scanner.syft", `{}`}, {"scanner.poutine", `[]`},
		{"scanner.osv", `{"results":[null]}`}, {"scanner.checkov", `{"results":{}}`},
	} {
		t.Run(tc.tool+tc.raw, func(t *testing.T) {
			if _, err := ParseScannerOutput(tc.tool, []byte(tc.raw)); err == nil {
				t.Fatal("malformed output accepted as clean")
			}
		})
	}
}

func TestSecretsScanSnapshot(t *testing.T) {
	args, err := NewScanner("scanner.gitleaks", "gitleaks").args(".", nil, nil)
	if err != nil || args[0] != "dir" || args[1] != "." {
		t.Fatalf("not scanning directory: %v %v", args, err)
	}
}
