package audit

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/andrew-ships-stuff/caphe/internal/findings"
)

func TestInteractiveHTMLContainsOfflineBundleAndReferences(t *testing.T) {
	bundle := Bundle{
		SchemaVersion: SchemaVersion,
		GeneratedAt:   time.Date(2026, 11, 14, 1, 2, 3, 0, time.UTC),
		Target:        ".",
		Status:        "succeeded",
		Metrics:       Metrics{Findings: 1, BySeverity: map[string]int{"high": 1}, ByTool: map[string]int{"scanner.grype": 1}},
		Findings:      []findings.Finding{{ID: "f1", RuleID: "CVE-2026-12345", Tool: "scanner.grype", Title: "unsafe <script>", Severity: findings.SeverityHigh}},
	}
	if err := setDigest(&bundle); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := RenderHTML(&out, bundle); err != nil {
		t.Fatal(err)
	}
	html := out.String()
	for _, want := range []string{"Caphe security posture", "nvd.nist.gov/vuln/detail", "application/octet-stream", "Search findings"} {
		if !strings.Contains(html, want) {
			t.Fatalf("HTML missing %q", want)
		}
	}
	if strings.Contains(html, "unsafe <script>") {
		t.Fatal("untrusted finding was emitted as executable markup")
	}
}

func TestReadJSONVerifiesDigest(t *testing.T) {
	bundle := Bundle{SchemaVersion: SchemaVersion, GeneratedAt: time.Now().UTC(), Status: "succeeded", Metrics: Metrics{BySeverity: map[string]int{}, ByTool: map[string]int{}}}
	if err := setDigest(&bundle); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "bundle.json")
	if err := WriteJSON(path, bundle); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadJSON(path); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	data = bytes.Replace(data, []byte(`"status": "succeeded"`), []byte(`"status": "tampered"`), 1)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadJSON(path); err == nil || !strings.Contains(err.Error(), "digest mismatch") {
		t.Fatalf("expected digest mismatch, got %v", err)
	}
}
