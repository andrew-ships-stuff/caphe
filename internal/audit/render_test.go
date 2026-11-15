package audit

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
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
	for _, want := range []string{"Caphe security posture", "nvd.nist.gov/vuln/detail", `id="caphe-bundle"`, "Search findings", "Download CSV", "Light mode", ".badge.critical,.badge.high{color:#f85149;background:#3d1d20}", "data-theme=light] .badge{background:#e8edf2", `data-tab="plan"`, "All findings", `id="tab-plan"`, `id="tab-findings" hidden`, `id="pipeline"`} {
		if !strings.Contains(html, want) {
			t.Fatalf("HTML missing %q", want)
		}
	}
	start := strings.Index(html, `id="caphe-bundle" hidden>`)
	if start < 0 {
		t.Fatal("payload container missing")
	}
	rest := html[start:]
	encoded := rest[strings.Index(rest, ">")+1 : strings.Index(rest, "</div>")]
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(encoded))
	if err != nil {
		t.Fatalf("embedded bundle payload is not valid base64: %v", err)
	}
	var check struct {
		Findings []findings.Finding `json:"findings"`
	}
	if err := json.Unmarshal(decoded, &check); err != nil {
		t.Fatalf("embedded bundle payload is not valid JSON: %v", err)
	}
	if len(check.Findings) != 1 {
		t.Fatalf("embedded payload findings = %d, want 1", len(check.Findings))
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
