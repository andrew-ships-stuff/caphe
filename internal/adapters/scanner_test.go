package adapters

import (
	"strings"
	"testing"

	"github.com/andrew-ships-stuff/caphe/internal/findings"
)

func TestParseOpengrep(t *testing.T) {
	raw := []byte(`{"results":[{"check_id":"go.lang.security.test","path":"main.go","start":{"line":7},"extra":{"message":"unsafe input","severity":"WARNING"}}]}`)
	r, err := ParseScannerOutput("scanner.opengrep", raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Findings) != 1 || r.Findings[0].Severity != findings.SeverityHigh || r.Findings[0].Location.StartLine != 7 {
		t.Fatalf("unexpected parse: %#v", r)
	}
}
func TestParseGrypePreservesOriginalProperties(t *testing.T) {
	raw := []byte(`{"matches":[{"vulnerability":{"id":"CVE-2026-1","severity":"Critical"},"artifact":{"name":"badlib","version":"1.0.0","type":"go-module"}}]}`)
	r, err := ParseScannerOutput("scanner.grype", raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Findings) != 1 || !strings.Contains(r.Findings[0].Title, "badlib@1.0.0") || r.Findings[0].Properties["artifact"] == nil {
		t.Fatalf("lost scanner data: %#v", r)
	}
}
func TestGitleaksSecretRedacted(t *testing.T) {
	raw := []byte(`[{"RuleID":"api-key","Description":"key","File":"x","StartLine":2,"Secret":"dont-store-me","Match":"dont-store-me"}]`)
	r, err := ParseScannerOutput("scanner.gitleaks", raw)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := r.Findings[0].Properties["Secret"]; ok {
		t.Fatal("secret persisted")
	}
}
func TestInvalidScannerJSON(t *testing.T) {
	if _, err := ParseScannerOutput("scanner.grype", []byte(`not-json`)); err == nil {
		t.Fatal("invalid JSON accepted")
	}
}
func TestParsePoutineSARIF(t *testing.T) {
	raw := []byte(`{"version":"2.1.0","runs":[{"results":[{"ruleId":"untrusted_checkout_exec","level":"error","message":{"text":"Untrusted code is executed"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":".github/workflows/ci.yml"},"region":{"startLine":19}}}]}]}]}`)
	r, err := ParseScannerOutput("scanner.poutine", raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Findings) != 1 || r.Findings[0].RuleID != "untrusted_checkout_exec" || r.Findings[0].Location.StartLine != 19 || r.Findings[0].Severity != findings.SeverityHigh {
		t.Fatalf("unexpected parse: %#v", r)
	}
}
func TestRunCommandOutputLimit(t *testing.T) {
	_, _, _, err := RunCommand(t.Context(), ".", "sh", []string{"-c", "printf 123456789"}, 4)
	if err != ErrOutputLimit {
		t.Fatalf("expected output limit, got %v", err)
	}
}
