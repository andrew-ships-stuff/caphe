package adapters

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
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

func TestParseOSV(t *testing.T) {
	raw := []byte(`{"results":[{"source":{"path":"go.mod","type":"lockfile"},"packages":[{"package":{"name":"example.org/bad","version":"1.0.0","ecosystem":"Go"},"vulnerabilities":[{"id":"GO-2026-0001","summary":"bad package","database_specific":{"severity":"HIGH"}}]}]}]}`)
	r, err := ParseScannerOutput("scanner.osv", raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Findings) != 1 || r.Findings[0].RuleID != "GO-2026-0001" || r.Findings[0].Severity != findings.SeverityHigh || r.Findings[0].Location.Path != "go.mod" {
		t.Fatalf("unexpected parse: %#v", r)
	}
}

func TestParseCheckovSingleAndMultiFramework(t *testing.T) {
	raw := []byte(`[{"check_type":"terraform","results":{"failed_checks":[{"check_id":"CKV_AWS_1","check_name":"Encrypt storage","file_path":"/main.tf","file_line_range":[4,8],"severity":"MEDIUM"}]}},{"check_type":"kubernetes","results":{"failed_checks":[{"check_id":"CKV_K8S_1","check_name":"Drop capabilities","file_path":"/pod.yaml","file_line_range":[9,12]}]}}]`)
	r, err := ParseScannerOutput("scanner.checkov", raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Findings) != 2 || r.Findings[0].Location.Path != "main.tf" || r.Findings[0].Location.StartLine != 4 || r.Findings[1].RuleID != "CKV_K8S_1" {
		t.Fatalf("unexpected parse: %#v", r)
	}
}

func TestParseKubescapeSARIF(t *testing.T) {
	raw := []byte(`{"version":"2.1.0","runs":[{"results":[{"ruleId":"C-0013","level":"warning","message":{"text":"Privileged container"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"deploy.yaml"},"region":{"startLine":17}}}]}]}]}`)
	r, err := ParseScannerOutput("scanner.kubescape", raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Findings) != 1 || r.Findings[0].Tool != "scanner.kubescape" || r.Findings[0].Location.StartLine != 17 {
		t.Fatalf("unexpected parse: %#v", r)
	}
}

func TestParseOPAResultContract(t *testing.T) {
	raw := []byte(`{"result":[{"expressions":[{"value":[{"id":"deny-public-bucket","message":"bucket is public","severity":"high","path":"infra/main.tf","line":12}]}]}]}`)
	r, err := ParseScannerOutput("scanner.opa", raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Findings) != 1 || r.Findings[0].RuleID != "deny-public-bucket" || r.Findings[0].Severity != findings.SeverityHigh || r.Findings[0].Location.StartLine != 12 {
		t.Fatalf("unexpected parse: %#v", r)
	}
}

func TestParseOPAResultsWithoutIDsRemainDistinct(t *testing.T) {
	raw := []byte(`{"result":[{"expressions":[{"value":["first violation","second violation",{"message":"third violation"},{"message":"fourth violation"}]}]}]}`)
	r, err := ParseScannerOutput("scanner.opa", raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Findings) != 4 {
		t.Fatalf("findings = %d, want 4", len(r.Findings))
	}
	seen := map[string]bool{}
	for _, finding := range r.Findings {
		if seen[finding.RuleID] {
			t.Fatalf("duplicate generated rule ID %q", finding.RuleID)
		}
		seen[finding.RuleID] = true
	}
}

func TestRedactCheckovOutput(t *testing.T) {
	raw := []byte(`{"results":{"failed_checks":[{"check_id":"CKV_SECRET_1","check_name":"No secrets","file_path":"/main.tf","code_block":[[1,"sensitive marker"]],"connected_node":{"value":"test-sensitive-marker"},"evaluations":{"value":"test-sensitive-marker"},"fixed_definition":{"api_token":"test-sensitive-marker"},"entity_tags":{"api_token":"test-sensitive-marker"}}]}}`)
	redacted, err := redactCheckovOutput(raw)
	if err != nil {
		t.Fatal(err)
	}
	for _, sensitive := range []string{"test-sensitive-marker", "code_block", "connected_node", "evaluations", "fixed_definition", "entity_tags"} {
		if strings.Contains(string(redacted), sensitive) {
			t.Fatalf("redacted output contains %q: %s", sensitive, redacted)
		}
	}
	parsed, err := ParseScannerOutput("scanner.checkov", redacted)
	if err != nil {
		t.Fatal(err)
	}
	if len(parsed.Findings) != 1 || parsed.Findings[0].RuleID != "CKV_SECRET_1" {
		t.Fatalf("redaction removed finding identity: %#v", parsed)
	}
}

func TestNewScannerArgumentsAndValidation(t *testing.T) {
	tests := []struct {
		id     string
		binary string
		config map[string]any
		want   []string
	}{
		{id: "scanner.osv", binary: "osv-scanner", config: map[string]any{"offline": true}, want: []string{"scan", "source", "--format", "json", "--recursive", "--offline", "."}},
		{id: "scanner.checkov", binary: "checkov", config: map[string]any{"framework": "terraform,kubernetes"}, want: []string{"-d", ".", "-o", "json", "--soft-fail", "--skip-results-upload", "--skip-download", "--compact", "--framework", "terraform,kubernetes"}},
		{id: "scanner.checkov-sensitive", binary: "checkov", config: map[string]any{"includeSensitiveOutput": true}, want: []string{"-d", ".", "-o", "json", "--soft-fail", "--skip-results-upload", "--skip-download"}},
		{id: "scanner.kubescape", binary: "kubescape", config: map[string]any{"useArtifactsFrom": ".kubescape"}, want: []string{"scan", ".", "--format", "sarif", "--use-artifacts-from", ".kubescape"}},
		{id: "scanner.opa", binary: "opa", config: map[string]any{"policy": "policy/deny.rego", "query": "data.caphe.deny", "input": "input.json"}, want: []string{"eval", "--format", "json", "--data", "policy/deny.rego", "--input", "input.json", "data.caphe.deny"}},
	}
	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			id := tt.id
			if id == "scanner.checkov-sensitive" {
				id = "scanner.checkov"
			}
			scanner := NewScanner(id, tt.binary)
			raw, err := json.Marshal(tt.config)
			if err != nil {
				t.Fatal(err)
			}
			if err := scanner.Validate(raw); err != nil {
				t.Fatal(err)
			}
			got, err := scanner.args(".", tt.config, nil)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("args = %#v, want %#v", got, tt.want)
			}
		})
	}
	checkov := NewScanner("scanner.checkov", "checkov")
	if err := checkov.Validate(json.RawMessage(`{"includeSensitiveOutput":"yes"}`)); err == nil {
		t.Fatal("non-boolean includeSensitiveOutput accepted")
	}

	opa := NewScanner("scanner.opa", "opa")
	for _, raw := range []json.RawMessage{json.RawMessage(`{}`), json.RawMessage(`{"policy":"../escape.rego","query":"data.deny"}`), json.RawMessage(`{"policy":"policy.rego","query":"-bad"}`), json.RawMessage(`{"policy":"policy.rego","query":"data.deny","extra":true}`)} {
		if err := opa.Validate(raw); err == nil {
			t.Fatalf("invalid OPA configuration accepted: %s", raw)
		}
	}
}

func TestCheckovExecuteRedactsRawOutputByDefault(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses a POSIX fake executable")
	}
	dir := t.TempDir()
	tool := filepath.Join(dir, "checkov")
	script := `#!/bin/sh
if [ "$1" = "--version" ]; then
  echo '3.2.0'
  exit 0
fi
printf '%s\n' '{"results":{"failed_checks":[{"check_id":"CKV_SECRET_1","check_name":"No secrets","file_path":"/main.tf","code_block":[[1,"sensitive marker"]],"evaluations":{"value":"test-sensitive-marker"}}]}}'
`
	if err := os.WriteFile(tool, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	scanner := NewScanner("scanner.checkov", "checkov")
	redacted, err := scanner.Execute(t.Context(), Request{Target: dir, Config: json.RawMessage(`{}`), MaxOutput: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(redacted.Raw), "test-sensitive-marker") || len(redacted.Findings.Findings) != 1 {
		t.Fatalf("default result was not safely redacted: %#v", redacted)
	}
	sensitive, err := scanner.Execute(t.Context(), Request{Target: dir, Config: json.RawMessage(`{"includeSensitiveOutput":true}`), MaxOutput: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(sensitive.Raw), "test-sensitive-marker") {
		t.Fatalf("explicit sensitive output was redacted: %s", sensitive.Raw)
	}
}

func TestDefaultRegistryIncludesPlannedScanners(t *testing.T) {
	registry := DefaultRegistry()
	for _, id := range []string{"scanner.opa", "scanner.osv", "scanner.checkov", "scanner.kubescape"} {
		if _, ok := registry.Get(id); !ok {
			t.Fatalf("%s is not registered", id)
		}
	}
}

func TestOSVFindingExitCodeIsSuccessful(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses a POSIX fake executable")
	}
	dir := t.TempDir()
	tool := filepath.Join(dir, "osv-scanner")
	script := `#!/bin/sh
if [ "$1" = "--version" ]; then
  echo 'osv-scanner 2.0.0'
  exit 0
fi
printf '%s\n' '{"results":[{"source":{"path":"go.mod"},"packages":[{"package":{"name":"bad","version":"1.0"},"vulnerabilities":[{"id":"OSV-1"}]}]}]}'
exit 1
`
	if err := os.WriteFile(tool, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	result, err := NewScanner("scanner.osv", "osv-scanner").Execute(t.Context(), Request{Target: dir, Config: json.RawMessage(`{}`), MaxOutput: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	if result.ExitCode != 1 || len(result.Findings.Findings) != 1 {
		t.Fatalf("finding exit was not preserved: %#v", result)
	}
}

func TestRunCommandOutputLimit(t *testing.T) {
	_, _, _, err := RunCommand(t.Context(), ".", "sh", []string{"-c", "printf 123456789"}, 4)
	if err != ErrOutputLimit {
		t.Fatalf("expected output limit, got %v", err)
	}
}
