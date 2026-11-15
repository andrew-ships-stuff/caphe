package e2e

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestCLICompileRunPersistAndReport(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("mock executable fixture currently uses POSIX scripts")
	}
	repo := repositoryRoot(t)
	temp := t.TempDir()
	binary := filepath.Join(temp, "caphe")
	run(t, repo, nil, "go", "build", "-o", binary, "./cmd/caphe")
	toolDir := filepath.Join(temp, "tools")
	if err := os.MkdirAll(toolDir, 0o700); err != nil {
		t.Fatal(err)
	}
	writeExecutable(t, filepath.Join(toolDir, "opengrep"), `#!/bin/sh
if [ "$1" = "--version" ]; then echo "e2e-opengrep-1"; exit 0; fi
printf '%s\n' '{"results":[{"check_id":"e2e.command-injection","path":"main.go","start":{"line":12},"extra":{"message":"E2E finding","severity":"ERROR"}}]}'
`)
	target := filepath.Join(temp, "target")
	if err := os.MkdirAll(target, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, "main.go"), []byte("package main\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	workflow := filepath.Join(temp, "workflow.yaml")
	if err := os.WriteFile(workflow, []byte(`apiVersion: caphe.dev/v1alpha1
kind: SecurityWorkflow
metadata: {name: e2e, version: "1"}
spec:
  target: {type: repository}
  tasks:
    - {id: sast, uses: scanner.opengrep, with: {ruleset: local}}
    - {id: normalize, uses: core.normalize, needs: [sast]}
`), 0o600); err != nil {
		t.Fatal(err)
	}
	env := append(os.Environ(), "PATH="+toolDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	lock := filepath.Join(temp, "workflow.lock.json")
	state := filepath.Join(temp, "state")
	run(t, repo, env, binary, "compile", workflow, "--output", lock, "--json")
	run(t, repo, env, binary, "validate", lock, "--json")
	out := run(t, repo, env, binary, "run", lock, "--target", target, "--data-dir", state, "--json")
	if !strings.Contains(out, `"findingCount": 1`) {
		t.Fatalf("run did not persist finding: %s", out)
	}
	findings := run(t, repo, env, binary, "findings", "list", "--data-dir", state, "--json")
	if !strings.Contains(findings, "e2e.command-injection") {
		t.Fatalf("finding absent: %s", findings)
	}
	sarif := filepath.Join(temp, "report.sarif")
	run(t, repo, env, binary, "report", "--format", "sarif", "--output", sarif, "--data-dir", state)
	data, err := os.ReadFile(sarif)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("invalid SARIF JSON: %v", err)
	}
	if doc["version"] != "2.1.0" {
		t.Fatalf("unexpected SARIF: %s", data)
	}
}

func TestInitAddsMissingSecurityConfigurationWithoutOverwrite(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("covered by Linux/macOS E2E")
	}
	repo := repositoryRoot(t)
	temp := t.TempDir()
	binary := filepath.Join(temp, "caphe")
	run(t, repo, nil, "go", "build", "-o", binary, "./cmd/caphe")
	project := filepath.Join(temp, "project")
	if err := os.MkdirAll(project, 0o700); err != nil {
		t.Fatal(err)
	}
	custom := []byte("disableVersionCheck: false\n")
	if err := os.WriteFile(filepath.Join(project, ".poutine.yml"), custom, 0o600); err != nil {
		t.Fatal(err)
	}
	run(t, repo, nil, binary, "init", "--project", project, "--data-dir", filepath.Join(temp, "state"), "--json")
	got, err := os.ReadFile(filepath.Join(project, ".poutine.yml"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(custom) {
		t.Fatal("init overwrote existing policy")
	}
	if _, err := os.Stat(filepath.Join(project, ".github", "dependabot.yml")); err != nil {
		t.Fatal("dependabot configuration was not created")
	}
}

func TestInitRejectsConfigurationDirectorySymlinkEscape(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("covered by Linux/macOS E2E")
	}
	repo := repositoryRoot(t)
	temp := t.TempDir()
	binary := filepath.Join(temp, "caphe")
	run(t, repo, nil, "go", "build", "-o", binary, "./cmd/caphe")
	project := filepath.Join(temp, "project")
	external := filepath.Join(temp, "external")
	if err := os.MkdirAll(project, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(external, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(external, filepath.Join(project, ".github")); err != nil {
		t.Fatal(err)
	}
	runFailure(t, repo, nil, binary, "init", "--project", project, "--data-dir", filepath.Join(temp, "state"), "--json")
	if _, err := os.Stat(filepath.Join(external, "dependabot.yml")); !os.IsNotExist(err) {
		t.Fatal("init wrote repository configuration through a symlink")
	}
}

func TestGitHubPRAnalyzeValidateAnnotateAndDryRunPublish(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("git fixture currently targets POSIX runners")
	}
	repo := repositoryRoot(t)
	temp := t.TempDir()
	binary := filepath.Join(temp, "caphe")
	run(t, repo, nil, "go", "build", "-o", binary, "./cmd/caphe")
	fixture := filepath.Join(temp, "fixture")
	if err := os.MkdirAll(fixture, 0o700); err != nil {
		t.Fatal(err)
	}
	run(t, fixture, nil, "git", "init", "--quiet")
	run(t, fixture, nil, "git", "config", "user.email", "e2e@caphe.dev")
	run(t, fixture, nil, "git", "config", "user.name", "Caphe E2E")
	if err := os.WriteFile(filepath.Join(fixture, "main.go"), []byte("package main\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	run(t, fixture, nil, "git", "add", "main.go")
	run(t, fixture, nil, "git", "commit", "--quiet", "-m", "base")
	baseSHA := strings.TrimSpace(run(t, fixture, nil, "git", "rev-parse", "HEAD"))
	if err := os.WriteFile(filepath.Join(fixture, "main.go"), []byte("package main\n// changed security-sensitive line\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	run(t, fixture, nil, "git", "add", "main.go")
	run(t, fixture, nil, "git", "commit", "--quiet", "-m", "head")
	headSHA := strings.TrimSpace(run(t, fixture, nil, "git", "rev-parse", "HEAD"))
	baseReport := filepath.Join(temp, "base.json")
	headReport := filepath.Join(temp, "head.json")
	run(t, fixture, nil, binary, "report", "--format", "json", "--output", baseReport, "--data-dir", filepath.Join(temp, "base-state"))
	if data, err := os.ReadFile(baseReport); err != nil {
		t.Fatal(err)
	} else if !strings.Contains(string(data), `"findings":[]`) {
		t.Fatalf("empty report must serialize findings as an empty array, got: %s", data)
	}
	findingID := "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	head := map[string]any{"schemaVersion": "caphe.dev/report/v1alpha1", "findings": []any{map[string]any{"id": findingID, "fingerprint": findingID, "tool": "scanner.opengrep", "ruleId": "e2e.security", "title": "Introduced E2E finding", "severity": "high", "location": map[string]any{"path": "main.go", "startLine": 2}, "artifactDigest": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}}}
	headData, err := json.Marshal(head)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(headReport, headData, 0o600); err != nil {
		t.Fatal(err)
	}
	artifact := filepath.Join(temp, "review.json")
	summary := filepath.Join(temp, "summary.md")
	sarif := filepath.Join(temp, "review.sarif")
	run(t, fixture, nil, binary, "github", "analyze", "--base-report", baseReport, "--head-report", headReport, "--base-sha", baseSHA, "--head-sha", headSHA, "--repository", "owner/repository", "--pr", "7", "--output", artifact, "--summary-output", summary, "--sarif-output", sarif, "--max-comments", "2", "--json")
	run(t, fixture, nil, binary, "github", "validate", artifact, "--repository", "owner/repository", "--pr", "7", "--base-sha", baseSHA, "--head-sha", headSHA, "--max-comments", "2", "--json")
	annotation := run(t, fixture, nil, binary, "github", "annotations", artifact, "--max-comments", "2")
	if !strings.Contains(annotation, "::error") || !strings.Contains(annotation, findingID) {
		t.Fatalf("unexpected annotation: %s", annotation)
	}
	published := run(t, fixture, nil, binary, "github", "publish", artifact, "--repository", "owner/repository", "--pr", "7", "--base-sha", baseSHA, "--head-sha", headSHA, "--max-comments", "2", "--dry-run", "--json")
	if !strings.Contains(published, `"dryRun": true`) {
		t.Fatalf("unexpected dry-run result: %s", published)
	}
	serveMissingURL := runFailure(t, fixture, nil, binary, "github", "analyze", "--base-report", baseReport, "--head-report", headReport, "--base-sha", baseSHA, "--head-sha", headSHA, "--repository", "owner/repository", "--pr", "7", "--output", artifact, "--ai", "--ai-serve", "--ai-model", "test-model", "--ai-model-digest", "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	if !strings.Contains(serveMissingURL, "--ai-model-url is required") {
		t.Fatalf("expected --ai-serve to require --ai-model-url, got: %s", serveMissingURL)
	}
	aiMissingModel := runFailure(t, fixture, nil, binary, "github", "analyze", "--base-report", baseReport, "--head-report", headReport, "--base-sha", baseSHA, "--head-sha", headSHA, "--repository", "owner/repository", "--pr", "7", "--output", artifact, "--ai")
	if !strings.Contains(aiMissingModel, "--ai-model and --ai-model-digest are required") {
		t.Fatalf("expected --ai to require model and digest, got: %s", aiMissingModel)
	}
	for _, flag := range []string{"--ai-serve", "--ai-model-url", "--ai-llama-server", "--ai-threads"} {
		usage := run(t, fixture, nil, binary, "github", "analyze", "--help")
		if !strings.Contains(usage, flag) {
			t.Fatalf("expected analyze --help to advertise %s", flag)
		}
	}
	data, err := os.ReadFile(artifact)
	if err != nil {
		t.Fatal(err)
	}
	data = []byte(strings.ReplaceAll(string(data), "Introduced E2E finding", "tampered finding"))
	if err := os.WriteFile(artifact, data, 0o600); err != nil {
		t.Fatal(err)
	}
	runFailure(t, fixture, nil, binary, "github", "validate", artifact, "--repository", "owner/repository", "--pr", "7", "--base-sha", baseSHA, "--head-sha", headSHA, "--max-comments", "2")
}

func TestAuditHeroCommandAggregatesAndDegrades(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("mock executable fixtures currently use POSIX scripts")
	}
	repo := repositoryRoot(t)
	temp := t.TempDir()
	binary := filepath.Join(temp, "caphe")
	run(t, repo, nil, "go", "build", "-o", binary, "./cmd/caphe")
	target := filepath.Join(temp, "target")
	if err := os.MkdirAll(target, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, "main.go"), []byte("package main\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	toolDir := filepath.Join(temp, "tools")
	if err := os.MkdirAll(toolDir, 0o700); err != nil {
		t.Fatal(err)
	}
	mocks := map[string]string{
		"opengrep": `#!/bin/sh
printf '%s\n' '{"results":[{"check_id":"e2e.injection","path":"main.go","start":{"line":2},"extra":{"message":"Command injection","severity":"ERROR"}},{"check_id":"e2e.hardcoded","path":"config.go","start":{"line":7},"extra":{"message":"Hardcoded credential","severity":"WARNING"}}]}'
`,
		"syft": `#!/bin/sh
printf '%s\n' '{"components":[{"name":"lib-a","version":"1.0"},{"name":"lib-b","version":"2.0"}]}'
`,
		"grype": `#!/bin/sh
printf '%s\n' '{"matches":[{"vulnerability":{"id":"CVE-2024-0001","severity":"High"},"artifact":{"name":"lib-a","version":"1.0"}}]}'
`,
		"gitleaks": `#!/bin/sh
printf '%s\n' '[{"RuleID":"generic-api-key","Description":"Generic API key","File":"config.go","StartLine":7,"Secret":"x","Match":"y","Entropy":4.2}]'
`,
		"poutine": `#!/bin/sh
printf '%s\n' '{"runs":[{"results":[{"ruleId":"untrusted-checkout-exec","level":"error","message":{"text":"Untrusted checkout executes code"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":".github/workflows/ci.yml"},"region":{"startLine":19}}}]}]}]}'
`,
	}
	for name, script := range mocks {
		writeExecutable(t, filepath.Join(toolDir, name), script)
	}
	bundlePath := filepath.Join(temp, "bundle.json")
	sarifPath := filepath.Join(temp, "bundle.sarif")
	markdownPath := filepath.Join(temp, "bundle.md")
	htmlPath := filepath.Join(temp, "bundle.html")
	env := append(os.Environ(), "PATH="+toolDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	out := run(t, temp, env, binary, "audit", target, "-o", bundlePath, "--sarif-output", sarifPath, "--markdown-output", markdownPath, "--html-output", htmlPath, "--data-dir", filepath.Join(temp, "state"), "--json")
	if !strings.Contains(out, `"findings": 5`) || !strings.Contains(out, "sha256:") {
		t.Fatalf("audit summary missing aggregate metrics: %s", out)
	}
	data, err := os.ReadFile(bundlePath)
	if err != nil {
		t.Fatal(err)
	}
	var bundle struct {
		SchemaVersion string `json:"schemaVersion"`
		Findings      []struct {
			Tool     string `json:"tool"`
			Severity string `json:"severity"`
		} `json:"findings"`
		Recommendations []struct {
			Source string `json:"source"`
		} `json:"recommendations"`
		Status string `json:"status"`
	}
	if err := json.Unmarshal(data, &bundle); err != nil {
		t.Fatal(err)
	}
	if bundle.SchemaVersion != "caphe.dev/audit/bundle/v1alpha1" || bundle.Status != "succeeded" || len(bundle.Findings) != 5 || len(bundle.Recommendations) != 5 {
		t.Fatalf("unexpected bundle: %s", data)
	}
	tools := map[string]bool{}
	for _, item := range bundle.Findings {
		tools[item.Tool] = true
	}
	for _, want := range []string{"scanner.opengrep", "scanner.gitleaks", "scanner.grype", "scanner.poutine"} {
		if !tools[want] {
			t.Fatalf("bundle missing findings from %s: %s", want, data)
		}
	}
	if bundle.Findings[0].Severity != "high" {
		t.Fatalf("bundle must sort worst findings first: %s", data)
	}
	sarif, err := os.ReadFile(sarifPath)
	if err != nil || !strings.Contains(string(sarif), "untrusted-checkout-exec") {
		t.Fatalf("sarif missing findings: %v", err)
	}
	markdown, err := os.ReadFile(markdownPath)
	if err != nil || !strings.Contains(string(markdown), "Caphe security audit") {
		t.Fatalf("markdown report missing: %v", err)
	}
	html, err := os.ReadFile(htmlPath)
	if err != nil || !strings.Contains(string(html), "Caphe security posture") || !strings.Contains(string(html), "nvd.nist.gov/vuln/detail") {
		t.Fatalf("interactive HTML report missing: %v", err)
	}
	renderedPath := filepath.Join(temp, "rendered.html")
	run(t, temp, env, binary, "report", bundlePath, "--format", "html", "--output", renderedPath)
	if rendered, err := os.ReadFile(renderedPath); err != nil || !strings.Contains(string(rendered), "Search findings") {
		t.Fatalf("bundle-to-HTML report missing: %v", err)
	}
	degraded := run(t, target, []string{"PATH=/usr/bin:/bin"}, binary, "audit", "-o", filepath.Join(temp, "degraded.json"), "--sarif-output", "", "--markdown-output", "", "--html-output", "", "--data-dir", filepath.Join(temp, "degraded-state"), "--json")
	if !strings.Contains(degraded, `"status": "succeeded"`) || !strings.Contains(degraded, `"findings": 0`) {
		t.Fatalf("audit must succeed with all scanners missing: %s", degraded)
	}
	aiState := filepath.Join(temp, "ai-state")
	missingModel := runFailure(t, temp, env, binary, "audit", target, "-o", filepath.Join(temp, "ai.json"), "--data-dir", aiState, "--ai")
	if !strings.Contains(missingModel, "--ai-model and --ai-model-digest are required") {
		t.Fatalf("expected AI flag validation, got: %s", missingModel)
	}
	if _, err := os.Stat(aiState); !os.IsNotExist(err) {
		t.Fatalf("invalid AI options must fail before audit state is created: %v", err)
	}
}

func repositoryRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("caller unavailable")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}
func writeExecutable(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o700); err != nil {
		t.Fatal(err)
	}
}
func run(t *testing.T, dir string, env []string, name string, args ...string) string {
	t.Helper()
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	if env != nil {
		cmd.Env = env
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%s %v failed: %v\n%s", name, args, err, out)
	}
	return string(out)
}
func runFailure(t *testing.T, dir string, env []string, name string, args ...string) string {
	t.Helper()
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	if env != nil {
		cmd.Env = env
	}
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("%s %v unexpectedly succeeded\n%s", name, args, out)
	}
	return string(out)
}
