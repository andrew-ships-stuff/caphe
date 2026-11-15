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
