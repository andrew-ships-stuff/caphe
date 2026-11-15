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
