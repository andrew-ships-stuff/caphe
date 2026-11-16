package cli

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/andrew-ships-stuff/caphe/internal/adapters"
	"github.com/andrew-ships-stuff/caphe/internal/compiler"
)

func TestParseSetupSelectionIncludesSyftForGrype(t *testing.T) {
	got, err := parseSetupSelection("1,grype,gitleaks")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"opengrep", "grype", "gitleaks", "syft"} {
		if !slices.Contains(got, want) {
			t.Fatalf("selection %v missing %s", got, want)
		}
	}
	if _, err := parseSetupSelection("unknown"); err == nil {
		t.Fatal("unknown setup selection must fail")
	}
	if none, err := parseSetupSelection("none"); err != nil || len(none) != 0 {
		t.Fatalf("none selection = %v, %v", none, err)
	}
}

func TestSelectedWorkflowCompiles(t *testing.T) {
	definition := selectedWorkflow([]string{"opengrep", "syft", "grype", "gitleaks", "poutine"})
	if _, err := compiler.New(adapters.DefaultRegistry()).Compile(definition); err != nil {
		t.Fatal(err)
	}
}

func TestSettingsRoundTrip(t *testing.T) {
	a := &app{dataDir: t.TempDir()}
	want := userSettings{Configured: true, Workflow: filepath.Join(t.TempDir(), "selected.yaml"), AIEnabled: true}
	if err := a.saveSettings(want); err != nil {
		t.Fatal(err)
	}
	got, err := a.loadSettings()
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("settings = %#v, want %#v", got, want)
	}
}

func TestInstallManagedToolsUsesInstallerAndUpdatesPath(t *testing.T) {
	if os.PathSeparator == '\\' {
		t.Skip("managed installer is a POSIX shell script")
	}
	dir := t.TempDir()
	installer := filepath.Join(dir, "install-tools.sh")
	logPath := filepath.Join(dir, "args.txt")
	script := "#!/bin/sh\nprintf '%s\\n' \"$*\" > \"$CAPHE_INSTALL_LOG\"\n"
	if err := os.WriteFile(installer, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	binDir := filepath.Join(dir, "bin")
	t.Setenv("CAPHE_INSTALLER", installer)
	t.Setenv("CAPHE_INSTALL_LOG", logPath)
	t.Setenv("CAPHE_TOOL_BIN", binDir)
	t.Setenv("PATH", "/usr/bin:/bin")
	a := &app{stderr: os.Stderr}
	if err := a.installManagedTools(context.Background(), []string{"llama.cpp", "gitleaks", "gitleaks"}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	want := "--bin-dir " + binDir + " --tools gitleaks,llama.cpp\n"
	if string(data) != want {
		t.Fatalf("installer args = %q, want %q", data, want)
	}
	if !strings.HasPrefix(os.Getenv("PATH"), binDir+string(os.PathListSeparator)) {
		t.Fatal("managed tool directory was not added to PATH")
	}
}
