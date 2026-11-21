package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/andrew-ships-stuff/caphe/internal/adapters"
)

func TestLocalAIStatusReportsDefaultAndSavedPreference(t *testing.T) {
	t.Setenv("CAPHE_LLAMA_SERVER", "/missing-cpu-runtime")
	a := &app{dataDir: t.TempDir()}
	status, err := a.localAIStatus()
	if err != nil || status["enabled"] != true || status["managed"] != true || status["available"] != false {
		t.Fatalf("default status: %v %v", status, err)
	}
	if err := a.saveSettings(userSettings{Configured: true, AIEnabled: false}); err != nil {
		t.Fatal(err)
	}
	status, err = a.localAIStatus()
	if err != nil || status["enabled"] != false {
		t.Fatalf("saved opt-out ignored: %v %v", status, err)
	}
}

func TestDoctorSuggestionsOfferManagedFixAndDayOneAudit(t *testing.T) {
	tools := []adapters.ToolInfo{
		{ID: "scanner.gitleaks", Error: "not found"},
		{ID: "scanner.opengrep", Available: true},
	}
	suggestions := doctorSuggestions(tools, inferenceReport{})
	text := suggestionText(suggestions)
	for _, wanted := range []string{"caphe doctor --fix", "caphe audit .", "caphe findings list", "--ai-serve", dogfoodModelDigest} {
		if !strings.Contains(text, wanted) {
			t.Fatalf("suggestions missing %q: %s", wanted, text)
		}
	}
}

func TestManagedToolBinHonorsOverride(t *testing.T) {
	t.Setenv("CAPHE_TOOL_BIN", "/tmp/caphe-tools")
	if got := managedToolBin(); got != "/tmp/caphe-tools" {
		t.Fatalf("managedToolBin = %q", got)
	}
}

func TestFindManagedInstallerFromRepository(t *testing.T) {
	path, err := findManagedInstaller()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(filepath.ToSlash(path), "scripts/install-tools.sh") {
		t.Fatalf("unexpected installer: %s", path)
	}
}

func TestFindManagedInstallerHonorsOverride(t *testing.T) {
	installer := filepath.Join(t.TempDir(), "install-tools.sh")
	if err := os.WriteFile(installer, []byte("#!/bin/sh\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CAPHE_INSTALLER", installer)
	got, err := findManagedInstaller()
	if err != nil {
		t.Fatal(err)
	}
	if got != installer {
		t.Fatalf("installer = %q, want %q", got, installer)
	}
}

func TestAddManagedToolsToPath(t *testing.T) {
	binDir := t.TempDir()
	t.Setenv("CAPHE_TOOL_BIN", binDir)
	t.Setenv("PATH", "/usr/bin")
	a := &app{}
	a.addManagedToolsToPath()
	if got := os.Getenv("PATH"); !strings.HasSuffix(got, string(os.PathListSeparator)+binDir) {
		t.Fatalf("PATH = %q, want managed directory appended", got)
	}
}

func suggestionText(suggestions []doctorSuggestion) string {
	var builder strings.Builder
	for _, suggestion := range suggestions {
		builder.WriteString(suggestion.Title)
		builder.WriteString(suggestion.Reason)
		builder.WriteString(strings.Join(suggestion.Commands, "\n"))
	}
	return builder.String()
}
