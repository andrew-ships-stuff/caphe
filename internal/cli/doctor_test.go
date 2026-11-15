package cli

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/andrew-ships-stuff/caphe/internal/adapters"
)

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

func suggestionText(suggestions []doctorSuggestion) string {
	var builder strings.Builder
	for _, suggestion := range suggestions {
		builder.WriteString(suggestion.Title)
		builder.WriteString(suggestion.Reason)
		builder.WriteString(strings.Join(suggestion.Commands, "\n"))
	}
	return builder.String()
}
