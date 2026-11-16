package cli

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"sort"
	"strings"

	"github.com/andrew-ships-stuff/caphe/internal/adapters"
)

const (
	dogfoodModelName   = "Qwen2.5-1.5B-Instruct-Q4_K_M.gguf"
	dogfoodModelURL    = "https://huggingface.co/bartowski/Qwen2.5-1.5B-Instruct-GGUF/resolve/main/Qwen2.5-1.5B-Instruct-Q4_K_M.gguf"
	dogfoodModelDigest = "sha256:1adf0b11065d8ad2e8123ea110d1ec956dab4ab038eab665614adba04b6c3370"
)

var managedScannerTools = map[string]string{
	"scanner.gitleaks": "gitleaks",
	"scanner.grype":    "grype",
	"scanner.poutine":  "poutine",
	"scanner.syft":     "syft",
}

func doctorSuggestions(tools []adapters.ToolInfo, inferenceStatus inferenceReport) []doctorSuggestion {
	missingManaged := []string{}
	missingExternal := []string{}
	for _, tool := range tools {
		if tool.Available {
			continue
		}
		if name := managedScannerTools[tool.ID]; name != "" {
			missingManaged = append(missingManaged, name)
			continue
		}
		missingExternal = append(missingExternal, strings.TrimPrefix(tool.ID, "scanner."))
	}
	if !inferenceStatus.RuntimeAvailable {
		missingManaged = append(missingManaged, "llama.cpp")
	}
	sort.Strings(missingManaged)
	sort.Strings(missingExternal)

	suggestions := []doctorSuggestion{}
	if len(missingManaged) > 0 {
		suggestions = append(suggestions, doctorSuggestion{
			Title:     "Install the missing checksum-pinned managed tools",
			Reason:    "--fix writes only to Caphe's cache and uses the reviewed versions and SHA-256 pins in this checkout.",
			Commands:  []string{"caphe doctor --fix", fmt.Sprintf("export PATH=\"%s:$PATH\"", managedToolBin())},
			Automatic: true,
		})
	}
	if len(missingExternal) > 0 {
		commands := externalInstallCommands(missingExternal)
		if len(commands) > 0 {
			suggestions = append(suggestions, doctorSuggestion{Title: "Install optional scanners not managed by Caphe", Reason: "Install only the adapters your workflows use, then rerun caphe doctor.", Commands: commands})
		}
	}
	suggestions = append(suggestions, doctorSuggestion{
		Title:  "Run the repository's first deterministic audit",
		Reason: "Missing optional scanners are recorded as skipped; available scanners still produce a complete digest-pinned bundle.",
		Commands: []string{
			"caphe audit .",
			"caphe findings list",
			reportOpenCommand(),
		},
	})
	if inferenceStatus.RuntimeAvailable || contains(missingManaged, "llama.cpp") {
		suggestions = append(suggestions, doctorSuggestion{
			Title:    "Optionally add one bounded local AI pass",
			Reason:   "Caphe downloads the digest-verified model, launches llama-server on an ephemeral loopback port, labels output as hypothesis, and stops the process afterward.",
			Commands: []string{fmt.Sprintf("caphe audit . --ai --ai-serve --ai-model %s --ai-model-url %s --ai-model-digest %s", shellQuote(dogfoodModelName), shellQuote(dogfoodModelURL), shellQuote(dogfoodModelDigest))},
		})
	}
	return suggestions
}

func externalInstallCommands(missing []string) []string {
	if runtime.GOOS == "darwin" {
		brew := []string{}
		for _, name := range missing {
			switch name {
			case "checkov", "kubescape", "opa", "osv":
				if name == "osv" {
					name = "osv-scanner"
				}
				brew = append(brew, name)
			}
		}
		commands := []string{}
		if len(brew) > 0 {
			commands = append(commands, "brew install "+strings.Join(brew, " "))
		}
		if contains(missing, "opengrep") {
			commands = append(commands, "open https://github.com/opengrep/opengrep/releases")
		}
		return commands
	}
	commands := []string{}
	for _, name := range missing {
		commands = append(commands, fmt.Sprintf("# Install %s from its upstream pinned release, then add it to PATH", name))
	}
	return commands
}

func (a *app) applyDoctorFixes(ctx context.Context, tools []adapters.ToolInfo, runtimeAvailable bool) error {
	requested := []string{}
	for _, tool := range tools {
		if !tool.Available {
			if managed := managedScannerTools[tool.ID]; managed != "" {
				requested = append(requested, managed)
			}
		}
	}
	if !runtimeAvailable {
		requested = append(requested, "llama.cpp")
	}
	if len(requested) == 0 {
		return nil
	}
	return a.installManagedTools(ctx, requested)
}

func (a *app) installManagedTools(ctx context.Context, requested []string) error {
	if len(requested) == 0 {
		return nil
	}
	sort.Strings(requested)
	requested = slices.Compact(requested)
	installer, err := findManagedInstaller()
	if err != nil {
		return err
	}
	binDir := managedToolBin()
	command := exec.CommandContext(ctx, "bash", installer, "--bin-dir", binDir, "--tools", strings.Join(requested, ","))
	command.Stdout = a.stderr
	command.Stderr = a.stderr
	if err := command.Run(); err != nil {
		return fmt.Errorf("install managed tools: %w", err)
	}
	path := os.Getenv("PATH")
	if !pathContains(path, binDir) {
		if err := os.Setenv("PATH", binDir+string(os.PathListSeparator)+path); err != nil {
			return err
		}
	}
	return nil
}

func findManagedInstaller() (string, error) {
	if override := strings.TrimSpace(os.Getenv("CAPHE_INSTALLER")); override != "" {
		if info, err := os.Stat(override); err == nil && !info.IsDir() {
			return override, nil
		}
		return "", fmt.Errorf("CAPHE_INSTALLER does not point to a file: %s", override)
	}
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		candidate := filepath.Join(dir, "scripts", "install-tools.sh")
		module := filepath.Join(dir, "go.mod")
		if fileContains(module, "module github.com/andrew-ships-stuff/caphe") {
			if info, statErr := os.Stat(candidate); statErr == nil && !info.IsDir() {
				return candidate, nil
			}
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	if executable, executableErr := os.Executable(); executableErr == nil {
		for _, candidate := range []string{
			filepath.Join(filepath.Dir(executable), "..", "libexec", "install-tools.sh"),
			filepath.Join(filepath.Dir(executable), "..", "libexec", "caphe", "install-tools.sh"),
		} {
			if info, statErr := os.Stat(candidate); statErr == nil && !info.IsDir() {
				return filepath.Clean(candidate), nil
			}
		}
	}
	return "", fmt.Errorf("managed installer not found; reinstall Caphe or run from a Caphe source checkout")
}

func fileContains(path, wanted string) bool {
	file, err := os.Open(path)
	if err != nil {
		return false
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		if strings.TrimSpace(scanner.Text()) == wanted {
			return true
		}
	}
	return false
}

func managedToolBin() string {
	if value := strings.TrimSpace(os.Getenv("CAPHE_TOOL_BIN")); value != "" {
		return value
	}
	cache := strings.TrimSpace(os.Getenv("XDG_CACHE_HOME"))
	if cache == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			home = os.TempDir()
		}
		cache = filepath.Join(home, ".cache")
	}
	return filepath.Join(cache, "caphe", "bin")
}

func reportOpenCommand() string {
	switch runtime.GOOS {
	case "darwin":
		return "open caphe-audit.html"
	case "windows":
		return "start caphe-audit.html"
	default:
		return "xdg-open caphe-audit.html"
	}
}

func contains(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func pathContains(path, wanted string) bool {
	wanted = filepath.Clean(wanted)
	for _, value := range filepath.SplitList(path) {
		if filepath.Clean(value) == wanted {
			return true
		}
	}
	return false
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'"
}
