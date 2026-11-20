package cli

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/andrew-ships-stuff/caphe/internal/compiler"
	"github.com/andrew-ships-stuff/caphe/internal/inference"
	"github.com/andrew-ships-stuff/caphe/internal/workflow"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

type userSettings struct {
	Configured bool   `json:"configured"`
	Workflow   string `json:"workflow,omitempty"`
	AIEnabled  bool   `json:"aiEnabled"`
}

type setupScanner struct {
	Name string
	ID   string
	Uses string
}

var setupScanners = []setupScanner{
	{Name: "Opengrep SAST", ID: "opengrep", Uses: "scanner.opengrep"},
	{Name: "Syft SBOM", ID: "syft", Uses: "scanner.syft"},
	{Name: "Grype dependencies (includes Syft)", ID: "grype", Uses: "scanner.grype"},
	{Name: "Gitleaks secrets", ID: "gitleaks", Uses: "scanner.gitleaks"},
	{Name: "Poutine GitHub Actions", ID: "poutine", Uses: "scanner.poutine"},
}

func (a *app) setupCmd() *cobra.Command {
	var selectedFlag string
	var aiFlag bool
	var installFlag bool
	var nonInteractive bool
	command := &cobra.Command{Use: "setup", Short: "Interactively choose scanners and bounded CPU inference", RunE: func(cmd *cobra.Command, _ []string) error {
		selected := selectedFlag
		aiEnabled := aiFlag
		install := installFlag
		if a.jsonOutput {
			nonInteractive = true
		}
		if !nonInteractive {
			reader := bufio.NewReader(cmd.InOrStdin())
			fmt.Fprintln(a.stdout, "Caphe setup\n\nChoose the scanners in your default audit workflow:")
			availability := map[string]bool{}
			for _, tool := range a.detectTools(cmd.Context()) {
				availability[tool.ID] = tool.Available
			}
			for i, scanner := range setupScanners {
				state := "not installed"
				if availability[scanner.Uses] {
					state = "available"
				}
				fmt.Fprintf(a.stdout, "  %d. %-34s %s\n", i+1, scanner.Name, state)
			}
			fmt.Fprint(a.stdout, "\nSelection [all]: ")
			line, err := reader.ReadString('\n')
			if err != nil && !errors.Is(err, io.EOF) {
				return err
			}
			selected = strings.TrimSpace(line)
			if selected == "" {
				selected = "all"
			}
			fmt.Fprint(a.stdout, "Enable bounded CPU inference by default? [Y/n]: ")
			line, err = reader.ReadString('\n')
			if err != nil && !errors.Is(err, io.EOF) {
				return err
			}
			answer := strings.ToLower(strings.TrimSpace(line))
			aiEnabled = answer == "" || answer == "y" || answer == "yes"
			if !cmd.Flags().Changed("install") {
				fmt.Fprint(a.stdout, "Install missing selected tools now? [Y/n]: ")
				line, err = reader.ReadString('\n')
				if err != nil && !errors.Is(err, io.EOF) {
					return err
				}
				answer = strings.ToLower(strings.TrimSpace(line))
				install = answer == "" || answer == "y" || answer == "yes"
			}
		}
		ids, err := parseSetupSelection(selected)
		if err != nil {
			return err
		}
		definition := selectedWorkflow(ids)
		if _, err := compiler.New(a.registry).Compile(definition); err != nil {
			return fmt.Errorf("compile selected workflow: %w", err)
		}
		store, err := a.initState()
		if err != nil {
			return err
		}
		if err := store.Close(); err != nil {
			return err
		}
		if install {
			requested := a.missingSetupManagedTools(cmd, ids, aiEnabled)
			if len(requested) > 0 && !a.jsonOutput {
				fmt.Fprintf(a.stdout, "\nInstalling checksum-verified tools: %s\n", strings.Join(requested, ", "))
			}
			if err := a.installManagedTools(cmd.Context(), requested); err != nil {
				return err
			}
			if aiEnabled {
				if _, err := inference.EnsureModel(cmd.Context(), filepath.Join(a.dataDir, "models"), dogfoodModelURL, dogfoodModelDigest); err != nil {
					return err
				}
			}
		}
		workflowDir := filepath.Join(a.dataDir, "workflows")
		if err := os.MkdirAll(workflowDir, 0o700); err != nil {
			return err
		}
		workflowPath := filepath.Join(workflowDir, "selected.yaml")
		workflowPath, err = filepath.Abs(workflowPath)
		if err != nil {
			return err
		}
		data, err := yaml.Marshal(definition)
		if err != nil {
			return err
		}
		if err := os.WriteFile(workflowPath, data, 0o600); err != nil {
			return err
		}
		settings := userSettings{Configured: true, Workflow: workflowPath, AIEnabled: aiEnabled}
		if err := a.saveSettings(settings); err != nil {
			return err
		}
		return a.printSetupResult(cmd, ids, settings)
	}}
	command.Flags().StringVar(&selectedFlag, "tools", "all", "comma-separated scanner names or numbers")
	command.Flags().BoolVar(&aiFlag, "ai", true, "enable bounded CPU inference by default")
	command.Flags().BoolVar(&installFlag, "install", false, "install missing selected checksum-pinned tools")
	command.Flags().BoolVar(&nonInteractive, "non-interactive", false, "save flag selections without prompting")
	return command
}

func (a *app) missingSetupManagedTools(cmd *cobra.Command, ids []string, aiEnabled bool) []string {
	selected := map[string]bool{}
	for _, id := range ids {
		selected[id] = true
	}
	missing := []string{}
	for _, tool := range a.detectTools(cmd.Context()) {
		id := strings.TrimPrefix(tool.ID, "scanner.")
		if selected[id] && !tool.Available {
			if managed := managedScannerTools[tool.ID]; managed != "" {
				missing = append(missing, managed)
			}
		}
	}
	if aiEnabled {
		if _, err := inference.ResolveLlamaServer(""); err != nil {
			missing = append(missing, "llama.cpp")
		}
	}
	sort.Strings(missing)
	return missing
}

func parseSetupSelection(value string) ([]string, error) {
	value = strings.TrimSpace(strings.ToLower(value))
	if value == "none" {
		return nil, nil
	}
	if value == "" || value == "all" {
		ids := make([]string, 0, len(setupScanners))
		for _, scanner := range setupScanners {
			ids = append(ids, scanner.ID)
		}
		return ids, nil
	}
	known := map[string]string{}
	for i, scanner := range setupScanners {
		known[scanner.ID] = scanner.ID
		known[strconv.Itoa(i+1)] = scanner.ID
	}
	seen := map[string]bool{}
	var ids []string
	for _, entry := range strings.Split(value, ",") {
		key := strings.TrimSpace(entry)
		id := known[key]
		if id == "" {
			return nil, fmt.Errorf("unknown scanner selection %q", key)
		}
		if !seen[id] {
			seen[id] = true
			ids = append(ids, id)
		}
	}
	if seen["grype"] && !seen["syft"] {
		ids = append(ids, "syft")
	}
	return ids, nil
}

func selectedWorkflow(ids []string) *workflow.Workflow {
	selected := map[string]bool{}
	for _, id := range ids {
		selected[id] = true
	}
	tasks := []workflow.Task{}
	normalizeNeeds := []string{}
	if selected["opengrep"] {
		tasks = append(tasks, workflow.Task{ID: "sast", Uses: "scanner.opengrep", Optional: true, With: map[string]any{"ruleset": "p/security-audit"}})
		normalizeNeeds = append(normalizeNeeds, "sast")
	}
	if selected["syft"] {
		tasks = append(tasks, workflow.Task{ID: "sbom", Uses: "scanner.syft", Optional: true, With: map[string]any{"outputFormat": "cyclonedx-json"}})
	}
	if selected["grype"] {
		tasks = append(tasks, workflow.Task{ID: "dependencies", Uses: "scanner.grype", Needs: []string{"sbom"}, Optional: true, With: map[string]any{"input": "${tasks.sbom.outputs.sbom}"}})
		normalizeNeeds = append(normalizeNeeds, "dependencies")
	}
	if selected["gitleaks"] {
		tasks = append(tasks, workflow.Task{ID: "secrets", Uses: "scanner.gitleaks", Optional: true})
		normalizeNeeds = append(normalizeNeeds, "secrets")
	}
	if selected["poutine"] {
		tasks = append(tasks, workflow.Task{ID: "git-workflows", Uses: "scanner.poutine", Optional: true})
		normalizeNeeds = append(normalizeNeeds, "git-workflows")
	}
	tasks = append(tasks, workflow.Task{ID: "normalize", Uses: "core.normalize", Needs: normalizeNeeds, OptionalNeeds: normalizeNeeds}, workflow.Task{ID: "correlate", Uses: "core.correlate", Needs: []string{"normalize"}})
	return &workflow.Workflow{APIVersion: workflow.APIVersion, Kind: "SecurityWorkflow", Metadata: workflow.Metadata{Name: "selected-local-audit", Version: "1.0.0"}, Spec: workflow.Spec{Target: workflow.Target{Type: "repository"}, Policies: workflow.Policy{Network: "restricted"}, Defaults: workflow.RuntimePolicy{TimeoutSeconds: 300}, Tasks: tasks}}
}

func (a *app) settingsPath() string { return filepath.Join(a.dataDir, "settings.json") }

func (a *app) loadSettings() (userSettings, error) {
	data, err := os.ReadFile(a.settingsPath())
	if errors.Is(err, os.ErrNotExist) {
		return userSettings{}, nil
	}
	if err != nil {
		return userSettings{}, err
	}
	var settings userSettings
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&settings); err != nil {
		return userSettings{}, fmt.Errorf("read Caphe settings: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return userSettings{}, fmt.Errorf("read Caphe settings: trailing JSON content")
	}
	return settings, nil
}

func (a *app) saveSettings(settings userSettings) error {
	if err := os.MkdirAll(a.dataDir, 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(settings, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(a.settingsPath(), append(data, '\n'), 0o600)
}

func (a *app) printSetupResult(cmd *cobra.Command, ids []string, settings userSettings) error {
	missing := []string{}
	missingExternal := []string{}
	selected := map[string]bool{}
	for _, id := range ids {
		selected[id] = true
	}
	for _, tool := range a.detectTools(cmd.Context()) {
		id := strings.TrimPrefix(tool.ID, "scanner.")
		if selected[id] && !tool.Available {
			if managed := managedScannerTools[tool.ID]; managed != "" {
				missing = append(missing, managed)
			} else {
				missingExternal = append(missingExternal, id)
			}
		}
	}
	sort.Strings(missing)
	if a.jsonOutput {
		return a.print(map[string]any{"configured": true, "workflow": settings.Workflow, "tools": ids, "aiEnabled": settings.AIEnabled, "missingManagedTools": missing, "missingExternalTools": missingExternal})
	}
	fmt.Fprintf(a.stdout, "\n✓ Saved default workflow to %s\n", settings.Workflow)
	fmt.Fprintf(a.stdout, "✓ Bounded CPU inference default: %s\n", map[bool]string{true: "enabled", false: "disabled"}[settings.AIEnabled])
	if len(missing) > 0 {
		fmt.Fprintln(a.stdout, "\nInstall selected missing scanners:")
		for _, tool := range missing {
			fmt.Fprintf(a.stdout, "  %s\n", managedScannerFix(tool))
		}
	}
	if len(missingExternal) > 0 {
		fmt.Fprintf(a.stdout, "\nRun caphe doctor for installation guidance for: %s\n", strings.Join(missingExternal, ", "))
	}
	if settings.AIEnabled {
		if _, err := inference.ResolveLlamaServer(""); err == nil {
			fmt.Fprintln(a.stdout, "\n✓ Local CPU runtime available; audit manages its lifecycle automatically")
		} else {
			fmt.Fprintln(a.stdout, "\nInstall the pinned CPU runtime with make tools-install TOOLS=llama.cpp, or build the bundled binary with make build-release")
		}
	}
	fmt.Fprintln(a.stdout, "\nRun: caphe audit .")
	return nil
}
