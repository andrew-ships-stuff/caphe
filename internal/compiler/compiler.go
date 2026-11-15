package compiler

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/andrew-ships-stuff/caphe/internal/adapters"
	"github.com/andrew-ships-stuff/caphe/internal/workflow"
)

const Version = "0.1.0"

var idPattern = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,63}$`)
var referencePattern = regexp.MustCompile(`^\$\{tasks\.([a-z][a-z0-9_-]{0,63})\.outputs\.([a-z][a-zA-Z0-9_-]{0,63})\}$`)

type GateResult struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Detail string `json:"detail"`
}

type Plan struct {
	SchemaVersion   string            `json:"schemaVersion"`
	Workflow        workflow.Metadata `json:"workflow"`
	Target          workflow.Target   `json:"target"`
	Policies        workflow.Policy   `json:"policies"`
	Tasks           []PlanTask        `json:"tasks"`
	Gates           []GateResult      `json:"gates"`
	PolicyVersion   string            `json:"policyVersion"`
	CompilerVersion string            `json:"compilerVersion"`
	Digest          string            `json:"digest"`
}

type PlanTask struct {
	ID                  string                 `json:"id"`
	Uses                string                 `json:"uses"`
	AdapterVersion      string                 `json:"adapterVersion"`
	Needs               []string               `json:"needs,omitempty"`
	OptionalNeeds       []string               `json:"optionalNeeds,omitempty"`
	Optional            bool                   `json:"optional,omitempty"`
	With                map[string]any         `json:"with,omitempty"`
	Runtime             workflow.RuntimePolicy `json:"runtime"`
	Resources           workflow.Resources     `json:"resources,omitempty"`
	ExternalToolVersion string                 `json:"externalToolVersion,omitempty"`
	InputSchema         map[string]string      `json:"inputSchema,omitempty"`
	OutputSchema        map[string]string      `json:"outputSchema"`
}

type Compiler struct{ registry *adapters.Registry }

func New(registry *adapters.Registry) *Compiler { return &Compiler{registry: registry} }

func (c *Compiler) Compile(w *workflow.Workflow) (*Plan, error) {
	if err := validateDocument(w); err != nil {
		return nil, fmt.Errorf("syntax gate: %w", err)
	}
	if err := c.validateSecurity(w); err != nil {
		return nil, fmt.Errorf("security gate: %w", err)
	}
	if err := validateDAG(w.Spec.Tasks); err != nil {
		return nil, fmt.Errorf("syntax gate: %w", err)
	}
	if err := validateReferences(w.Spec.Tasks); err != nil {
		return nil, fmt.Errorf("syntax gate: %w", err)
	}
	tasks := make([]PlanTask, 0, len(w.Spec.Tasks))
	for _, t := range w.Spec.Tasks {
		a, _ := c.registry.Get(t.Uses)
		raw, err := workflow.RawConfig(t.With)
		if err != nil {
			return nil, fmt.Errorf("task %q configuration: %w", t.ID, err)
		}
		if err := a.Validate(raw); err != nil {
			return nil, fmt.Errorf("syntax gate: task %q: %w", t.ID, err)
		}
		rp := mergeRuntime(w.Spec.Defaults, t.Runtime)
		if rp.TimeoutSeconds <= 0 {
			rp.TimeoutSeconds = 300
		}
		if rp.TimeoutSeconds > 3600 {
			return nil, fmt.Errorf("security gate: task %q timeout exceeds 3600 seconds", t.ID)
		}
		if rp.Retries < 0 || rp.Retries > 5 {
			return nil, fmt.Errorf("security gate: task %q retries must be between 0 and 5", t.ID)
		}
		if rp.BackoffMillis <= 0 {
			rp.BackoffMillis = 250
		}
		needs := append([]string(nil), t.Needs...)
		sort.Strings(needs)
		opts := append([]string(nil), t.OptionalNeeds...)
		sort.Strings(opts)
		externalVersion := ""
		if strings.HasPrefix(t.Uses, "scanner.") {
			externalVersion = "detected-and-recorded-at-execution"
		}
		inputs, outputs := schemasFor(t.Uses)
		tasks = append(tasks, PlanTask{ID: t.ID, Uses: t.Uses, AdapterVersion: a.Version(), Needs: needs, OptionalNeeds: opts, Optional: t.Optional, With: t.With, Runtime: rp, Resources: t.Resources, ExternalToolVersion: externalVersion, InputSchema: inputs, OutputSchema: outputs})
	}
	sort.Slice(tasks, func(i, j int) bool { return tasks[i].ID < tasks[j].ID })
	p := &Plan{
		SchemaVersion: "caphe.dev/lock/v1alpha1", Workflow: w.Metadata, Target: w.Spec.Target,
		Policies: w.Spec.Policies, Tasks: tasks, PolicyVersion: "builtin-v1", CompilerVersion: Version,
		Gates: []GateResult{
			{Name: "security", Status: "passed", Detail: "allowlist and bounded-operation checks passed"},
			{Name: "syntax", Status: "passed", Detail: "schema, adapter configuration, references, and DAG passed"},
			{Name: "execution", Status: "not_evaluated", Detail: "target-specific execution validation occurs at run time"},
			{Name: "accuracy", Status: "not_evaluated", Detail: "no golden dataset is configured for this workflow"},
		},
	}
	digest, err := Digest(p)
	if err != nil {
		return nil, err
	}
	p.Digest = digest
	return p, nil
}

func Digest(p *Plan) (string, error) {
	copy := *p
	copy.Digest = ""
	b, err := json.Marshal(copy)
	if err != nil {
		return "", err
	}
	s := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(s[:]), nil
}

func ValidateLock(p *Plan, registry *adapters.Registry) error {
	if p.SchemaVersion != "caphe.dev/lock/v1alpha1" {
		return fmt.Errorf("unsupported schemaVersion %q", p.SchemaVersion)
	}
	want, err := Digest(p)
	if err != nil {
		return err
	}
	if p.Digest != want {
		return fmt.Errorf("lock digest mismatch: got %s, computed %s", p.Digest, want)
	}
	ids := map[string]bool{}
	for _, t := range p.Tasks {
		if ids[t.ID] {
			return fmt.Errorf("duplicate task %q", t.ID)
		}
		ids[t.ID] = true
		a, ok := registry.Get(t.Uses)
		if !ok {
			return fmt.Errorf("task %q uses unapproved adapter %q", t.ID, t.Uses)
		}
		if a.Version() != t.AdapterVersion {
			return fmt.Errorf("task %q adapter version mismatch: lock=%s runtime=%s", t.ID, t.AdapterVersion, a.Version())
		}
	}
	return nil
}

func validateDocument(w *workflow.Workflow) error {
	if w.APIVersion != workflow.APIVersion {
		return fmt.Errorf("apiVersion must be %q", workflow.APIVersion)
	}
	if w.Kind != "SecurityWorkflow" {
		return fmt.Errorf("kind must be SecurityWorkflow")
	}
	if !idPattern.MatchString(w.Metadata.Name) {
		return fmt.Errorf("metadata.name must match %s", idPattern)
	}
	if strings.TrimSpace(w.Metadata.Version) == "" {
		return fmt.Errorf("metadata.version is required")
	}
	if w.Spec.Target.Type != "repository" {
		return fmt.Errorf("spec.target.type must be repository")
	}
	if len(w.Spec.Tasks) == 0 {
		return fmt.Errorf("at least one task is required")
	}
	return nil
}

func (c *Compiler) validateSecurity(w *workflow.Workflow) error {
	seen := map[string]bool{}
	for _, t := range w.Spec.Tasks {
		if !idPattern.MatchString(t.ID) {
			return fmt.Errorf("invalid task id %q", t.ID)
		}
		if seen[t.ID] {
			return fmt.Errorf("duplicate task id %q", t.ID)
		}
		seen[t.ID] = true
		if _, ok := c.registry.Get(t.Uses); !ok {
			return fmt.Errorf("task %q uses unapproved adapter %q", t.ID, t.Uses)
		}
		for k, v := range t.With {
			if strings.Contains(strings.ToLower(k), "command") || strings.Contains(strings.ToLower(k), "executable") {
				return fmt.Errorf("task %q contains forbidden configuration key %q", t.ID, k)
			}
			if s, ok := v.(string); ok && (strings.Contains(s, "\x00") || strings.Contains(s, "\n")) {
				return fmt.Errorf("task %q configuration %q contains control characters", t.ID, k)
			}
		}
		if t.Resources.CPUMillis < 0 || t.Resources.MemoryBytes < 0 {
			return fmt.Errorf("task %q has negative resource budget", t.ID)
		}
	}
	return nil
}

func validateDAG(tasks []workflow.Task) error {
	all := map[string]workflow.Task{}
	for _, t := range tasks {
		all[t.ID] = t
	}
	for _, t := range tasks {
		opt := map[string]bool{}
		for _, n := range t.OptionalNeeds {
			opt[n] = true
		}
		for n := range opt {
			found := false
			for _, dep := range t.Needs {
				if dep == n {
					found = true
				}
			}
			if !found {
				return fmt.Errorf("task %q optionalNeed %q must also appear in needs", t.ID, n)
			}
		}
		for _, n := range t.Needs {
			if n == t.ID {
				return fmt.Errorf("task %q depends on itself", t.ID)
			}
			if _, ok := all[n]; !ok {
				return fmt.Errorf("task %q references missing dependency %q", t.ID, n)
			}
		}
	}
	state := map[string]uint8{}
	var visit func(string) error
	visit = func(id string) error {
		if state[id] == 1 {
			return fmt.Errorf("dependency cycle includes %q", id)
		}
		if state[id] == 2 {
			return nil
		}
		state[id] = 1
		for _, n := range all[id].Needs {
			if err := visit(n); err != nil {
				return err
			}
		}
		state[id] = 2
		return nil
	}
	for id := range all {
		if err := visit(id); err != nil {
			return err
		}
	}
	return nil
}

func validateReferences(tasks []workflow.Task) error {
	byID := map[string]workflow.Task{}
	for _, t := range tasks {
		byID[t.ID] = t
	}
	for _, t := range tasks {
		needs := map[string]bool{}
		for _, n := range t.Needs {
			needs[n] = true
		}
		for key, value := range t.With {
			s, ok := value.(string)
			if !ok || !strings.Contains(s, "${tasks.") {
				continue
			}
			m := referencePattern.FindStringSubmatch(s)
			if m == nil {
				return fmt.Errorf("task %q configuration %q has invalid or interpolated task reference", t.ID, key)
			}
			producer, ok := byID[m[1]]
			if !ok {
				return fmt.Errorf("task %q references missing task %q", t.ID, m[1])
			}
			if !needs[m[1]] {
				return fmt.Errorf("task %q references %q without declaring it in needs", t.ID, m[1])
			}
			_, outputs := schemasFor(producer.Uses)
			if _, ok := outputs[m[2]]; !ok {
				return fmt.Errorf("task %q references unknown output %q from %q", t.ID, m[2], m[1])
			}
		}
	}
	return nil
}

func schemasFor(uses string) (map[string]string, map[string]string) {
	inputs := map[string]string{"target": "repository"}
	outputs := map[string]string{"raw": "artifact", "findings": "finding_list"}
	switch uses {
	case "scanner.syft":
		outputs["sbom"] = "cyclonedx_or_syft_json"
	case "scanner.grype":
		inputs["input"] = "sbom_artifact"
	case "core.normalize":
		inputs = map[string]string{"findings": "finding_list"}
		outputs = map[string]string{"normalized": "finding_list"}
	case "core.correlate":
		inputs = map[string]string{"normalized": "finding_list"}
		outputs = map[string]string{"evidence": "evidence_graph"}
	case "core.verify":
		inputs = map[string]string{"evidence": "evidence_graph"}
		outputs = map[string]string{"verification": "verification_result"}
	}
	return inputs, outputs
}

func mergeRuntime(a, b workflow.RuntimePolicy) workflow.RuntimePolicy {
	if b.TimeoutSeconds != 0 {
		a.TimeoutSeconds = b.TimeoutSeconds
	}
	if b.Retries != 0 {
		a.Retries = b.Retries
	}
	if b.BackoffMillis != 0 {
		a.BackoffMillis = b.BackoffMillis
	}
	return a
}
