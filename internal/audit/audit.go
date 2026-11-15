// Package audit implements Caphe's hero flow: aggregate every available
// scanner over a repository, normalize and correlate the evidence, optionally
// annotate findings and synthesize a repository posture with a budgeted local
// LLM, and emit one ingestable bundle.
package audit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"time"

	"github.com/andrew-ships-stuff/caphe/internal/adapters"
	"github.com/andrew-ships-stuff/caphe/internal/artifacts"
	"github.com/andrew-ships-stuff/caphe/internal/compiler"
	"github.com/andrew-ships-stuff/caphe/internal/findings"
	"github.com/andrew-ships-stuff/caphe/internal/inference"
	"github.com/andrew-ships-stuff/caphe/internal/source"
	"github.com/andrew-ships-stuff/caphe/internal/storage"

	"github.com/andrew-ships-stuff/caphe/internal/workflow"

	capheruntime "github.com/andrew-ships-stuff/caphe/internal/runtime"
)

const SchemaVersion = "caphe.dev/audit/bundle/v1alpha1"

type AIOptions struct {
	Enabled         bool
	Serve           bool
	Endpoint        string
	Model           string
	ModelDigest     string
	ModelURL        string
	LlamaServer     string
	Threads         int
	MaxCalls        int
	MaxInputTokens  int
	MaxOutputTokens int
	MaxTotalTime    time.Duration
}

type Options struct {
	Target       string
	Workflow     string
	DataDir      string
	Concurrency  int
	CapheVersion string
	Registry     *adapters.Registry
	Plan         *compiler.Plan
	SourceLimits source.Limits
	AI           AIOptions
}

type Recommendation struct {
	FindingID     string   `json:"findingId"`
	EvidenceIDs   []string `json:"evidenceIds"`
	Explanation   string   `json:"explanation"`
	Remediation   string   `json:"remediation"`
	Source        string   `json:"source"`
	Status        string   `json:"status"`
	ModelDigest   string   `json:"modelDigest,omitempty"`
	PromptVersion string   `json:"promptVersion,omitempty"`
	SchemaVersion string   `json:"schemaVersion,omitempty"`
}

type Synthesis struct {
	RiskSummary   string     `json:"riskSummary"`
	Priorities    []Priority `json:"priorities"`
	ModelDigest   string     `json:"modelDigest,omitempty"`
	PromptVersion string     `json:"promptVersion,omitempty"`
	SchemaVersion string     `json:"schemaVersion,omitempty"`
}

type Priority struct {
	Title       string   `json:"title"`
	Rationale   string   `json:"rationale"`
	EvidenceIDs []string `json:"evidenceIds"`
	Rank        int      `json:"rank"`
}

type DedupSuggestion struct {
	GroupID       string `json:"groupId"`
	DuplicateOf   string `json:"duplicateOf"`
	Rationale     string `json:"rationale"`
	Source        string `json:"source"`
	Status        string `json:"status"`
	ModelDigest   string `json:"modelDigest,omitempty"`
	PromptVersion string `json:"promptVersion,omitempty"`
	SchemaVersion string `json:"schemaVersion,omitempty"`
}

type Metrics struct {
	Findings   int            `json:"findings"`
	BySeverity map[string]int `json:"bySeverity"`
	ByTool     map[string]int `json:"byTool"`
	ModelCalls int            `json:"modelCalls"`
}

type AIInfo struct {
	Enabled     bool     `json:"enabled"`
	Model       string   `json:"model,omitempty"`
	ModelDigest string   `json:"modelDigest,omitempty"`
	Endpoint    string   `json:"endpoint,omitempty"`
	Calls       int      `json:"calls"`
	Errors      []string `json:"errors,omitempty"`
}

type Bundle struct {
	SchemaVersion   string                    `json:"schemaVersion"`
	GeneratedAt     time.Time                 `json:"generatedAt"`
	CapheVersion    string                    `json:"capheVersion"`
	Target          string                    `json:"target"`
	Workflow        string                    `json:"workflow"`
	WorkflowDigest  string                    `json:"workflowDigest"`
	ExecutionID     string                    `json:"executionId"`
	Status          string                    `json:"status"`
	Tasks           []capheruntime.TaskResult `json:"tasks"`
	Metrics         Metrics                   `json:"metrics"`
	Findings        []findings.Finding        `json:"findings"`
	Recommendations []Recommendation          `json:"recommendations,omitempty"`
	Dedup           []DedupSuggestion         `json:"dedup,omitempty"`
	Synthesis       *Synthesis                `json:"synthesis,omitempty"`
	AI              AIInfo                    `json:"ai"`
	Digest          string                    `json:"digest"`
}

var severityRank = map[findings.Severity]int{findings.SeverityCritical: 5, findings.SeverityHigh: 4, findings.SeverityMedium: 3, findings.SeverityLow: 2, findings.SeverityInfo: 1, findings.SeverityUnknown: 0}

// Run executes the aggregate workflow and produces the bundle. Missing
// optional scanners degrade to skipped tasks rather than failures.
func Run(ctx context.Context, options Options) (Bundle, error) {
	if options.Target == "" {
		options.Target = "."
	}
	if options.Workflow == "" {
		options.Workflow = "caphe:default"
	}
	if options.Registry == nil {
		options.Registry = adapters.DefaultRegistry()
	}
	if options.Concurrency <= 0 {
		options.Concurrency = runtime.NumCPU()
	}
	if options.DataDir == "" {
		return Bundle{}, fmt.Errorf("data directory is required")
	}
	if err := validateAIOptions(options.AI); err != nil {
		return Bundle{}, err
	}
	prepared, err := source.PrepareWithLimits(options.Target, options.SourceLimits)
	if err != nil {
		return Bundle{}, err
	}
	defer prepared.Cleanup()
	plan := options.Plan
	if plan == nil {
		workflowDefinition, err := workflow.Load(options.Workflow)
		if err != nil {
			return Bundle{}, err
		}
		plan, err = compiler.New(options.Registry).Compile(workflowDefinition)
		if err != nil {
			return Bundle{}, err
		}
	} else if err := compiler.ValidateLock(plan, options.Registry); err != nil {
		return Bundle{}, fmt.Errorf("validate workflow lock: %w", err)
	}
	if err := os.MkdirAll(filepath.Join(options.DataDir, "artifacts"), 0o700); err != nil {
		return Bundle{}, err
	}
	store, err := storage.Open(filepath.Join(options.DataDir, "caphe.db"))
	if err != nil {
		return Bundle{}, err
	}
	defer store.Close()
	executor := capheruntime.New(options.Registry, artifacts.New(filepath.Join(options.DataDir, "artifacts")), store, options.Concurrency)
	manifest, runErr := executor.Run(ctx, plan, prepared.Path)
	if runErr != nil {
		return Bundle{}, fmt.Errorf("workflow execution failed: %w", runErr)
	}
	items, err := store.ListFindingsForExecution(ctx, manifest.ExecutionID)
	if err != nil {
		return Bundle{}, err
	}
	bundle := Bundle{SchemaVersion: SchemaVersion, GeneratedAt: time.Now().UTC(), CapheVersion: options.CapheVersion, Target: options.Target, Workflow: options.Workflow, WorkflowDigest: manifest.WorkflowDigest, ExecutionID: manifest.ExecutionID, Status: manifest.Status, Tasks: manifest.Tasks, Findings: items, Metrics: Metrics{BySeverity: map[string]int{}, ByTool: map[string]int{}}}
	for _, item := range items {
		bundle.Metrics.Findings++
		bundle.Metrics.BySeverity[string(item.Severity)]++
		bundle.Metrics.ByTool[item.Tool]++
	}
	// Deterministic ingest order: worst first, then stable by identity.
	sort.SliceStable(bundle.Findings, func(i, j int) bool {
		left, right := bundle.Findings[i], bundle.Findings[j]
		if severityRank[left.Severity] != severityRank[right.Severity] {
			return severityRank[left.Severity] > severityRank[right.Severity]
		}
		return left.ID < right.ID
	})
	for _, finding := range bundle.Findings {
		bundle.Recommendations = append(bundle.Recommendations, Recommendation{FindingID: finding.ID, EvidenceIDs: []string{finding.ID}, Explanation: fmt.Sprintf("%s reported %s%s.", finding.Tool, finding.RuleID, locationSuffix(finding)), Remediation: "Review the cited scanner evidence and apply the narrowest change that removes the reported condition; rerun caphe audit to verify.", Source: "deterministic", Status: "evidence-backed-recommendation"})
	}
	if options.AI.Enabled {
		if err := attachAI(ctx, &bundle, options); err != nil {
			return Bundle{}, err
		}
	}
	if err := setDigest(&bundle); err != nil {
		return Bundle{}, err
	}
	return bundle, nil
}

func validateAIOptions(ai AIOptions) error {
	if !ai.Enabled {
		return nil
	}
	if ai.Model == "" || ai.ModelDigest == "" {
		return fmt.Errorf("--ai-model and --ai-model-digest are required with --ai")
	}
	if ai.Serve && ai.ModelURL == "" {
		return fmt.Errorf("--ai-model-url is required with --ai-serve")
	}
	if ai.MaxCalls <= 0 || ai.MaxCalls > 20 || ai.MaxInputTokens <= 0 || ai.MaxInputTokens > 8192 || ai.MaxOutputTokens <= 0 || ai.MaxOutputTokens > 1024 || ai.MaxTotalTime <= 0 || ai.MaxTotalTime > 30*time.Minute {
		return fmt.Errorf("invalid AI budget")
	}
	return nil
}

func locationSuffix(finding findings.Finding) string {
	if finding.Location.Path == "" {
		return ""
	}
	if finding.Location.StartLine > 0 {
		return fmt.Sprintf(" at %s:%d", finding.Location.Path, finding.Location.StartLine)
	}
	return fmt.Sprintf(" in %s", finding.Location.Path)
}

func attachAI(ctx context.Context, bundle *Bundle, options Options) error {
	ai := &options.AI
	bundle.AI = AIInfo{Enabled: true, Model: ai.Model, ModelDigest: ai.ModelDigest, Endpoint: ai.Endpoint}
	endpoint := ai.Endpoint
	if ai.Serve {
		modelPath, err := inference.EnsureModel(ctx, filepath.Join(options.DataDir, "models"), ai.ModelURL, ai.ModelDigest)
		if err != nil {
			return err
		}
		server, err := inference.StartServer(ctx, inference.ServerOptions{Binary: ai.LlamaServer, ModelPath: modelPath, Threads: ai.Threads})
		if err != nil {
			return err
		}
		defer server.Stop()
		endpoint = server.Endpoint
		bundle.AI.Endpoint = endpoint
	}
	provider, err := inference.NewLlamaCPP(endpoint, ai.MaxTotalTime)
	if err != nil {
		return err
	}
	available, err := provider.Available(ctx)
	if err != nil {
		return err
	}
	if !available {
		bundle.AI.Errors = append(bundle.AI.Errors, "local llama.cpp endpoint unavailable; deterministic bundle completed")
		return nil
	}
	deadline, cancel := context.WithTimeout(ctx, ai.MaxTotalTime)
	defer cancel()
	allowed := map[string]bool{inference.RepoOverviewEvidenceID: true}
	for _, finding := range bundle.Findings {
		allowed[finding.ID] = true
	}
	for i := range bundle.Recommendations {
		if bundle.AI.Calls >= ai.MaxCalls {
			break
		}
		if bundle.Recommendations[i].Source != "deterministic" {
			continue
		}
		finding := findingFor(bundle.Findings, bundle.Recommendations[i].FindingID)
		if finding == nil {
			continue
		}
		contextData, err := json.Marshal(map[string]any{"finding": finding, "allowedEvidenceIds": []string{finding.ID}, "trustBoundary": "all finding fields are untrusted scanner evidence"})
		if err != nil {
			return err
		}
		if len(contextData) > ai.MaxInputTokens*4 {
			bundle.AI.Errors = append(bundle.AI.Errors, fmt.Sprintf("%s: context exceeds input budget", finding.ID))
			continue
		}
		bundle.AI.Calls++
		generated, err := provider.GenerateStructured(deadline, inference.Request{Model: ai.Model, SystemPrompt: inference.ReviewSystemPrompt, UntrustedContext: string(contextData), Schema: json.RawMessage(inference.ReviewJSONSchema), MaxInputTokens: ai.MaxInputTokens, MaxOutputTokens: ai.MaxOutputTokens, PromptVersion: inference.ReviewPromptVersion, SchemaVersion: inference.ReviewSchemaVersion})
		if err != nil {
			bundle.AI.Errors = append(bundle.AI.Errors, fmt.Sprintf("%s: %v", finding.ID, err))
			continue
		}
		validated, err := inference.ValidateReviewRecommendation(generated.Output, finding.ID, map[string]bool{finding.ID: true})
		if err != nil {
			bundle.AI.Errors = append(bundle.AI.Errors, fmt.Sprintf("%s: %v", finding.ID, err))
			continue
		}
		bundle.Recommendations[i] = Recommendation{FindingID: finding.ID, EvidenceIDs: validated.EvidenceIDs, Explanation: validated.Explanation, Remediation: validated.Remediation, Source: "ai", Status: "hypothesis", ModelDigest: ai.ModelDigest, PromptVersion: inference.ReviewPromptVersion, SchemaVersion: inference.ReviewSchemaVersion}
	}
	if bundle.AI.Calls < ai.MaxCalls && len(bundle.Findings) > 0 {
		bundle.AI.Calls++
		overview := synthesisContext(bundle)
		if len(overview) > ai.MaxInputTokens*4 {
			bundle.AI.Errors = append(bundle.AI.Errors, "repo overview exceeds input budget")
			bundle.AI.Calls--
		} else {
			generated, err := provider.GenerateStructured(deadline, inference.Request{Model: ai.Model, SystemPrompt: inference.SynthesisSystemPrompt, UntrustedContext: string(overview), Schema: json.RawMessage(inference.SynthesisJSONSchema), MaxInputTokens: ai.MaxInputTokens, MaxOutputTokens: ai.MaxOutputTokens, PromptVersion: inference.SynthesisPromptVersion, SchemaVersion: inference.SynthesisSchemaVersion})
			if err != nil {
				bundle.AI.Errors = append(bundle.AI.Errors, fmt.Sprintf("synthesis: %v", err))
			} else {
				validated, err := inference.ValidateRepoSynthesis(generated.Output, allowed)
				if err != nil {
					bundle.AI.Errors = append(bundle.AI.Errors, fmt.Sprintf("synthesis: %v", err))
				} else {
					synthesis := &Synthesis{RiskSummary: validated.RiskSummary, ModelDigest: ai.ModelDigest, PromptVersion: inference.SynthesisPromptVersion, SchemaVersion: inference.SynthesisSchemaVersion}
					for _, priority := range validated.Priorities {
						synthesis.Priorities = append(synthesis.Priorities, Priority{Title: priority.Title, Rationale: priority.Rationale, EvidenceIDs: priority.EvidenceIDs, Rank: priority.Rank})
					}
					bundle.Synthesis = synthesis
				}
			}
		}
	}
	if bundle.AI.Calls < ai.MaxCalls && len(bundle.Findings) > 0 {
		groups, _ := buildRemediation(bundle)
		if len(groups) >= 2 {
			overview, err := dedupContext(bundle, groups)
			if err != nil {
				bundle.AI.Errors = append(bundle.AI.Errors, fmt.Sprintf("dedup: %v", err))
			} else if len(overview) > ai.MaxInputTokens*4 {
				bundle.AI.Errors = append(bundle.AI.Errors, "dedup: context exceeds input budget")
			} else {
				bundle.AI.Calls++
				generated, err := provider.GenerateStructured(deadline, inference.Request{Model: ai.Model, SystemPrompt: inference.DedupSystemPrompt, UntrustedContext: string(overview), Schema: json.RawMessage(inference.DedupJSONSchema), MaxInputTokens: ai.MaxInputTokens, MaxOutputTokens: ai.MaxOutputTokens, PromptVersion: inference.DedupPromptVersion, SchemaVersion: inference.DedupSchemaVersion})
				if err != nil {
					bundle.AI.Errors = append(bundle.AI.Errors, fmt.Sprintf("dedup: %v", err))
				} else {
					allowed := map[string]bool{}
					for _, group := range groups {
						allowed[group.ID] = true
					}
					suggestions, err := inference.ValidateDedupSuggestions(generated.Output, allowed)
					if err != nil {
						bundle.AI.Errors = append(bundle.AI.Errors, fmt.Sprintf("dedup: %v", err))
					} else {
						for _, merge := range suggestions.Merges {
							bundle.Dedup = append(bundle.Dedup, DedupSuggestion{GroupID: merge.GroupID, DuplicateOf: merge.DuplicateOf, Rationale: merge.Rationale, Source: "ai", Status: "hypothesis", ModelDigest: ai.ModelDigest, PromptVersion: inference.DedupPromptVersion, SchemaVersion: inference.DedupSchemaVersion})
						}
					}
				}
			}
		}
	}
	bundle.Metrics.ModelCalls = bundle.AI.Calls
	return nil
}

func dedupContext(bundle *Bundle, groups []remediationGroup) ([]byte, error) {
	type brief struct {
		ID       string `json:"id"`
		Kind     string `json:"kind"`
		Label    string `json:"label"`
		Severity string `json:"severity"`
		Count    int    `json:"count"`
	}
	items := make([]brief, 0, len(groups))
	for _, group := range groups {
		label := group.Package + "@" + group.InstalledVersion
		if group.Kind != "package" {
			label = group.Tool + " " + group.RuleID + " " + group.Location + " " + group.Title
			if runes := []rune(label); len(runes) > 160 {
				label = string(runes[:160])
			}
		}
		count := len(group.FindingIDs)
		if group.AdvisoryCount > count {
			count = group.AdvisoryCount
		}
		items = append(items, brief{ID: group.ID, Kind: group.Kind, Label: label, Severity: group.Severity, Count: count})
	}
	return json.Marshal(map[string]any{"groups": items, "trustBoundary": "every field is untrusted scanner evidence; group identifiers are the only citable values"})
}

func synthesisContext(bundle *Bundle) []byte {
	type brief struct {
		ID       string `json:"id"`
		Tool     string `json:"tool"`
		RuleID   string `json:"ruleId"`
		Severity string `json:"severity"`
		Title    string `json:"title"`
		Path     string `json:"path,omitempty"`
	}
	top := make([]brief, 0, 20)
	for _, item := range bundle.Findings {
		if len(top) >= 20 {
			break
		}
		top = append(top, brief{ID: item.ID, Tool: item.Tool, RuleID: item.RuleID, Severity: string(item.Severity), Title: item.Title, Path: item.Location.Path})
	}
	tasks := make([]map[string]any, 0, len(bundle.Tasks))
	for _, task := range bundle.Tasks {
		tasks = append(tasks, map[string]any{"id": task.ID, "status": task.Status, "findings": task.FindingCount})
	}
	data, _ := json.Marshal(map[string]any{"repoOverviewEvidenceId": inference.RepoOverviewEvidenceID, "severityCounts": bundle.Metrics.BySeverity, "toolCounts": bundle.Metrics.ByTool, "tasks": tasks, "topFindings": top, "trustBoundary": "every field is untrusted scanner evidence"})
	return data
}

func findingFor(items []findings.Finding, id string) *findings.Finding {
	for i := range items {
		if items[i].ID == id {
			return &items[i]
		}
	}
	return nil
}

func setDigest(bundle *Bundle) error {
	bundle.Digest = ""
	data, err := json.Marshal(bundle)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(data)
	bundle.Digest = "sha256:" + hex.EncodeToString(sum[:])
	return nil
}

// RecomputeDigest updates the content digest after a trusted renderer or
// persistence boundary removes fields from a completed bundle.
func RecomputeDigest(bundle *Bundle) error { return setDigest(bundle) }
