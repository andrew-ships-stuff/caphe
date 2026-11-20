package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"

	"github.com/andrew-ships-stuff/caphe/internal/inference"
)

// Budget and order are assigned before starting workers. Results are reduced in
// that same order, independent of completion order and without shared writes.
func reviewFindings(ctx context.Context, bundle *Bundle, ai AIOptions, provider inference.Provider, limit int) int {
	groups, _ := buildRemediation(bundle)
	indices := map[string]int{}
	for i, rec := range bundle.Recommendations {
		indices[rec.FindingID] = i
	}
	var jobs []int
	for depth := 0; len(jobs) < limit; depth++ {
		added := false
		for _, group := range groups {
			if depth < len(group.FindingIDs) && len(jobs) < limit {
				jobs = append(jobs, indices[group.FindingIDs[depth]])
				added = true
			}
		}
		if !added {
			break
		}
	}
	type outcome struct {
		promptTokens, completionTokens int
		rec                            Recommendation
		err                            error
	}
	outcomes := make([]outcome, len(jobs))
	queue := make(chan int)
	var wg sync.WaitGroup
	for worker := 0; worker < min(max(1, ai.Parallel), len(jobs)); worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for slot := range queue {
				index := jobs[slot]
				finding := findingFor(bundle.Findings, bundle.Recommendations[index].FindingID)
				if finding == nil {
					continue
				}
				brief := map[string]any{"id": finding.ID, "tool": finding.Tool, "rule": finding.RuleID, "title": clip(finding.Title, 500), "location": finding.Location, "severity": finding.Severity, "description": clip(finding.Description, 1000), "evidence": compactEvidence(*finding)}
				data, _ := json.Marshal(map[string]any{"finding": brief, "allowedEvidenceIds": []string{finding.ID}})
				generated, err := provider.GenerateStructured(ctx, inference.Request{Model: ai.Model, SystemPrompt: inference.ReviewSystemPrompt, UntrustedContext: string(data), Schema: json.RawMessage(inference.ReviewJSONSchema), MaxInputTokens: ai.MaxInputTokens, MaxOutputTokens: ai.MaxOutputTokens, PromptVersion: inference.ReviewPromptVersion, SchemaVersion: inference.ReviewSchemaVersion})
				outcomes[slot].promptTokens = generated.PromptTokens
				outcomes[slot].completionTokens = generated.CompletionTokens
				if err != nil {
					outcomes[slot].err = err
					continue
				}
				validated, err := inference.ValidateReviewRecommendation(generated.Output, finding.ID, map[string]bool{finding.ID: true})
				if err != nil {
					outcomes[slot].err = err
					continue
				}
				outcomes[slot].rec = Recommendation{FindingID: finding.ID, EvidenceIDs: validated.EvidenceIDs, Explanation: validated.Explanation, Remediation: validated.Remediation, Source: "ai", Status: "hypothesis", ModelDigest: ai.ModelDigest, PromptVersion: inference.ReviewPromptVersion, SchemaVersion: inference.ReviewSchemaVersion}
			}
		}()
	}
	for slot := range jobs {
		queue <- slot
	}
	close(queue)
	wg.Wait()
	reviewed := 0
	bundle.AI.Calls += len(jobs)
	for slot, result := range outcomes {
		bundle.AI.PromptTokens += result.promptTokens
		bundle.AI.CompletionTokens += result.completionTokens
		if result.err != nil {
			bundle.AI.Errors = append(bundle.AI.Errors, fmt.Sprintf("%s: %v", bundle.Recommendations[jobs[slot]].FindingID, result.err))
			continue
		}
		if result.rec.Source == "ai" {
			bundle.Recommendations[jobs[slot]] = result.rec
			reviewed++
		}
	}
	return reviewed
}

func clip(value string, limit int) string {
	runes := []rune(value)
	if len(runes) > limit {
		return string(runes[:limit]) + "…"
	}
	return value
}
