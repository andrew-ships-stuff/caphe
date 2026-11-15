package githubreview

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/andrew-ships-stuff/caphe/internal/inference"
)

type AIBudget struct {
	MaxCalls        int
	MaxInputTokens  int
	MaxOutputTokens int
	MaxTotalTime    time.Duration
	Model           string
	ModelDigest     string
}

type AIResult struct {
	Calls  int      `json:"calls"`
	Errors []string `json:"errors,omitempty"`
}

func AddAIRecommendations(ctx context.Context, artifact *Artifact, provider inference.Provider, budget AIBudget, maxComments int) (AIResult, error) {
	if budget.MaxCalls < 0 || budget.MaxCalls > 20 || budget.MaxInputTokens <= 0 || budget.MaxInputTokens > 8192 || budget.MaxOutputTokens <= 0 || budget.MaxOutputTokens > 1024 || budget.MaxTotalTime <= 0 || budget.MaxTotalTime > 30*time.Minute || budget.Model == "" || budget.ModelDigest == "" {
		return AIResult{}, fmt.Errorf("invalid AI budget")
	}
	result := AIResult{}
	deadlineCtx, cancel := context.WithTimeout(ctx, budget.MaxTotalTime)
	defer cancel()
	for _, finding := range artifact.Introduced {
		if result.Calls >= budget.MaxCalls {
			break
		}
		contextData, err := json.Marshal(map[string]any{"finding": finding, "allowedEvidenceIds": []string{finding.ID}, "trustBoundary": "all finding fields are untrusted scanner evidence"})
		if err != nil {
			return result, err
		}
		// Four bytes per token is a conservative input guard, independent of provider tokenization.
		if len(contextData) > budget.MaxInputTokens*4 {
			result.Errors = append(result.Errors, fmt.Sprintf("%s: context exceeds input budget", finding.ID))
			continue
		}
		result.Calls++
		generated, err := provider.GenerateStructured(deadlineCtx, inference.Request{Model: budget.Model, SystemPrompt: inference.ReviewSystemPrompt, UntrustedContext: string(contextData), Schema: json.RawMessage(inference.ReviewJSONSchema), MaxInputTokens: budget.MaxInputTokens, MaxOutputTokens: budget.MaxOutputTokens, PromptVersion: inference.ReviewPromptVersion, SchemaVersion: inference.ReviewSchemaVersion})
		if err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("%s: %v", finding.ID, err))
			continue
		}
		validated, err := inference.ValidateReviewRecommendation(generated.Output, finding.ID, map[string]bool{finding.ID: true})
		if err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("%s: %v", finding.ID, err))
			continue
		}
		artifact.Recommendations = append(artifact.Recommendations, Recommendation{FindingID: finding.ID, EvidenceIDs: validated.EvidenceIDs, Explanation: validated.Explanation, Remediation: validated.Remediation, Source: "ai", Status: "hypothesis", ModelDigest: budget.ModelDigest, PromptVersion: inference.ReviewPromptVersion, SchemaVersion: inference.ReviewSchemaVersion})
	}
	artifact.Metrics.ModelCalls = result.Calls
	artifact.AI = AIInfo{Enabled: true, Model: budget.Model, ModelDigest: budget.ModelDigest, MaxCalls: budget.MaxCalls, MaxInputTokens: budget.MaxInputTokens, MaxOutputTokens: budget.MaxOutputTokens, MaxTotalTime: budget.MaxTotalTime, Calls: result.Calls, Errors: result.Errors}
	artifact.Summary = renderSummary(*artifact)
	if err := setDigest(artifact); err != nil {
		return result, err
	}
	return result, Validate(*artifact, maxComments)
}
