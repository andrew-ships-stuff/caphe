package audit

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/andrew-ships-stuff/caphe/internal/findings"
	"github.com/andrew-ships-stuff/caphe/internal/inference"
)

func TestRealCPUConcurrentAudit(t *testing.T) {
	if os.Getenv("CAPHE_TEST_LLAMA") != "1" {
		t.Skip("opt-in real CPU model validation")
	}
	cache := os.Getenv("CAPHE_TEST_MODEL_CACHE")
	if cache == "" {
		cache = t.TempDir()
	}
	bundle := Bundle{Metrics: Metrics{BySeverity: map[string]int{"high": 2}, ByTool: map[string]int{"scanner.gitleaks": 2}}, Findings: []findings.Finding{
		{ID: "f1", Tool: "scanner.gitleaks", RuleID: "generic-api-key", Title: "API key in current source file", Severity: findings.SeverityHigh, Location: findings.Location{Path: "config.go", StartLine: 4}},
		{ID: "f2", Tool: "scanner.gitleaks", RuleID: "private-key", Title: "Private key in current source file", Severity: findings.SeverityHigh, Location: findings.Location{Path: "credentials.pem", StartLine: 1}},
	}, Recommendations: []Recommendation{{FindingID: "f1", Source: "deterministic"}, {FindingID: "f2", Source: "deterministic"}}}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Minute)
	defer cancel()
	start := time.Now()
	err := attachAI(ctx, &bundle, Options{DataDir: t.TempDir(), AI: AIOptions{Enabled: true, Serve: true, Model: inference.DefaultModel, ModelURL: inference.DefaultModelURL, ModelDigest: inference.DefaultModelDigest, ModelCache: cache, Threads: 4, Parallel: 2, MaxCalls: 4, MaxInputTokens: 4096, MaxOutputTokens: 512, MaxTotalTime: 8 * time.Minute}})
	if err != nil {
		t.Fatal(err)
	}
	if len(bundle.AI.Errors) > 0 || bundle.AI.ReviewedFindings != 2 || bundle.Synthesis == nil || bundle.Synthesis.Status != "hypothesis" || bundle.AI.DedupGroupsReviewed != 2 {
		t.Fatalf("incomplete real inference: %+v synthesis=%+v", bundle.AI, bundle.Synthesis)
	}
	t.Logf("real CPU audit: %d calls, %d reviewed, %d dedup groups, elapsed %s", bundle.AI.Calls, bundle.AI.ReviewedFindings, bundle.AI.DedupGroupsReviewed, time.Since(start))
}
