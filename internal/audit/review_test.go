package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/andrew-ships-stuff/caphe/internal/findings"
	"github.com/andrew-ships-stuff/caphe/internal/inference"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type concurrentReviewer struct {
	active, peak atomic.Int32
	ready        chan struct{}
	once         sync.Once
}

func (*concurrentReviewer) Name() string                            { return "test" }
func (*concurrentReviewer) Available(context.Context) (bool, error) { return true, nil }
func (*concurrentReviewer) Capabilities(context.Context) (inference.Capabilities, error) {
	return inference.Capabilities{}, nil
}
func (p *concurrentReviewer) GenerateStructured(ctx context.Context, r inference.Request) (inference.Result, error) {
	n := p.active.Add(1)
	defer p.active.Add(-1)
	for old := p.peak.Load(); n > old; old = p.peak.Load() {
		if p.peak.CompareAndSwap(old, n) {
			break
		}
	}
	if n == 2 {
		p.once.Do(func() { close(p.ready) })
	}
	select {
	case <-p.ready:
	case <-ctx.Done():
		return inference.Result{}, ctx.Err()
	}
	var input struct {
		Finding struct {
			ID string `json:"id"`
		} `json:"finding"`
	}
	if err := json.Unmarshal([]byte(r.UntrustedContext), &input); err != nil {
		return inference.Result{}, err
	}
	data, _ := json.Marshal(inference.ReviewRecommendation{FindingID: input.Finding.ID, EvidenceIDs: []string{input.Finding.ID}, Explanation: "Observed by scanner", Remediation: "Review evidence", Confidence: "hypothesis"})
	return inference.Result{Output: data}, nil
}

func TestReviewConcurrencyIsBoundedAndResultsStayOrdered(t *testing.T) {
	bundle := Bundle{}
	for i := 0; i < 5; i++ {
		id := fmt.Sprint(i)
		bundle.Findings = append(bundle.Findings, findings.Finding{ID: id, Tool: "scanner.test", RuleID: id, Title: id, Severity: findings.SeverityHigh})
		bundle.Recommendations = append(bundle.Recommendations, Recommendation{FindingID: id, Source: "deterministic"})
	}
	provider := &concurrentReviewer{ready: make(chan struct{})}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	count := reviewFindings(ctx, &bundle, AIOptions{Parallel: 2, MaxInputTokens: 4096, MaxOutputTokens: 512}, provider, 3)
	if count != 3 || bundle.AI.Calls != 3 || provider.peak.Load() != 2 {
		t.Fatalf("count=%d calls=%d peak=%d errors=%v", count, bundle.AI.Calls, provider.peak.Load(), bundle.AI.Errors)
	}
	for i, rec := range bundle.Recommendations {
		if rec.FindingID != fmt.Sprint(i) {
			t.Fatal("completion reordered evidence")
		}
		if i < 3 && rec.Status != "hypothesis" {
			t.Fatal("model output not labeled")
		}
		if i >= 3 && rec.Source != "deterministic" {
			t.Fatal("exceeded review budget")
		}
	}
}
