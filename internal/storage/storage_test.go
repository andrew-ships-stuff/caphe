package storage

import (
	"path/filepath"
	"testing"

	"github.com/andrew-ships-stuff/caphe/internal/findings"
)

func TestFindingRoundTripAndGraphNode(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := t.Context()
	if err := s.BeginExecution(ctx, "e1", "sha256:x", "."); err != nil {
		t.Fatal(err)
	}
	f := findings.Finding{ID: "f1", Fingerprint: "f1", Tool: "scanner.test", RuleID: "r1", Title: "test", Severity: findings.SeverityHigh}
	if err := s.SaveFindings(ctx, "e1", []findings.Finding{f}); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetFinding(ctx, "f1")
	if err != nil {
		t.Fatal(err)
	}
	if got.Tool != f.Tool {
		t.Fatalf("got %#v", got)
	}
	g, err := s.GraphForFinding(ctx, "f1")
	if err != nil {
		t.Fatal(err)
	}
	if g["node"] == nil {
		t.Fatal("graph node absent")
	}
}

func TestListFindingsForExecutionDoesNotUseLatestRun(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := t.Context()
	for _, id := range []string{"e1", "e2"} {
		if err := s.BeginExecution(ctx, id, "sha256:x", "."); err != nil {
			t.Fatal(err)
		}
		f := findings.Finding{ID: "finding-" + id, Fingerprint: "finding-" + id, Tool: "scanner.test", RuleID: id, Title: id}
		if err := s.SaveFindings(ctx, id, []findings.Finding{f}); err != nil {
			t.Fatal(err)
		}
	}
	got, err := s.ListFindingsForExecution(ctx, "e1")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].ID != "finding-e1" {
		t.Fatalf("unexpected findings: %#v", got)
	}
}

func TestAICacheAndHypothesisRemainHypothesized(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := t.Context()
	if err := s.BeginExecution(ctx, "e1", "sha256:x", "."); err != nil {
		t.Fatal(err)
	}
	f := findings.Finding{ID: "f1", Fingerprint: "f1", Tool: "scanner.test", RuleID: "r", Title: "observed"}
	if err := s.SaveFindings(ctx, "e1", []findings.Finding{f}); err != nil {
		t.Fatal(err)
	}
	response := []byte(`{"confidence":"hypothesis"}`)
	if err := s.PutAICache(ctx, "key", response, "sha256:model", "p1", "s1"); err != nil {
		t.Fatal(err)
	}
	got, ok, err := s.GetAICache(ctx, "key")
	if err != nil || !ok || string(got) != string(response) {
		t.Fatalf("cache got=%s ok=%v err=%v", got, ok, err)
	}
	id, err := s.SaveInvariantHypothesis(ctx, "f1", "sha256:model", "key", map[string]any{"confidence": "hypothesis"})
	if err != nil {
		t.Fatal(err)
	}
	g, err := s.GraphForFinding(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	node := g["node"].(map[string]any)
	if node["status"] != "hypothesized" {
		t.Fatalf("model output promoted: %#v", node)
	}
}
