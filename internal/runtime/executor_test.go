package runtime

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/andrew-ships-stuff/caphe/internal/adapters"
	"github.com/andrew-ships-stuff/caphe/internal/artifacts"
	"github.com/andrew-ships-stuff/caphe/internal/compiler"
	"github.com/andrew-ships-stuff/caphe/internal/findings"
	"github.com/andrew-ships-stuff/caphe/internal/storage"
	"github.com/andrew-ships-stuff/caphe/internal/workflow"
)

type fixedAdapter struct{ id string }

func (f fixedAdapter) ID() string                          { return f.id }
func (f fixedAdapter) Version() string                     { return "test-v1" }
func (f fixedAdapter) Capabilities() []adapters.Capability { return []adapters.Capability{"test"} }
func (f fixedAdapter) Detect(context.Context) adapters.ToolInfo {
	return adapters.ToolInfo{ID: f.id, Available: true, Version: f.Version()}
}
func (f fixedAdapter) Validate(json.RawMessage) error { return nil }
func (f fixedAdapter) Execute(context.Context, adapters.Request) (adapters.Result, error) {
	return adapters.Result{
		Raw: []byte(`{"fixed":true}`),
		Findings: findings.Result{Findings: []findings.Finding{{
			ID: "f1", Fingerprint: "f1", Tool: f.id, RuleID: "r1", Title: "test",
			Severity: findings.SeverityHigh, Location: findings.Location{Path: "main.go", StartLine: 1},
		}}},
	}, nil
}

func TestExecutorPersistsFindingsAndArtifacts(t *testing.T) {
	dir := t.TempDir()
	db, err := storage.Open(filepath.Join(dir, "caphe.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	reg := adapters.NewRegistry(fixedAdapter{id: "scanner.fixed"})
	w, err := workflow.Parse([]byte(`apiVersion: caphe.dev/v1alpha1
kind: SecurityWorkflow
metadata: {name: test, version: "1"}
spec: {target: {type: repository}, tasks: [{id: scan, uses: scanner.fixed}]}
`))
	if err != nil {
		t.Fatal(err)
	}
	p, err := compiler.New(reg).Compile(w)
	if err != nil {
		t.Fatal(err)
	}
	m, err := New(reg, artifacts.New(filepath.Join(dir, "artifacts")), db, 2).Run(t.Context(), p, dir)
	if err != nil {
		t.Fatal(err)
	}
	if m.Status != "succeeded" || m.FindingCount != 1 || m.Tasks[0].ArtifactDigest == "" {
		t.Fatalf("unexpected manifest: %#v", m)
	}
	got, err := db.ListFindings(t.Context())
	if err != nil || len(got) != 1 {
		t.Fatalf("findings=%#v err=%v", got, err)
	}
}
