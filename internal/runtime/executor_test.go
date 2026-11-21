package runtime

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"

	"github.com/andrew-ships-stuff/caphe/internal/adapters"
	"github.com/andrew-ships-stuff/caphe/internal/artifacts"
	"github.com/andrew-ships-stuff/caphe/internal/compiler"
	"github.com/andrew-ships-stuff/caphe/internal/findings"
	"github.com/andrew-ships-stuff/caphe/internal/storage"
	"github.com/andrew-ships-stuff/caphe/internal/workflow"
)

type failingAdapter struct {
	fixedAdapter
	err error
}

func (f failingAdapter) Execute(context.Context, adapters.Request) (adapters.Result, error) {
	return adapters.Result{}, f.err
}

func TestOptionalFailureIsNotUnavailable(t *testing.T) {
	for _, tc := range []struct {
		name, message string
		status        TaskStatus
	}{
		{"absent", "scanner unavailable", StatusSkipped},
		{"broken", "invalid vulnerability database", StatusFailed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			store, err := storage.Open(filepath.Join(dir, "state.db"))
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			scanErr := errors.New(tc.message)
			if tc.name == "absent" {
				scanErr = fmt.Errorf("%s: %w", tc.message, exec.ErrNotFound)
			}
			registry := adapters.NewRegistry(failingAdapter{fixedAdapter: fixedAdapter{id: "scanner.fixed"}, err: scanErr})
			definition, err := workflow.Parse([]byte("apiVersion: caphe.dev/v1alpha1\nkind: SecurityWorkflow\nmetadata: {name: test, version: '1'}\nspec: {target: {type: repository}, tasks: [{id: scan, uses: scanner.fixed, optional: true}]}"))
			if err != nil {
				t.Fatal(err)
			}
			plan, err := compiler.New(registry).Compile(definition)
			if err != nil {
				t.Fatal(err)
			}
			manifest, err := New(registry, artifacts.New(filepath.Join(dir, "artifacts")), store, 1).Run(t.Context(), plan, dir)
			if err != nil || manifest.Status != "incomplete" || manifest.Tasks[0].Status != tc.status {
				t.Fatalf("manifest=%+v err=%v", manifest, err)
			}
		})
	}
}

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
	var events []TaskEvent
	var eventsMu sync.Mutex
	m, err := New(reg, artifacts.New(filepath.Join(dir, "artifacts")), db, 2).WithProgress(func(event TaskEvent) {
		eventsMu.Lock()
		defer eventsMu.Unlock()
		events = append(events, event)
	}).Run(t.Context(), p, dir)
	if err != nil {
		t.Fatal(err)
	}
	if m.Status != "succeeded" || m.FindingCount != 1 || m.Tasks[0].ArtifactDigest == "" {
		t.Fatalf("unexpected manifest: %#v", m)
	}
	if m.Tasks[0].Uses != "scanner.fixed" {
		t.Fatalf("task uses = %q, want scanner.fixed", m.Tasks[0].Uses)
	}
	if len(events) != 2 || events[0].Done || !events[1].Done || events[1].Result.FindingCount != 1 {
		t.Fatalf("unexpected progress events: %#v", events)
	}
	got, err := db.ListFindings(t.Context())
	if err != nil || len(got) != 1 {
		t.Fatalf("findings=%#v err=%v", got, err)
	}
}
