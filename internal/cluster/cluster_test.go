package cluster

import (
	"archive/zip"
	"context"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/andrew-ships-stuff/caphe/internal/adapters"
	"github.com/andrew-ships-stuff/caphe/internal/audit"
	"github.com/andrew-ships-stuff/caphe/internal/compiler"
	"github.com/andrew-ships-stuff/caphe/internal/source"
	"github.com/andrew-ships-stuff/caphe/internal/workflow"
)

func TestStoreLeaseRejectsStaleWorker(t *testing.T) {
	store, err := OpenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	digest := "sha256:" + strings.Repeat("a", 64)
	archive := zipFixture(t)
	file, err := os.Open(archive)
	if err != nil {
		t.Fatal(err)
	}
	job, err := store.CreateJob("tenant", Submission{WorkflowDigest: digest, Source: Source{Kind: "archive"}}, file, true)
	file.Close()
	if err != nil {
		t.Fatal(err)
	}
	lease, claimed, err := store.Claim("worker")
	if err != nil || claimed.ID != job.ID {
		t.Fatalf("claimed=%#v err=%v", claimed, err)
	}
	stale := lease
	stale.Token = "wrong"
	if err := store.Finish(stale, func(*Job) {}); err != ErrLeaseLost {
		t.Fatalf("expected lease loss, got %v", err)
	}
}

func TestWorkerProducesVerifiedRedactedBundle(t *testing.T) {
	root := t.TempDir()
	store, err := OpenStore(root)
	if err != nil {
		t.Fatal(err)
	}
	registry := adapters.DefaultRegistry()
	definition, err := workflow.Parse([]byte(`apiVersion: caphe.dev/v1alpha1
kind: SecurityWorkflow
metadata: {name: cluster-test, version: "1"}
spec:
  target: {type: repository}
  tasks:
    - id: normalize
      uses: core.normalize
`))
	if err != nil {
		t.Fatal(err)
	}
	plan, err := compiler.New(registry).Compile(definition)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.RegisterWorkflow(plan); err != nil {
		t.Fatal(err)
	}
	archive := zipFixture(t)
	file, err := os.Open(archive)
	if err != nil {
		t.Fatal(err)
	}
	job, err := store.CreateJob("tenant", Submission{WorkflowDigest: plan.Digest, Source: Source{Kind: "archive"}, Limits: Limits{CPUMillis: 1000, MemoryBytes: 1 << 30, TimeoutSeconds: 30, Network: "disabled"}}, file, true)
	file.Close()
	if err != nil {
		t.Fatal(err)
	}
	worker, err := NewWorker(WorkerConfig{Store: store, Registry: registry, PollInterval: 10 * time.Millisecond, LeaseTimeout: time.Second, NetworkEnforced: true, ArchiveLimits: source.Limits{MaxFiles: 10, MaxExpandedBytes: 1 << 20}})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- worker.Run(ctx) }()
	deadline := time.Now().Add(5 * time.Second)
	for {
		current, err := store.LoadJob(job.ID)
		if err != nil {
			t.Fatal(err)
		}
		if current.Phase == PhaseSucceeded {
			break
		}
		if current.Phase == PhaseFailed {
			t.Fatalf("job failed: %s", current.Error)
		}
		if time.Now().After(deadline) {
			t.Fatal("worker did not finish")
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	bundlePath := filepath.Join(store.JobDir(job.ID), "caphe-audit.json")
	bundle, err := audit.ReadJSON(bundlePath)
	if err != nil {
		t.Fatal(err)
	}
	if bundle.WorkflowDigest != plan.Digest || bundle.Digest == "" {
		t.Fatalf("unexpected bundle: %#v", bundle)
	}
	if _, err := os.Stat(filepath.Join(store.JobDir(job.ID), "state")); !os.IsNotExist(err) {
		t.Fatalf("raw worker state persisted: %v", err)
	}
}

func TestServerAcceptsArchiveAndEnforcesTenantAccess(t *testing.T) {
	store, err := OpenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	registry := adapters.DefaultRegistry()
	definition, err := workflow.Parse([]byte(`apiVersion: caphe.dev/v1alpha1
kind: SecurityWorkflow
metadata: {name: api-test, version: "1"}
spec: {target: {type: repository}, tasks: [{id: normalize, uses: core.normalize}]}
`))
	if err != nil {
		t.Fatal(err)
	}
	plan, err := compiler.New(registry).Compile(definition)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.RegisterWorkflow(plan); err != nil {
		t.Fatal(err)
	}
	tokenA, tokenB := strings.Repeat("a", 32), strings.Repeat("b", 32)
	authPath := filepath.Join(t.TempDir(), "auth.json")
	if err := os.WriteFile(authPath, []byte(`{"tokens":[{"tenant":"a","token":"`+tokenA+`"},{"tenant":"b","token":"`+tokenB+`"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	auth, err := LoadAuthenticator(authPath, false)
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewServer(ServerConfig{Store: store, Auth: auth, NetworkEnforced: true, ArchiveLimits: source.Limits{MaxFiles: 10, MaxExpandedBytes: 1 << 20}})
	if err != nil {
		t.Fatal(err)
	}
	httpServer := httptest.NewServer(server.http.Handler)
	defer httpServer.Close()
	clientA, err := NewClient(httpServer.URL, tokenA)
	if err != nil {
		t.Fatal(err)
	}
	job, err := clientA.Submit(t.Context(), Submission{WorkflowDigest: plan.Digest, Source: Source{Kind: "archive"}, Limits: Limits{Network: "disabled"}}, zipFixture(t))
	if err != nil {
		t.Fatal(err)
	}
	if job.Tenant != "a" || job.Phase != PhaseQueued {
		t.Fatalf("unexpected job: %#v", job)
	}
	clientB, err := NewClient(httpServer.URL, tokenB)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := clientB.Get(t.Context(), job.ID); err == nil || !strings.Contains(err.Error(), "job not found") {
		t.Fatalf("cross-tenant access was not hidden: %v", err)
	}
}

func zipFixture(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "source.zip")
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	writer := zip.NewWriter(file)
	entry, err := writer.Create("repo/main.go")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := entry.Write([]byte("package main\n")); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}
