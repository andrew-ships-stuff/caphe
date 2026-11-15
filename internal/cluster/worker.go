package cluster

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/andrew-ships-stuff/caphe/internal/adapters"
	"github.com/andrew-ships-stuff/caphe/internal/audit"
	"github.com/andrew-ships-stuff/caphe/internal/compiler"
	"github.com/andrew-ships-stuff/caphe/internal/source"
)

type WorkerConfig struct {
	ID              string
	Store           *Store
	Registry        *adapters.Registry
	Concurrency     int
	TaskConcurrency int
	PollInterval    time.Duration
	LeaseTimeout    time.Duration
	MaxOutputBytes  int64
	ArchiveLimits   source.Limits
	CapheVersion    string
	NetworkEnforced bool
	Log             io.Writer
}

type Worker struct{ config WorkerConfig }

func NewWorker(config WorkerConfig) (*Worker, error) {
	if config.Store == nil {
		return nil, fmt.Errorf("cluster store is required")
	}
	if config.Registry == nil {
		config.Registry = adapters.DefaultRegistry()
	}
	if config.Concurrency <= 0 {
		config.Concurrency = 1
	}
	if config.TaskConcurrency <= 0 {
		config.TaskConcurrency = 1
	}
	if config.PollInterval <= 0 {
		config.PollInterval = time.Second
	}
	if config.LeaseTimeout <= 0 {
		config.LeaseTimeout = 2 * time.Minute
	}
	if config.MaxOutputBytes <= 0 {
		config.MaxOutputBytes = 64 << 20
	}
	if config.ArchiveLimits.MaxFiles <= 0 {
		config.ArchiveLimits.MaxFiles = 100_000
	}
	if config.ArchiveLimits.MaxExpandedBytes == 0 {
		config.ArchiveLimits.MaxExpandedBytes = 2 << 30
	}
	if config.ID == "" {
		id, err := newID("worker-")
		if err != nil {
			return nil, err
		}
		config.ID = id
	}
	return &Worker{config: config}, nil
}

func (w *Worker) Run(ctx context.Context) error {
	if err := w.config.Store.RequeueStale(w.config.LeaseTimeout); err != nil {
		return err
	}
	var group sync.WaitGroup
	for i := 0; i < w.config.Concurrency; i++ {
		group.Add(1)
		go func(slot int) {
			defer group.Done()
			w.loop(ctx, fmt.Sprintf("%s-%d", w.config.ID, slot))
		}(i)
	}
	group.Wait()
	return nil
}

func (w *Worker) loop(ctx context.Context, workerID string) {
	ticker := time.NewTicker(w.config.PollInterval)
	defer ticker.Stop()
	for {
		lease, job, err := w.config.Store.Claim(workerID)
		if err == nil {
			w.execute(ctx, lease, job)
			continue
		}
		if !errors.Is(err, ErrNotFound) && w.config.Log != nil {
			fmt.Fprintf(w.config.Log, "cluster worker claim: %v\n", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			_ = w.config.Store.RequeueStale(w.config.LeaseTimeout)
		}
	}
}

func (w *Worker) execute(parent context.Context, lease Lease, job Job) {
	if !job.NetworkEnforced || !w.config.NetworkEnforced {
		w.fail(lease, "worker network isolation is not enforced")
		return
	}
	plan, err := w.config.Store.LoadWorkflow(job.Submission.WorkflowDigest)
	if err != nil || compiler.ValidateLock(plan, w.config.Registry) != nil {
		w.fail(lease, "registered workflow lock is unavailable or invalid")
		return
	}
	timeout := time.Duration(job.Submission.Limits.TimeoutSeconds) * time.Second
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	heartbeatDone := make(chan struct{})
	go w.heartbeat(ctx, lease, heartbeatDone)
	defer close(heartbeatDone)
	stateDir, err := os.MkdirTemp("", "caphe-cluster-state-")
	if err != nil {
		w.fail(lease, "create isolated worker state")
		return
	}
	defer os.RemoveAll(stateDir)
	bundle, err := audit.Run(ctx, audit.Options{
		Target:       filepath.Join(w.config.Store.JobDir(job.ID), "source.zip"),
		Workflow:     job.Submission.WorkflowDigest,
		DataDir:      stateDir,
		Concurrency:  w.config.TaskConcurrency,
		CapheVersion: w.config.CapheVersion,
		Registry:     w.config.Registry,
		Plan:         plan,
		SourceLimits: w.config.ArchiveLimits,
	})
	if err != nil {
		if parent.Err() != nil {
			return
		}
		w.fail(lease, "audit execution failed")
		return
	}
	redactBundle(&bundle)
	if err := audit.RecomputeDigest(&bundle); err != nil {
		w.fail(lease, "finalize redacted audit result")
		return
	}
	jobDir := w.config.Store.JobDir(job.ID)
	paths := []struct {
		name  string
		write func(string, audit.Bundle) error
	}{
		{"caphe-audit.json", audit.WriteJSON},
		{"caphe-audit.sarif", audit.WriteSARIF},
		{"caphe-audit.md", audit.WriteMarkdown},
		{"caphe-audit.html", audit.WriteHTML},
	}
	var total int64
	for _, output := range paths {
		path := filepath.Join(jobDir, output.name)
		if err := output.write(path, bundle); err != nil {
			w.fail(lease, "write audit result")
			return
		}
		info, err := os.Stat(path)
		if err != nil {
			w.fail(lease, "inspect audit result")
			return
		}
		total += info.Size()
		if total > w.config.MaxOutputBytes {
			for _, item := range paths {
				_ = os.Remove(filepath.Join(jobDir, item.name))
			}
			w.fail(lease, "audit result exceeds output limit")
			return
		}
	}
	if err := w.config.Store.Finish(lease, func(current *Job) {
		current.Phase = PhaseSucceeded
		current.BundleDigest = bundle.Digest
		current.Findings = bundle.Metrics.Findings
		current.Error = ""
	}); err != nil && !errors.Is(err, ErrLeaseLost) && w.config.Log != nil {
		fmt.Fprintf(w.config.Log, "cluster worker finish: %v\n", err)
	}
}

func (w *Worker) heartbeat(ctx context.Context, lease Lease, done <-chan struct{}) {
	interval := w.config.LeaseTimeout / 3
	if interval < time.Second {
		interval = time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-done:
			return
		case <-ticker.C:
			if err := w.config.Store.Heartbeat(lease); err != nil {
				return
			}
		}
	}
}

func (w *Worker) fail(lease Lease, message string) {
	_ = w.config.Store.Finish(lease, func(job *Job) {
		job.Phase = PhaseFailed
		job.Error = message
	})
}

func redactBundle(bundle *audit.Bundle) {
	for i := range bundle.Tasks {
		if bundle.Tasks[i].Error != "" {
			bundle.Tasks[i].Error = "scanner task failed; detailed subprocess output was not persisted by the cluster worker"
		}
	}
	for i := range bundle.Findings {
		bundle.Findings[i].Properties = redactMap(bundle.Findings[i].Properties)
	}
}

func redactMap(input map[string]any) map[string]any {
	if input == nil {
		return nil
	}
	out := make(map[string]any, len(input))
	for key, value := range input {
		switch strings.ToLower(key) {
		case "secret", "match", "entropy", "snippet", "lines", "code", "source":
			continue
		}
		switch item := value.(type) {
		case map[string]any:
			out[key] = redactMap(item)
		case []any:
			values := make([]any, len(item))
			for i, child := range item {
				if childMap, ok := child.(map[string]any); ok {
					values[i] = redactMap(childMap)
				} else {
					values[i] = child
				}
			}
			out[key] = values
		default:
			out[key] = value
		}
	}
	return out
}
