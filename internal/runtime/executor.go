package runtime

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/andrew-ships-stuff/caphe/internal/adapters"
	"github.com/andrew-ships-stuff/caphe/internal/artifacts"
	"github.com/andrew-ships-stuff/caphe/internal/compiler"
	"github.com/andrew-ships-stuff/caphe/internal/findings"
	"github.com/andrew-ships-stuff/caphe/internal/storage"
	"github.com/andrew-ships-stuff/caphe/internal/workflow"
)

type TaskStatus string

const (
	StatusPending   TaskStatus = "pending"
	StatusRunning   TaskStatus = "running"
	StatusSucceeded TaskStatus = "succeeded"
	StatusFailed    TaskStatus = "failed"
	StatusSkipped   TaskStatus = "skipped"
)

type TaskResult struct {
	ID             string     `json:"id"`
	Status         TaskStatus `json:"status"`
	Attempts       int        `json:"attempts"`
	ArtifactDigest string     `json:"artifactDigest,omitempty"`
	DurationMillis int64      `json:"durationMillis"`
	ErrorClass     string     `json:"errorClass,omitempty"`
	Error          string     `json:"error,omitempty"`
	FindingCount   int        `json:"findingCount"`
	ToolVersion    string     `json:"toolVersion,omitempty"`
}
type Manifest struct {
	ExecutionID    string       `json:"executionId"`
	WorkflowDigest string       `json:"workflowDigest"`
	Target         string       `json:"target"`
	Status         string       `json:"status"`
	Tasks          []TaskResult `json:"tasks"`
	FindingCount   int          `json:"findingCount"`
}
type Executor struct {
	registry    *adapters.Registry
	artifacts   *artifacts.Store
	db          *storage.Store
	concurrency int
}

func New(reg *adapters.Registry, as *artifacts.Store, db *storage.Store, concurrency int) *Executor {
	if concurrency < 1 {
		concurrency = 1
	}
	return &Executor{registry: reg, artifacts: as, db: db, concurrency: concurrency}
}

func (e *Executor) Run(ctx context.Context, plan *compiler.Plan, target string) (Manifest, error) {
	if err := compiler.ValidateLock(plan, e.registry); err != nil {
		return Manifest{}, err
	}
	abs, err := filepath.Abs(target)
	if err != nil {
		return Manifest{}, err
	}
	info, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return Manifest{}, fmt.Errorf("resolve target: %w", err)
	}
	abs = info
	id, err := executionID()
	if err != nil {
		return Manifest{}, err
	}
	m := Manifest{ExecutionID: id, WorkflowDigest: plan.Digest, Target: abs, Status: "running"}
	if err := e.db.BeginExecution(ctx, id, plan.Digest, abs); err != nil {
		return m, err
	}
	states := map[string]TaskResult{}
	artPaths := map[string]string{}
	allFindings := []findings.Finding{}
	for _, t := range plan.Tasks {
		states[t.ID] = TaskResult{ID: t.ID, Status: StatusPending}
	}
	remaining := len(plan.Tasks)
	for remaining > 0 {
		ready := []compiler.PlanTask{}
		for _, t := range plan.Tasks {
			if states[t.ID].Status != StatusPending {
				continue
			}
			depsDone := true
			hardFailure := false
			optionalSet := map[string]bool{}
			for _, n := range t.OptionalNeeds {
				optionalSet[n] = true
			}
			for _, n := range t.Needs {
				s := states[n].Status
				if s == StatusPending || s == StatusRunning {
					depsDone = false
				}
				if (s == StatusFailed || s == StatusSkipped) && !optionalSet[n] {
					hardFailure = true
				}
			}
			if hardFailure {
				r := states[t.ID]
				r.Status = StatusSkipped
				r.ErrorClass = "dependency_failed"
				r.Error = "required dependency did not succeed"
				states[t.ID] = r
				remaining--
				_ = e.db.SaveTask(ctx, id, t.ID, string(r.Status), 0, "", r.ErrorClass, r.Error, 0)
			} else if depsDone {
				ready = append(ready, t)
			}
		}
		if len(ready) == 0 {
			if remaining > 0 {
				break
			}
			continue
		}
		sort.Slice(ready, func(i, j int) bool { return ready[i].ID < ready[j].ID })
		sem := make(chan struct{}, e.concurrency)
		var wg sync.WaitGroup
		var mu sync.Mutex
		for _, t := range ready {
			t := t
			wg.Add(1)
			go func() {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()
				mu.Lock()
				r := states[t.ID]
				r.Status = StatusRunning
				states[t.ID] = r
				inputs := map[string]string{}
				for _, n := range t.Needs {
					if p := artPaths[n]; p != "" {
						inputs["sbom"] = p
					}
				}
				mu.Unlock()
				result, path, fs := e.runTask(ctx, t, abs, inputs)
				_ = e.db.SaveTask(ctx, id, t.ID, string(result.Status), result.Attempts, result.ArtifactDigest, result.ErrorClass, result.Error, time.Duration(result.DurationMillis)*time.Millisecond)
				mu.Lock()
				states[t.ID] = result
				if path != "" {
					artPaths[t.ID] = path
				}
				allFindings = append(allFindings, fs...)
				mu.Unlock()
			}()
		}
		wg.Wait()
		remaining -= len(ready)
	}
	failed := false
	for _, t := range plan.Tasks {
		r := states[t.ID]
		m.Tasks = append(m.Tasks, r)
		m.FindingCount += r.FindingCount
		if r.Status == StatusFailed && !t.Optional {
			failed = true
		}
	}
	if err := e.db.SaveFindings(ctx, id, allFindings); err != nil {
		failed = true
	}
	if failed {
		m.Status = "partial_failure"
	} else {
		m.Status = "succeeded"
	}
	_ = e.db.FinishExecution(ctx, id, m.Status, m)
	if failed {
		return m, fmt.Errorf("execution completed with required task failures")
	}
	return m, nil
}

func (e *Executor) runTask(parent context.Context, t compiler.PlanTask, target string, inputs map[string]string) (TaskResult, string, []findings.Finding) {
	r := TaskResult{ID: t.ID, Status: StatusFailed}
	a, _ := e.registry.Get(t.Uses)
	cfg, _ := workflow.RawConfig(t.With)
	start := time.Now()
	var last error
	var res adapters.Result
	for attempt := 1; attempt <= t.Runtime.Retries+1; attempt++ {
		r.Attempts = attempt
		ctx, cancel := context.WithTimeout(parent, time.Duration(t.Runtime.TimeoutSeconds)*time.Second)
		res, last = a.Execute(ctx, adapters.Request{Target: target, Config: cfg, Inputs: inputs, Timeout: time.Duration(t.Runtime.TimeoutSeconds) * time.Second, MaxOutput: 64 << 20})
		cancel()
		if last == nil {
			break
		}
		if attempt <= t.Runtime.Retries {
			timer := time.NewTimer(time.Duration(t.Runtime.BackoffMillis) * time.Millisecond * time.Duration(1<<(attempt-1)))
			select {
			case <-parent.Done():
				timer.Stop()
				last = parent.Err()
				attempt = t.Runtime.Retries + 1
			case <-timer.C:
			}
		}
	}
	r.DurationMillis = time.Since(start).Milliseconds()
	if last != nil {
		r.ErrorClass = classify(last)
		r.Error = last.Error()
		if t.Optional {
			r.Status = StatusSkipped
		} else {
			r.Status = StatusFailed
		}
		return r, "", nil
	}
	digest, path, err := e.artifacts.Put(res.Raw)
	if err != nil {
		r.ErrorClass = "artifact_error"
		r.Error = err.Error()
		return r, "", nil
	}
	for i := range res.Findings.Findings {
		res.Findings.Findings[i].ArtifactDigest = digest
	}
	r.Status = StatusSucceeded
	r.ArtifactDigest = digest
	r.FindingCount = len(res.Findings.Findings)
	r.ToolVersion = res.Version
	return r, path, res.Findings.Findings
}
func classify(err error) string {
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return "timeout"
	case errors.Is(err, context.Canceled):
		return "cancelled"
	case errors.Is(err, adapters.ErrOutputLimit):
		return "output_limit"
	case strings.Contains(err.Error(), "unavailable"):
		return "tool_unavailable"
	default:
		return "tool_error"
	}
}
func executionID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "exec-" + hex.EncodeToString(b), nil
}
