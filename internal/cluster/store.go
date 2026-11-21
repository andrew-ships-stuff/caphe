package cluster

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/andrew-ships-stuff/caphe/internal/compiler"
)

var ErrNotFound = errors.New("cluster object not found")
var ErrLeaseLost = errors.New("cluster job lease lost")

type Store struct{ root string }

type Lease struct {
	JobID string
	Token string
	path  string
}

func OpenStore(root string) (*Store, error) {
	if root == "" {
		return nil, fmt.Errorf("cluster root is required")
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	for _, name := range []string{"jobs", "queue", "running", "workflows"} {
		if err := os.MkdirAll(filepath.Join(abs, name), 0o700); err != nil {
			return nil, err
		}
	}
	return &Store{root: abs}, nil
}

func (s *Store) Root() string { return s.root }

func (s *Store) RegisterWorkflow(plan *compiler.Plan) error {
	if !digestPattern.MatchString(plan.Digest) {
		return fmt.Errorf("invalid workflow digest")
	}
	return writeJSONAtomic(s.workflowPath(plan.Digest), plan)
}

func (s *Store) LoadWorkflow(digest string) (*compiler.Plan, error) {
	if !digestPattern.MatchString(digest) {
		return nil, fmt.Errorf("invalid workflow digest")
	}
	var plan compiler.Plan
	if err := readJSON(s.workflowPath(digest), &plan); err != nil {
		return nil, err
	}
	return &plan, nil
}

func (s *Store) WorkflowDigests() ([]string, error) {
	entries, err := os.ReadDir(filepath.Join(s.root, "workflows"))
	if err != nil {
		return nil, err
	}
	var out []string
	for _, entry := range entries {
		name := entry.Name()
		if !entry.IsDir() && filepath.Ext(name) == ".json" {
			digest := "sha256:" + name[:len(name)-len(".json")]
			if digestPattern.MatchString(digest) {
				out = append(out, digest)
			}
		}
	}
	sort.Strings(out)
	return out, nil
}

func (s *Store) workflowPath(digest string) string {
	return filepath.Join(s.root, "workflows", strings.TrimPrefix(digest, "sha256:")+".json")
}

func (s *Store) CreateJob(tenant string, sub Submission, archive io.Reader, networkEnforced bool) (Job, error) {
	if !validTenant(tenant) {
		return Job{}, fmt.Errorf("invalid tenant")
	}
	id, err := newID("job-")
	if err != nil {
		return Job{}, err
	}
	dir := s.JobDir(id)
	if err := os.Mkdir(dir, 0o700); err != nil {
		return Job{}, err
	}
	failed := true
	defer func() {
		if failed {
			_ = os.RemoveAll(dir)
			_ = os.Remove(filepath.Join(s.root, "queue", id))
		}
	}()
	if archive != nil {
		file, err := os.OpenFile(filepath.Join(dir, "source.zip"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err != nil {
			return Job{}, err
		}
		_, copyErr := io.Copy(file, archive)
		closeErr := file.Close()
		if copyErr != nil {
			return Job{}, copyErr
		}
		if closeErr != nil {
			return Job{}, closeErr
		}
		sub.Source.Archive = "source.zip"
	}
	job := Job{SchemaVersion: SchemaVersion, ID: id, Tenant: tenant, Submission: sub, Phase: PhaseQueued, CreatedAt: time.Now().UTC(), NetworkEnforced: networkEnforced}
	if err := s.SaveJob(job); err != nil {
		return Job{}, err
	}
	if err := os.WriteFile(filepath.Join(s.root, "queue", id), []byte{}, 0o600); err != nil {
		return Job{}, err
	}
	failed = false
	return job, nil
}

func (s *Store) JobDir(id string) string { return filepath.Join(s.root, "jobs", id) }

func (s *Store) SaveJob(job Job) error {
	if !validJobID(job.ID) || !validTenant(job.Tenant) {
		return fmt.Errorf("invalid job identity")
	}
	return writeJSONAtomic(filepath.Join(s.JobDir(job.ID), "job.json"), job)
}

func (s *Store) LoadJob(id string) (Job, error) {
	if !validJobID(id) {
		return Job{}, ErrNotFound
	}
	var job Job
	if err := readJSON(filepath.Join(s.JobDir(id), "job.json"), &job); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Job{}, ErrNotFound
		}
		return Job{}, err
	}
	return job, nil
}

func (s *Store) Claim(workerID string) (Lease, Job, error) {
	entries, err := os.ReadDir(filepath.Join(s.root, "queue"))
	if err != nil {
		return Lease{}, Job{}, err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	for _, entry := range entries {
		id := entry.Name()
		if !validJobID(id) {
			continue
		}
		token, err := newID("")
		if err != nil {
			return Lease{}, Job{}, err
		}
		from := filepath.Join(s.root, "queue", id)
		to := filepath.Join(s.root, "running", id)
		if err := os.Rename(from, to); err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return Lease{}, Job{}, err
		}
		if err := os.WriteFile(to, []byte(token), 0o600); err != nil {
			_ = os.Rename(to, from)
			return Lease{}, Job{}, err
		}
		job, err := s.LoadJob(id)
		if err != nil {
			_ = os.Remove(to)
			return Lease{}, Job{}, err
		}
		if job.Phase == PhaseSucceeded || job.Phase == PhaseFailed {
			_ = os.Remove(to)
			continue
		}
		now := time.Now().UTC()
		job.Phase = PhaseRunning
		job.StartedAt = &now
		job.FinishedAt = nil
		job.WorkerID = workerID
		job.Attempts++
		job.Error = ""
		if err := s.SaveJob(job); err != nil {
			_ = os.Rename(to, from)
			return Lease{}, Job{}, err
		}
		return Lease{JobID: id, Token: token, path: to}, job, nil
	}
	return Lease{}, Job{}, ErrNotFound
}

func (s *Store) Heartbeat(lease Lease) error {
	data, err := os.ReadFile(lease.path)
	if err != nil || string(data) != lease.Token {
		return ErrLeaseLost
	}
	now := time.Now()
	return os.Chtimes(lease.path, now, now)
}

func (s *Store) Finish(lease Lease, update func(*Job)) error {
	if err := s.Heartbeat(lease); err != nil {
		return err
	}
	job, err := s.LoadJob(lease.JobID)
	if err != nil {
		return err
	}
	update(&job)
	now := time.Now().UTC()
	job.FinishedAt = &now
	if err := s.SaveJob(job); err != nil {
		return err
	}
	return os.Remove(lease.path)
}

func (s *Store) RequeueStale(maxAge time.Duration) error {
	entries, err := os.ReadDir(filepath.Join(s.root, "running"))
	if err != nil {
		return err
	}
	cutoff := time.Now().Add(-maxAge)
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil || info.ModTime().After(cutoff) || !validJobID(entry.Name()) {
			continue
		}
		from := filepath.Join(s.root, "running", entry.Name())
		to := filepath.Join(s.root, "queue", entry.Name())
		if err := os.Rename(from, to); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		job, err := s.LoadJob(entry.Name())
		if err == nil {
			if job.Phase == PhaseSucceeded || job.Phase == PhaseFailed {
				_ = os.Remove(to)
				continue
			}
			job.Phase = PhaseQueued
			job.WorkerID = ""
			job.Error = "worker lease expired; job requeued"
			_ = s.SaveJob(job)
		}
	}
	return nil
}

func (s *Store) Prune(retention time.Duration) error {
	entries, err := os.ReadDir(filepath.Join(s.root, "jobs"))
	if err != nil {
		return err
	}
	cutoff := time.Now().Add(-retention)
	for _, entry := range entries {
		if !entry.IsDir() || !validJobID(entry.Name()) {
			continue
		}
		job, err := s.LoadJob(entry.Name())
		if err != nil || job.FinishedAt == nil || job.FinishedAt.After(cutoff) {
			continue
		}
		_ = os.Remove(filepath.Join(s.root, "queue", job.ID))
		_ = os.Remove(filepath.Join(s.root, "running", job.ID))
		if err := os.RemoveAll(s.JobDir(job.ID)); err != nil {
			return err
		}
	}
	return nil
}

func newID(prefix string) (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return prefix + hex.EncodeToString(b), nil
}

func openForRead(path string) (*os.File, error) {
	var lastErr error
	for attempt := 0; attempt < 50; attempt++ {
		file, err := os.Open(path)
		if err == nil {
			return file, nil
		}
		lastErr = err
		if !fileLocked(err) {
			return nil, err
		}
		time.Sleep(10 * time.Millisecond)
	}
	return nil, lastErr
}

// fileLocked reports whether err is a Windows sharing violation, which
// antivirus/indexer scans raise transiently on freshly written job files.
func fileLocked(err error) bool {
	if runtime.GOOS != "windows" {
		return false
	}
	var errno syscall.Errno
	return errors.As(err, &errno) && errno == 32
}

func readJSON(path string, out any) error {
	file, err := openForRead(path)
	if err != nil {
		return err
	}
	defer file.Close()
	decoder := json.NewDecoder(file)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(out); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return fmt.Errorf("trailing JSON content")
	}
	return nil
}

func writeJSONAtomic(path string, value any) error {
	dir := filepath.Dir(path)
	file, err := os.CreateTemp(dir, ".caphe-*.tmp")
	if err != nil {
		return err
	}
	name := file.Name()
	defer os.Remove(name)
	if err := file.Chmod(0o600); err != nil {
		file.Close()
		return err
	}
	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(value); err != nil {
		file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, path); err == nil {
		return nil
	} else if runtime.GOOS != "windows" {
		return err
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return os.Rename(name, path)
}

type JobPage struct {
	Jobs       []Job  `json:"jobs"`
	NextCursor string `json:"nextCursor,omitempty"`
}

func (s *Store) ListJobs(tenant, cursor string, limit int) (JobPage, error) {
	if !validTenant(tenant) || limit < 1 || limit > 200 {
		return JobPage{}, fmt.Errorf("invalid job listing request")
	}
	var before Job
	if cursor != "" {
		var err error
		before, err = s.LoadJob(cursor)
		if err != nil || before.Tenant != tenant {
			return JobPage{}, ErrNotFound
		}
	}
	entries, err := os.ReadDir(filepath.Join(s.root, "jobs"))
	if err != nil {
		return JobPage{}, err
	}
	jobs := []Job{}
	for _, entry := range entries {
		if !entry.IsDir() || !validJobID(entry.Name()) {
			continue
		}
		job, err := s.LoadJob(entry.Name())
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return JobPage{}, err
		}
		if job.Tenant != tenant {
			continue
		}
		if cursor != "" && (job.CreatedAt.After(before.CreatedAt) || (job.CreatedAt.Equal(before.CreatedAt) && job.ID >= before.ID)) {
			continue
		}
		jobs = append(jobs, job)
	}
	sort.Slice(jobs, func(i, j int) bool {
		if jobs[i].CreatedAt.Equal(jobs[j].CreatedAt) {
			return jobs[i].ID > jobs[j].ID
		}
		return jobs[i].CreatedAt.After(jobs[j].CreatedAt)
	})
	page := JobPage{Jobs: jobs}
	if len(jobs) > limit {
		page.Jobs = jobs[:limit]
		page.NextCursor = jobs[limit-1].ID
	}
	return page, nil
}
