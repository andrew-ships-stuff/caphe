package cluster

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"
)

const SchemaVersion = "caphe.dev/cluster/job/v1alpha1"

type Phase string

const (
	PhaseQueued    Phase = "queued"
	PhaseRunning   Phase = "running"
	PhaseSucceeded Phase = "succeeded"
	PhaseFailed    Phase = "failed"
)

type Source struct {
	Kind      string `json:"kind"`
	GitURL    string `json:"gitUrl,omitempty"`
	CommitSHA string `json:"commitSha,omitempty"`
	Archive   string `json:"archive,omitempty"`
}

type Limits struct {
	CPUMillis      int64  `json:"cpuMillis"`
	MemoryBytes    int64  `json:"memoryBytes"`
	TimeoutSeconds int64  `json:"timeoutSeconds"`
	Network        string `json:"network"`
}

type Submission struct {
	WorkflowDigest string `json:"workflowDigest"`
	Source         Source `json:"source"`
	Limits         Limits `json:"limits"`
}

type Job struct {
	SchemaVersion   string     `json:"schemaVersion"`
	ID              string     `json:"id"`
	Tenant          string     `json:"tenant"`
	Submission      Submission `json:"submission"`
	Phase           Phase      `json:"phase"`
	CreatedAt       time.Time  `json:"createdAt"`
	StartedAt       *time.Time `json:"startedAt,omitempty"`
	FinishedAt      *time.Time `json:"finishedAt,omitempty"`
	WorkerID        string     `json:"workerId,omitempty"`
	Attempts        int        `json:"attempts"`
	Error           string     `json:"error,omitempty"`
	BundleDigest    string     `json:"bundleDigest,omitempty"`
	Findings        int        `json:"findings,omitempty"`
	NetworkEnforced bool       `json:"networkEnforced"`
}

type Policy struct {
	MaxCPUMillis       int64
	MaxMemoryBytes     int64
	MaxTimeout         time.Duration
	AllowWorkerNetwork bool
	AllowedGitHosts    map[string]bool
}

var digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
var commitPattern = regexp.MustCompile(`^(?:[0-9a-f]{40}|[0-9a-f]{64})$`)
var tenantPattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$`)
var jobIDPattern = regexp.MustCompile(`^job-[0-9a-f]{32}$`)

func (p Policy) Normalize() Policy {
	if p.MaxCPUMillis <= 0 {
		p.MaxCPUMillis = 8000
	}
	if p.MaxMemoryBytes <= 0 {
		p.MaxMemoryBytes = 16 << 30
	}
	if p.MaxTimeout <= 0 {
		p.MaxTimeout = time.Hour
	}
	if p.AllowedGitHosts == nil {
		p.AllowedGitHosts = map[string]bool{}
	}
	return p
}

func ValidateSubmission(sub *Submission, policy Policy) error {
	policy = policy.Normalize()
	if !digestPattern.MatchString(sub.WorkflowDigest) {
		return fmt.Errorf("workflowDigest must be a sha256 digest")
	}
	if sub.Source.Kind != "archive" && sub.Source.Kind != "git" {
		return fmt.Errorf("source.kind must be archive or git")
	}
	if sub.Source.Kind == "archive" {
		if sub.Source.GitURL != "" || sub.Source.CommitSHA != "" {
			return fmt.Errorf("archive source cannot include Git fields")
		}
	} else {
		if sub.Source.Archive != "" {
			return fmt.Errorf("Git source cannot include an archive")
		}
		if !commitPattern.MatchString(strings.ToLower(sub.Source.CommitSHA)) {
			return fmt.Errorf("Git source requires an immutable 40- or 64-character commit SHA")
		}
		sub.Source.CommitSHA = strings.ToLower(sub.Source.CommitSHA)
		u, err := url.Parse(sub.Source.GitURL)
		if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
			return fmt.Errorf("Git URL must be an HTTPS URL without credentials, query, or fragment")
		}
		host := strings.ToLower(u.Hostname())
		if !policy.AllowedGitHosts[host] {
			return fmt.Errorf("Git host %q is not allowed", host)
		}
	}
	if sub.Limits.CPUMillis <= 0 {
		sub.Limits.CPUMillis = 1000
	}
	if sub.Limits.MemoryBytes <= 0 {
		sub.Limits.MemoryBytes = 1 << 30
	}
	if sub.Limits.TimeoutSeconds <= 0 {
		sub.Limits.TimeoutSeconds = 1800
	}
	if sub.Limits.Network == "" {
		sub.Limits.Network = "disabled"
	}
	if sub.Limits.CPUMillis > policy.MaxCPUMillis || sub.Limits.MemoryBytes > policy.MaxMemoryBytes || time.Duration(sub.Limits.TimeoutSeconds)*time.Second > policy.MaxTimeout {
		return fmt.Errorf("requested resources exceed server policy")
	}
	if sub.Limits.Network != "disabled" && sub.Limits.Network != "restricted" {
		return fmt.Errorf("network must be disabled or restricted")
	}
	if sub.Limits.Network == "restricted" && !policy.AllowWorkerNetwork {
		return fmt.Errorf("worker network access is disabled by server policy")
	}
	return nil
}

func validTenant(tenant string) bool { return tenantPattern.MatchString(tenant) }
func validJobID(id string) bool      { return jobIDPattern.MatchString(id) }
