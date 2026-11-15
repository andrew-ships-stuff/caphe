package cluster

import (
	"os"
	"strings"
	"testing"
	"time"
)

func TestValidateSubmissionTrustBoundary(t *testing.T) {
	policy := Policy{AllowedGitHosts: map[string]bool{"github.com": true}}
	valid := Submission{
		WorkflowDigest: "sha256:" + strings.Repeat("a", 64),
		Source:         Source{Kind: "git", GitURL: "https://github.com/acme/repo.git", CommitSHA: strings.Repeat("b", 40)},
		Limits:         Limits{CPUMillis: 1000, MemoryBytes: 1 << 30, TimeoutSeconds: 60, Network: "disabled"},
	}
	if err := ValidateSubmission(&valid, policy); err != nil {
		t.Fatal(err)
	}
	cases := map[string]Submission{
		"floating ref":     {WorkflowDigest: valid.WorkflowDigest, Source: Source{Kind: "git", GitURL: valid.Source.GitURL, CommitSHA: "main"}},
		"unapproved host":  {WorkflowDigest: valid.WorkflowDigest, Source: Source{Kind: "git", GitURL: "https://example.com/repo", CommitSHA: valid.Source.CommitSHA}},
		"URL credentials":  {WorkflowDigest: valid.WorkflowDigest, Source: Source{Kind: "git", GitURL: "https://token@github.com/repo", CommitSHA: valid.Source.CommitSHA}},
		"mixed source":     {WorkflowDigest: valid.WorkflowDigest, Source: Source{Kind: "archive", GitURL: valid.Source.GitURL}},
		"unknown workflow": {WorkflowDigest: "latest", Source: Source{Kind: "archive"}},
		"excess timeout":   {WorkflowDigest: valid.WorkflowDigest, Source: Source{Kind: "archive"}, Limits: Limits{TimeoutSeconds: int64((2 * time.Hour) / time.Second)}},
	}
	for name, submission := range cases {
		t.Run(name, func(t *testing.T) {
			if err := ValidateSubmission(&submission, policy); err == nil {
				t.Fatal("expected submission rejection")
			}
		})
	}
}

func TestAuthenticatorTenantIsolation(t *testing.T) {
	path := t.TempDir() + "/auth.json"
	token := strings.Repeat("x", 32)
	if err := os.WriteFile(path, []byte(`{"tokens":[{"tenant":"acme","token":"`+token+`"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	auth, err := LoadAuthenticator(path, false)
	if err != nil {
		t.Fatal(err)
	}
	if tenant, ok := auth.Authenticate(token); !ok || tenant != "acme" {
		t.Fatalf("tenant=%q ok=%v", tenant, ok)
	}
	if _, ok := auth.Authenticate(strings.Repeat("y", 32)); ok {
		t.Fatal("unexpected authentication")
	}
}
