package cli

import (
	"bytes"
	"strings"
	"testing"

	"github.com/andrew-ships-stuff/caphe/internal/audit"
	capheruntime "github.com/andrew-ships-stuff/caphe/internal/runtime"
)

func TestAuditProgressDescribesScannerInferenceAndRemediation(t *testing.T) {
	var output bytes.Buffer
	a := &app{stdout: &output}
	progress := a.auditProgress(".", "caphe:default")
	progress(audit.ProgressEvent{Kind: "task_started", Task: capheruntime.TaskResult{Uses: "scanner.opengrep"}})
	progress(audit.ProgressEvent{Kind: "task_finished", Task: capheruntime.TaskResult{Uses: "scanner.opengrep", Status: capheruntime.StatusSucceeded, FindingCount: 3, DurationMillis: 12}})
	progress(audit.ProgressEvent{Kind: "task_finished", Task: capheruntime.TaskResult{Uses: "scanner.gitleaks", Status: capheruntime.StatusSkipped, ErrorClass: "tool_unavailable", Error: "gitleaks unavailable"}})
	progress(audit.ProgressEvent{Kind: "evidence_ready", FindingCount: 3})
	progress(audit.ProgressEvent{Kind: "ai_review_started", Model: "small-cpu-model", FindingCount: 3})
	progress(audit.ProgressEvent{Kind: "ai_review_finished", Model: "small-cpu-model", FindingCount: 2, ProposalCount: 3})
	progress(audit.ProgressEvent{Kind: "ai_dedup_finished", Model: "small-cpu-model", GroupCount: 3, ProposalCount: 1})
	progress(audit.ProgressEvent{Kind: "remediation_ready", FindingCount: 3, GroupCount: 2})
	got := output.String()
	for _, want := range []string{
		"Workflow  caphe:default (fixed DAG)",
		"Running SAST scan with Opengrep",
		"SAST scan with Opengrep done — 3 findings",
		"secret scan with Gitleaks skipped — gitleaks unavailable",
		"caphe setup --install",
		"Deterministically normalized and correlated 3 scanner findings",
		"Using small-cpu-model to interpret 3 findings as unverified hypotheses",
		"schema-valid remediation hypotheses for 2 of 3 findings",
		"proposed 1 possible duplicate merge across 3 groups",
		"Built deterministic remediation plan — 2 groups from 3 findings",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("progress output missing %q:\n%s", want, got)
		}
	}
}

func TestAuditProgressIsSilentForJSON(t *testing.T) {
	var output bytes.Buffer
	a := &app{stdout: &output, jsonOutput: true}
	if progress := a.auditProgress(".", "caphe:default"); progress != nil {
		t.Fatal("JSON audit must not install a human progress reporter")
	}
	if output.Len() != 0 {
		t.Fatalf("JSON audit wrote progress: %q", output.String())
	}
}

func TestAuditProgressGrypeDatabaseRecovery(t *testing.T) {
	for _, reason := range []string{
		"scanner process: exit status 1: current database is invalid",
		"failed to load vulnerability db: unable to migrate: constraint failed",
	} {
		t.Run(reason, func(t *testing.T) {
			var output bytes.Buffer
			a := &app{stdout: &output}
			a.auditProgress(".", "caphe:default")(audit.ProgressEvent{Kind: "task_finished", Task: capheruntime.TaskResult{
				Uses: "scanner.grype", Status: capheruntime.StatusSkipped, Error: reason,
			}})
			got := output.String()
			if !strings.Contains(got, "grype db update") || !strings.Contains(got, "grype db delete") || strings.Contains(got, "setup --install") {
				t.Fatalf("incorrect database recovery guidance: %s", got)
			}
		})
	}
	if got := scannerFailureSuggestion(capheruntime.TaskResult{Uses: "scanner.grype", Error: "grype unavailable"}); !strings.Contains(got, "setup --install") {
		t.Fatalf("missing Grype should suggest installation: %s", got)
	}
}
