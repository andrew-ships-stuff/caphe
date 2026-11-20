package audit

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/andrew-ships-stuff/caphe/internal/findings"
)

func TestCrossScannerAdvisoryAliasesPreserveEvidence(t *testing.T) {
	bundle := Bundle{Findings: []findings.Finding{
		{ID: "grype", Tool: "scanner.grype", RuleID: "CVE-2026-1", Severity: findings.SeverityHigh, Properties: map[string]any{"artifact": map[string]any{"name": "example.org/lib", "version": "1.0", "type": "go-module"}, "vulnerability": map[string]any{"id": "CVE-2026-1"}}},
		{ID: "osv", Tool: "scanner.osv", RuleID: "GHSA-aaaa-bbbb-cccc", Severity: findings.SeverityHigh, Properties: map[string]any{"package": map[string]any{"name": "example.org/lib", "version": "1.0", "ecosystem": "Go"}, "vulnerability": map[string]any{"id": "GHSA-aaaa-bbbb-cccc", "aliases": []any{"CVE-2026-1"}}}},
	}}
	groups, _ := buildRemediation(&bundle)
	if len(groups) != 1 || len(groups[0].FindingIDs) != 2 || groups[0].AdvisoryCount != 1 {
		t.Fatalf("lost evidence or failed alias grouping: %+v", groups)
	}
}

func grypeFinding(id, name, version, advisory string, fixed []string) findings.Finding {
	return findings.Finding{
		ID: id, Tool: "scanner.grype", RuleID: advisory, Title: advisory + " affects " + name + "@" + version,
		Severity: findings.SeverityHigh,
		Properties: map[string]any{
			"artifact":      map[string]any{"name": name, "version": version, "type": "npm"},
			"vulnerability": map[string]any{"id": advisory, "fix": map[string]any{"state": "fixed", "versions": anySlice(fixed)}},
		},
	}
}

func anySlice(items []string) []any {
	out := make([]any, 0, len(items))
	for _, item := range items {
		out = append(out, item)
	}
	return out
}

func TestBuildRemediationDedupesPackagesAndTalliesAdvisories(t *testing.T) {
	bundle := Bundle{
		SchemaVersion: SchemaVersion, Target: ".", Digest: "sha256:" + strings.Repeat("a", 64),
		Findings: []findings.Finding{
			grypeFinding("f1", "leftpad", "1.0.0", "CVE-2026-0001", []string{"1.0.3", "2.0.1"}),
			grypeFinding("f2", "leftpad", "1.0.0", "GHSA-xxxx-yyyy", []string{"1.0.2"}),
			grypeFinding("f3", "leftpad", "1.0.0", "CVE-2026-0002", nil),
			grypeFinding("f4", "rightpad", "0.9.0", "CVE-2026-0003", []string{"0.9.5"}),
			{ID: "f5", Tool: "scanner.gitleaks", RuleID: "generic-api-key", Title: "secret", Severity: findings.SeverityCritical, Location: findings.Location{Path: ".env", StartLine: 3}},
		},
	}
	groups, note := buildRemediation(&bundle)
	if len(groups) != 3 {
		t.Fatalf("expected 3 deduped groups, got %d: %#v", len(groups), groups)
	}
	if groups[0].Kind != "finding" || groups[0].FindingIDs[0] != "f5" {
		t.Fatalf("critical gitleaks finding should sort first: %#v", groups[0])
	}
	var leftpad *remediationGroup
	for i := range groups {
		if groups[i].Package == "leftpad" {
			leftpad = &groups[i]
		}
	}
	if leftpad == nil {
		t.Fatal("leftpad package group missing")
	}
	if leftpad.AdvisoryCount != 3 || leftpad.CVECount != 2 {
		t.Fatalf("advisory tally wrong: count=%d cves=%d ids=%v", leftpad.AdvisoryCount, leftpad.CVECount, leftpad.AdvisoryIDs)
	}
	if !strings.Contains(leftpad.FixedPreview, "1.0.2") || !strings.Contains(leftpad.FixedPreview, "2.0.1") {
		t.Fatalf("fixed preview missing union of fix versions: %q", leftpad.FixedPreview)
	}
	if strings.Join(leftpad.FindingIDs, ",") != "f1,f2,f3" {
		t.Fatalf("finding ids: %v", leftpad.FindingIDs)
	}
	for _, want := range []string{"Caphe fix task", "Upgrade leftpad (npm) from 1.0.0", "CVE-2026-0001: 1.0.3, 2.0.1", "CVE-2026-0002: no fix published", "Finding IDs: f1, f2, f3", "untrusted input", bundle.Digest} {
		if !strings.Contains(leftpad.Prompt, want) {
			t.Fatalf("package prompt missing %q:\n%s", want, leftpad.Prompt)
		}
	}
	if !strings.Contains(note, "2 packages") || !strings.Contains(note, "4 advisories") || !strings.Contains(note, "3 CVEs") || !strings.Contains(note, "5 raw findings") {
		t.Fatalf("unexpected note: %s", note)
	}
}

func TestBuildRemediationDedupesIdenticalNonPackageFindings(t *testing.T) {
	mk := func(id string) findings.Finding {
		return findings.Finding{ID: id, Tool: "scanner.opengrep", RuleID: "go.lang.security.audit.net.unescaped-data-in-url.unescaped-data-in-url", Title: "Found a formatted template string passed to 'template.URL()'", Severity: findings.SeverityHigh, Location: findings.Location{Path: "internal/audit/remediation.go", StartLine: 86}}
	}
	bundle := Bundle{SchemaVersion: SchemaVersion, Target: ".", Digest: "sha256:" + strings.Repeat("d", 64), Findings: []findings.Finding{mk("f1"), mk("f2"), mk("f3"), {ID: "f4", Tool: "scanner.opengrep", RuleID: mk("f4").RuleID, Title: mk("f4").Title, Severity: findings.SeverityHigh, Location: findings.Location{Path: "internal/audit/remediation.go", StartLine: 66}}}}
	groups, _ := buildRemediation(&bundle)
	if len(groups) != 2 {
		t.Fatalf("expected 2 groups (same rule+location collapsed), got %d: %#v", len(groups), groups)
	}
	var tallied *remediationGroup
	for i := range groups {
		if groups[i].Location == "internal/audit/remediation.go:86" {
			tallied = &groups[i]
		}
	}
	if tallied == nil || strings.Join(tallied.FindingIDs, ",") != "f1,f2,f3" {
		t.Fatalf("occurrences not tallied: %#v", groups)
	}
	if !strings.Contains(tallied.Prompt, "Finding IDs: f1, f2, f3") {
		t.Fatalf("prompt missing all finding IDs:\n%s", tallied.Prompt)
	}
}

func TestRenderHTMLShowsAILabeledDedupSuggestions(t *testing.T) {
	bundle := Bundle{
		SchemaVersion: SchemaVersion, Target: ".", Digest: "sha256:" + strings.Repeat("e", 64), Status: "succeeded",
		Findings: []findings.Finding{grypeFinding("f1", "leftpad", "1.0.0", "CVE-2026-0001", []string{"1.0.3"}), grypeFinding("f2", "rightpad", "2.0.0", "CVE-2026-0002", []string{"2.0.5"})},
		Dedup:    []DedupSuggestion{{GroupID: "r2", DuplicateOf: "r1", Rationale: "both fix the same dependency line", Source: "ai", Status: "hypothesis"}},
	}
	var out bytes.Buffer
	if err := RenderHTML(&out, bundle); err != nil {
		t.Fatal(err)
	}
	html := out.String()
	for _, want := range []string{"AI dedup suggestions", "hypothesis · unverified", "r2</code> may duplicate <code>r1", "both fix the same dependency line"} {
		if !strings.Contains(html, want) {
			t.Fatalf("HTML missing %q", want)
		}
	}
}

func TestBuildRemediationIncludesAILabeledHypothesis(t *testing.T) {
	bundle := Bundle{
		SchemaVersion: SchemaVersion, Target: ".", Digest: "sha256:" + strings.Repeat("b", 64),
		Findings:        []findings.Finding{{ID: "f1", Tool: "scanner.opengrep", RuleID: "rule-x", Title: "dangerous eval", Severity: findings.SeverityMedium, Description: "eval used", Properties: map[string]any{"message": "eval"}}},
		Recommendations: []Recommendation{{FindingID: "f1", Source: "ai", Status: "hypothesis", Remediation: "Replace eval with a parser."}},
	}
	groups, _ := buildRemediation(&bundle)
	if len(groups) != 1 {
		t.Fatalf("groups: %#v", groups)
	}
	prompt := groups[0].Prompt
	for _, want := range []string{"AI remediation hypothesis (unverified, advisory only): Replace eval with a parser.", `Resolve medium finding "dangerous eval" (rule-x) reported by scanner.opengrep`, "Description: eval used", "Evidence:"} {
		if !strings.Contains(prompt, want) {
			t.Fatalf("finding prompt missing %q:\n%s", want, prompt)
		}
	}
}

func TestRenderHTMLRemediationPlanPaginationAndPromptLibrary(t *testing.T) {
	advisories := []string{"CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003", "CVE-2026-0004", "CVE-2026-0005", "GHSA-xxxx-yyyy-zzzz", "OSV-2026-777"}
	var items []findings.Finding
	for i, advisory := range advisories {
		items = append(items, grypeFinding(fmt.Sprintf("f%d", i+1), "leftpad", "1.0.0", advisory, []string{"1.0.3"}))
	}
	items = append(items, findings.Finding{ID: "fg1", Tool: "scanner.opengrep", RuleID: "go.lang.security.audit.net.use-tls.use-tls", Title: "HTTP server without TLS", Severity: findings.SeverityHigh, Location: findings.Location{Path: "main.go", StartLine: 42}})
	bundle := Bundle{
		SchemaVersion: SchemaVersion, GeneratedAt: time.Date(2026, 11, 14, 1, 2, 3, 0, time.UTC), Target: ".", Status: "succeeded",
		Metrics:  Metrics{Findings: len(items), BySeverity: map[string]int{"high": len(items)}, ByTool: map[string]int{"scanner.grype": 7, "scanner.opengrep": 1}},
		Findings: items,
	}
	if err := setDigest(&bundle); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := RenderHTML(&out, bundle); err != nil {
		t.Fatal(err)
	}
	html := out.String()
	for _, want := range []string{
		"Remediation plan", "Copy all remediation prompts", `value="ALL"`, "Copy fix prompt", `class="caphe-prompt"`,
		`data-findings="f1 f2 f3 f4 f5 f6 f7 "`, "caphe-prompt\" caphe-audit.html", "grep -n", "7 advisories", "Installed → fixed",
		`href="https://nvd.nist.gov/vuln/detail/CVE-2026-0001"`,
		`href="https://github.com/advisories/GHSA-xxxx-yyyy-zzzz"`,
		`href="https://osv.dev/vulnerability/OSV-2026-777"`,
		`class="adv-more" hidden`,
		`(+1 more)`,
		`href="https://semgrep.dev/r/go.lang.security.audit.net.use-tls.use-tls"`,
		"appearance:none",
		"Copied!",
		"document.execCommand('copy')",
	} {
		if !strings.Contains(html, want) {
			t.Fatalf("HTML missing %q", want)
		}
	}
	if strings.Contains(html, `<script class="caphe-prompt"`) {
		t.Fatal("prompt library must be inert text, not executable markup")
	}
}

func TestRemediationPromptEscapesUntrustedTitles(t *testing.T) {
	bundle := Bundle{
		SchemaVersion: SchemaVersion, Target: ".", Digest: "sha256:" + strings.Repeat("c", 64),
		Findings: []findings.Finding{{ID: "f1", Tool: "scanner.opengrep", RuleID: "r", Title: "unsafe <script>alert(1)</script>", Severity: findings.SeverityHigh}},
	}
	groups, _ := buildRemediation(&bundle)
	var out bytes.Buffer
	if err := auditHTML.Execute(&out, htmlData{Payload: "e30=", Groups: groups, Note: "n"}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "unsafe <script>") {
		t.Fatal("untrusted finding title emitted as executable markup")
	}
	if !strings.Contains(out.String(), "unsafe &lt;script&gt;") {
		t.Fatal("untrusted finding title was not escaped")
	}
}
