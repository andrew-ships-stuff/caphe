package githubreview

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/andrew-ships-stuff/caphe/internal/findings"
)

const SchemaVersion = "caphe.dev/github/pr-review/v1alpha1"
const MaxArtifactBytes = 16 << 20

type LineRange struct {
	Start int `json:"start"`
	End   int `json:"end"`
}

type ChangedFile struct {
	Path       string      `json:"path"`
	AddedLines []LineRange `json:"addedLines,omitempty"`
}

type Recommendation struct {
	FindingID     string   `json:"findingId"`
	EvidenceIDs   []string `json:"evidenceIds"`
	Explanation   string   `json:"explanation"`
	Remediation   string   `json:"remediation"`
	Source        string   `json:"source"`
	Status        string   `json:"status"`
	ModelDigest   string   `json:"modelDigest,omitempty"`
	PromptVersion string   `json:"promptVersion,omitempty"`
	SchemaVersion string   `json:"schemaVersion,omitempty"`
}

type AIInfo struct {
	Enabled         bool          `json:"enabled"`
	Model           string        `json:"model,omitempty"`
	ModelDigest     string        `json:"modelDigest,omitempty"`
	MaxCalls        int           `json:"maxCalls,omitempty"`
	MaxInputTokens  int           `json:"maxInputTokens,omitempty"`
	MaxOutputTokens int           `json:"maxOutputTokens,omitempty"`
	MaxTotalTime    time.Duration `json:"maxTotalTime,omitempty"`
	Calls           int           `json:"calls"`
	Errors          []string      `json:"errors,omitempty"`
}

type Comment struct {
	FindingID string `json:"findingId"`
	Path      string `json:"path"`
	Line      int    `json:"line"`
	Side      string `json:"side"`
	Body      string `json:"body"`
}

type Policy struct {
	SeverityThreshold findings.Severity `json:"severityThreshold"`
	Fail              bool              `json:"fail"`
	Reason            string            `json:"reason,omitempty"`
}

type Metrics struct {
	Introduced int `json:"introduced"`
	Resolved   int `json:"resolved"`
	Existing   int `json:"existing"`
	Inline     int `json:"inlineComments"`
	ModelCalls int `json:"modelCalls"`
}

type Artifact struct {
	SchemaVersion   string             `json:"schemaVersion"`
	Repository      string             `json:"repository"`
	PullRequest     int                `json:"pullRequest"`
	BaseSHA         string             `json:"baseSha"`
	HeadSHA         string             `json:"headSha"`
	GeneratedAt     time.Time          `json:"generatedAt"`
	ChangedFiles    []ChangedFile      `json:"changedFiles"`
	Introduced      []findings.Finding `json:"introduced"`
	Resolved        []findings.Finding `json:"resolved"`
	Existing        []findings.Finding `json:"existing"`
	Recommendations []Recommendation   `json:"recommendations,omitempty"`
	Comments        []Comment          `json:"comments,omitempty"`
	Summary         string             `json:"summary"`
	Policy          Policy             `json:"policy"`
	Metrics         Metrics            `json:"metrics"`
	AI              AIInfo             `json:"ai"`
	Digest          string             `json:"digest"`
}

type Options struct {
	Repository        string
	PullRequest       int
	BaseSHA           string
	HeadSHA           string
	SeverityThreshold findings.Severity
	FailOnNew         bool
	MaxComments       int
}

var shaPattern = regexp.MustCompile(`^[0-9a-f]{40,64}$`)
var repositoryPattern = regexp.MustCompile(`^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$`)

func LoadReport(path string) ([]findings.Finding, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(b) > MaxArtifactBytes {
		return nil, fmt.Errorf("report exceeds %d bytes", MaxArtifactBytes)
	}
	trimmed := bytes.TrimLeft(b, " \t\r\n")
	if len(trimmed) > 0 && trimmed[0] == '{' {
		var native struct {
			Findings []findings.Finding `json:"findings"`
		}
		if err := json.Unmarshal(b, &native); err != nil {
			return nil, fmt.Errorf("parse findings report: %w", err)
		}
		return native.Findings, nil
	}
	var direct []findings.Finding
	if err := json.Unmarshal(b, &direct); err != nil {
		return nil, fmt.Errorf("parse findings report: %w", err)
	}
	return direct, nil
}

func CollectDiff(ctx context.Context, repositoryRoot, baseSHA, headSHA string) ([]ChangedFile, error) {
	if !shaPattern.MatchString(baseSHA) || !shaPattern.MatchString(headSHA) {
		return nil, fmt.Errorf("base and head must be full hexadecimal commit SHAs")
	}
	cmd := exec.CommandContext(ctx, "git", "diff", "--no-ext-diff", "--unified=0", "--no-color", baseSHA, headSHA, "--")
	cmd.Dir = repositoryRoot
	cmd.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1")
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("collect git diff: %w", err)
	}
	return ParseDiff(out)
}

var hunkPattern = regexp.MustCompile(`^@@ -[0-9]+(?:,[0-9]+)? \+([0-9]+)(?:,([0-9]+))? @@`)

func ParseDiff(raw []byte) ([]ChangedFile, error) {
	files := map[string]*ChangedFile{}
	var current *ChangedFile
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.HasPrefix(line, "+++ b/") {
			path := strings.TrimPrefix(line, "+++ b/")
			path = filepath.ToSlash(filepath.Clean(path))
			if path == "." || strings.HasPrefix(path, "../") {
				return nil, fmt.Errorf("unsafe diff path %q", path)
			}
			if files[path] == nil {
				files[path] = &ChangedFile{Path: path}
			}
			current = files[path]
			continue
		}
		if current == nil || !strings.HasPrefix(line, "@@") {
			continue
		}
		match := hunkPattern.FindStringSubmatch(line)
		if match == nil {
			return nil, fmt.Errorf("invalid diff hunk %q", line)
		}
		start, _ := strconv.Atoi(match[1])
		count := 1
		if match[2] != "" {
			count, _ = strconv.Atoi(match[2])
		}
		if count > 0 {
			current.AddedLines = append(current.AddedLines, LineRange{Start: start, End: start + count - 1})
		}
	}
	paths := make([]string, 0, len(files))
	for path := range files {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	result := make([]ChangedFile, 0, len(paths))
	for _, path := range paths {
		result = append(result, *files[path])
	}
	return result, nil
}

func Analyze(base, head []findings.Finding, changed []ChangedFile, options Options) (Artifact, error) {
	if !repositoryPattern.MatchString(options.Repository) || options.PullRequest <= 0 {
		return Artifact{}, fmt.Errorf("valid repository and pull request number are required")
	}
	if !shaPattern.MatchString(options.BaseSHA) || !shaPattern.MatchString(options.HeadSHA) || options.BaseSHA == options.HeadSHA {
		return Artifact{}, fmt.Errorf("valid distinct base and head SHAs are required")
	}
	if options.MaxComments < 0 || options.MaxComments > 100 {
		return Artifact{}, fmt.Errorf("max comments must be between 0 and 100")
	}
	if _, ok := severityRank[options.SeverityThreshold]; !ok {
		return Artifact{}, fmt.Errorf("invalid severity threshold")
	}
	introduced, resolved, existing := classify(base, head)
	a := Artifact{SchemaVersion: SchemaVersion, Repository: options.Repository, PullRequest: options.PullRequest, BaseSHA: options.BaseSHA, HeadSHA: options.HeadSHA, GeneratedAt: time.Now().UTC(), ChangedFiles: changed, Introduced: introduced, Resolved: resolved, Existing: existing}
	for _, finding := range introduced {
		rec := Recommendation{FindingID: finding.ID, EvidenceIDs: []string{finding.ID}, Explanation: fmt.Sprintf("%s reported %s at %s.", finding.Tool, finding.RuleID, displayLocation(finding)), Remediation: "Review the cited scanner evidence and apply the narrowest change that removes the reported condition; rerun the same compiled Caphe workflow to verify the result.", Source: "deterministic", Status: "evidence-backed-recommendation"}
		a.Recommendations = append(a.Recommendations, rec)
		if len(a.Comments) < options.MaxComments && lineIsChanged(changed, finding.Location.Path, finding.Location.StartLine) && meetsThreshold(finding.Severity, options.SeverityThreshold) {
			a.Comments = append(a.Comments, Comment{FindingID: finding.ID, Path: filepath.ToSlash(finding.Location.Path), Line: finding.Location.StartLine, Side: "RIGHT", Body: commentBody(finding, rec)})
		}
	}
	fail := options.FailOnNew && anyAtThreshold(introduced, options.SeverityThreshold)
	a.Policy = Policy{SeverityThreshold: options.SeverityThreshold, Fail: fail}
	if fail {
		a.Policy.Reason = fmt.Sprintf("new finding meets the %s severity threshold", options.SeverityThreshold)
	}
	a.Metrics = Metrics{Introduced: len(introduced), Resolved: len(resolved), Existing: len(existing), Inline: len(a.Comments)}
	a.Summary = renderSummary(a)
	if err := setDigest(&a); err != nil {
		return Artifact{}, err
	}
	return a, Validate(a, options.MaxComments)
}

func classify(base, head []findings.Finding) (introduced, resolved, existing []findings.Finding) {
	baseExact := map[string]int{}
	baseSemantic := map[string][]int{}
	matched := make([]bool, len(base))
	for i, f := range base {
		baseExact[f.Fingerprint] = i
		baseSemantic[semanticKey(f)] = append(baseSemantic[semanticKey(f)], i)
	}
	for _, f := range head {
		idx, ok := baseExact[f.Fingerprint]
		if ok && !matched[idx] {
			matched[idx] = true
			existing = append(existing, f)
			continue
		}
		found := -1
		for _, candidate := range baseSemantic[semanticKey(f)] {
			if !matched[candidate] {
				found = candidate
				break
			}
		}
		if found >= 0 {
			matched[found] = true
			existing = append(existing, f)
		} else {
			introduced = append(introduced, f)
		}
	}
	for i, f := range base {
		if !matched[i] {
			resolved = append(resolved, f)
		}
	}
	sortFindings(introduced)
	sortFindings(resolved)
	sortFindings(existing)
	return
}

func semanticKey(f findings.Finding) string {
	return strings.Join([]string{f.Tool, f.RuleID, filepath.ToSlash(filepath.Clean(f.Location.Path)), f.Title}, "\x00")
}

func sortFindings(items []findings.Finding) {
	sort.Slice(items, func(i, j int) bool { return items[i].ID < items[j].ID })
}

func lineIsChanged(files []ChangedFile, path string, line int) bool {
	path = filepath.ToSlash(filepath.Clean(path))
	for _, file := range files {
		if file.Path != path {
			continue
		}
		for _, r := range file.AddedLines {
			if line >= r.Start && line <= r.End {
				return true
			}
		}
	}
	return false
}

var severityRank = map[findings.Severity]int{findings.SeverityUnknown: 0, findings.SeverityInfo: 1, findings.SeverityLow: 2, findings.SeverityMedium: 3, findings.SeverityHigh: 4, findings.SeverityCritical: 5}

func meetsThreshold(actual, threshold findings.Severity) bool {
	return severityRank[actual] >= severityRank[threshold]
}
func anyAtThreshold(items []findings.Finding, threshold findings.Severity) bool {
	for _, item := range items {
		if meetsThreshold(item.Severity, threshold) {
			return true
		}
	}
	return false
}

func displayLocation(f findings.Finding) string {
	if f.Location.Path == "" {
		return "repository-level evidence"
	}
	return fmt.Sprintf("%s:%d", f.Location.Path, f.Location.StartLine)
}

func commentBody(f findings.Finding, r Recommendation) string {
	return fmt.Sprintf("<!-- caphe-finding:%s -->\n**Caphe: %s** (`%s`)\n\n%s\n\nRecommendation: %s\n\nEvidence: `%s` · scanner observation, not an exploitability claim.", f.ID, strings.ToUpper(string(f.Severity)), f.RuleID, r.Explanation, r.Remediation, f.ID)
}

func renderSummary(a Artifact) string {
	return fmt.Sprintf("<!-- caphe-review:%d -->\n## Caphe security review\n\n| Introduced | Resolved | Existing | Inline candidates |\n|---:|---:|---:|---:|\n| %d | %d | %d | %d |\n\nBase `%s` → head `%s`. Policy decision: **%s**. AI recommendations, when present, are unverified advisory text and never determine this decision.\n", a.PullRequest, len(a.Introduced), len(a.Resolved), len(a.Existing), len(a.Comments), shortSHA(a.BaseSHA), shortSHA(a.HeadSHA), map[bool]string{true: "fail", false: "pass"}[a.Policy.Fail])
}

func shortSHA(s string) string {
	if len(s) > 12 {
		return s[:12]
	}
	return s
}

func digest(a Artifact) (string, error) {
	a.Digest = ""
	b, err := json.Marshal(a)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func setDigest(a *Artifact) error {
	d, err := digest(*a)
	if err != nil {
		return err
	}
	a.Digest = d
	return nil
}

func Validate(a Artifact, maxComments int) error {
	if a.SchemaVersion != SchemaVersion || !repositoryPattern.MatchString(a.Repository) || a.PullRequest <= 0 || !shaPattern.MatchString(a.BaseSHA) || !shaPattern.MatchString(a.HeadSHA) || a.BaseSHA == a.HeadSHA {
		return fmt.Errorf("invalid artifact identity")
	}
	if maxComments < 0 || maxComments > 100 || len(a.Comments) > maxComments {
		return fmt.Errorf("artifact exceeds comment limit")
	}
	expected, err := digest(a)
	if err != nil || !constantStringEqual(expected, a.Digest) {
		return fmt.Errorf("artifact digest mismatch")
	}
	introduced := map[string]bool{}
	for _, f := range a.Introduced {
		if f.ID == "" || f.ID != f.Fingerprint {
			return fmt.Errorf("invalid introduced finding identity")
		}
		introduced[f.ID] = true
	}
	for _, rec := range a.Recommendations {
		if !introduced[rec.FindingID] || len(rec.EvidenceIDs) == 0 || (rec.Source != "deterministic" && rec.Source != "ai") {
			return fmt.Errorf("invalid recommendation reference")
		}
		for _, id := range rec.EvidenceIDs {
			if !introduced[id] {
				return fmt.Errorf("fabricated evidence reference %q", id)
			}
		}
		if rec.Source == "ai" && (rec.Status != "hypothesis" || rec.ModelDigest == "" || rec.PromptVersion == "" || rec.SchemaVersion == "") {
			return fmt.Errorf("AI recommendation must remain a versioned hypothesis")
		}
	}
	seenComments := map[string]bool{}
	for _, c := range a.Comments {
		if !introduced[c.FindingID] || seenComments[c.FindingID] || c.Side != "RIGHT" || c.Line <= 0 || len(c.Body) > 65536 || !lineIsChanged(a.ChangedFiles, c.Path, c.Line) {
			return fmt.Errorf("invalid inline comment")
		}
		seenComments[c.FindingID] = true
	}
	if a.Metrics.Introduced != len(a.Introduced) || a.Metrics.Resolved != len(a.Resolved) || a.Metrics.Existing != len(a.Existing) || a.Metrics.Inline != len(a.Comments) {
		return fmt.Errorf("artifact metrics mismatch")
	}
	return nil
}

func constantStringEqual(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	return bytes.Equal([]byte(a), []byte(b))
}

func LoadArtifact(path string, maxComments int) (Artifact, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return Artifact{}, err
	}
	if len(b) > MaxArtifactBytes {
		return Artifact{}, fmt.Errorf("artifact exceeds %d bytes", MaxArtifactBytes)
	}
	var a Artifact
	decoder := json.NewDecoder(bytes.NewReader(b))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&a); err != nil {
		return Artifact{}, fmt.Errorf("parse review artifact: %w", err)
	}
	if err := Validate(a, maxComments); err != nil {
		return Artifact{}, err
	}
	return a, nil
}
