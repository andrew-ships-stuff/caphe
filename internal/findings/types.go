package findings

import "time"

type Severity string

const (
	SeverityUnknown  Severity = "unknown"
	SeverityInfo     Severity = "info"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

type Location struct {
	Path      string `json:"path,omitempty"`
	StartLine int    `json:"startLine,omitempty"`
	EndLine   int    `json:"endLine,omitempty"`
	URI       string `json:"uri,omitempty"`
}

type Finding struct {
	ID             string         `json:"id"`
	Tool           string         `json:"tool"`
	RuleID         string         `json:"ruleId"`
	Title          string         `json:"title"`
	Description    string         `json:"description,omitempty"`
	Severity       Severity       `json:"severity"`
	Category       string         `json:"category,omitempty"`
	Location       Location       `json:"location,omitempty"`
	Fingerprint    string         `json:"fingerprint"`
	ArtifactDigest string         `json:"artifactDigest"`
	Properties     map[string]any `json:"properties,omitempty"`
	ObservedAt     time.Time      `json:"observedAt"`
}

type Result struct {
	Findings []Finding      `json:"findings"`
	Metadata map[string]any `json:"metadata,omitempty"`
}
