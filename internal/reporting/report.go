package reporting

import (
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"sort"
	"time"

	"github.com/andrew-ships-stuff/caphe/internal/findings"
)

type Native struct {
	SchemaVersion string             `json:"schemaVersion"`
	GeneratedAt   time.Time          `json:"generatedAt"`
	Findings      []findings.Finding `json:"findings"`
}

func JSON(w io.Writer, items []findings.Finding) error {
	if items == nil {
		items = []findings.Finding{}
	}
	return json.NewEncoder(w).Encode(Native{SchemaVersion: "caphe.dev/report/v1alpha1", GeneratedAt: time.Now().UTC(), Findings: items})
}

type sarif struct {
	Version string     `json:"version"`
	Schema  string     `json:"$schema"`
	Runs    []sarifRun `json:"runs"`
}
type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}
type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}
type sarifDriver struct {
	Name           string      `json:"name"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules,omitempty"`
}
type sarifRule struct {
	ID               string    `json:"id"`
	Name             string    `json:"name,omitempty"`
	ShortDescription sarifText `json:"shortDescription"`
}
type sarifText struct {
	Text string `json:"text"`
}
type sarifResult struct {
	RuleID       string            `json:"ruleId"`
	Level        string            `json:"level"`
	Message      sarifText         `json:"message"`
	Locations    []sarifLocation   `json:"locations,omitempty"`
	Fingerprints map[string]string `json:"fingerprints,omitempty"`
	Properties   map[string]any    `json:"properties,omitempty"`
}
type sarifLocation struct {
	PhysicalLocation physicalLocation `json:"physicalLocation"`
}
type physicalLocation struct {
	ArtifactLocation artifactLocation `json:"artifactLocation"`
	Region           region           `json:"region,omitempty"`
}
type artifactLocation struct {
	URI string `json:"uri"`
}
type region struct {
	StartLine int `json:"startLine,omitempty"`
	EndLine   int `json:"endLine,omitempty"`
}

func SARIF(w io.Writer, items []findings.Finding) error {
	rules := map[string]sarifRule{}
	results := make([]sarifResult, 0, len(items))
	for _, f := range items {
		key := f.Tool + ":" + f.RuleID
		rules[key] = sarifRule{ID: key, Name: f.RuleID, ShortDescription: sarifText{Text: f.Title}}
		r := sarifResult{RuleID: key, Level: sarifLevel(f.Severity), Message: sarifText{Text: f.Title}, Fingerprints: map[string]string{"caphe/v1": f.Fingerprint}, Properties: map[string]any{"sourceTool": f.Tool, "verificationStatus": "confirmed-scanner-observation"}}
		if f.Location.Path != "" {
			r.Locations = []sarifLocation{{PhysicalLocation: physicalLocation{ArtifactLocation: artifactLocation{URI: f.Location.Path}, Region: region{StartLine: f.Location.StartLine, EndLine: f.Location.EndLine}}}}
		}
		results = append(results, r)
	}
	keys := make([]string, 0, len(rules))
	for k := range rules {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	rs := make([]sarifRule, 0, len(keys))
	for _, k := range keys {
		rs = append(rs, rules[k])
	}
	doc := sarif{Version: "2.1.0", Schema: "https://json.schemastore.org/sarif-2.1.0.json", Runs: []sarifRun{{Tool: sarifTool{Driver: sarifDriver{Name: "Caphe", InformationURI: "https://github.com/andrew-ships-stuff/caphe", Rules: rs}}, Results: results}}}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}

func sarifLevel(s findings.Severity) string {
	switch s {
	case findings.SeverityCritical, findings.SeverityHigh:
		return "error"
	case findings.SeverityMedium:
		return "warning"
	default:
		return "note"
	}
}

var htmlReport = template.Must(template.New("report").Funcs(template.FuncMap{"sev": func(s findings.Severity) string { return string(s) }}).Parse(`<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Caphe Security Report</title><style>body{font:15px system-ui;max-width:1100px;margin:40px auto;padding:0 20px;color:#17212b;background:#f6f8fa}h1{margin-bottom:4px}.card{background:white;border:1px solid #d8dee4;border-radius:10px;padding:18px;margin:12px 0}.sev{font-weight:700;text-transform:uppercase}.critical,.high{color:#b42318}.medium{color:#b54708}.low{color:#027a48}code{word-break:break-all}</style></head><body><h1>Caphe Security Report</h1><p>{{len .}} observed scanner findings. Hypotheses are never presented as confirmed observations.</p>{{range .}}<section class="card"><div class="sev {{sev .Severity}}">{{.Severity}} · {{.Tool}}</div><h2>{{.Title}}</h2><p><code>{{.RuleID}}</code></p>{{if .Location.Path}}<p>{{.Location.Path}}:{{.Location.StartLine}}</p>{{end}}<small>ID: {{.ID}}</small></section>{{else}}<section class="card">No findings recorded.</section>{{end}}</body></html>`))

func HTML(w io.Writer, items []findings.Finding) error {
	if err := htmlReport.Execute(w, items); err != nil {
		return fmt.Errorf("render HTML: %w", err)
	}
	return nil
}
