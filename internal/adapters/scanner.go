package adapters

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/andrew-ships-stuff/caphe/internal/findings"
)

type Scanner struct{ id, binary, version string }

func NewScanner(id, binary string) *Scanner {
	return &Scanner{id: id, binary: binary, version: "adapter-v1"}
}
func (s *Scanner) ID() string                 { return s.id }
func (s *Scanner) Version() string            { return s.version }
func (s *Scanner) Capabilities() []Capability { return []Capability{"repository-scan"} }
func (s *Scanner) Detect(ctx context.Context) ToolInfo {
	p, err := exec.LookPath(s.binary)
	if err != nil {
		return ToolInfo{ID: s.id, Error: err.Error()}
	}
	args := []string{"version"}
	if s.binary == "opengrep" {
		args = []string{"--version"}
	}
	out, _, _, err := RunCommand(ctx, ".", p, args, 1<<20)
	info := ToolInfo{ID: s.id, Available: err == nil, Path: p, Version: strings.TrimSpace(string(out))}
	if err != nil {
		info.Error = err.Error()
	}
	return info
}
func (s *Scanner) Validate(raw json.RawMessage) error {
	var c map[string]any
	if err := json.Unmarshal(raw, &c); err != nil {
		return err
	}
	allowed := map[string]bool{}
	switch s.id {
	case "scanner.opengrep":
		allowed["ruleset"] = true
	case "scanner.syft":
		allowed["outputFormat"] = true
	case "scanner.grype":
		allowed["input"] = true
	case "scanner.gitleaks":
		allowed["redact"] = true
	case "scanner.poutine":
		allowed["config"] = true
	}
	for k := range c {
		if !allowed[k] {
			return fmt.Errorf("unsupported configuration key %q", k)
		}
	}
	return nil
}
func (s *Scanner) Execute(ctx context.Context, req Request) (Result, error) {
	start := time.Now()
	p, err := exec.LookPath(s.binary)
	if err != nil {
		return Result{}, fmt.Errorf("%s unavailable: %w", s.binary, err)
	}
	var cfg map[string]any
	if err := json.Unmarshal(req.Config, &cfg); err != nil {
		return Result{}, err
	}
	args, err := s.args(req.Target, cfg, req.Inputs)
	if err != nil {
		return Result{}, err
	}
	out, _, code, err := RunCommand(ctx, req.Target, p, args, req.MaxOutput)
	if err != nil {
		return Result{Command: append([]string{p}, args...), ExitCode: code, Duration: time.Since(start)}, err
	}
	parsed, err := ParseScannerOutput(s.id, out)
	if err != nil {
		return Result{Raw: out, Command: append([]string{p}, args...), ExitCode: code, Duration: time.Since(start)}, err
	}
	return Result{Findings: parsed, Raw: out, Command: append([]string{p}, args...), ExitCode: code, Duration: time.Since(start), Version: s.Detect(ctx).Version}, nil
}
func (s *Scanner) args(target string, cfg map[string]any, inputs map[string]string) ([]string, error) {
	switch s.id {
	case "scanner.opengrep":
		rules := "p/security-audit"
		if v, ok := cfg["ruleset"].(string); ok && v != "" {
			rules = v
		}
		if strings.HasPrefix(rules, "-") {
			return nil, fmt.Errorf("invalid ruleset")
		}
		return []string{"scan", "--json", "--config", rules, "."}, nil
	case "scanner.syft":
		format := "cyclonedx-json"
		if v, ok := cfg["outputFormat"].(string); ok && v != "" {
			format = v
		}
		if format != "cyclonedx-json" && format != "syft-json" {
			return nil, fmt.Errorf("unsupported outputFormat %q", format)
		}
		return []string{"scan", ".", "-o", format}, nil
	case "scanner.grype":
		input := "."
		if v := inputs["sbom"]; v != "" {
			input = "sbom:" + v
		}
		return []string{input, "-o", "json"}, nil
	case "scanner.gitleaks":
		return []string{"detect", "--source", ".", "--report-format", "json", "--report-path", "-", "--redact", "--exit-code", "0"}, nil
	case "scanner.poutine":
		args := []string{"analyze_local", ".", "--format", "sarif", "--quiet"}
		if v, ok := cfg["config"].(string); ok && v != "" {
			if strings.HasPrefix(v, "-") || filepath.IsAbs(v) || strings.Contains(filepath.ToSlash(v), "../") {
				return nil, fmt.Errorf("invalid poutine config path")
			}
			args = append(args, "--config", v)
		}
		return args, nil
	}
	return nil, fmt.Errorf("unsupported scanner")
}

func ParseScannerOutput(tool string, raw []byte) (findings.Result, error) {
	var doc any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return findings.Result{}, fmt.Errorf("parse %s JSON: %w", tool, err)
	}
	result := findings.Result{Metadata: map[string]any{"source": tool}}
	switch tool {
	case "scanner.opengrep":
		m, _ := doc.(map[string]any)
		rows, _ := m["results"].([]any)
		for _, row := range rows {
			r, _ := row.(map[string]any)
			path, _ := r["path"].(string)
			check, _ := r["check_id"].(string)
			extra, _ := r["extra"].(map[string]any)
			msg, _ := extra["message"].(string)
			sev, _ := extra["severity"].(string)
			start, _ := r["start"].(map[string]any)
			result.Findings = append(result.Findings, newFinding(tool, check, msg, sev, path, intNumber(start["line"]), r))
		}
	case "scanner.gitleaks":
		rows, _ := doc.([]any)
		for _, row := range rows {
			r, _ := row.(map[string]any)
			rule, _ := r["RuleID"].(string)
			desc, _ := r["Description"].(string)
			file, _ := r["File"].(string)
			result.Findings = append(result.Findings, newFinding(tool, rule, desc, "high", file, intNumber(r["StartLine"]), redactMap(r)))
		}
	case "scanner.grype":
		m, _ := doc.(map[string]any)
		rows, _ := m["matches"].([]any)
		for _, row := range rows {
			r, _ := row.(map[string]any)
			vuln, _ := r["vulnerability"].(map[string]any)
			art, _ := r["artifact"].(map[string]any)
			id, _ := vuln["id"].(string)
			sev, _ := vuln["severity"].(string)
			name, _ := art["name"].(string)
			ver, _ := art["version"].(string)
			result.Findings = append(result.Findings, newFinding(tool, id, fmt.Sprintf("%s affects %s@%s", id, name, ver), sev, "", 0, r))
		}
	case "scanner.syft":
		// An SBOM is evidence rather than a vulnerability list. Preserve package count in metadata.
		m, _ := doc.(map[string]any)
		if rows, ok := m["components"].([]any); ok {
			result.Metadata["packageCount"] = len(rows)
		} else if rows, ok := m["artifacts"].([]any); ok {
			result.Metadata["packageCount"] = len(rows)
		}
	case "scanner.poutine":
		m, _ := doc.(map[string]any)
		runs, _ := m["runs"].([]any)
		for _, runValue := range runs {
			run, _ := runValue.(map[string]any)
			results, _ := run["results"].([]any)
			for _, resultValue := range results {
				r, _ := resultValue.(map[string]any)
				ruleID, _ := r["ruleId"].(string)
				level, _ := r["level"].(string)
				message := ruleID
				if msg, ok := r["message"].(map[string]any); ok {
					if value, ok := msg["text"].(string); ok && value != "" {
						message = value
					}
				}
				path := ""
				line := 0
				if locations, ok := r["locations"].([]any); ok && len(locations) > 0 {
					if loc, ok := locations[0].(map[string]any); ok {
						if physical, ok := loc["physicalLocation"].(map[string]any); ok {
							if artifact, ok := physical["artifactLocation"].(map[string]any); ok {
								path, _ = artifact["uri"].(string)
							}
							if region, ok := physical["region"].(map[string]any); ok {
								line = intNumber(region["startLine"])
							}
						}
					}
				}
				result.Findings = append(result.Findings, newFinding(tool, ruleID, message, level, path, line, r))
			}
		}
	default:
		return findings.Result{}, fmt.Errorf("unsupported parser %q", tool)
	}
	return result, nil
}
func intNumber(v any) int { f, _ := v.(float64); return int(f) }
func normalizedSeverity(s string) findings.Severity {
	switch strings.ToLower(s) {
	case "critical":
		return findings.SeverityCritical
	case "high", "warning", "error":
		return findings.SeverityHigh
	case "medium":
		return findings.SeverityMedium
	case "low":
		return findings.SeverityLow
	case "info", "note":
		return findings.SeverityInfo
	default:
		return findings.SeverityUnknown
	}
}
func newFinding(tool, rule, title, sev, path string, line int, props map[string]any) findings.Finding {
	if title == "" {
		title = rule
	}
	fpRaw := tool + "\x00" + rule + "\x00" + filepath.ToSlash(path) + fmt.Sprint(line)
	sum := sha256.Sum256([]byte(fpRaw))
	fp := "sha256:" + hex.EncodeToString(sum[:])
	return findings.Finding{ID: fp, Fingerprint: fp, Tool: tool, RuleID: rule, Title: title, Severity: normalizedSeverity(sev), Location: findings.Location{Path: filepath.ToSlash(path), StartLine: line}, Properties: props}
}
func redactMap(in map[string]any) map[string]any {
	out := make(map[string]any, len(in))
	for k, v := range in {
		switch strings.ToLower(k) {
		case "secret", "match", "entropy":
			continue
		}
		out[k] = v
	}
	return out
}
