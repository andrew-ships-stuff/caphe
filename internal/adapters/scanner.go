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
	if s.binary == "opengrep" || s.binary == "osv-scanner" || s.binary == "checkov" {
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
	case "scanner.opa":
		allowed["policy"] = true
		allowed["query"] = true
		allowed["input"] = true
	case "scanner.checkov":
		allowed["framework"] = true
	case "scanner.osv":
		allowed["offline"] = true
	case "scanner.kubescape":
		allowed["useArtifactsFrom"] = true
	}
	for k := range c {
		if !allowed[k] {
			return fmt.Errorf("unsupported configuration key %q", k)
		}
	}
	if s.id == "scanner.opa" {
		if _, err := requiredSafeString(c, "policy", true); err != nil {
			return err
		}
		if _, err := requiredSafeString(c, "query", false); err != nil {
			return err
		}
		if _, ok := c["input"]; ok {
			if _, err := requiredSafeString(c, "input", true); err != nil {
				return err
			}
		}
	}
	if s.id == "scanner.checkov" {
		if _, ok := c["framework"]; ok {
			if _, err := requiredSafeString(c, "framework", false); err != nil {
				return err
			}
		}
	}
	if s.id == "scanner.osv" {
		if value, ok := c["offline"]; ok {
			if _, ok := value.(bool); !ok {
				return fmt.Errorf("offline must be a boolean")
			}
		}
	}
	if s.id == "scanner.kubescape" {
		if _, ok := c["useArtifactsFrom"]; ok {
			if _, err := requiredSafeString(c, "useArtifactsFrom", true); err != nil {
				return err
			}
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
	if err != nil && !(s.id == "scanner.osv" && code == 1) {
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
	case "scanner.osv":
		args := []string{"scan", "source", "--format", "json", "--recursive"}
		if offline, _ := cfg["offline"].(bool); offline {
			args = append(args, "--offline")
		}
		return append(args, "."), nil
	case "scanner.checkov":
		args := []string{"-d", ".", "-o", "json", "--soft-fail", "--skip-results-upload", "--skip-download"}
		if framework, ok := cfg["framework"].(string); ok && framework != "" {
			args = append(args, "--framework", framework)
		}
		return args, nil
	case "scanner.kubescape":
		args := []string{"scan", ".", "--format", "sarif"}
		if _, ok := cfg["useArtifactsFrom"]; ok {
			artifacts, err := requiredSafeString(cfg, "useArtifactsFrom", true)
			if err != nil {
				return nil, err
			}
			args = append(args, "--use-artifacts-from", artifacts)
		}
		return args, nil
	case "scanner.opa":
		policy, err := requiredSafeString(cfg, "policy", true)
		if err != nil {
			return nil, err
		}
		query, err := requiredSafeString(cfg, "query", false)
		if err != nil {
			return nil, err
		}
		args := []string{"eval", "--format", "json", "--data", policy}
		if _, ok := cfg["input"]; ok {
			input, err := requiredSafeString(cfg, "input", true)
			if err != nil {
				return nil, err
			}
			args = append(args, "--input", input)
		}
		return append(args, query), nil
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
	case "scanner.poutine", "scanner.kubescape":
		parseSARIF(tool, doc, &result)
	case "scanner.osv":
		parseOSV(doc, &result)
	case "scanner.checkov":
		parseCheckov(doc, &result)
	case "scanner.opa":
		parseOPA(doc, &result)
	default:
		return findings.Result{}, fmt.Errorf("unsupported parser %q", tool)
	}
	return result, nil
}

func parseSARIF(tool string, doc any, result *findings.Result) {
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
}

func parseOSV(doc any, result *findings.Result) {
	m, _ := doc.(map[string]any)
	rows, _ := m["results"].([]any)
	for _, rowValue := range rows {
		row, _ := rowValue.(map[string]any)
		source, _ := row["source"].(map[string]any)
		path, _ := source["path"].(string)
		packages, _ := row["packages"].([]any)
		for _, packageValue := range packages {
			packageRow, _ := packageValue.(map[string]any)
			pkg, _ := packageRow["package"].(map[string]any)
			name, _ := pkg["name"].(string)
			version, _ := pkg["version"].(string)
			vulnerabilities, _ := packageRow["vulnerabilities"].([]any)
			for _, vulnerabilityValue := range vulnerabilities {
				vulnerability, _ := vulnerabilityValue.(map[string]any)
				id, _ := vulnerability["id"].(string)
				title, _ := vulnerability["summary"].(string)
				if title == "" {
					title = fmt.Sprintf("%s affects %s@%s", id, name, version)
				}
				severity := osvSeverity(vulnerability)
				props := map[string]any{"source": source, "package": pkg, "vulnerability": vulnerability}
				result.Findings = append(result.Findings, newFinding("scanner.osv", id, title, severity, path, 0, props))
			}
		}
	}
}

func osvSeverity(vulnerability map[string]any) string {
	if database, ok := vulnerability["database_specific"].(map[string]any); ok {
		if severity, ok := database["severity"].(string); ok {
			return severity
		}
	}
	return "unknown"
}

func parseCheckov(doc any, result *findings.Result) {
	walkJSON(doc, func(m map[string]any) {
		rows, ok := m["failed_checks"].([]any)
		if !ok {
			return
		}
		for _, rowValue := range rows {
			row, _ := rowValue.(map[string]any)
			id, _ := row["check_id"].(string)
			title, _ := row["check_name"].(string)
			path, _ := row["file_path"].(string)
			severity, _ := row["severity"].(string)
			line := firstLine(row["file_line_range"])
			result.Findings = append(result.Findings, newFinding("scanner.checkov", id, title, severity, strings.TrimPrefix(path, "/"), line, row))
		}
	})
}

func parseOPA(doc any, result *findings.Result) {
	m, _ := doc.(map[string]any)
	rows, _ := m["result"].([]any)
	for _, rowValue := range rows {
		row, _ := rowValue.(map[string]any)
		expressions, _ := row["expressions"].([]any)
		for _, expressionValue := range expressions {
			expression, _ := expressionValue.(map[string]any)
			appendOPAValue(expression["value"], result)
		}
	}
}

func appendOPAValue(value any, result *findings.Result) {
	switch v := value.(type) {
	case []any:
		for _, item := range v {
			appendOPAValue(item, result)
		}
	case map[string]any:
		id := firstString(v, "id", "rule_id", "code")
		title := firstString(v, "message", "msg", "title")
		path := firstString(v, "path", "file")
		severity := firstString(v, "severity", "level")
		result.Findings = append(result.Findings, newFinding("scanner.opa", id, title, severity, path, intNumber(v["line"]), v))
	case string:
		result.Findings = append(result.Findings, newFinding("scanner.opa", "policy-violation", v, "unknown", "", 0, map[string]any{"value": v}))
	case bool:
		if v {
			result.Findings = append(result.Findings, newFinding("scanner.opa", "policy-violation", "OPA policy violation", "unknown", "", 0, map[string]any{"value": v}))
		}
	}
}

func walkJSON(value any, visit func(map[string]any)) {
	switch v := value.(type) {
	case []any:
		for _, child := range v {
			walkJSON(child, visit)
		}
	case map[string]any:
		visit(v)
		for _, child := range v {
			walkJSON(child, visit)
		}
	}
}

func firstLine(value any) int {
	rows, _ := value.([]any)
	if len(rows) == 0 {
		return 0
	}
	return intNumber(rows[0])
}

func firstString(m map[string]any, keys ...string) string {
	for _, key := range keys {
		if value, ok := m[key].(string); ok && value != "" {
			return value
		}
	}
	return ""
}

func requiredSafeString(config map[string]any, key string, path bool) (string, error) {
	value, ok := config[key].(string)
	if !ok || value == "" {
		return "", fmt.Errorf("%s must be a non-empty string", key)
	}
	if strings.HasPrefix(value, "-") || strings.ContainsAny(value, "\x00\r\n") {
		return "", fmt.Errorf("invalid %s", key)
	}
	if path && (filepath.IsAbs(value) || strings.Contains(filepath.ToSlash(value), "../")) {
		return "", fmt.Errorf("invalid %s path", key)
	}
	return value, nil
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
