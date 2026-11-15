package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"sync"
	"text/tabwriter"
	"time"
	"unicode"

	"github.com/andrew-ships-stuff/caphe/internal/adapters"
	"github.com/andrew-ships-stuff/caphe/internal/findings"
	"github.com/andrew-ships-stuff/caphe/internal/hardware"
	capheruntime "github.com/andrew-ships-stuff/caphe/internal/runtime"
)

type doctorReport struct {
	Healthy     bool                `json:"healthy"`
	Storage     storageReport       `json:"storage"`
	Hardware    hardware.Inspection `json:"hardware"`
	Tools       []adapters.ToolInfo `json:"tools"`
	Inference   inferenceReport     `json:"inference"`
	Suggestions []doctorSuggestion  `json:"suggestions,omitempty"`
}

type storageReport struct {
	Path      string `json:"path"`
	Available bool   `json:"available"`
}

type inferenceReport struct {
	Provider         string `json:"provider"`
	Available        bool   `json:"available"`
	Endpoint         string `json:"endpoint"`
	RuntimeAvailable bool   `json:"runtimeAvailable"`
	RuntimePath      string `json:"runtimePath,omitempty"`
	LaunchMode       string `json:"launchMode"`
}

type doctorSuggestion struct {
	Title     string   `json:"title"`
	Reason    string   `json:"reason,omitempty"`
	Commands  []string `json:"commands"`
	Automatic bool     `json:"automatic,omitempty"`
}

type versionReport struct {
	Version         string `json:"version"`
	CompilerVersion string `json:"compilerVersion"`
	Go              string `json:"go"`
	OS              string `json:"os"`
	Architecture    string `json:"architecture"`
}

func (a *app) printHuman(value any) error {
	switch v := value.(type) {
	case string:
		_, err := fmt.Fprintln(a.stdout, v)
		return err
	case doctorReport:
		return renderDoctor(a.stdout, v)
	case versionReport:
		_, err := fmt.Fprintf(a.stdout, "Caphe %s\n  Compiler  %s\n  Runtime   %s\n  Platform  %s/%s\n", v.Version, v.CompilerVersion, v.Go, v.OS, v.Architecture)
		return err
	case []adapters.ToolInfo:
		return renderTools(a.stdout, v, true)
	case hardware.Inspection:
		return renderHardware(a.stdout, v, true)
	case capheruntime.Manifest:
		return renderManifest(a.stdout, v)
	case []findings.Finding:
		return renderFindings(a.stdout, v)
	case findings.Finding:
		return renderFinding(a.stdout, v, true)
	default:
		return renderGeneric(a.stdout, value)
	}
}

func renderDoctor(w io.Writer, report doctorReport) error {
	status := "✓ Caphe core is healthy"
	if !report.Healthy {
		status = "✗ Caphe core needs attention"
	}
	if _, err := fmt.Fprintf(w, "Caphe doctor\n%s\n\n", status); err != nil {
		return err
	}
	storageMark := mark(report.Storage.Available)
	if _, err := fmt.Fprintf(w, "Storage\n  %s State database\t%s\n\n", storageMark, report.Storage.Path); err != nil {
		return err
	}
	if err := renderHardware(w, report.Hardware, true); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(w); err != nil {
		return err
	}
	if err := renderTools(w, report.Tools, true); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(w, "\nInference"); err != nil {
		return err
	}
	if report.Inference.Available {
		if _, err := fmt.Fprintf(w, "  ✓ External endpoint\treachable at %s\n", report.Inference.Endpoint); err != nil {
			return err
		}
	} else {
		if _, err := fmt.Fprintf(w, "  ○ External endpoint\tnot running (optional)\n"); err != nil {
			return err
		}
	}
	if report.Inference.RuntimeAvailable {
		if _, err := fmt.Fprintf(w, "  ✓ Managed runtime\t%s\n", report.Inference.RuntimePath); err != nil {
			return err
		}
	} else {
		if _, err := fmt.Fprintln(w, "  ✗ Managed runtime\tnot installed"); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintln(w, "    Caphe starts a private loopback subprocess for --ai-serve and stops it after the run."); err != nil {
		return err
	}
	if len(report.Suggestions) == 0 {
		return nil
	}
	if _, err := fmt.Fprintln(w, "\nNext steps"); err != nil {
		return err
	}
	for index, suggestion := range report.Suggestions {
		if _, err := fmt.Fprintf(w, "  %d. %s\n", index+1, suggestion.Title); err != nil {
			return err
		}
		if suggestion.Reason != "" {
			if _, err := fmt.Fprintf(w, "     %s\n", suggestion.Reason); err != nil {
				return err
			}
		}
		for _, command := range suggestion.Commands {
			if _, err := fmt.Fprintf(w, "     $ %s\n", command); err != nil {
				return err
			}
		}
	}
	return nil
}

func renderHardware(w io.Writer, inspection hardware.Inspection, heading bool) error {
	if heading {
		if _, err := fmt.Fprintln(w, "Hardware"); err != nil {
			return err
		}
	}
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintf(tw, "  ✓ Platform\t%s/%s\n", inspection.OS, inspection.Architecture)
	fmt.Fprintf(tw, "  ✓ CPU\t%d logical / %d physical cores\n", inspection.LogicalCores, inspection.PhysicalCores)
	fmt.Fprintf(tw, "  ✓ Memory\t%s available / %s total\n", humanBytes(inspection.AvailableMemoryBytes), humanBytes(inspection.TotalMemoryBytes))
	fmt.Fprintf(tw, "  ✓ Disk\t%s free\n", humanBytes(inspection.DiskFreeBytes))
	container := "host"
	if inspection.Containerized {
		container = "container"
	}
	fmt.Fprintf(tw, "  ✓ Runtime\t%s\n", container)
	return tw.Flush()
}

func renderTools(w io.Writer, tools []adapters.ToolInfo, heading bool) error {
	available := 0
	for _, tool := range tools {
		if tool.Available {
			available++
		}
	}
	if heading {
		if _, err := fmt.Fprintf(w, "Scanners (%d/%d available)\n", available, len(tools)); err != nil {
			return err
		}
	}
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	for _, tool := range tools {
		name := strings.TrimPrefix(tool.ID, "scanner.")
		if tool.Available {
			fmt.Fprintf(tw, "  ✓ %s\t%s\t%s\n", name, conciseVersion(tool.Version), tool.Path)
			continue
		}
		reason := "not found in PATH"
		if tool.Error != "" && !strings.Contains(tool.Error, "executable file not found") {
			reason = tool.Error
		}
		fmt.Fprintf(tw, "  ✗ %s\t%s\n", name, reason)
	}
	return tw.Flush()
}

func renderManifest(w io.Writer, manifest capheruntime.Manifest) error {
	mark := statusMark(manifest.Status)
	if _, err := fmt.Fprintf(w, "%s Workflow %s\n", mark, humanStatus(manifest.Status)); err != nil {
		return err
	}
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintf(tw, "  Execution\t%s\n  Target\t%s\n  Findings\t%d\n\n", manifest.ExecutionID, manifest.Target, manifest.FindingCount)
	for _, task := range manifest.Tasks {
		detail := fmt.Sprintf("%d finding(s), %s", task.FindingCount, humanDuration(task.DurationMillis))
		if task.Error != "" {
			detail = task.Error
		}
		fmt.Fprintf(tw, "  %s %s\t%s\n", statusMark(string(task.Status)), task.ID, detail)
	}
	return tw.Flush()
}

func renderFindings(w io.Writer, items []findings.Finding) error {
	if len(items) == 0 {
		_, err := fmt.Fprintln(w, "✓ No findings in the latest execution")
		return err
	}
	if _, err := fmt.Fprintf(w, "Findings (%d)\n", len(items)); err != nil {
		return err
	}
	for _, finding := range items {
		if err := renderFinding(w, finding, false); err != nil {
			return err
		}
	}
	return nil
}

func renderFinding(w io.Writer, finding findings.Finding, detailed bool) error {
	location := finding.Location.Path
	if finding.Location.StartLine > 0 {
		location += fmt.Sprintf(":%d", finding.Location.StartLine)
	}
	if location == "" {
		location = "no source location"
	}
	if _, err := fmt.Fprintf(w, "  %s [%s] %s\n    %s · %s · %s\n", severityMark(finding.Severity), strings.ToUpper(string(finding.Severity)), finding.Title, finding.Tool, finding.RuleID, location); err != nil {
		return err
	}
	if detailed {
		_, err := fmt.Fprintf(w, "    Evidence: %s\n    Fingerprint: %s\n", finding.ID, finding.Fingerprint)
		return err
	}
	return nil
}

func renderGeneric(w io.Writer, value any) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	var normalized any
	if err := json.Unmarshal(data, &normalized); err != nil {
		return err
	}
	return renderValue(w, normalized, 0, "")
}

func renderValue(w io.Writer, value any, depth int, label string) error {
	indent := strings.Repeat("  ", depth)
	switch v := value.(type) {
	case map[string]any:
		if label != "" {
			if _, err := fmt.Fprintf(w, "%s%s\n", indent, humanLabel(label)); err != nil {
				return err
			}
			depth++
			indent = strings.Repeat("  ", depth)
		}
		keys := make([]string, 0, len(v))
		for key := range v {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			child := v[key]
			switch child.(type) {
			case map[string]any, []any:
				if err := renderValue(w, child, depth, key); err != nil {
					return err
				}
			default:
				if _, err := fmt.Fprintf(w, "%s%s%s  %s\n", indent, valueMark(key, child), humanLabel(key), humanScalar(child)); err != nil {
					return err
				}
			}
		}
	case []any:
		if label != "" {
			if _, err := fmt.Fprintf(w, "%s%s (%d)\n", indent, humanLabel(label), len(v)); err != nil {
				return err
			}
			depth++
			indent = strings.Repeat("  ", depth)
		}
		if len(v) == 0 {
			_, err := fmt.Fprintf(w, "%s— none\n", indent)
			return err
		}
		for _, child := range v {
			switch child.(type) {
			case map[string]any, []any:
				if _, err := fmt.Fprintf(w, "%s•\n", indent); err != nil {
					return err
				}
				if err := renderValue(w, child, depth+1, ""); err != nil {
					return err
				}
			default:
				if _, err := fmt.Fprintf(w, "%s• %s\n", indent, humanScalar(child)); err != nil {
					return err
				}
			}
		}
	default:
		_, err := fmt.Fprintf(w, "%s%s\n", indent, humanScalar(v))
		return err
	}
	return nil
}

func (a *app) startSpinner(label string) func() {
	if a.jsonOutput || !terminalWriter(a.stdout) {
		return func() {}
	}
	done := make(chan struct{})
	finished := make(chan struct{})
	frames := []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}
	go func() {
		defer close(finished)
		ticker := time.NewTicker(80 * time.Millisecond)
		defer ticker.Stop()
		index := 0
		for {
			fmt.Fprintf(a.stdout, "\r%s %s", frames[index%len(frames)], label)
			index++
			select {
			case <-done:
				fmt.Fprint(a.stdout, "\r\x1b[2K")
				return
			case <-ticker.C:
			}
		}
	}()
	var once sync.Once
	return func() {
		once.Do(func() {
			close(done)
			<-finished
		})
	}
}

func terminalWriter(w io.Writer) bool {
	file, ok := w.(*os.File)
	if !ok {
		return false
	}
	info, err := file.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}

func mark(ok bool) string {
	if ok {
		return "✓"
	}
	return "✗"
}

func statusMark(status string) string {
	switch strings.ToLower(status) {
	case "succeeded", "success", "available", "valid", "healthy", "confirmed", "passed", "complete", "completed":
		return "✓"
	case "failed", "error", "critical", "partial_failure", "invalid":
		return "✗"
	case "skipped", "pending", "running", "unavailable", "not_run":
		return "○"
	default:
		return "•"
	}
}

func severityMark(severity findings.Severity) string {
	switch severity {
	case findings.SeverityCritical, findings.SeverityHigh:
		return "✗"
	case findings.SeverityMedium, findings.SeverityLow:
		return "!"
	default:
		return "•"
	}
}

func valueMark(key string, value any) string {
	boolean, ok := value.(bool)
	if !ok {
		if status, ok := value.(string); ok && (strings.EqualFold(key, "status") || strings.HasSuffix(strings.ToLower(key), "status")) {
			return statusMark(status) + " "
		}
		return ""
	}
	lower := strings.ToLower(key)
	for _, word := range []string{"available", "healthy", "valid", "initialized", "reachable", "enabled", "managed", "loopback"} {
		if strings.Contains(lower, word) {
			return mark(boolean) + " "
		}
	}
	return ""
}

func humanLabel(value string) string {
	value = strings.ReplaceAll(value, "_", " ")
	var out []rune
	for index, r := range []rune(value) {
		if index > 0 && unicode.IsUpper(r) && out[len(out)-1] != ' ' {
			out = append(out, ' ')
		}
		out = append(out, r)
	}
	if len(out) == 0 {
		return value
	}
	out[0] = unicode.ToUpper(out[0])
	return string(out)
}

func humanScalar(value any) string {
	switch v := value.(type) {
	case nil:
		return "—"
	case bool:
		if v {
			return "yes"
		}
		return "no"
	case float64:
		if v == float64(int64(v)) {
			return fmt.Sprintf("%d", int64(v))
		}
		return fmt.Sprintf("%g", v)
	case string:
		if v == "" {
			return "—"
		}
		return v
	default:
		return fmt.Sprint(v)
	}
}

func conciseVersion(value string) string {
	for _, line := range strings.Split(value, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(strings.ToLower(line), "version:") {
			return strings.TrimSpace(strings.TrimPrefix(line, "Version:"))
		}
	}
	line, _, _ := strings.Cut(strings.TrimSpace(value), "\n")
	if line == "" {
		return "available"
	}
	return line
}

func humanStatus(value string) string {
	return strings.ReplaceAll(value, "_", " ")
}

func humanBytes(value uint64) string {
	const unit = uint64(1024)
	if value < unit {
		return fmt.Sprintf("%d B", value)
	}
	units := []string{"KiB", "MiB", "GiB", "TiB"}
	size := float64(value)
	index := -1
	for size >= float64(unit) && index < len(units)-1 {
		size /= float64(unit)
		index++
	}
	return fmt.Sprintf("%.1f %s", size, units[index])
}

func humanDuration(milliseconds int64) string {
	return (time.Duration(milliseconds) * time.Millisecond).Round(time.Millisecond).String()
}
