package audit

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/andrew-ships-stuff/caphe/internal/reporting"
)

func WriteJSON(path string, bundle Bundle) error {
	data, err := json.MarshalIndent(bundle, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o600)
}

func WriteSARIF(path string, bundle Bundle) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	sarifErr := reporting.SARIF(file, bundle.Findings)
	closeErr := file.Close()
	if sarifErr != nil {
		return sarifErr
	}
	return closeErr
}

func WriteMarkdown(path string, bundle Bundle) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	markdownErr := RenderMarkdown(file, bundle)
	closeErr := file.Close()
	if markdownErr != nil {
		return markdownErr
	}
	return closeErr
}

func RenderMarkdown(w io.Writer, bundle Bundle) error {
	fmt.Fprintf(w, "# Caphe security audit\n\n")
	fmt.Fprintf(w, "Target `%s` · workflow `%s` · execution `%s` · status **%s** · bundle `%s`\n\n", bundle.Target, bundle.Workflow, bundle.ExecutionID, bundle.Status, bundle.Digest)
	fmt.Fprintf(w, "| Findings | Critical | High | Medium | Low | Model calls |\n|---:|---:|---:|---:|---:|---:|\n")
	fmt.Fprintf(w, "| %d | %d | %d | %d | %d | %d |\n\n", bundle.Metrics.Findings, bundle.Metrics.BySeverity["critical"], bundle.Metrics.BySeverity["high"], bundle.Metrics.BySeverity["medium"], bundle.Metrics.BySeverity["low"], bundle.Metrics.ModelCalls)
	fmt.Fprintf(w, "Scanner tasks: ")
	for index, task := range bundle.Tasks {
		if index > 0 {
			fmt.Fprint(w, ", ")
		}
		fmt.Fprintf(w, "`%s` (%s)", task.ID, task.Status)
	}
	fmt.Fprint(w, "\n\n")
	if bundle.Synthesis != nil {
		fmt.Fprint(w, "## Repository posture (AI hypothesis, unverified)\n\n")
		fmt.Fprint(w, strings.ReplaceAll(strings.TrimSpace(bundle.Synthesis.RiskSummary), "\r", "")+"\n\n")
		if len(bundle.Synthesis.Priorities) > 0 {
			fmt.Fprint(w, "## Priorities (AI hypothesis, unverified)\n\n")
			for _, priority := range bundle.Synthesis.Priorities {
				fmt.Fprintf(w, "%d. **%s** — %s\n   Evidence: `%s`\n", priority.Rank, priority.Title, priority.Rationale, strings.Join(priority.EvidenceIDs, "`, `"))
			}
			fmt.Fprint(w, "\n")
		}
	}
	if len(bundle.Recommendations) > 0 {
		fmt.Fprint(w, "## Recommendations\n\n")
		for _, recommendation := range bundle.Recommendations {
			source := recommendation.Source
			if recommendation.Status == "hypothesis" {
				source = "AI hypothesis (unverified)"
			}
			fmt.Fprintf(w, "- `%s` (%s): %s\n  Remediation: %s\n", recommendation.FindingID, source, recommendation.Explanation, recommendation.Remediation)
		}
		fmt.Fprint(w, "\n")
	}
	if len(bundle.AI.Errors) > 0 {
		fmt.Fprint(w, "## AI notes\n\n")
		for _, message := range bundle.AI.Errors {
			fmt.Fprintf(w, "- %s\n", message)
		}
		fmt.Fprint(w, "\n")
	}
	fmt.Fprint(w, "AI text is advisory, never claims verification, and never determines policy.\n")
	return nil
}
