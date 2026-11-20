package cli

import (
	"fmt"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/andrew-ships-stuff/caphe/internal/audit"
	capheruntime "github.com/andrew-ships-stuff/caphe/internal/runtime"
	"github.com/spf13/cobra"
)

func (a *app) auditCmd() *cobra.Command {
	var workflowRef, output, sarifOutput, markdownOutput, htmlOutput, aiEndpoint, aiModel, aiModelDigest, aiModelURL, aiLlamaServer, aiModelCache string
	var concurrency, aiThreads, aiParallel, maxModelCalls, maxInputTokens, maxOutputTokens int
	var aiEnabled, aiServe, aiOffline bool
	var maxInferenceTime time.Duration
	command := &cobra.Command{Use: "audit [TARGET]", Short: "Aggregate every available scanner, correlate evidence, optionally annotate with a budgeted local LLM, and emit one ingestable bundle", Args: cobra.MaximumNArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		configured, err := a.loadSettings()
		if err != nil {
			return err
		}
		if !cmd.Flags().Changed("workflow") && configured.Workflow != "" {
			workflowRef = configured.Workflow
		}
		target := "."
		if len(args) == 1 {
			target = args[0]
		}
		implicitAI := !cmd.Flags().Changed("ai")
		if implicitAI {
			if configured.Configured {
				aiEnabled = configured.AIEnabled
			} else {
				aiEnabled = true
			}
		}
		progress := a.auditProgress(target, workflowRef)
		bundle, err := audit.Run(cmd.Context(), audit.Options{Target: target, Workflow: workflowRef, DataDir: a.dataDir, Concurrency: concurrency, CapheVersion: Version, Registry: a.registry, Progress: progress, AI: audit.AIOptions{Enabled: aiEnabled, Serve: aiServe, Offline: aiOffline, ModelCache: aiModelCache, Endpoint: aiEndpoint, Model: aiModel, ModelDigest: aiModelDigest, ModelURL: aiModelURL, LlamaServer: aiLlamaServer, Threads: aiThreads, Parallel: aiParallel, MaxCalls: maxModelCalls, MaxInputTokens: maxInputTokens, MaxOutputTokens: maxOutputTokens, MaxTotalTime: maxInferenceTime, BestEffort: implicitAI}})
		if err != nil {
			return err
		}
		if output != "" {
			if err := audit.WriteJSON(output, bundle); err != nil {
				return err
			}
		}
		if sarifOutput != "" {
			if err := audit.WriteSARIF(sarifOutput, bundle); err != nil {
				return err
			}
		}
		if markdownOutput != "" {
			if err := audit.WriteMarkdown(markdownOutput, bundle); err != nil {
				return err
			}
		}
		if htmlOutput != "" {
			if err := audit.WriteHTML(htmlOutput, bundle); err != nil {
				return err
			}
		}
		return a.print(map[string]any{"bundle": output, "sarif": sarifOutput, "markdown": markdownOutput, "html": htmlOutput, "digest": bundle.Digest, "status": bundle.Status, "coverage": bundle.Coverage, "metrics": bundle.Metrics, "synthesis": bundle.Synthesis != nil, "ai": bundle.AI})
	}}
	command.Flags().StringVar(&workflowRef, "workflow", "caphe:default", "workflow YAML or caphe:<bundled-name>; default aggregates opengrep, syft, grype, gitleaks, and poutine with graceful degradation")
	command.Flags().StringVarP(&output, "output", "o", "caphe-audit.json", "bundle JSON output (empty skips)")
	command.Flags().StringVar(&sarifOutput, "sarif-output", "caphe-audit.sarif", "SARIF output (empty skips)")
	command.Flags().StringVar(&markdownOutput, "markdown-output", "caphe-audit.md", "Markdown report output (empty skips)")
	command.Flags().StringVar(&htmlOutput, "html-output", "caphe-audit.html", "self-contained interactive HTML report (empty skips)")
	command.Flags().IntVar(&concurrency, "concurrency", 0, "maximum concurrent scanner tasks (0 uses Go's effective CPU allowance)")
	command.Flags().BoolVar(&aiEnabled, "ai", true, "enable local CPU inference by default; --ai=false disables it")
	command.Flags().BoolVar(&aiServe, "ai-serve", true, "launch a private llama-server subprocess on an ephemeral loopback port")
	command.Flags().BoolVar(&aiOffline, "ai-offline", false, "require verified cached model weights; never download a model")
	command.Flags().StringVar(&aiModelCache, "ai-model-cache", "", "model cache directory (defaults to models under --data-dir)")
	command.Flags().StringVar(&aiEndpoint, "ai-endpoint", "http://127.0.0.1:8080", "loopback llama.cpp endpoint when --ai-serve is false")
	command.Flags().StringVar(&aiModel, "ai-model", dogfoodModelName, "model identifier")
	command.Flags().StringVar(&aiModelDigest, "ai-model-digest", dogfoodModelDigest, "verified model content digest")
	command.Flags().StringVar(&aiModelURL, "ai-model-url", dogfoodModelURL, "HTTPS model URL downloaded and digest-verified before serving")
	command.Flags().StringVar(&aiLlamaServer, "ai-llama-server", "", "explicit llama-server binary; defaults to CAPHE_LLAMA_SERVER, managed tools, then PATH")
	command.Flags().IntVar(&aiThreads, "ai-threads", 0, "llama-server CPU threads (0 selects the llama.cpp default)")
	command.Flags().IntVar(&aiParallel, "ai-parallel", 2, "concurrent inference slots sharing one loaded model (1-16)")
	command.Flags().IntVar(&maxModelCalls, "max-model-calls", 12, "maximum model calls per audit (1-20; reserves aggregate synthesis and dedup calls)")
	command.Flags().IntVar(&maxInputTokens, "max-input-tokens", 4096, "maximum tokenized input per model call, including chat template")
	command.Flags().IntVar(&maxOutputTokens, "max-output-tokens", 512, "maximum output tokens per model call")
	command.Flags().DurationVar(&maxInferenceTime, "max-inference-time", 10*time.Minute, "maximum total inference time")
	return command
}

func (a *app) auditProgress(target, workflow string) audit.ProgressFunc {
	if a.jsonOutput {
		return nil
	}
	fmt.Fprintf(a.stdout, "Caphe audit\n  Target    %s\n  Workflow  %s (fixed DAG)\n\n", target, workflow)
	var mu sync.Mutex
	return func(event audit.ProgressEvent) {
		mu.Lock()
		defer mu.Unlock()
		switch event.Kind {
		case "task_started":
			fmt.Fprintf(a.stdout, "→ Running %s...\n", auditTaskLabel(event.Task.Uses))
		case "task_finished":
			label := auditTaskLabel(event.Task.Uses)
			duration := time.Duration(event.Task.DurationMillis) * time.Millisecond
			switch event.Task.Status {
			case "succeeded":
				if strings.HasPrefix(event.Task.Uses, "scanner.") {
					fmt.Fprintf(a.stdout, "✓ %s done — %d %s · %s\n", label, event.Task.FindingCount, plural(event.Task.FindingCount, "finding", "findings"), duration)
				} else {
					fmt.Fprintf(a.stdout, "✓ %s done · %s\n", label, duration)
				}
			case "skipped":
				fmt.Fprintf(a.stdout, "○ %s skipped — %s\n", label, progressReason(event.Task.Error, event.Task.ErrorClass))
				if suggestion := scannerFailureSuggestion(event.Task); suggestion != "" {
					fmt.Fprintf(a.stdout, "  Fix: %s\n", suggestion)
				}
			default:
				fmt.Fprintf(a.stdout, "✗ %s failed — %s\n", label, progressReason(event.Task.Error, event.Task.ErrorClass))
			}
		case "evidence_ready":
			fmt.Fprintf(a.stdout, "✓ Deterministically normalized and correlated %d scanner %s\n", event.FindingCount, plural(event.FindingCount, "finding", "findings"))
		case "ai_runtime_started":
			fmt.Fprintf(a.stdout, "→ Preparing digest-verified CPU model %s on loopback...\n", event.Model)
		case "ai_no_evidence":
			fmt.Fprintln(a.stdout, "○ Inference enabled; no scanner findings to interpret. Check scan coverage before drawing conclusions.")
		case "ai_runtime_finished":
			fmt.Fprintf(a.stdout, "✓ CPU model %s ready on an ephemeral loopback server\n", event.Model)
		case "ai_unavailable":
			fmt.Fprintf(a.stdout, "○ Model %s unavailable — %s\n", event.Model, progressReason(event.Message, "inference_unavailable"))
			fmt.Fprintf(a.stdout, "  Fix: run caphe setup --install\n")
		case "ai_review_started":
			fmt.Fprintf(a.stdout, "→ Using %s to interpret %d %s as unverified hypotheses...\n", event.Model, event.FindingCount, plural(event.FindingCount, "finding", "findings"))
		case "ai_review_finished":
			fmt.Fprintf(a.stdout, "✓ Model produced schema-valid remediation hypotheses for %d of %d %s\n", event.FindingCount, event.ProposalCount, plural(event.ProposalCount, "finding", "findings"))
		case "ai_synthesis_started":
			fmt.Fprintf(a.stdout, "→ Using %s to prioritize repository risk from %d findings...\n", event.Model, event.FindingCount)
		case "ai_synthesis_finished":
			fmt.Fprintf(a.stdout, "✓ Model proposed %d repository priorities (hypothesis · unverified)\n", event.ProposalCount)
		case "ai_dedup_started":
			fmt.Fprintf(a.stdout, "→ Using %s to review %d deterministic remediation groups for possible duplicates...\n", event.Model, event.GroupCount)
		case "ai_dedup_finished":
			fmt.Fprintf(a.stdout, "✓ Model proposed %d possible duplicate %s across %d %s (hypothesis · unverified)\n", event.ProposalCount, plural(event.ProposalCount, "merge", "merges"), event.GroupCount, plural(event.GroupCount, "group", "groups"))
		case "remediation_ready":
			fmt.Fprintf(a.stdout, "✓ Built deterministic remediation plan — %d %s from %d %s\n\n", event.GroupCount, plural(event.GroupCount, "group", "groups"), event.FindingCount, plural(event.FindingCount, "finding", "findings"))
		}
	}
}

func scannerFailureSuggestion(task capheruntime.TaskResult) string {
	reason := strings.ToLower(task.Error)
	if task.Uses == "scanner.grype" && (strings.Contains(reason, "failed to load vulnerability db") || strings.Contains(reason, "current database is invalid")) {
		return "run the managed grype db update; for persistent corruption, run grype db delete then grype db update; repeated migration failures may require an upstream fix"
	}
	return scannerInstallSuggestion(task.Uses)
}

func auditTaskLabel(uses string) string {
	labels := map[string]string{
		"scanner.opengrep":  "SAST scan with Opengrep",
		"scanner.syft":      "SBOM inventory with Syft",
		"scanner.grype":     "dependency vulnerability scan with Grype",
		"scanner.gitleaks":  "secret scan with Gitleaks",
		"scanner.poutine":   "GitHub Actions scan with Poutine",
		"scanner.opa":       "policy scan with OPA",
		"scanner.osv":       "dependency vulnerability scan with OSV-Scanner",
		"scanner.checkov":   "infrastructure-as-code scan with Checkov",
		"scanner.kubescape": "Kubernetes scan with Kubescape",
		"core.normalize":    "evidence normalization",
		"core.correlate":    "evidence correlation",
		"core.verify":       "evidence verification",
	}
	if label := labels[uses]; label != "" {
		return label
	}
	return strings.TrimPrefix(uses, "scanner.")
}

func progressReason(message, class string) string {
	if strings.TrimSpace(message) != "" {
		return message
	}
	if class != "" {
		return strings.ReplaceAll(class, "_", " ")
	}
	return "no details available"
}

func scannerInstallSuggestion(uses string) string {
	if tool := managedScannerTools[uses]; tool != "" {
		return managedScannerFix(tool)
	}
	if strings.HasPrefix(uses, "scanner.") {
		return "run caphe doctor for platform-specific installation guidance"
	}
	return ""
}

func managedScannerFix(tool string) string {
	if runtime.GOOS == "darwin" {
		return fmt.Sprintf("run caphe setup --install; or install only this scanner with brew install %s", tool)
	}
	return "run caphe setup --install"
}

func plural(count int, singular, multiple string) string {
	if count == 1 {
		return singular
	}
	return multiple
}
