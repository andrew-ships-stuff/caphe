package cli

import (
	"time"

	"github.com/andrew-ships-stuff/caphe/internal/audit"
	"github.com/spf13/cobra"
)

func (a *app) auditCmd() *cobra.Command {
	var workflowRef, output, sarifOutput, markdownOutput, htmlOutput, aiEndpoint, aiModel, aiModelDigest, aiModelURL, aiLlamaServer string
	var concurrency, aiThreads, maxModelCalls, maxInputTokens, maxOutputTokens int
	var aiEnabled, aiServe bool
	var maxInferenceTime time.Duration
	command := &cobra.Command{Use: "audit [TARGET]", Short: "Aggregate every available scanner, correlate evidence, optionally annotate with a budgeted local LLM, and emit one ingestable bundle", Args: cobra.MaximumNArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		target := "."
		if len(args) == 1 {
			target = args[0]
		}
		stop := a.startSpinner("Running security audit")
		bundle, err := audit.Run(cmd.Context(), audit.Options{Target: target, Workflow: workflowRef, DataDir: a.dataDir, Concurrency: concurrency, CapheVersion: Version, Registry: a.registry, AI: audit.AIOptions{Enabled: aiEnabled, Serve: aiServe, Endpoint: aiEndpoint, Model: aiModel, ModelDigest: aiModelDigest, ModelURL: aiModelURL, LlamaServer: aiLlamaServer, Threads: aiThreads, MaxCalls: maxModelCalls, MaxInputTokens: maxInputTokens, MaxOutputTokens: maxOutputTokens, MaxTotalTime: maxInferenceTime}})
		stop()
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
		return a.print(map[string]any{"bundle": output, "sarif": sarifOutput, "markdown": markdownOutput, "html": htmlOutput, "digest": bundle.Digest, "status": bundle.Status, "metrics": bundle.Metrics, "synthesis": bundle.Synthesis != nil, "ai": bundle.AI})
	}}
	command.Flags().StringVar(&workflowRef, "workflow", "caphe:default", "workflow YAML or caphe:<bundled-name>; default aggregates opengrep, syft, grype, gitleaks, and poutine with graceful degradation")
	command.Flags().StringVarP(&output, "output", "o", "caphe-audit.json", "bundle JSON output (empty skips)")
	command.Flags().StringVar(&sarifOutput, "sarif-output", "caphe-audit.sarif", "SARIF output (empty skips)")
	command.Flags().StringVar(&markdownOutput, "markdown-output", "caphe-audit.md", "Markdown report output (empty skips)")
	command.Flags().StringVar(&htmlOutput, "html-output", "caphe-audit.html", "self-contained interactive HTML report (empty skips)")
	command.Flags().IntVar(&concurrency, "concurrency", 0, "maximum concurrent scanner tasks (0 uses all cores)")
	command.Flags().BoolVar(&aiEnabled, "ai", false, "enable optional local CPU inference for recommendations and repo synthesis")
	command.Flags().BoolVar(&aiServe, "ai-serve", false, "launch a private llama-server subprocess on an ephemeral loopback port")
	command.Flags().StringVar(&aiEndpoint, "ai-endpoint", "http://127.0.0.1:8080", "loopback llama.cpp endpoint when --ai-serve is false")
	command.Flags().StringVar(&aiModel, "ai-model", "", "explicit model identifier")
	command.Flags().StringVar(&aiModelDigest, "ai-model-digest", "", "verified model content digest")
	command.Flags().StringVar(&aiModelURL, "ai-model-url", "", "HTTPS model URL downloaded and digest-verified before serving")
	command.Flags().StringVar(&aiLlamaServer, "ai-llama-server", "", "explicit llama-server binary; defaults to CAPHE_LLAMA_SERVER, managed tools, then PATH")
	command.Flags().IntVar(&aiThreads, "ai-threads", 0, "llama-server CPU threads (0 selects the llama.cpp default)")
	command.Flags().IntVar(&maxModelCalls, "max-model-calls", 6, "maximum model calls per audit (0-20; per-finding recs plus one synthesis)")
	command.Flags().IntVar(&maxInputTokens, "max-input-tokens", 2048, "maximum input tokens per model call")
	command.Flags().IntVar(&maxOutputTokens, "max-output-tokens", 256, "maximum output tokens per model call")
	command.Flags().DurationVar(&maxInferenceTime, "max-inference-time", 10*time.Minute, "maximum total inference time")
	return command
}
