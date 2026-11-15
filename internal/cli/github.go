package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/andrew-ships-stuff/caphe/internal/findings"
	"github.com/andrew-ships-stuff/caphe/internal/githubreview"
	"github.com/andrew-ships-stuff/caphe/internal/inference"
	"github.com/andrew-ships-stuff/caphe/internal/reporting"
	"github.com/spf13/cobra"
)

func (a *app) githubCmd() *cobra.Command {
	command := &cobra.Command{Use: "github", Short: "Create and publish validated GitHub pull-request reviews"}
	command.AddCommand(a.githubAnalyzeCmd(), a.githubValidateCmd(), a.githubPublishCmd(), a.githubAnnotationsCmd())
	return command
}

func (a *app) githubAnalyzeCmd() *cobra.Command {
	var baseReport, headReport, baseSHA, headSHA, repository, output, summaryOutput, sarifOutput, severity, aiEndpoint, aiModel, aiModelDigest string
	var pullRequest, maxComments, maxModelCalls, maxInputTokens, maxOutputTokens int
	var failOnNew, aiEnabled bool
	var maxInferenceTime time.Duration
	command := &cobra.Command{Use: "analyze", Short: "Compare base/head findings and create a signed-by-digest PR review artifact", RunE: func(cmd *cobra.Command, _ []string) error {
		if baseReport == "" || headReport == "" || baseSHA == "" || headSHA == "" || repository == "" || pullRequest <= 0 || output == "" { return fmt.Errorf("base/head reports, SHAs, repository, pull request, and output are required") }
		threshold, err := parseSeverity(severity); if err != nil { return err }
		base, err := githubreview.LoadReport(baseReport); if err != nil { return err }
		head, err := githubreview.LoadReport(headReport); if err != nil { return err }
		changed, err := githubreview.CollectDiff(cmd.Context(), ".", baseSHA, headSHA); if err != nil { return err }
		artifact, err := githubreview.Analyze(base, head, changed, githubreview.Options{Repository: repository, PullRequest: pullRequest, BaseSHA: baseSHA, HeadSHA: headSHA, SeverityThreshold: threshold, FailOnNew: failOnNew, MaxComments: maxComments})
		if err != nil { return err }
		aiResult := githubreview.AIResult{}
		if aiEnabled {
			if aiModel == "" || aiModelDigest == "" { return fmt.Errorf("--ai-model and --ai-model-digest are required with --ai") }
			provider, err := inference.NewLlamaCPP(aiEndpoint, maxInferenceTime); if err != nil { return err }
			available, err := provider.Available(cmd.Context()); if err != nil { return err }
			if available {
				aiResult, err = githubreview.AddAIRecommendations(cmd.Context(), &artifact, provider, githubreview.AIBudget{MaxCalls: maxModelCalls, MaxInputTokens: maxInputTokens, MaxOutputTokens: maxOutputTokens, MaxTotalTime: maxInferenceTime, Model: aiModel, ModelDigest: aiModelDigest}, maxComments)
				if err != nil { return err }
			} else {
				aiResult.Errors = []string{"local llama.cpp endpoint unavailable; deterministic review completed"}
			}
		}
		data, err := json.MarshalIndent(artifact, "", "  "); if err != nil { return err }
		if err := os.WriteFile(output, append(data, '\n'), 0o600); err != nil { return err }
		if summaryOutput != "" { if err := os.WriteFile(summaryOutput, []byte(artifact.Summary), 0o600); err != nil { return err } }
		if sarifOutput != "" { f, err := os.Create(sarifOutput); if err != nil { return err }; sarifErr := reporting.SARIF(f, artifact.Introduced); closeErr := f.Close(); if sarifErr != nil { return sarifErr }; if closeErr != nil { return closeErr } }
		if err := a.print(map[string]any{"artifact": output, "digest": artifact.Digest, "metrics": artifact.Metrics, "policy": artifact.Policy, "ai": aiResult}); err != nil { return err }
		if artifact.Policy.Fail { return fmt.Errorf("GitHub PR policy failed: %s", artifact.Policy.Reason) }
		return nil
	}}
	command.Flags().StringVar(&baseReport, "base-report", "", "base revision Caphe JSON report")
	command.Flags().StringVar(&headReport, "head-report", "", "head revision Caphe JSON report")
	command.Flags().StringVar(&baseSHA, "base-sha", "", "full base commit SHA")
	command.Flags().StringVar(&headSHA, "head-sha", "", "full head commit SHA")
	command.Flags().StringVar(&repository, "repository", "", "GitHub owner/repository")
	command.Flags().IntVar(&pullRequest, "pr", 0, "pull request number")
	command.Flags().StringVarP(&output, "output", "o", "caphe-pr-review.json", "review artifact output")
	command.Flags().StringVar(&summaryOutput, "summary-output", "", "validated Markdown summary output")
	command.Flags().StringVar(&sarifOutput, "sarif-output", "", "SARIF containing introduced findings")
	command.Flags().StringVar(&severity, "severity-threshold", "high", "minimum severity for policy and inline comments")
	command.Flags().BoolVar(&failOnNew, "fail-on-new", false, "fail after writing outputs when a new finding meets the threshold")
	command.Flags().IntVar(&maxComments, "max-comments", 10, "maximum inline comment candidates (0-100)")
	command.Flags().BoolVar(&aiEnabled, "ai", false, "enable optional local CPU inference")
	command.Flags().StringVar(&aiEndpoint, "ai-endpoint", "http://127.0.0.1:8080", "loopback llama.cpp endpoint")
	command.Flags().StringVar(&aiModel, "ai-model", "", "explicit model identifier")
	command.Flags().StringVar(&aiModelDigest, "ai-model-digest", "", "verified model content digest")
	command.Flags().IntVar(&maxModelCalls, "max-model-calls", 3, "maximum model calls per PR (0-20)")
	command.Flags().IntVar(&maxInputTokens, "max-input-tokens", 2048, "maximum input tokens per model call")
	command.Flags().IntVar(&maxOutputTokens, "max-output-tokens", 256, "maximum output tokens per model call")
	command.Flags().DurationVar(&maxInferenceTime, "max-inference-time", 5*time.Minute, "maximum total inference time")
	return command
}

func (a *app) githubValidateCmd() *cobra.Command {
	var repository, baseSHA, headSHA, summaryOutput string
	var pullRequest, maxComments int
	command := &cobra.Command{Use: "validate ARTIFACT", Args: cobra.ExactArgs(1), Short: "Validate artifact schema, digest, references, and expected PR identity", RunE: func(cmd *cobra.Command, args []string) error {
		artifact, err := githubreview.LoadArtifact(args[0], maxComments); if err != nil { return err }
		if err := matchExpectedIdentity(artifact, repository, pullRequest, baseSHA, headSHA); err != nil { return err }
		if summaryOutput != "" { if err := os.WriteFile(summaryOutput, []byte(artifact.Summary), 0o600); err != nil { return err } }
		return a.print(map[string]any{"valid": true, "digest": artifact.Digest, "repository": artifact.Repository, "pr": artifact.PullRequest, "baseSha": artifact.BaseSHA, "headSha": artifact.HeadSHA, "policy": artifact.Policy})
	}}
	addIdentityFlags(command, &repository, &pullRequest, &baseSHA, &headSHA)
	command.Flags().IntVar(&maxComments, "max-comments", 10, "maximum accepted inline comments")
	command.Flags().StringVar(&summaryOutput, "summary-output", "", "write the validated summary")
	return command
}

func (a *app) githubPublishCmd() *cobra.Command {
	var repository, baseSHA, headSHA, token, apiURL string
	var pullRequest, maxComments int
	var summaryOnly, dryRun bool
	command := &cobra.Command{Use: "publish ARTIFACT", Args: cobra.ExactArgs(1), Short: "Publish only a validated review artifact using the GitHub API", RunE: func(cmd *cobra.Command, args []string) error {
		artifact, err := githubreview.LoadArtifact(args[0], maxComments); if err != nil { return err }
		if err := matchExpectedIdentity(artifact, repository, pullRequest, baseSHA, headSHA); err != nil { return err }
		if token == "" { token = os.Getenv("GITHUB_TOKEN") }
		if apiURL == "" { apiURL = os.Getenv("GITHUB_API_URL") }
		result, err := githubreview.Publish(cmd.Context(), artifact, githubreview.PublishOptions{Token: token, APIURL: apiURL, SummaryOnly: summaryOnly, DryRun: dryRun, MaxComments: maxComments})
		if err != nil { return err }
		return a.print(result)
	}}
	addIdentityFlags(command, &repository, &pullRequest, &baseSHA, &headSHA)
	command.Flags().StringVar(&token, "token", "", "GitHub token (defaults to GITHUB_TOKEN)")
	command.Flags().StringVar(&apiURL, "api-url", "", "GitHub API HTTPS origin (defaults to GITHUB_API_URL or api.github.com)")
	command.Flags().IntVar(&maxComments, "max-comments", 10, "maximum accepted inline comments")
	command.Flags().BoolVar(&summaryOnly, "summary-only", false, "publish only the consolidated summary")
	command.Flags().BoolVar(&dryRun, "dry-run", false, "validate without making API calls")
	return command
}

func (a *app) githubAnnotationsCmd() *cobra.Command {
	var maxComments int
	command := &cobra.Command{Use: "annotations ARTIFACT", Args: cobra.ExactArgs(1), Short: "Emit escaped GitHub workflow annotations from a validated artifact", RunE: func(cmd *cobra.Command, args []string) error {
		artifact, err := githubreview.LoadArtifact(args[0], maxComments); if err != nil { return err }
		for _, f := range artifact.Introduced {
			level := "warning"; if f.Severity == findings.SeverityCritical || f.Severity == findings.SeverityHigh { level = "error" }
			properties := "title=" + escapeWorkflowProperty("Caphe "+f.RuleID)
			if f.Location.Path != "" { properties += ",file=" + escapeWorkflowProperty(f.Location.Path); if f.Location.StartLine > 0 { properties += fmt.Sprintf(",line=%d", f.Location.StartLine) } }
			fmt.Fprintf(a.stdout, "::%s %s::%s\n", level, properties, escapeWorkflowData(f.Title+" [evidence "+f.ID+"]"))
		}
		return nil
	}}
	command.Flags().IntVar(&maxComments, "max-comments", 10, "maximum accepted inline comments")
	return command
}

func addIdentityFlags(command *cobra.Command, repository *string, pullRequest *int, baseSHA, headSHA *string) {
	command.Flags().StringVar(repository, "repository", "", "expected owner/repository")
	command.Flags().IntVar(pullRequest, "pr", 0, "expected pull request number")
	command.Flags().StringVar(baseSHA, "base-sha", "", "expected full base commit SHA")
	command.Flags().StringVar(headSHA, "head-sha", "", "expected full head commit SHA")
}

func matchExpectedIdentity(artifact githubreview.Artifact, repository string, pullRequest int, baseSHA, headSHA string) error {
	if repository == "" || pullRequest <= 0 || baseSHA == "" || headSHA == "" { return fmt.Errorf("expected repository, PR, base SHA, and head SHA are required") }
	if artifact.Repository != repository || artifact.PullRequest != pullRequest || artifact.BaseSHA != baseSHA || artifact.HeadSHA != headSHA { return fmt.Errorf("artifact identity does not match trusted event context") }
	return nil
}

func parseSeverity(value string) (findings.Severity, error) {
	severity := findings.Severity(strings.ToLower(value))
	switch severity { case findings.SeverityInfo, findings.SeverityLow, findings.SeverityMedium, findings.SeverityHigh, findings.SeverityCritical: return severity, nil }
	return "", fmt.Errorf("invalid severity threshold %q", value)
}

func escapeWorkflowData(value string) string { return strings.NewReplacer("%", "%25", "\r", "%0D", "\n", "%0A").Replace(value) }
func escapeWorkflowProperty(value string) string { return strings.NewReplacer("%", "%25", "\r", "%0D", "\n", "%0A", ":", "%3A", ",", "%2C").Replace(value) }
