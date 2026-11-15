package cli

import (
	"encoding/json"
	"fmt"
	"math"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/andrew-ships-stuff/caphe/internal/audit"
	"github.com/andrew-ships-stuff/caphe/internal/cluster"
	"github.com/andrew-ships-stuff/caphe/internal/compiler"
	"github.com/andrew-ships-stuff/caphe/internal/source"
	"github.com/andrew-ships-stuff/caphe/internal/workflow"
	"github.com/spf13/cobra"
)

func (a *app) clusterCmd() *cobra.Command {
	command := &cobra.Command{Use: "cluster", Short: "Submit and execute bounded audits across Caphe workers"}
	command.AddCommand(a.clusterServeCmd(), a.clusterWorkerCmd(), a.clusterSubmitCmd(), a.clusterGetCmd(), a.clusterDownloadCmd(), a.clusterWorkflowsCmd())
	return command
}

func (a *app) clusterServeCmd() *cobra.Command {
	var listen, root, authFile, maxMemory string
	var workflowRefs, gitHosts []string
	var insecure, allowWorkerNetwork, networkEnforced bool
	var maxCPU, maxFiles int64
	var maxTimeout, retention, gitTimeout time.Duration
	var maxUpload, maxExpanded int64
	command := &cobra.Command{Use: "serve", Short: "Run the authenticated cluster control plane", RunE: func(cmd *cobra.Command, _ []string) error {
		if insecure && !loopbackListen(listen) {
			return fmt.Errorf("--insecure-no-auth is allowed only on a loopback listener")
		}
		if maxCPU <= 0 || maxUpload <= 0 || maxTimeout <= 0 || retention <= 0 || gitTimeout <= 0 {
			return fmt.Errorf("cluster server limits and durations must be positive")
		}
		archiveLimits, err := clusterSourceLimits(maxFiles, maxExpanded)
		if err != nil {
			return err
		}
		memoryBytes, err := parseBytes(maxMemory)
		if err != nil {
			return fmt.Errorf("invalid --max-memory: %w", err)
		}
		store, err := cluster.OpenStore(root)
		if err != nil {
			return err
		}
		for _, ref := range workflowRefs {
			plan, err := a.clusterPlan(ref)
			if err != nil {
				return fmt.Errorf("register workflow %q: %w", ref, err)
			}
			if err := store.RegisterWorkflow(plan); err != nil {
				return err
			}
			fmt.Fprintf(a.stderr, "Registered workflow %s (%s)\n", plan.Workflow.Name, plan.Digest)
		}
		auth, err := cluster.LoadAuthenticator(authFile, insecure)
		if err != nil {
			return err
		}
		allowedHosts := map[string]bool{}
		for _, host := range gitHosts {
			host = strings.ToLower(strings.TrimSpace(host))
			if host == "" || strings.ContainsAny(host, "/:@") {
				return fmt.Errorf("invalid Git host %q", host)
			}
			allowedHosts[host] = true
		}
		server, err := cluster.NewServer(cluster.ServerConfig{
			ListenAddress: listen,
			Store:         store,
			Auth:          auth,
			Policy: cluster.Policy{
				MaxCPUMillis:       maxCPU,
				MaxMemoryBytes:     memoryBytes,
				MaxTimeout:         maxTimeout,
				AllowWorkerNetwork: allowWorkerNetwork,
				AllowedGitHosts:    allowedHosts,
			},
			ArchiveLimits:   archiveLimits,
			MaxUploadBytes:  maxUpload,
			Retention:       retention,
			GitTimeout:      gitTimeout,
			NetworkEnforced: networkEnforced,
			Log:             a.stderr,
		})
		if err != nil {
			return err
		}
		return server.Run(cmd.Context())
	}}
	defaultRoot := filepath.Join(a.dataDir, "cluster")
	command.Flags().StringVar(&listen, "listen", "127.0.0.1:8787", "API listen address")
	command.Flags().StringVar(&root, "root", defaultRoot, "shared cluster state directory")
	command.Flags().StringVar(&authFile, "auth-file", "", "JSON tenant token file")
	command.Flags().BoolVar(&insecure, "insecure-no-auth", false, "disable authentication on loopback only")
	command.Flags().StringSliceVar(&workflowRefs, "workflow", []string{"caphe:default"}, "trusted workflow YAML, bundled reference, or compiled lock to register")
	command.Flags().StringSliceVar(&gitHosts, "git-host", nil, "allowed HTTPS Git host (repeatable; none disables Git submissions)")
	command.Flags().Int64Var(&maxCPU, "max-cpu-millis", 8000, "maximum admitted CPU request")
	command.Flags().StringVar(&maxMemory, "max-memory", "16GiB", "maximum admitted memory request")
	command.Flags().DurationVar(&maxTimeout, "max-timeout", time.Hour, "maximum job duration")
	command.Flags().Int64Var(&maxUpload, "max-upload-bytes", 256<<20, "maximum compressed archive upload")
	command.Flags().Int64Var(&maxExpanded, "max-expanded-bytes", 2<<30, "maximum expanded source size")
	command.Flags().Int64Var(&maxFiles, "max-files", 100_000, "maximum source file count")
	command.Flags().DurationVar(&retention, "retention", 7*24*time.Hour, "completed job retention")
	command.Flags().DurationVar(&gitTimeout, "git-timeout", 5*time.Minute, "Git acquisition timeout")
	command.Flags().BoolVar(&allowWorkerNetwork, "allow-worker-network", false, "admit restricted-network worker jobs")
	command.Flags().BoolVar(&networkEnforced, "network-enforced", false, "record that deployment policy enforces submitted worker network modes")
	return command
}

func (a *app) clusterWorkerCmd() *cobra.Command {
	var root, workerID string
	var concurrency, taskConcurrency int
	var maxFiles int64
	var poll, leaseTimeout time.Duration
	var maxOutput, maxExpanded int64
	var networkEnforced bool
	command := &cobra.Command{Use: "worker", Short: "Run one or more cluster worker slots", RunE: func(cmd *cobra.Command, _ []string) error {
		if concurrency <= 0 || taskConcurrency <= 0 || poll <= 0 || leaseTimeout <= 0 || maxOutput <= 0 {
			return fmt.Errorf("worker concurrency, durations, and limits must be positive")
		}
		archiveLimits, err := clusterSourceLimits(maxFiles, maxExpanded)
		if err != nil {
			return err
		}
		store, err := cluster.OpenStore(root)
		if err != nil {
			return err
		}
		worker, err := cluster.NewWorker(cluster.WorkerConfig{ID: workerID, Store: store, Registry: a.registry, Concurrency: concurrency, TaskConcurrency: taskConcurrency, PollInterval: poll, LeaseTimeout: leaseTimeout, MaxOutputBytes: maxOutput, ArchiveLimits: archiveLimits, CapheVersion: Version, NetworkEnforced: networkEnforced, Log: a.stderr})
		if err != nil {
			return err
		}
		return worker.Run(cmd.Context())
	}}
	command.Flags().StringVar(&root, "root", filepath.Join(a.dataDir, "cluster"), "shared cluster state directory")
	command.Flags().StringVar(&workerID, "worker-id", "", "stable worker identifier (generated when empty)")
	command.Flags().IntVar(&concurrency, "concurrency", 1, "concurrent jobs in this process")
	command.Flags().IntVar(&taskConcurrency, "task-concurrency", 1, "scanner tasks per job")
	command.Flags().DurationVar(&poll, "poll-interval", time.Second, "queue polling interval")
	command.Flags().DurationVar(&leaseTimeout, "lease-timeout", 2*time.Minute, "stale worker lease timeout")
	command.Flags().Int64Var(&maxOutput, "max-output-bytes", 64<<20, "maximum combined derived report size")
	command.Flags().Int64Var(&maxFiles, "max-files", 100_000, "maximum source file count")
	command.Flags().Int64Var(&maxExpanded, "max-expanded-bytes", 2<<30, "maximum expanded source size")
	command.Flags().BoolVar(&networkEnforced, "network-enforced", false, "confirm the runtime externally enforces job network policy")
	return command
}

func (a *app) clusterSubmitCmd() *cobra.Command {
	var endpoint, token, gitURL, commit, archive, workflowDigest, memory, networkMode string
	var cpu float64
	var timeout time.Duration
	var wait bool
	command := &cobra.Command{Use: "submit", Short: "Submit an immutable Git commit or ZIP archive", RunE: func(cmd *cobra.Command, _ []string) error {
		if (gitURL == "") == (archive == "") {
			return fmt.Errorf("exactly one of --git or --archive is required")
		}
		if gitURL != "" && commit == "" {
			return fmt.Errorf("--ref must be an immutable commit SHA with --git")
		}
		if archive != "" && commit != "" {
			return fmt.Errorf("--ref is only valid with --git")
		}
		memoryBytes, err := parseBytes(memory)
		if err != nil {
			return fmt.Errorf("invalid --memory: %w", err)
		}
		if cpu <= 0 || math.IsNaN(cpu) || math.IsInf(cpu, 0) || cpu > float64(math.MaxInt64)/1000 {
			return fmt.Errorf("--cpu must be positive")
		}
		if timeout <= 0 {
			return fmt.Errorf("--timeout must be positive")
		}
		sub := cluster.Submission{WorkflowDigest: workflowDigest, Limits: cluster.Limits{CPUMillis: int64(cpu * 1000), MemoryBytes: memoryBytes, TimeoutSeconds: int64(timeout / time.Second), Network: networkMode}}
		if archive != "" {
			sub.Source = cluster.Source{Kind: "archive"}
		} else {
			sub.Source = cluster.Source{Kind: "git", GitURL: gitURL, CommitSHA: strings.ToLower(commit)}
		}
		client, err := cluster.NewClient(endpointValue(endpoint), tokenValue(token))
		if err != nil {
			return err
		}
		job, err := client.Submit(cmd.Context(), sub, archive)
		if err != nil {
			return err
		}
		if wait {
			job, err = waitForClusterJob(cmd, client, job.ID)
			if err != nil {
				return err
			}
		}
		return a.print(job)
	}}
	command.Flags().StringVar(&endpoint, "endpoint", "", "cluster API endpoint (or CAPHE_CLUSTER_ENDPOINT)")
	command.Flags().StringVar(&token, "token", "", "bearer token (prefer CAPHE_CLUSTER_TOKEN)")
	command.Flags().StringVar(&gitURL, "git", "", "HTTPS Git repository URL")
	command.Flags().StringVar(&commit, "ref", "", "immutable 40- or 64-character commit SHA")
	command.Flags().StringVar(&archive, "archive", "", "ZIP archive to upload")
	command.Flags().StringVar(&workflowDigest, "workflow-digest", "", "registered compiled workflow digest")
	command.Flags().Float64Var(&cpu, "cpu", 1, "requested CPU cores")
	command.Flags().StringVar(&memory, "memory", "1GiB", "requested memory")
	command.Flags().DurationVar(&timeout, "timeout", 30*time.Minute, "job timeout")
	command.Flags().StringVar(&networkMode, "network", "disabled", "worker network mode: disabled or restricted")
	command.Flags().BoolVar(&wait, "wait", false, "wait for the job to finish")
	return command
}

func (a *app) clusterGetCmd() *cobra.Command {
	var endpoint, token string
	command := &cobra.Command{Use: "get JOB", Args: cobra.ExactArgs(1), Short: "Get tenant-scoped job status", RunE: func(cmd *cobra.Command, args []string) error {
		client, err := cluster.NewClient(endpointValue(endpoint), tokenValue(token))
		if err != nil {
			return err
		}
		job, err := client.Get(cmd.Context(), args[0])
		if err != nil {
			return err
		}
		return a.print(job)
	}}
	clusterClientFlags(command, &endpoint, &token)
	return command
}

func (a *app) clusterDownloadCmd() *cobra.Command {
	var endpoint, token, output string
	command := &cobra.Command{Use: "download JOB", Args: cobra.ExactArgs(1), Short: "Download a completed digest-verified audit bundle", RunE: func(cmd *cobra.Command, args []string) error {
		client, err := cluster.NewClient(endpointValue(endpoint), tokenValue(token))
		if err != nil {
			return err
		}
		if err := client.Download(cmd.Context(), args[0], output); err != nil {
			return err
		}
		if _, err := auditBundleDigest(output); err != nil {
			_ = os.Remove(output)
			return err
		}
		return a.print(map[string]any{"job": args[0], "bundle": output, "verified": true})
	}}
	clusterClientFlags(command, &endpoint, &token)
	command.Flags().StringVarP(&output, "output", "o", "caphe-audit.json", "new bundle output path")
	return command
}

func (a *app) clusterWorkflowsCmd() *cobra.Command {
	var endpoint, token string
	command := &cobra.Command{Use: "workflows", Short: "List registered workflow digests", RunE: func(cmd *cobra.Command, _ []string) error {
		client, err := cluster.NewClient(endpointValue(endpoint), tokenValue(token))
		if err != nil {
			return err
		}
		digests, err := client.Workflows(cmd.Context())
		if err != nil {
			return err
		}
		return a.print(map[string]any{"workflows": digests})
	}}
	clusterClientFlags(command, &endpoint, &token)
	return command
}

func (a *app) clusterPlan(ref string) (*compiler.Plan, error) {
	if data, err := os.ReadFile(ref); err == nil {
		var plan compiler.Plan
		if json.Unmarshal(data, &plan) == nil && plan.SchemaVersion != "" {
			if err := compiler.ValidateLock(&plan, a.registry); err != nil {
				return nil, err
			}
			return &plan, nil
		}
	}
	definition, err := workflow.Load(ref)
	if err != nil {
		return nil, err
	}
	return compiler.New(a.registry).Compile(definition)
}

func waitForClusterJob(cmd *cobra.Command, client *cluster.Client, id string) (cluster.Job, error) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		job, err := client.Get(cmd.Context(), id)
		if err != nil {
			return cluster.Job{}, err
		}
		if job.Phase == cluster.PhaseSucceeded || job.Phase == cluster.PhaseFailed {
			return job, nil
		}
		select {
		case <-cmd.Context().Done():
			return cluster.Job{}, cmd.Context().Err()
		case <-ticker.C:
		}
	}
}

func auditBundleDigest(path string) (string, error) {
	bundle, err := audit.ReadJSON(path)
	if err != nil {
		return "", err
	}
	return bundle.Digest, nil
}

func clusterClientFlags(command *cobra.Command, endpoint, token *string) {
	command.Flags().StringVar(endpoint, "endpoint", "", "cluster API endpoint (or CAPHE_CLUSTER_ENDPOINT)")
	command.Flags().StringVar(token, "token", "", "bearer token (prefer CAPHE_CLUSTER_TOKEN)")
}

func endpointValue(value string) string {
	if value == "" {
		value = os.Getenv("CAPHE_CLUSTER_ENDPOINT")
	}
	return value
}

func tokenValue(value string) string {
	if value == "" {
		value = os.Getenv("CAPHE_CLUSTER_TOKEN")
	}
	return value
}

func loopbackListen(address string) bool {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return false
	}
	return host == "localhost" || net.ParseIP(host) != nil && net.ParseIP(host).IsLoopback()
}

var byteSizePattern = regexp.MustCompile(`^([0-9]+)(B|KiB|MiB|GiB|TiB)$`)

func parseBytes(value string) (int64, error) {
	match := byteSizePattern.FindStringSubmatch(value)
	if match == nil {
		return 0, fmt.Errorf("use an integer followed by B, KiB, MiB, GiB, or TiB")
	}
	n, err := strconv.ParseInt(match[1], 10, 64)
	if err != nil {
		return 0, err
	}
	multipliers := map[string]int64{"B": 1, "KiB": 1 << 10, "MiB": 1 << 20, "GiB": 1 << 30, "TiB": 1 << 40}
	multiplier := multipliers[match[2]]
	if n <= 0 || n > math.MaxInt64/multiplier {
		return 0, fmt.Errorf("size is out of range")
	}
	return n * multiplier, nil
}

func clusterSourceLimits(maxFiles, maxExpanded int64) (source.Limits, error) {
	if maxFiles <= 0 || uint64(maxFiles) > uint64(^uint(0)>>1) {
		return source.Limits{}, fmt.Errorf("--max-files must be a positive platform-sized integer")
	}
	if maxExpanded <= 0 {
		return source.Limits{}, fmt.Errorf("--max-expanded-bytes must be positive")
	}
	return source.Limits{MaxFiles: int(maxFiles), MaxExpandedBytes: uint64(maxExpanded)}, nil
}
