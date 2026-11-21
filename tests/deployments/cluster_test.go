package deployments

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/andrew-ships-stuff/caphe/internal/audit"
	"github.com/andrew-ships-stuff/caphe/internal/cluster"
)

func TestDeployedCluster(t *testing.T) {
	endpoint := os.Getenv("CAPHE_TEST_ENDPOINT")
	if endpoint == "" {
		t.Skip("set CAPHE_TEST_ENDPOINT to test a deployed cluster")
	}
	t.Run("direct API", func(t *testing.T) { testDeployedCluster(t, endpoint) })
	if ui := os.Getenv("CAPHE_TEST_UI_ENDPOINT"); ui != "" {
		t.Run("workbench proxy", func(t *testing.T) { testDeployedCluster(t, ui+"/api") })
	}
}

func testDeployedCluster(t *testing.T, endpoint string) {
	if endpoint == "" {
		t.Skip("set CAPHE_TEST_ENDPOINT to test a deployed cluster")
	}
	data, err := os.ReadFile(os.Getenv("CAPHE_TEST_AUTH_FILE"))
	if err != nil {
		t.Fatal(err)
	}
	var auth struct {
		Tokens []struct{ Tenant, Token string }
	}
	if err := json.Unmarshal(data, &auth); err != nil {
		t.Fatal(err)
	}
	if len(auth.Tokens) < 2 || auth.Tokens[0].Tenant == auth.Tokens[1].Tenant {
		t.Fatal("two distinct tenants are required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()
	client, err := cluster.NewClient(endpoint, auth.Tokens[0].Token)
	if err != nil {
		t.Fatal(err)
	}
	request := func(method, path, token, body string, want int) {
		t.Helper()
		req, err := http.NewRequestWithContext(ctx, method, endpoint+path, strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		if body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != want {
			t.Fatalf("%s %s: got %d, want %d", method, path, resp.StatusCode, want)
		}
	}
	request("GET", "/healthz", "", "", 200)
	request("GET", "/v1/workflows", "", "", 401)
	request("GET", "/v1/workflows", "invalid", "", 401)
	workflows, err := client.Workflows(ctx)
	if err != nil || len(workflows) == 0 {
		t.Fatalf("registered workflows: %v, %v", workflows, err)
	}
	sub := cluster.Submission{WorkflowDigest: workflows[0], Source: cluster.Source{Kind: "archive"}, Limits: cluster.Limits{CPUMillis: 1000, MemoryBytes: 1 << 30, TimeoutSeconds: 300, Network: "disabled"}}
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	f, err := zw.Create("fixture/README.md")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write([]byte("# Deployment integration fixture\nA repository with a synthetic package lock; no dependencies are downloaded.\n")); err != nil {
		t.Fatal(err)
	}
	f, err = zw.Create("fixture/package-lock.json")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write([]byte(`{"name":"deployment-fixture","version":"1.0.0","lockfileVersion":3,"packages":{"":{"name":"deployment-fixture","version":"1.0.0"},"node_modules/left-pad":{"version":"1.3.0"}}}`)); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(t.TempDir(), "source.zip")
	if err := os.WriteFile(archive, buf.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		want   string
		mutate func(*cluster.Submission)
	}{
		{"unregistered workflow", "workflow digest is not registered", func(s *cluster.Submission) { s.WorkflowDigest = "sha256:" + strings.Repeat("0", 64) }},
		{"excess CPU", "requested resources exceed server policy", func(s *cluster.Submission) { s.Limits.CPUMillis = 1 << 40 }},
		{"network request", "worker network access is disabled", func(s *cluster.Submission) { s.Limits.Network = "restricted" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			invalid := sub
			tc.mutate(&invalid)
			if _, err := client.Submit(ctx, invalid, archive); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("expected %q, got %v", tc.want, err)
			}
		})
	}
	request("POST", "/v1/jobs", auth.Tokens[0].Token, `{"unknown":true}`, 400)
	request("POST", "/v1/jobs", auth.Tokens[0].Token, `{} {}`, 400)
	badArchive := filepath.Join(t.TempDir(), "invalid.zip")
	if err := os.WriteFile(badArchive, []byte("not a zip"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Submit(ctx, sub, badArchive); err == nil {
		t.Fatal("malformed ZIP accepted")
	}
	job, err := client.Submit(ctx, sub, archive)
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/v1/jobs/" + job.ID, "/v1/jobs/" + job.ID + "/bundle"} {
		request("GET", path, "", "", 401)
		request("GET", path, auth.Tokens[1].Token, "", 404)
	}
	for job.Phase != cluster.PhaseSucceeded {
		if job.Phase == cluster.PhaseFailed {
			t.Fatalf("job failed: %s", job.Error)
		}
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(time.Second):
		}
		job, err = client.Get(ctx, job.ID)
		if err != nil {
			t.Fatal(err)
		}
	}
	if !job.NetworkEnforced || job.WorkerID == "" || job.Attempts < 1 {
		t.Fatalf("missing worker execution metadata: %+v", job)
	}
	bundlePath := filepath.Join(t.TempDir(), "bundle.json")
	if err := client.Download(ctx, job.ID, bundlePath); err != nil {
		t.Fatal(err)
	}
	bundle, err := audit.ReadJSON(bundlePath)
	if err != nil {
		t.Fatal(err)
	}
	if len(bundle.Tasks) == 0 || bundle.WorkflowDigest != sub.WorkflowDigest {
		t.Fatal("bundle missing executed workflow tasks")
	}
	for _, id := range []string{"sbom", "secrets", "git-workflows"} {
		succeeded := false
		for _, task := range bundle.Tasks {
			if task.ID == id && task.Status == "succeeded" {
				succeeded = true
			}
		}
		if !succeeded {
			t.Fatalf("installed scanner %s did not succeed: %+v", id, bundle.Coverage)
		}
	}
	t.Logf("scanner coverage: %+v", bundle.Coverage)
	for _, rec := range bundle.Recommendations {
		if rec.Source == "ai" && rec.Status != "hypothesis" {
			t.Fatal("AI recommendation not labeled hypothesis")
		}
	}
	if bundle.Digest != job.BundleDigest {
		t.Fatal("job and verified bundle digest differ")
	}
	request("GET", "/v1/jobs/"+job.ID+"/bundle", auth.Tokens[1].Token, "", 404)
	t.Logf("job %s completed; bundle verified: %s", job.ID, bundle.Digest)
}
