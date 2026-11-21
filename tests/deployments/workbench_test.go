package deployments

import (
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

func TestDeployedWorkbenchAssets(t *testing.T) {
	endpoint := os.Getenv("CAPHE_TEST_UI_ENDPOINT")
	if endpoint == "" {
		t.Skip("set CAPHE_TEST_UI_ENDPOINT to test the workbench")
	}
	client := &http.Client{Timeout: 15 * time.Second}
	for _, path := range []string{"/", "/app.mjs", "/style.css", "/caphe-mark.png", "/healthz"} {
		t.Run(path, func(t *testing.T) {
			resp, err := client.Get(endpoint + path)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
			if err != nil {
				t.Fatal(err)
			}
			if resp.StatusCode != 200 || len(body) == 0 {
				t.Fatalf("asset %s: %d", path, resp.StatusCode)
			}
			if resp.Header.Get("Cache-Control") != "no-store" || !strings.Contains(resp.Header.Get("Content-Security-Policy"), "frame-ancestors 'none'") {
				t.Fatal("missing workbench security headers")
			}
			if path == "/" && !strings.Contains(string(body), "Security workbench") {
				t.Fatal("not the workbench document")
			}
		})
	}
}
