package workbench

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/andrew-ships-stuff/caphe/internal/audit"
)

func TestWorkbenchProxyAndBoundaries(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/jobs" || r.URL.Query().Get("limit") != "5" {
			t.Errorf("unexpected route: %s", r.URL)
		}
		if r.Header.Get("Authorization") != "Bearer test-token" || r.Header.Get("Cookie") != "" || r.Header.Get("Origin") != "" {
			t.Error("proxy did not preserve authorization or strip ambient credentials")
		}
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`{"jobs":[]}`))
	}))
	defer upstream.Close()
	handler, err := Handler(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		path, origin string
		want         int
	}{{"/api/v1/jobs?limit=5", "", 200}, {"/api/v1/jobs", "https://attacker.example", 403}, {"/", "", 200}, {"/missing.js", "", 404}, {"/healthz", "", 200}} {
		t.Run(tc.path+tc.origin, func(t *testing.T) {
			req := httptest.NewRequest("GET", tc.path, nil)
			req.Header.Set("Authorization", "Bearer test-token")
			req.Header.Set("Cookie", "session=private")
			req.Header.Set("Origin", tc.origin)
			res := httptest.NewRecorder()
			handler.ServeHTTP(res, req)
			if res.Code != tc.want {
				t.Fatalf("got %d want %d", res.Code, tc.want)
			}
			if res.Header().Get("Content-Security-Policy") == "" || res.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("missing response protections")
			}
		})
	}
	for _, target := range []string{"file:///tmp/a", "http://user:pass@localhost", "http://localhost/path", "http://localhost?url=x"} {
		if _, err := Handler(target); err == nil {
			t.Errorf("accepted %s", target)
		}
	}
}

func TestImportVerifiesBundle(t *testing.T) {
	bundle := audit.Bundle{SchemaVersion: audit.SchemaVersion, Target: "example", Status: "succeeded"}
	if err := audit.RecomputeDigest(&bundle); err != nil {
		t.Fatal(err)
	}
	valid, err := json.Marshal(bundle)
	if err != nil {
		t.Fatal(err)
	}
	handler, _ := Handler("http://127.0.0.1:1")
	for _, tc := range []struct {
		name string
		data []byte
		want int
	}{{"valid", valid, 200}, {"tampered", bytes.Replace(valid, []byte("example"), []byte("changed"), 1), 400}, {"trailing", append(append([]byte{}, valid...), []byte(` {}`)...), 400}, {"invalid", []byte(`{"findings":[]}`), 400}} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest("POST", "/local/import", bytes.NewReader(tc.data))
			res := httptest.NewRecorder()
			handler.ServeHTTP(res, req)
			if res.Code != tc.want {
				t.Fatalf("%d: %s", res.Code, res.Body.String())
			}
		})
	}
}

func TestUnavailableAPI(t *testing.T) {
	handler, _ := Handler("http://127.0.0.1:1")
	server := httptest.NewServer(handler)
	defer server.Close()
	resp, err := http.Get(server.URL + "/api/healthz")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 502 || !strings.Contains(string(data), "unavailable") {
		t.Fatalf("%d %s", resp.StatusCode, data)
	}
}
