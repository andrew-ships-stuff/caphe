package inference

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestEnsureModelDigestAndCache(t *testing.T) {
	content := []byte("fake gguf weights")
	sum := sha256.Sum256(content)
	digest := "sha256:" + hex.EncodeToString(sum[:])
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(content)
	}))
	defer server.Close()
	cache := t.TempDir()
	path, err := EnsureModel(context.Background(), cache, server.URL+"/model.gguf", digest, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Base(path) != strings.TrimPrefix(digest, "sha256:")+".gguf" {
		t.Fatalf("expected content-addressed filename, got %s", path)
	}
	cached, err := EnsureModel(context.Background(), cache, server.URL+"/model.gguf", digest, server.Client())
	if err != nil || cached != path {
		t.Fatalf("expected cache hit at same path: %v %s", err, cached)
	}
}

func TestEnsureModelRejects(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("tampered"))
	}))
	defer server.Close()
	if _, err := EnsureModel(context.Background(), t.TempDir(), server.URL+"/model.gguf", "sha256:"+strings.Repeat("a", 64)); err == nil {
		t.Fatal("expected digest mismatch error")
	}
	if _, err := EnsureModel(context.Background(), t.TempDir(), "http://example.invalid/model.gguf", "sha256:"+strings.Repeat("a", 64)); err == nil {
		t.Fatal("expected rejection of non-HTTPS URL")
	}
	if _, err := EnsureModel(context.Background(), t.TempDir(), "https://example.invalid/model.gguf", "md5:nope"); err == nil {
		t.Fatal("expected rejection of malformed digest")
	}
}

func TestMain(m *testing.M) {
	if os.Getenv("CAPHE_FAKE_LLAMA") == "1" {
		port := os.Getenv("CAPHE_FAKE_LLAMA_PORT")
		mux := http.NewServeMux()
		mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(`{"status":"ok"}`)) })
		mux.HandleFunc("/v1/chat/completions", func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"model":"fake","choices":[{"message":{"content":"{\"answer\":42}"}}],"usage":{"prompt_tokens":7,"completion_tokens":3}}`))
		})
		server := &http.Server{Addr: "127.0.0.1:" + port, Handler: mux}
		_ = server.ListenAndServe()
		return
	}
	os.Exit(m.Run())
}

func TestStartServerWithFakeLlamaServer(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake shim is a POSIX shell script")
	}
	dir := t.TempDir()
	shim := filepath.Join(dir, "llama-server")
	script := "#!/bin/sh\n" +
		"port=\"\"\n" +
		"while [ $# -gt 0 ]; do case \"$1\" in --port) port=\"$2\"; shift 2 ;; *) shift ;; esac; done\n" +
		"[ -n \"$port\" ] || { echo \"missing --port\" >&2; exit 2; }\n" +
		"echo \"fake llama-server listening on $port\"\n" +
		"exec env CAPHE_FAKE_LLAMA=1 CAPHE_FAKE_LLAMA_PORT=\"$port\" \"" + os.Args[0] + "\" -test.run '^TestNoSuchTestXYZ$'\n"
	if err := os.WriteFile(shim, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("CAPHE_TOOL_BIN", filepath.Join(dir, "empty-managed-tools"))
	model := filepath.Join(dir, "model.gguf")
	if err := os.WriteFile(model, []byte("weights"), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	server, err := StartServer(ctx, ServerOptions{ModelPath: model, StartupTimeout: 30 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Stop()
	if !strings.HasPrefix(server.Endpoint, "http://127.0.0.1:") {
		t.Fatalf("unexpected endpoint %s", server.Endpoint)
	}
	provider, err := NewLlamaCPP(server.Endpoint, 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	ok, err := provider.Available(ctx)
	if err != nil || !ok {
		t.Fatalf("expected available fake server: %v %v", ok, err)
	}
	result, err := provider.GenerateStructured(ctx, Request{Model: "fake", MaxInputTokens: 100, MaxOutputTokens: 50})
	if err != nil {
		t.Fatal(err)
	}
	if !json.Valid(result.Output) {
		t.Fatalf("invalid JSON output: %s", result.Output)
	}
}

func TestResolveLlamaServerPreference(t *testing.T) {
	dir := t.TempDir()
	explicit := filepath.Join(dir, "explicit-llama-server")
	if err := os.WriteFile(explicit, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CAPHE_LLAMA_SERVER", "")
	got, err := ResolveLlamaServer(explicit)
	if err != nil || got != explicit {
		t.Fatalf("explicit binary should win: %v %s", err, got)
	}
	envBinary := filepath.Join(dir, "env-llama-server")
	if err := os.WriteFile(envBinary, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CAPHE_LLAMA_SERVER", envBinary)
	got, err = ResolveLlamaServer("")
	if err != nil || got != envBinary {
		t.Fatalf("CAPHE_LLAMA_SERVER should be used: %v %s", err, got)
	}
	t.Setenv("CAPHE_LLAMA_SERVER", "")
	managed := filepath.Join(dir, "managed", fmt.Sprintf("llama.cpp-%s", managedLlamaPinnedVersion))
	if err := os.MkdirAll(managed, 0o755); err != nil {
		t.Fatal(err)
	}
	managedBinary := filepath.Join(managed, llamaServerName())
	if err := os.WriteFile(managedBinary, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CAPHE_TOOL_BIN", filepath.Join(dir, "managed"))
	t.Setenv("PATH", dir)
	got, err = ResolveLlamaServer("")
	if err != nil || got != managedBinary {
		t.Fatalf("managed tool should be used before PATH: %v %s", err, got)
	}
}

func TestSubprocessEnvStripsSecrets(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", "secret-token")
	t.Setenv("PATH", "/usr/bin")
	env := subprocessEnv("/opt/llama/bin/llama-server")
	for _, entry := range env {
		if strings.HasPrefix(entry, "GITHUB_TOKEN=") {
			t.Fatalf("GITHUB_TOKEN leaked to subprocess: %s", entry)
		}
	}
	binary := "/opt/llama/bin/llama-server"
	want := "LD_LIBRARY_PATH=" + filepath.Dir(binary)
	if runtime.GOOS == "darwin" {
		want = "DYLD_LIBRARY_PATH=" + filepath.Dir(binary)
	}
	found := false
	for _, entry := range env {
		if entry == want {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected library path entry %s in %v", want, env)
	}
}

// TestRealLlamaCPPDogfood downloads the pinned CI model and runs a real
// structured generation through the subprocess launcher. Opt-in:
//
//	CAPHE_TEST_LLAMA=1 go test ./internal/inference -run TestRealLlamaCPPDogfood -v
func TestRealLlamaCPPDogfood(t *testing.T) {
	if os.Getenv("CAPHE_TEST_LLAMA") != "1" {
		t.Skip("set CAPHE_TEST_LLAMA=1 to download the pinned model and run real CPU inference")
	}
	binary, err := ResolveLlamaServer("")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()
	digest := "sha256:1adf0b11065d8ad2e8123ea110d1ec956dab4ab038eab665614adba04b6c3370"
	url := "https://huggingface.co/bartowski/Qwen2.5-1.5B-Instruct-GGUF/resolve/main/Qwen2.5-1.5B-Instruct-Q4_K_M.gguf"
	modelPath, err := EnsureModel(ctx, t.TempDir(), url, digest)
	if err != nil {
		t.Fatal(err)
	}
	server, err := StartServer(ctx, ServerOptions{Binary: binary, ModelPath: modelPath, Threads: 4, StartupTimeout: 5 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Stop()
	provider, err := NewLlamaCPP(server.Endpoint, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	result, err := provider.GenerateStructured(ctx, Request{Model: "qwen2.5-1.5b-instruct", SystemPrompt: "Return exactly one JSON object.", UntrustedContext: "BEGIN_UNTRUSTED_DATA\nSay hello in JSON.\nEND_UNTRUSTED_DATA", Schema: json.RawMessage(`{"type":"object","additionalProperties":false,"required":["greeting"],"properties":{"greeting":{"type":"string"}}}`), MaxInputTokens: 512, MaxOutputTokens: 64})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("model output: %s (%d prompt/%d completion tokens)", result.Output, result.PromptTokens, result.CompletionTokens)
	var out struct {
		Greeting string `json:"greeting"`
	}
	if err := json.Unmarshal(result.Output, &out); err != nil {
		t.Fatalf("structured output invalid: %v (%s)", err, result.Output)
	}
}
