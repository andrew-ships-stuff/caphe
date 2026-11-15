package inference

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"
)

var managedLlamaPinnedVersion = "b12359"

const maxServerLogTail = 8 << 10

type ServerOptions struct {
	Binary         string
	ModelPath      string
	ModelID        string
	Threads        int
	StartupTimeout time.Duration
}

type Server struct {
	Endpoint string
	cmd      *exec.Cmd
	client   *http.Client
	waited   chan error
}

// ResolveLlamaServer finds a llama-server binary: explicit path, then
// CAPHE_LLAMA_SERVER, then the managed tools directory, then PATH.
func ResolveLlamaServer(explicit string) (string, error) {
	if explicit != "" {
		return requireExecutable(explicit)
	}
	if env := strings.TrimSpace(os.Getenv("CAPHE_LLAMA_SERVER")); env != "" {
		return requireExecutable(env)
	}
	base := filepath.Join(managedToolsDir(), fmt.Sprintf("llama.cpp-%s", managedLlamaPinnedVersion))
	for _, candidate := range []string{filepath.Join(base, llamaServerName()), filepath.Join(base, "bin", llamaServerName())} {
		if _, err := requireExecutable(candidate); err == nil {
			return candidate, nil
		}
	}
	if found, err := exec.LookPath("llama-server"); err == nil {
		return found, nil
	}
	return "", fmt.Errorf("llama-server not found; install the managed tool (scripts/install-tools.sh --tools llama.cpp), set CAPHE_LLAMA_SERVER, add llama-server to PATH, or pass --ai-llama-server")
}

func llamaServerName() string {
	if runtime.GOOS == "windows" {
		return "llama-server.exe"
	}
	return "llama-server"
}

func managedToolsDir() string {
	if dir := strings.TrimSpace(os.Getenv("CAPHE_TOOL_BIN")); dir != "" {
		return dir
	}
	base := os.Getenv("XDG_CACHE_HOME")
	if base == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			home = os.TempDir()
		}
		base = filepath.Join(home, ".cache")
	}
	return filepath.Join(base, "caphe", "bin")
}

func requireExecutable(p string) (string, error) {
	abs, err := filepath.Abs(p)
	if err != nil {
		return "", err
	}
	info, err := os.Stat(abs)
	if err != nil {
		return "", err
	}
	if info.IsDir() || info.Mode()&0o111 == 0 {
		return "", fmt.Errorf("%s is not an executable file", abs)
	}
	return abs, nil
}

// StartServer launches llama-server as a subprocess on an ephemeral loopback
// port so it never collides with a llama.cpp instance the user already runs.
func StartServer(ctx context.Context, options ServerOptions) (*Server, error) {
	binary, err := ResolveLlamaServer(options.Binary)
	if err != nil {
		return nil, err
	}
	if options.ModelPath == "" {
		return nil, fmt.Errorf("model path is required to serve")
	}
	if _, err := os.Stat(options.ModelPath); err != nil {
		return nil, fmt.Errorf("model file: %w", err)
	}
	timeout := options.StartupTimeout
	if timeout <= 0 {
		timeout = 5 * time.Minute
	}
	args := []string{"-m", options.ModelPath, "--host", "127.0.0.1"}
	if options.Threads > 0 {
		args = append(args, "--threads", fmt.Sprintf("%d", options.Threads))
	}
	logTail := &cappedBuffer{limit: maxServerLogTail}
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		port, listenErr := freeLoopbackPort()
		if listenErr != nil {
			return nil, listenErr
		}
		cmd := exec.CommandContext(ctx, binary, append(args, "--port", fmt.Sprintf("%d", port))...)
		cmd.Env = subprocessEnv(binary)
		cmd.Stdout = logTail
		cmd.Stderr = logTail
		if startErr := cmd.Start(); startErr != nil {
			return nil, fmt.Errorf("start llama-server: %w", startErr)
		}
		waited := make(chan error, 1)
		go func() { waited <- cmd.Wait() }()
		endpoint := fmt.Sprintf("http://127.0.0.1:%d", port)
		s := &Server{Endpoint: endpoint, cmd: cmd, client: &http.Client{Timeout: 5 * time.Second}, waited: waited}
		if waitErr := s.waitReady(ctx, timeout); waitErr != nil {
			s.Stop()
			lastErr = fmt.Errorf("llama-server on port %d did not become ready: %w\nlast log: %s", port, waitErr, logTail.String())
			continue
		}
		return s, nil
	}
	return nil, lastErr
}

func (s *Server) waitReady(ctx context.Context, timeout time.Duration) error {
	healthCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	for {
		ok, err := (&LlamaCPP{endpoint: mustLoopbackURL(s.Endpoint), client: s.client}).Available(healthCtx)
		if err == nil && ok {
			return nil
		}
		select {
		case waitErr := <-s.waited:
			return fmt.Errorf("process exited: %v", waitErr)
		case <-ctx.Done():
			return ctx.Err()
		case <-healthCtx.Done():
			return fmt.Errorf("timed out after %s", timeout)
		case <-ticker.C:
		}
	}
}

func (s *Server) Stop() {
	if s.cmd != nil && s.cmd.Process != nil {
		_ = s.cmd.Process.Kill()
	}
	if s.waited != nil {
		select {
		case <-s.waited:
		case <-time.After(10 * time.Second):
		}
	}
}

func freeLoopbackPort() (int, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, fmt.Errorf("allocate loopback port: %w", err)
	}
	defer listener.Close()
	return listener.Addr().(*net.TCPAddr).Port, nil
}

var modelDigestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// EnsureModel downloads a model into a content-addressed cache under cacheDir
// and verifies the sha256 digest before exposing the file. An optional HTTP
// client may be supplied (tests); production callers rely on a sane default.
func EnsureModel(ctx context.Context, cacheDir, rawURL, digest string, client ...*http.Client) (string, error) {
	if !modelDigestPattern.MatchString(digest) {
		return "", fmt.Errorf("model digest must be sha256:<64 hex>")
	}
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
		return "", fmt.Errorf("model URL must be HTTPS without credentials")
	}
	httpClient := http.DefaultClient
	if len(client) > 0 && client[0] != nil {
		httpClient = client[0]
	}
	name := strings.TrimPrefix(digest, "sha256:") + ".gguf"
	final := filepath.Join(cacheDir, name)
	if info, err := os.Stat(final); err == nil && !info.IsDir() {
		if verifyErr := verifyFileDigest(final, digest); verifyErr == nil {
			return final, nil
		} else {
			_ = os.Remove(final)
		}
	}
	if err := os.MkdirAll(cacheDir, 0o700); err != nil {
		return "", err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return "", err
	}
	resp, err := httpClient.Do(request)
	if err != nil {
		return "", fmt.Errorf("download model: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return "", fmt.Errorf("download model: HTTP %d", resp.StatusCode)
	}
	tempFile, err := os.CreateTemp(cacheDir, ".model-*")
	if err != nil {
		return "", err
	}
	tempPath := tempFile.Name()
	defer os.Remove(tempPath)
	hash := sha256.New()
	if _, err := io.Copy(io.MultiWriter(tempFile, hash), resp.Body); err != nil {
		tempFile.Close()
		return "", fmt.Errorf("download model: %w", err)
	}
	if err := tempFile.Close(); err != nil {
		return "", err
	}
	if got := "sha256:" + hex.EncodeToString(hash.Sum(nil)); got != digest {
		return "", fmt.Errorf("model digest mismatch: got %s", got)
	}
	if err := os.Rename(tempPath, final); err != nil {
		return "", err
	}
	return final, nil
}

func verifyFileDigest(path, digest string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return err
	}
	if got := "sha256:" + hex.EncodeToString(hash.Sum(nil)); got != digest {
		return fmt.Errorf("model digest mismatch: got %s", got)
	}
	return nil
}

// subprocessEnv deliberately excludes ambient secrets (e.g. GITHUB_TOKEN)
// while keeping what a native binary needs to load, including the binary's
// own directory so bundled llama.cpp shared libraries resolve.
func subprocessEnv(binary string) []string {
	keep := map[string]bool{"PATH": true, "HOME": true, "USER": true, "TMPDIR": true, "TMP": true, "TEMP": true, "LD_LIBRARY_PATH": true, "DYLD_LIBRARY_PATH": true, "SSL_CERT_FILE": true, "SSL_CERT_DIR": true, "HTTP_PROXY": true, "HTTPS_PROXY": true, "NO_PROXY": true}
	env := make([]string, 0, len(keep)+1)
	for _, entry := range os.Environ() {
		if key, _, found := strings.Cut(entry, "="); found && keep[key] {
			env = append(env, entry)
		}
	}
	libVar := "LD_LIBRARY_PATH"
	if runtime.GOOS == "darwin" {
		libVar = "DYLD_LIBRARY_PATH"
	}
	dir := filepath.Dir(binary)
	for i, entry := range env {
		if strings.HasPrefix(entry, libVar+"=") {
			env[i] = libVar + "=" + dir + string(os.PathListSeparator) + strings.TrimPrefix(entry, libVar+"=")
			return env
		}
	}
	return append(env, libVar+"="+dir)
}

type cappedBuffer struct {
	limit int
	buf   bytes.Buffer
}

func (c *cappedBuffer) Write(p []byte) (int, error) {
	c.buf.Write(p)
	if over := c.buf.Len() - c.limit; over > 0 {
		c.buf.Next(over)
	}
	return len(p), nil
}

func (c *cappedBuffer) String() string { return strings.TrimSpace(c.buf.String()) }

func mustLoopbackURL(endpoint string) *url.URL {
	u, _ := url.Parse(endpoint)
	return u
}
