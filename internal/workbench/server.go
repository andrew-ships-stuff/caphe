package workbench

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/andrew-ships-stuff/caphe/internal/audit"
)

//go:embed web/*
var assets embed.FS

func Handler(endpoint string) (http.Handler, error) {
	target, err := url.Parse(endpoint)
	if err != nil || target.Host == "" || (target.Scheme != "http" && target.Scheme != "https") || target.User != nil || target.RawQuery != "" || target.Fragment != "" || (target.Path != "" && target.Path != "/") {
		return nil, fmt.Errorf("API endpoint must be an HTTP(S) origin without credentials")
	}
	proxy := &httputil.ReverseProxy{
		Rewrite: func(r *httputil.ProxyRequest) {
			r.SetURL(target)
			r.Out.URL.Path = strings.TrimPrefix(r.In.URL.Path, "/api")
			r.Out.URL.RawPath = ""
			r.Out.Header.Del("Cookie")
			r.Out.Header.Del("Origin")
		},
		Transport: &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: 10 * time.Second}).DialContext, ResponseHeaderTimeout: 30 * time.Second},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			http.Error(w, "Cluster API unavailable. Check the API endpoint and service.", http.StatusBadGateway)
		},
	}
	root, _ := fs.Sub(assets, "web")
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"status":"ok","service":"caphe-workbench"}`)
	})
	mux.Handle("GET /api/", proxy)
	mux.Handle("POST /api/v1/jobs", proxy)
	mux.HandleFunc("POST /local/import", func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, 128<<20)
		file, err := os.CreateTemp("", "caphe-import-*.json")
		if err != nil {
			http.Error(w, "Cannot create verification workspace", 500)
			return
		}
		defer os.Remove(file.Name())
		_, copyErr := io.Copy(file, r.Body)
		closeErr := file.Close()
		if copyErr != nil || closeErr != nil {
			http.Error(w, "Bundle unreadable or larger than 128 MiB", 400)
			return
		}
		bundle, err := audit.ReadJSON(file.Name())
		if err != nil {
			http.Error(w, "Bundle schema or digest verification failed", 400)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(bundle)
	})
	mux.Handle("GET /", http.FileServer(http.FS(root)))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		protectionHeaders(w.Header())
		if origin := r.Header.Get("Origin"); origin != "" {
			u, err := url.Parse(origin)
			if err != nil || u.Host != r.Host || (u.Scheme != "http" && u.Scheme != "https") {
				http.Error(w, "Cross-origin request rejected", 403)
				return
			}
		}
		// FileServer strips Cache-Control from error responses, so the
		// headers are re-applied at WriteHeader time to stay non-negotiable.
		mux.ServeHTTP(&headerWriter{ResponseWriter: w}, r)
	}), nil
}

const workbenchCSP = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; font-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"

func protectionHeaders(h http.Header) {
	h.Set("Content-Security-Policy", workbenchCSP)
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Cache-Control", "no-store")
}

type headerWriter struct {
	http.ResponseWriter
}

func (w *headerWriter) WriteHeader(code int) {
	protectionHeaders(w.Header())
	w.ResponseWriter.WriteHeader(code)
}

func (w *headerWriter) Write(p []byte) (int, error) {
	protectionHeaders(w.Header())
	return w.ResponseWriter.Write(p)
}

func Serve(ctx context.Context, listen, endpoint string, log io.Writer) error {
	handler, err := Handler(endpoint)
	if err != nil {
		return err
	}
	listener, err := net.Listen("tcp", listen)
	if err != nil {
		return err
	}
	server := &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Minute, WriteTimeout: 10 * time.Minute, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10}
	fmt.Fprintf(log, "Caphe workbench: http://%s (API: %s)\n", listener.Addr(), endpoint)
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdown)
	}()
	if err := server.Serve(listener); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
