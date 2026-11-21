package cluster

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/andrew-ships-stuff/caphe/internal/source"
)

type ServerConfig struct {
	ListenAddress   string
	Store           *Store
	Auth            *Authenticator
	Policy          Policy
	ArchiveLimits   source.Limits
	MaxUploadBytes  int64
	Retention       time.Duration
	GitTimeout      time.Duration
	NetworkEnforced bool
	Log             io.Writer
}

type Server struct {
	config ServerConfig
	http   *http.Server
}

func NewServer(config ServerConfig) (*Server, error) {
	if config.Store == nil || config.Auth == nil {
		return nil, fmt.Errorf("cluster store and authenticator are required")
	}
	if config.ListenAddress == "" {
		config.ListenAddress = "127.0.0.1:8787"
	}
	if config.MaxUploadBytes <= 0 {
		config.MaxUploadBytes = 256 << 20
	}
	if config.ArchiveLimits.MaxFiles <= 0 {
		config.ArchiveLimits.MaxFiles = 100_000
	}
	if config.ArchiveLimits.MaxExpandedBytes == 0 {
		config.ArchiveLimits.MaxExpandedBytes = 2 << 30
	}
	if config.Retention <= 0 {
		config.Retention = 7 * 24 * time.Hour
	}
	if config.GitTimeout <= 0 {
		config.GitTimeout = 5 * time.Minute
	}
	server := &Server{config: config}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", server.health)
	mux.HandleFunc("GET /v1/workflows", server.authorize(server.workflows))
	mux.HandleFunc("GET /v1/jobs", server.authorize(server.listJobs))
	mux.HandleFunc("POST /v1/jobs", server.authorize(server.submit))
	mux.HandleFunc("GET /v1/jobs/{id}", server.authorize(server.getJob))
	mux.HandleFunc("GET /v1/jobs/{id}/bundle", server.authorize(server.bundle))
	server.http = &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Minute, WriteTimeout: 10 * time.Minute, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10}
	return server, nil
}

func (s *Server) Run(ctx context.Context) error {
	listener, err := net.Listen("tcp", s.config.ListenAddress)
	if err != nil {
		return err
	}
	if s.config.Log != nil {
		fmt.Fprintf(s.config.Log, "Caphe cluster API listening on %s\n", listener.Addr())
	}
	go s.retentionLoop(ctx)
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = s.http.Shutdown(shutdown)
	}()
	err = s.http.Serve(listener)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func (s *Server) authorize(next func(http.ResponseWriter, *http.Request, string)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		header := r.Header.Get("Authorization")
		token := ""
		if strings.HasPrefix(header, "Bearer ") {
			token = strings.TrimPrefix(header, "Bearer ")
		}
		tenant, ok := s.config.Auth.Authenticate(token)
		if !ok {
			w.Header().Set("WWW-Authenticate", "Bearer")
			writeError(w, http.StatusUnauthorized, "authentication required")
			return
		}
		next(w, r, tenant)
	}
}

func (s *Server) health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok"})
}

func (s *Server) workflows(w http.ResponseWriter, _ *http.Request, _ string) {
	digests, err := s.config.Store.WorkflowDigests()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "list workflows")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"workflows": digests})
}

func (s *Server) submit(w http.ResponseWriter, r *http.Request, tenant string) {
	var sub Submission
	var archivePath string
	var cleanup func()
	contentType := r.Header.Get("Content-Type")
	if strings.HasPrefix(contentType, "multipart/form-data") {
		var err error
		sub, archivePath, cleanup, err = s.readMultipart(w, r)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
	} else {
		defer r.Body.Close()
		decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&sub); err != nil {
			writeError(w, http.StatusBadRequest, "invalid submission JSON")
			return
		}
		if err := decoder.Decode(&struct{}{}); err != io.EOF {
			writeError(w, http.StatusBadRequest, "submission contains trailing content")
			return
		}
	}
	if cleanup != nil {
		defer cleanup()
	}
	if err := ValidateSubmission(&sub, s.config.Policy); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if _, err := s.config.Store.LoadWorkflow(sub.WorkflowDigest); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			writeError(w, http.StatusBadRequest, "workflow digest is not registered")
		} else {
			writeError(w, http.StatusInternalServerError, "load workflow")
		}
		return
	}
	if sub.Source.Kind == "archive" {
		if archivePath == "" {
			writeError(w, http.StatusBadRequest, "archive source requires one uploaded archive")
			return
		}
		if err := source.ValidateZIP(archivePath, s.config.ArchiveLimits); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
	} else {
		if archivePath != "" {
			writeError(w, http.StatusBadRequest, "Git source cannot include an uploaded archive")
			return
		}
		gitCtx, cancel := context.WithTimeout(r.Context(), s.config.GitTimeout)
		defer cancel()
		var err error
		archivePath, cleanup, err = acquireGit(gitCtx, sub.Source, s.config.ArchiveLimits, s.config.MaxUploadBytes)
		if err != nil {
			writeError(w, http.StatusBadGateway, err.Error())
			return
		}
		defer cleanup()
	}
	file, err := os.Open(archivePath)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "open source snapshot")
		return
	}
	defer file.Close()
	job, err := s.config.Store.CreateJob(tenant, sub, file, s.config.NetworkEnforced)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "create job")
		return
	}
	writeJSON(w, http.StatusAccepted, job)
}

func (s *Server) readMultipart(w http.ResponseWriter, r *http.Request) (Submission, string, func(), error) {
	r.Body = http.MaxBytesReader(w, r.Body, s.config.MaxUploadBytes+(128<<10))
	reader, err := r.MultipartReader()
	if err != nil {
		return Submission{}, "", nil, fmt.Errorf("invalid multipart submission")
	}
	tempDir, err := os.MkdirTemp("", "caphe-upload-")
	if err != nil {
		return Submission{}, "", nil, err
	}
	cleanup := func() { _ = os.RemoveAll(tempDir) }
	var sub Submission
	var metadataSeen, archiveSeen bool
	for {
		part, err := reader.NextPart()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			cleanup()
			return Submission{}, "", nil, err
		}
		switch part.FormName() {
		case "metadata":
			if metadataSeen {
				part.Close()
				cleanup()
				return Submission{}, "", nil, fmt.Errorf("metadata must appear exactly once")
			}
			metadataSeen = true
			decoder := json.NewDecoder(io.LimitReader(part, 64<<10))
			decoder.DisallowUnknownFields()
			if err := decoder.Decode(&sub); err != nil {
				part.Close()
				cleanup()
				return Submission{}, "", nil, fmt.Errorf("invalid submission metadata")
			}
			if err := decoder.Decode(&struct{}{}); err != io.EOF {
				part.Close()
				cleanup()
				return Submission{}, "", nil, fmt.Errorf("submission metadata contains trailing content")
			}
		case "archive":
			if archiveSeen || part.FileName() == "" {
				part.Close()
				cleanup()
				return Submission{}, "", nil, fmt.Errorf("archive must appear exactly once")
			}
			archiveSeen = true
			file, err := os.OpenFile(filepath.Join(tempDir, "source.zip"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
			if err != nil {
				part.Close()
				cleanup()
				return Submission{}, "", nil, err
			}
			written, copyErr := io.Copy(file, io.LimitReader(part, s.config.MaxUploadBytes+1))
			closeErr := file.Close()
			if copyErr != nil || closeErr != nil || written > s.config.MaxUploadBytes {
				part.Close()
				cleanup()
				return Submission{}, "", nil, fmt.Errorf("archive exceeds upload limit")
			}
		default:
			part.Close()
			cleanup()
			return Submission{}, "", nil, fmt.Errorf("unsupported multipart field %q", part.FormName())
		}
		part.Close()
	}
	if !metadataSeen || !archiveSeen {
		cleanup()
		return Submission{}, "", nil, fmt.Errorf("metadata and archive are required")
	}
	return sub, filepath.Join(tempDir, "source.zip"), cleanup, nil
}

func (s *Server) getJob(w http.ResponseWriter, r *http.Request, tenant string) {
	job, err := s.config.Store.LoadJob(r.PathValue("id"))
	if err != nil || job.Tenant != tenant {
		writeError(w, http.StatusNotFound, "job not found")
		return
	}
	writeJSON(w, http.StatusOK, job)
}

func (s *Server) bundle(w http.ResponseWriter, r *http.Request, tenant string) {
	job, err := s.config.Store.LoadJob(r.PathValue("id"))
	if err != nil || job.Tenant != tenant || job.Phase != PhaseSucceeded {
		writeError(w, http.StatusNotFound, "bundle not found")
		return
	}
	path := filepath.Join(s.config.Store.JobDir(job.ID), "caphe-audit.json")
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s-caphe-audit.json"`, job.ID))
	http.ServeFile(w, r, path)
}

func (s *Server) retentionLoop(ctx context.Context) {
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := s.config.Store.Prune(s.config.Retention); err != nil && s.config.Log != nil {
				fmt.Fprintf(s.config.Log, "cluster retention: %v\n", err)
			}
		}
	}
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}

func (s *Server) listJobs(w http.ResponseWriter, r *http.Request, tenant string) {
	limit := 100
	if value := r.URL.Query().Get("limit"); value != "" {
		n, err := strconv.Atoi(value)
		if err != nil || n < 1 || n > 200 {
			writeError(w, 400, "limit must be between 1 and 200")
			return
		}
		limit = n
	}
	page, err := s.config.Store.ListJobs(tenant, r.URL.Query().Get("cursor"), limit)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			writeError(w, 400, "invalid cursor")
		} else {
			writeError(w, 500, "list jobs")
		}
		return
	}
	writeJSON(w, 200, page)
}
