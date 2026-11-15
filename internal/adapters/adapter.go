package adapters

import (
	"context"
	"encoding/json"
	"time"

	"github.com/andrew-ships-stuff/caphe/internal/findings"
)

type Capability string

type ToolInfo struct {
	ID        string `json:"id"`
	Available bool   `json:"available"`
	Path      string `json:"path,omitempty"`
	Version   string `json:"version,omitempty"`
	Error     string `json:"error,omitempty"`
}

type Request struct {
	Target       string
	Config       json.RawMessage
	Inputs       map[string]string
	Timeout      time.Duration
	MaxOutput    int64
	ArtifactPath string
}

type Result struct {
	Findings findings.Result
	Raw      []byte
	Command  []string
	Version  string
	Duration time.Duration
	ExitCode int
}

type Adapter interface {
	ID() string
	Version() string
	Capabilities() []Capability
	Detect(context.Context) ToolInfo
	Validate(json.RawMessage) error
	Execute(context.Context, Request) (Result, error)
}

type Registry struct{ items map[string]Adapter }

func NewRegistry(list ...Adapter) *Registry {
	r := &Registry{items: make(map[string]Adapter)}
	for _, a := range list {
		r.items[a.ID()] = a
	}
	return r
}

func (r *Registry) Get(id string) (Adapter, bool) { a, ok := r.items[id]; return a, ok }
func (r *Registry) List() []Adapter {
	out := make([]Adapter, 0, len(r.items))
	for _, a := range r.items {
		out = append(out, a)
	}
	return out
}
