package adapters

import (
	"context"
	"encoding/json"
	"fmt"
)

type Core struct{ id string }

func NewCore(id string) *Core              { return &Core{id: id} }
func (c *Core) ID() string                 { return c.id }
func (c *Core) Version() string            { return "core-v1" }
func (c *Core) Capabilities() []Capability { return []Capability{"transform"} }
func (c *Core) Detect(context.Context) ToolInfo {
	return ToolInfo{ID: c.id, Available: true, Version: c.Version()}
}
func (c *Core) Validate(raw json.RawMessage) error {
	var v map[string]any
	if err := json.Unmarshal(raw, &v); err != nil {
		return err
	}
	if len(v) > 0 {
		return fmt.Errorf("%s takes no configuration", c.id)
	}
	return nil
}
func (c *Core) Execute(context.Context, Request) (Result, error) { return Result{}, nil }

func DefaultRegistry() *Registry {
	return NewRegistry(
		NewScanner("scanner.opengrep", "opengrep"), NewScanner("scanner.syft", "syft"), NewScanner("scanner.grype", "grype"), NewScanner("scanner.gitleaks", "gitleaks"), NewScanner("scanner.poutine", "poutine"),
		NewCore("core.normalize"), NewCore("core.correlate"), NewCore("core.verify"),
	)
}
