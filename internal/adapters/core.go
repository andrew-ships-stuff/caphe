package adapters

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/andrew-ships-stuff/caphe/internal/findings"
	"sort"
)

type Core struct{ id string }

func NewCore(id string) *Core              { return &Core{id: id} }
func (c *Core) ID() string                 { return c.id }
func (c *Core) Version() string            { return "core-v2" }
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
func (c *Core) Execute(_ context.Context, request Request) (Result, error) {
	items := append([]findings.Finding(nil), request.Evidence...)
	sort.Slice(items, func(i, j int) bool { return items[i].ID < items[j].ID })
	groups := map[string][]string{}
	for _, item := range items {
		if item.ID == "" || item.Tool == "" || item.RuleID == "" {
			return Result{}, fmt.Errorf("invalid normalized scanner identity")
		}
		groups[findings.GroupKey(item)] = append(groups[findings.GroupKey(item)], item.ID)
	}
	data, err := json.Marshal(map[string]any{"stage": c.id, "observations": items, "groups": groups, "verification": "scanner observations only; exploitability unverified"})
	return Result{Raw: data, Version: c.Version()}, err
}

func DefaultRegistry() *Registry {
	return NewRegistry(
		NewScanner("scanner.opengrep", "opengrep"), NewScanner("scanner.syft", "syft"), NewScanner("scanner.grype", "grype"), NewScanner("scanner.gitleaks", "gitleaks"), NewScanner("scanner.poutine", "poutine"),
		NewScanner("scanner.opa", "opa"), NewScanner("scanner.osv", "osv-scanner"), NewScanner("scanner.checkov", "checkov"), NewScanner("scanner.kubescape", "kubescape"),
		NewCore("core.normalize"), NewCore("core.correlate"), NewCore("core.verify"),
	)
}
