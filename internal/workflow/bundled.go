package workflow

import (
	"embed"
	"fmt"
	"io/fs"
	"strings"
)

//go:embed bundled/*.yaml
var bundledFS embed.FS

const bundledPrefix = "bundled/"

// IsBundled reports whether a reference names an embedded workflow, e.g. "caphe:default".
func IsBundled(ref string) bool { return strings.HasPrefix(ref, "caphe:") }

// BundledNames lists the embedded workflow names usable as caphe:<name>.
func BundledNames() ([]string, error) {
	entries, err := fs.Glob(bundledFS, bundledPrefix+"*.yaml")
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, strings.TrimSuffix(strings.TrimPrefix(entry, bundledPrefix), ".yaml"))
	}
	return names, nil
}

func LoadBundled(ref string) (*Workflow, error) {
	name := strings.TrimPrefix(ref, "caphe:")
	if name == "" || strings.ContainsAny(name, "/\\..\x00") {
		return nil, fmt.Errorf("invalid bundled workflow name %q", ref)
	}
	data, err := bundledFS.ReadFile(bundledPrefix + name + ".yaml")
	if err != nil {
		available, _ := BundledNames()
		return nil, fmt.Errorf("bundled workflow %q not found (available: %s)", name, strings.Join(available, ", "))
	}
	return Parse(data)
}
