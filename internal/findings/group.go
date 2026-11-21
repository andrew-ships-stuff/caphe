package findings

import (
	"encoding/json"
	"strings"
)

func Ecosystem(value string) string {
	switch strings.ToLower(value) {
	case "go", "go-module":
		return "Go"
	case "npm", "javascript", "js":
		return "npm"
	case "pypi", "python":
		return "PyPI"
	case "maven", "java-archive":
		return "Maven"
	}
	return value
}

// GroupKey groups remediation targets, never discarding scanner observations.
func GroupKey(f Finding) string {
	var pkg map[string]any
	ecosystemKey := "ecosystem"
	switch f.Tool {
	case "scanner.grype":
		pkg, _ = f.Properties["artifact"].(map[string]any)
		ecosystemKey = "type"
	case "scanner.osv":
		pkg, _ = f.Properties["package"].(map[string]any)
	}
	name, _ := pkg["name"].(string)
	version, _ := pkg["version"].(string)
	ecosystem, _ := pkg[ecosystemKey].(string)
	var key any = []any{"finding", f.Tool, f.RuleID, f.Location.Path, f.Location.StartLine, f.Title}
	if name != "" && version != "" {
		key = []string{"package", Ecosystem(ecosystem), name, version}
	}
	data, _ := json.Marshal(key)
	return string(data)
}
