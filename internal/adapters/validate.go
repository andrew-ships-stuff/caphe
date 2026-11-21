package adapters

import "fmt"

// Reject incompatible/error payloads instead of interpreting them as clean scans.
func validateScannerDocument(tool string, doc any) error {
	object, _ := doc.(map[string]any)
	array := func(value any, name string) error {
		rows, ok := value.([]any)
		if !ok {
			return fmt.Errorf("%s must be an array", name)
		}
		for _, row := range rows {
			if _, ok := row.(map[string]any); !ok {
				return fmt.Errorf("%s entries must be objects", name)
			}
		}
		return nil
	}
	if value, present := object["errors"]; present && value != nil {
		errors, ok := value.([]any)
		if !ok || len(errors) > 0 {
			return fmt.Errorf("scanner reported errors or malformed error metadata")
		}
	}
	switch tool {
	case "scanner.opengrep":
		if err := array(object["results"], "results"); err != nil {
			return err
		}
		for _, value := range object["results"].([]any) {
			row := value.(map[string]any)
			if id, ok := row["check_id"].(string); !ok || id == "" {
				return fmt.Errorf("result missing rule id")
			}
			if _, ok := row["path"].(string); !ok {
				return fmt.Errorf("result missing source path")
			}
		}
	case "scanner.osv":
		if err := array(object["results"], "results"); err != nil {
			return err
		}
		for _, value := range object["results"].([]any) {
			row := value.(map[string]any)
			if err := array(row["packages"], "packages"); err != nil {
				return err
			}
			for _, value := range row["packages"].([]any) {
				pkg := value.(map[string]any)
				identity, _ := pkg["package"].(map[string]any)
				if name, ok := identity["name"].(string); !ok || name == "" {
					return fmt.Errorf("missing package identity")
				}
				if err := array(pkg["vulnerabilities"], "vulnerabilities"); err != nil {
					return err
				}
				for _, value := range pkg["vulnerabilities"].([]any) {
					if id, ok := value.(map[string]any)["id"].(string); !ok || id == "" {
						return fmt.Errorf("missing vulnerability id")
					}
				}
			}
		}
	case "scanner.grype":
		if err := array(object["matches"], "matches"); err != nil {
			return err
		}
		for _, value := range object["matches"].([]any) {
			row := value.(map[string]any)
			vuln, _ := row["vulnerability"].(map[string]any)
			artifact, _ := row["artifact"].(map[string]any)
			if id, ok := vuln["id"].(string); !ok || id == "" {
				return fmt.Errorf("match missing vulnerability id")
			}
			if name, ok := artifact["name"].(string); !ok || name == "" {
				return fmt.Errorf("match missing package name")
			}
		}
	case "scanner.gitleaks":
		return array(doc, "findings")
	case "scanner.syft":
		if _, ok := object["components"]; ok {
			return array(object["components"], "components")
		}
		return array(object["artifacts"], "artifacts")
	case "scanner.poutine", "scanner.kubescape":
		if err := array(object["runs"], "runs"); err != nil {
			return err
		}
		for _, value := range object["runs"].([]any) {
			run := value.(map[string]any)
			if rows, present := run["results"]; present && rows != nil {
				if err := array(rows, "SARIF results"); err != nil {
					return err
				}
			}
		}
	case "scanner.opa":
		return array(object["result"], "result")
	case "scanner.checkov":
		rows, ok := doc.([]any)
		if !ok {
			rows = []any{doc}
		}
		for _, value := range rows {
			row, _ := value.(map[string]any)
			results, _ := row["results"].(map[string]any)
			if err := array(results["failed_checks"], "failed_checks"); err != nil {
				return err
			}
		}
	}
	return nil
}
