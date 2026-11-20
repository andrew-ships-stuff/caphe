package audit

import "sort"

// Alias edges come only from scanner evidence, never inferred from model text.
func advisoryAliases(bundle *Bundle, group *remediationGroup) map[string][]string {
	parent := map[string]string{}
	var root func(string) string
	root = func(id string) string {
		if _, ok := parent[id]; !ok {
			parent[id] = id
		}
		if parent[id] != id {
			parent[id] = root(parent[id])
		}
		return parent[id]
	}
	join := func(a, b string) {
		if a != "" && b != "" {
			left, right := root(a), root(b)
			if left < right {
				parent[right] = left
			} else {
				parent[left] = right
			}
		}
	}
	for _, id := range group.AdvisoryIDs {
		root(id)
	}
	for _, id := range group.FindingIDs {
		finding := findingFor(bundle.Findings, id)
		if finding == nil {
			continue
		}
		vulnerability, _ := finding.Properties["vulnerability"].(map[string]any)
		advisory, _ := vulnerability["id"].(string)
		if advisory == "" {
			continue
		}
		aliases, _ := vulnerability["aliases"].([]any)
		for _, value := range aliases {
			if alias, ok := value.(string); ok {
				join(advisory, alias)
			}
		}
		related, _ := finding.Properties["relatedVulnerabilities"].([]any)
		for _, value := range related {
			row, _ := value.(map[string]any)
			if alias, ok := row["id"].(string); ok {
				join(advisory, alias)
			}
		}
	}
	groups := map[string][]string{}
	for id := range parent {
		key := root(id)
		groups[key] = append(groups[key], id)
	}
	for key := range groups {
		sort.Strings(groups[key])
	}
	return groups
}
