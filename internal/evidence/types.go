package evidence

import "fmt"

type Class string

const (
	Observed     Class = "observed"
	Derived      Class = "derived"
	Hypothesis   Class = "hypothesis"
	Verification Class = "verification"
)

type Status string

const (
	Confirmed           Status = "confirmed"
	SupportedUnverified Status = "supported_unverified"
	Hypothesized        Status = "hypothesized"
	Contradicted        Status = "contradicted"
	Inconclusive        Status = "inconclusive"
)

var nodeTypes = map[string]bool{"Repository": true, "Commit": true, "SourceFile": true, "Function": true, "APIEndpoint": true, "Service": true, "Package": true, "Dependency": true, "Vulnerability": true, "ContainerImage": true, "KubernetesWorkload": true, "ServiceAccount": true, "Permission": true, "SecretReference": true, "TrustBoundary": true, "SecurityInvariant": true, "Hypothesis": true, "Verification": true, "Finding": true}
var edgeTypes = map[string]bool{"CONTAINS": true, "CALLS": true, "EXPOSES": true, "DEPENDS_ON": true, "DEPLOYED_AS": true, "USES_IDENTITY": true, "GRANTS_PERMISSION": true, "REFERENCES": true, "REACHES": true, "CROSSES_BOUNDARY": true, "SUPPORTS": true, "CONTRADICTS": true, "VERIFIED_BY": true}

func ValidateNodeType(v string) error {
	if !nodeTypes[v] {
		return fmt.Errorf("unsupported evidence node type %q", v)
	}
	return nil
}
func ValidateEdgeType(v string) error {
	if !edgeTypes[v] {
		return fmt.Errorf("unsupported evidence edge type %q", v)
	}
	return nil
}
