package evidence

import "testing"

func TestEvidenceTypeAllowlists(t *testing.T) {
	if err := ValidateNodeType("Finding"); err != nil {
		t.Fatal(err)
	}
	if err := ValidateEdgeType("EXECUTES_SHELL"); err == nil {
		t.Fatal("unknown edge accepted")
	}
}
