package inference

import "testing"

func TestInvariantContract(t *testing.T) {
	raw := []byte(`{"invariant_type":"object_authorization","property":"caller must own target account","subjects":["caller","target_account"],"required_evidence":["caller_identity","ownership_relationship"],"verification_strategy":"authorization_regression_test","confidence":"hypothesis"}`)
	if _, err := ValidateSecurityInvariant(raw); err != nil {
		t.Fatal(err)
	}
}
func TestInvariantRejectsShellStrategy(t *testing.T) {
	raw := []byte(`{"invariant_type":"object_authorization","property":"x","subjects":["x"],"required_evidence":["x"],"verification_strategy":"run_shell_command","confidence":"hypothesis"}`)
	if _, err := ValidateSecurityInvariant(raw); err == nil {
		t.Fatal("arbitrary strategy accepted")
	}
}
func TestInvariantCannotClaimConfirmation(t *testing.T) {
	raw := []byte(`{"invariant_type":"object_authorization","property":"x","subjects":["x"],"required_evidence":["x"],"verification_strategy":"authorization_regression_test","confidence":"confirmed"}`)
	if _, err := ValidateSecurityInvariant(raw); err == nil {
		t.Fatal("model promoted its own hypothesis")
	}
}
