package workflow

import "testing"

func TestMalformedYAMLRejected(t *testing.T) {
	if _, err := Parse([]byte("spec: [")); err == nil {
		t.Fatal("malformed YAML accepted")
	}
}
