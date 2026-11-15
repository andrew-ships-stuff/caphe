package compiler

import (
	"strings"
	"testing"

	"github.com/andrew-ships-stuff/caphe/internal/adapters"
	"github.com/andrew-ships-stuff/caphe/internal/workflow"
)

func compileYAML(t *testing.T, src string) (*Plan, error) {
	t.Helper()
	w, err := workflow.Parse([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	r := adapters.NewRegistry(adapters.NewCore("core.normalize"), adapters.NewCore("core.correlate"))
	return New(r).Compile(w)
}

func TestCanonicalDigestIgnoresTaskOrder(t *testing.T) {
	a := `apiVersion: caphe.dev/v1alpha1
kind: SecurityWorkflow
metadata: {name: test, version: "1"}
spec:
  target: {type: repository}
  policies: {network: restricted}
  tasks:
    - {id: b, uses: core.correlate, needs: [a]}
    - {id: a, uses: core.normalize}
`
	b := strings.Replace(a, "    - {id: b, uses: core.correlate, needs: [a]}\n    - {id: a, uses: core.normalize}", "    - {id: a, uses: core.normalize}\n    - {id: b, uses: core.correlate, needs: [a]}", 1)
	pa, err := compileYAML(t, a)
	if err != nil {
		t.Fatal(err)
	}
	pb, err := compileYAML(t, b)
	if err != nil {
		t.Fatal(err)
	}
	if pa.Digest != pb.Digest {
		t.Fatalf("semantic equivalents differ: %s != %s", pa.Digest, pb.Digest)
	}
}

func TestCycleRejected(t *testing.T) {
	src := `apiVersion: caphe.dev/v1alpha1
kind: SecurityWorkflow
metadata: {name: test, version: "1"}
spec:
  target: {type: repository}
  tasks:
    - {id: a, uses: core.normalize, needs: [b]}
    - {id: b, uses: core.correlate, needs: [a]}
`
	_, err := compileYAML(t, src)
	if err == nil || !strings.Contains(err.Error(), "cycle") {
		t.Fatalf("expected cycle error, got %v", err)
	}
}

func TestCommandConfigurationRejected(t *testing.T) {
	src := `apiVersion: caphe.dev/v1alpha1
kind: SecurityWorkflow
metadata: {name: test, version: "1"}
spec:
  target: {type: repository}
  tasks:
    - id: a
      uses: core.normalize
      with: {command: "rm -rf /"}
`
	_, err := compileYAML(t, src)
	if err == nil || !strings.Contains(err.Error(), "forbidden") {
		t.Fatalf("expected security rejection, got %v", err)
	}
}

func TestTamperedLockRejected(t *testing.T) {
	p, err := compileYAML(t, `apiVersion: caphe.dev/v1alpha1
kind: SecurityWorkflow
metadata: {name: test, version: "1"}
spec: {target: {type: repository}, tasks: [{id: a, uses: core.normalize}]}
`)
	if err != nil {
		t.Fatal(err)
	}
	p.Workflow.Version = "2"
	r := adapters.NewRegistry(adapters.NewCore("core.normalize"), adapters.NewCore("core.correlate"))
	if err := ValidateLock(p, r); err == nil {
		t.Fatal("tampered lock accepted")
	}
}

func TestUndeclaredTaskReferenceRejected(t *testing.T) {
	src := `apiVersion: caphe.dev/v1alpha1
kind: SecurityWorkflow
metadata: {name: test, version: "1"}
spec:
  target: {type: repository}
  tasks:
    - {id: a, uses: core.normalize}
    - id: b
      uses: core.correlate
      with: {input: "${tasks.a.outputs.normalized}"}
`
	_, err := compileYAML(t, src)
	if err == nil || !strings.Contains(err.Error(), "without declaring") {
		t.Fatalf("expected reference error, got %v", err)
	}
}
