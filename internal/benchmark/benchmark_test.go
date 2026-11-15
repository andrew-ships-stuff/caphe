package benchmark

import "testing"

func TestRun(t *testing.T) {
	r, err := Run(5)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Baselines) != 4 || !r.Baselines[0].Reproducible {
		t.Fatalf("unexpected report: %#v", r)
	}
}
