package hardware

import "testing"

func TestRecommendReservesMemory(t *testing.T) {
	r := Recommend(Inspection{TotalMemoryBytes: 4 << 30, AvailableMemoryBytes: 900 << 20})
	if r.Mode != "deterministic" {
		t.Fatalf("unsafe recommendation: %#v", r)
	}
}
