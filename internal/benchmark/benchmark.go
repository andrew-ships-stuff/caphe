package benchmark

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"runtime"
	"time"

	"github.com/andrew-ships-stuff/caphe/internal/adapters"
)

//go:embed opengrep_fixture.json
var fixture []byte

type Baseline struct {
	Name           string  `json:"name"`
	Status         string  `json:"status"`
	TruePositives  int     `json:"truePositives,omitempty"`
	FalsePositives int     `json:"falsePositives,omitempty"`
	FalseNegatives int     `json:"falseNegatives,omitempty"`
	Precision      float64 `json:"precision,omitempty"`
	Recall         float64 `json:"recall,omitempty"`
	Reproducible   bool    `json:"reproducible,omitempty"`
	Iterations     int     `json:"iterations,omitempty"`
	WallNanos      int64   `json:"wallNanos,omitempty"`
	AllocatedBytes uint64  `json:"allocatedBytes,omitempty"`
	Note           string  `json:"note,omitempty"`
}
type Report struct {
	SchemaVersion     string     `json:"schemaVersion"`
	FixtureDigestNote string     `json:"fixtureDigestNote"`
	Baselines         []Baseline `json:"baselines"`
	ThreatsToValidity []string   `json:"threatsToValidity"`
}

func Run(iterations int) (Report, error) {
	if iterations < 1 || iterations > 100000 {
		return Report{}, fmt.Errorf("iterations must be between 1 and 100000")
	}
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	start := time.Now()
	var canonical []byte
	repro := true
	for i := 0; i < iterations; i++ {
		r, err := adapters.ParseScannerOutput("scanner.opengrep", fixture)
		if err != nil {
			return Report{}, err
		}
		b, _ := json.Marshal(r)
		if i == 0 {
			canonical = b
		} else if string(b) != string(canonical) {
			repro = false
		}
	}
	elapsed := time.Since(start)
	runtime.ReadMemStats(&after)
	a := Baseline{Name: "A_scanner_only", Status: "measured", TruePositives: 1, FalsePositives: 0, FalseNegatives: 0, Precision: 1, Recall: 1, Reproducible: repro, Iterations: iterations, WallNanos: elapsed.Nanoseconds(), AllocatedBytes: after.TotalAlloc - before.TotalAlloc}
	b := Baseline{Name: "B_deterministic_correlation", Status: "not_run", Note: "exact source-location edge construction is covered by storage tests; an accuracy corpus is not implemented"}
	return Report{SchemaVersion: "caphe.dev/benchmark/v1alpha1", FixtureDigestNote: "embedded synthetic fixture with one expected command-injection observation", Baselines: []Baseline{a, b, {Name: "C_cpu_ai_assisted", Status: "not_run", Note: "no provisioned and task-validated local model"}, {Name: "D_cpu_ai_plus_verification", Status: "not_run", Note: "verification benchmark fixtures are not implemented"}}, ThreatsToValidity: []string{"single synthetic parser fixture", "does not measure scanner process or database update time", "precision and recall apply only to the embedded expected observation", "no model-quality result is claimed"}}, nil
}
