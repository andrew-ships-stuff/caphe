package audit

import (
	capheruntime "github.com/andrew-ships-stuff/caphe/internal/runtime"
	"testing"
)

func TestCoverageNeverCallsEmptyOrFailedScansComplete(t *testing.T) {
	for _, status := range []capheruntime.TaskStatus{capheruntime.StatusSkipped, capheruntime.StatusFailed} {
		coverage := scanCoverage([]capheruntime.TaskResult{{ID: "scan", Uses: "scanner.grype", Status: status}, {ID: "normalize", Uses: "core.normalize", Status: capheruntime.StatusSucceeded}})
		if coverage.Complete || len(coverage.Succeeded) != 0 {
			t.Fatalf("false coverage: %+v", coverage)
		}
	}
	if scanCoverage(nil).Complete {
		t.Fatal("empty scan called complete")
	}
}
