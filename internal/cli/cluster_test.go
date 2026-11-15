package cli

import "testing"

func TestClusterSourceLimits(t *testing.T) {
	for _, test := range []struct {
		name        string
		maxFiles    int64
		maxExpanded int64
	}{
		{name: "zero files", maxFiles: 0, maxExpanded: 1},
		{name: "negative files", maxFiles: -1, maxExpanded: 1},
		{name: "zero expanded size", maxFiles: 1, maxExpanded: 0},
		{name: "negative expanded size", maxFiles: 1, maxExpanded: -1},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := clusterSourceLimits(test.maxFiles, test.maxExpanded); err == nil {
				t.Fatal("invalid source limits accepted")
			}
		})
	}
	limits, err := clusterSourceLimits(100, 1024)
	if err != nil {
		t.Fatal(err)
	}
	if limits.MaxFiles != 100 || limits.MaxExpandedBytes != 1024 {
		t.Fatalf("limits = %#v", limits)
	}
}
