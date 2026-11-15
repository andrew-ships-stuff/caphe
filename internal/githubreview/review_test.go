package githubreview

import (
	"os"
	"path/filepath"
	"testing"
)

func writeReport(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "report.json")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadReportFormats(t *testing.T) {
	tests := []struct {
		name    string
		content string
		count   int
		wantErr bool
	}{
		{name: "native empty array", content: `{"schemaVersion":"caphe.dev/report/v1alpha1","findings":[]}`, count: 0},
		{name: "native null findings", content: `{"schemaVersion":"caphe.dev/report/v1alpha1","findings":null}`, count: 0},
		{name: "native missing findings", content: `{"schemaVersion":"caphe.dev/report/v1alpha1"}`, count: 0},
		{name: "native populated", content: `{"findings":[{"id":"sha256:aaaa","fingerprint":"sha256:aaaa","tool":"t","ruleId":"r","title":"x","severity":"high"}]}`, count: 1},
		{name: "direct array", content: `[{"id":"sha256:aaaa","fingerprint":"sha256:aaaa","tool":"t","ruleId":"r","title":"x","severity":"high"}]`, count: 1},
		{name: "direct empty array", content: `[]`, count: 0},
		{name: "scalar", content: `42`, wantErr: true},
		{name: "array of scalars", content: `[1,2]`, wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			items, err := LoadReport(writeReport(t, tc.content))
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got %d items", len(items))
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if len(items) != tc.count {
				t.Fatalf("expected %d items, got %d", tc.count, len(items))
			}
		})
	}
}
