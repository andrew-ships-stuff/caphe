package reporting

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/andrew-ships-stuff/caphe/internal/findings"
)

func TestSARIFShape(t *testing.T) {
	var b bytes.Buffer
	f := findings.Finding{ID: "f", Fingerprint: "fp", Tool: "scanner.test", RuleID: "r", Title: "title", Severity: findings.SeverityHigh, Location: findings.Location{Path: "main.go", StartLine: 3}}
	if err := SARIF(&b, []findings.Finding{f}); err != nil {
		t.Fatal(err)
	}
	var d map[string]any
	if err := json.Unmarshal(b.Bytes(), &d); err != nil {
		t.Fatal(err)
	}
	if d["version"] != "2.1.0" || d["$schema"] == nil {
		t.Fatalf("invalid SARIF envelope: %s", b.String())
	}
}
func TestHTMLEscapesFindingContent(t *testing.T) {
	var b bytes.Buffer
	if err := HTML(&b, []findings.Finding{{Title: "<script>alert(1)</script>"}}); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(b.Bytes(), []byte("<script>alert")) {
		t.Fatal("report contains unescaped finding content")
	}
}
