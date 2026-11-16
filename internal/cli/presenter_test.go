package cli

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/andrew-ships-stuff/caphe/internal/adapters"
	"github.com/andrew-ships-stuff/caphe/internal/hardware"
)

func TestDoctorHumanOutput(t *testing.T) {
	var out bytes.Buffer
	a := &app{stdout: &out}
	report := doctorReport{
		Healthy:     true,
		Storage:     storageReport{Path: "/tmp/caphe", Available: true},
		Hardware:    hardware.Inspection{OS: "darwin", Architecture: "arm64", LogicalCores: 10, PhysicalCores: 8, TotalMemoryBytes: 32 << 30, AvailableMemoryBytes: 12 << 30, DiskFreeBytes: 100 << 30},
		Tools:       []adapters.ToolInfo{{ID: "scanner.opa", Available: true, Path: "/bin/opa", Version: "Version: 1.0.0"}, {ID: "scanner.osv", Error: `exec: "osv-scanner": executable file not found in $PATH`}},
		Inference:   inferenceReport{Provider: "llama.cpp", Endpoint: "http://127.0.0.1:8080", RuntimeAvailable: true, RuntimePath: "/tmp/llama-server", LaunchMode: "ephemeral-loopback-subprocess"},
		Suggestions: []doctorSuggestion{{Title: "Run the first audit", Commands: []string{"caphe audit ."}}},
	}
	if err := a.print(report); err != nil {
		t.Fatal(err)
	}
	text := out.String()
	for _, want := range []string{"Caphe doctor", "✓ Caphe core is healthy", "Scanners (1/2 available)", "✓ opa", "✗ osv", "○ External endpoint", "✓ Managed runtime", "Next steps", "$ caphe audit ."} {
		if !strings.Contains(text, want) {
			t.Fatalf("human output missing %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, `"healthy"`) || strings.Contains(text, "{") {
		t.Fatalf("human output contains JSON: %s", text)
	}
}

func TestJSONOutputPreservesDoctorSchema(t *testing.T) {
	var out bytes.Buffer
	a := &app{stdout: &out, jsonOutput: true}
	report := doctorReport{Healthy: true, Storage: storageReport{Path: "/tmp/caphe", Available: true}}
	if err := a.print(report); err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(out.Bytes(), &decoded); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, out.String())
	}
	if decoded["healthy"] != true {
		t.Fatalf("healthy schema changed: %#v", decoded)
	}
	storage, ok := decoded["storage"].(map[string]any)
	if !ok || storage["path"] != "/tmp/caphe" || storage["available"] != true {
		t.Fatalf("storage schema changed: %#v", decoded)
	}
}

func TestGenericHumanOutputIsStableAndNotJSON(t *testing.T) {
	var out bytes.Buffer
	a := &app{stdout: &out}
	if err := a.print(map[string]any{"valid": true, "digest": "sha256:abc", "status": "succeeded"}); err != nil {
		t.Fatal(err)
	}
	text := out.String()
	if !strings.Contains(text, "✓ Valid  yes") || !strings.Contains(text, "✓ Status  succeeded") || strings.Contains(text, "{") {
		t.Fatalf("unexpected human output: %s", text)
	}
}
