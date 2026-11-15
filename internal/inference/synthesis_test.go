package inference

import (
	"encoding/json"
	"strings"
	"testing"
)

func allowedEvidence() map[string]bool {
	return map[string]bool{"sha256:aaa": true, "sha256:bbb": true, RepoOverviewEvidenceID: true}
}

func TestValidateRepoSynthesisAccepts(t *testing.T) {
	raw := json.RawMessage(`{"risk_summary":"Two supply-chain issues dominate.","priorities":[{"title":"Pin actions","rationale":"Third-party actions execute untrusted code.","evidence_ids":["sha256:aaa","repo-overview"],"rank":1},{"title":"Rotate secrets","rationale":"A live token was committed.","evidence_ids":["sha256:bbb"],"rank":2}],"confidence":"hypothesis"}`)
	synthesis, err := ValidateRepoSynthesis(raw, allowedEvidence())
	if err != nil {
		t.Fatal(err)
	}
	if len(synthesis.Priorities) != 2 || synthesis.Priorities[1].Rank != 2 {
		t.Fatalf("unexpected priorities: %+v", synthesis.Priorities)
	}
}

func TestValidateRepoSynthesisRejects(t *testing.T) {
	cases := map[string]string{
		"trailing":          `{"risk_summary":"x","priorities":[],"confidence":"hypothesis"}{"a":1}`,
		"unknown field":     `{"risk_summary":"x","priorities":[],"confidence":"hypothesis","extra":1}`,
		"wrong confidence":  `{"risk_summary":"x","priorities":[],"confidence":"confirmed"}`,
		"empty summary":     `{"risk_summary":"","priorities":[],"confidence":"hypothesis"}`,
		"fabricated id":     `{"risk_summary":"x","priorities":[{"title":"t","rationale":"r","evidence_ids":["sha256:zzz"],"rank":1}],"confidence":"hypothesis"}`,
		"duplicate rank":    `{"risk_summary":"x","priorities":[{"title":"t","rationale":"r","evidence_ids":["sha256:aaa"],"rank":1},{"title":"t","rationale":"r","evidence_ids":["sha256:bbb"],"rank":1}],"confidence":"hypothesis"}`,
		"rank out of range": `{"risk_summary":"x","priorities":[{"title":"t","rationale":"r","evidence_ids":["sha256:aaa"],"rank":9}],"confidence":"hypothesis"}`,
		"empty evidence":    `{"risk_summary":"x","priorities":[{"title":"t","rationale":"r","evidence_ids":[],"rank":1}],"confidence":"hypothesis"}`,
		"not object":        `[1,2]`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ValidateRepoSynthesis([]byte(body), allowedEvidence()); err == nil {
				t.Fatalf("expected rejection for %s", name)
			}
		})
	}
}

func TestValidateRepoSynthesisEmptyPrioritiesAllowed(t *testing.T) {
	if _, err := ValidateRepoSynthesis([]byte(`{"risk_summary":"Clean repository posture.","priorities":[],"confidence":"hypothesis"}`), allowedEvidence()); err != nil {
		t.Fatal(err)
	}
}

func TestSynthesisSchemaBoundsMatchValidator(t *testing.T) {
	var schema map[string]any
	if err := json.Unmarshal([]byte(SynthesisJSONSchema), &schema); err != nil {
		t.Fatalf("synthesis schema is not valid JSON: %v", err)
	}
	properties, _ := schema["properties"].(map[string]any)
	for _, required := range []string{"risk_summary", "priorities", "confidence"} {
		if _, ok := properties[required]; !ok {
			t.Fatalf("schema missing %s", required)
		}
	}
	long := strings.Repeat("x", 1501)
	if _, err := ValidateRepoSynthesis([]byte(`{"risk_summary":"`+long+`","priorities":[],"confidence":"hypothesis"}`), allowedEvidence()); err == nil {
		t.Fatal("validator must enforce the schema risk_summary bound")
	}
}
