package audit

import (
	"errors"
	"testing"
)

func TestUnavailableAIBestEffortPreservesDeterministicAudit(t *testing.T) {
	var event ProgressEvent
	options := Options{AI: AIOptions{Model: "cpu-model", BestEffort: true}, Progress: func(got ProgressEvent) { event = got }}
	var bundle Bundle
	if err := unavailableAI(&bundle, options, errors.New("llama-server missing")); err != nil {
		t.Fatal(err)
	}
	if len(bundle.AI.Errors) != 1 || event.Kind != "ai_unavailable" || event.Message != "llama-server missing" {
		t.Fatalf("bundle=%#v event=%#v", bundle, event)
	}
}

func TestUnavailableAIRequiredReturnsError(t *testing.T) {
	want := errors.New("required AI failed")
	if got := unavailableAI(&Bundle{}, Options{}, want); !errors.Is(got, want) {
		t.Fatalf("error = %v, want %v", got, want)
	}
}
