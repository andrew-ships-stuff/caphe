package workflow

import (
	"encoding/json"
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

const APIVersion = "caphe.dev/v1alpha1"

type Workflow struct {
	APIVersion string   `yaml:"apiVersion" json:"apiVersion"`
	Kind       string   `yaml:"kind" json:"kind"`
	Metadata   Metadata `yaml:"metadata" json:"metadata"`
	Spec       Spec     `yaml:"spec" json:"spec"`
}

type Metadata struct {
	Name    string `yaml:"name" json:"name"`
	Version string `yaml:"version" json:"version"`
}

type Spec struct {
	Target   Target        `yaml:"target" json:"target"`
	Policies Policy        `yaml:"policies" json:"policies"`
	Tasks    []Task        `yaml:"tasks" json:"tasks"`
	Defaults RuntimePolicy `yaml:"defaults,omitempty" json:"defaults,omitempty"`
}

type Target struct {
	Type string `yaml:"type" json:"type"`
}

type Policy struct {
	Network              string `yaml:"network" json:"network"`
	ExecuteGeneratedCode bool   `yaml:"executeGeneratedCode" json:"executeGeneratedCode"`
	AllowActiveTesting   bool   `yaml:"allowActiveTesting" json:"allowActiveTesting"`
}

type RuntimePolicy struct {
	TimeoutSeconds int `yaml:"timeoutSeconds,omitempty" json:"timeoutSeconds,omitempty"`
	Retries        int `yaml:"retries,omitempty" json:"retries,omitempty"`
	BackoffMillis  int `yaml:"backoffMillis,omitempty" json:"backoffMillis,omitempty"`
}

type Resources struct {
	CPUMillis   int64 `yaml:"cpuMillis,omitempty" json:"cpuMillis,omitempty"`
	MemoryBytes int64 `yaml:"memoryBytes,omitempty" json:"memoryBytes,omitempty"`
}

type Task struct {
	ID            string         `yaml:"id" json:"id"`
	Uses          string         `yaml:"uses" json:"uses"`
	Needs         []string       `yaml:"needs,omitempty" json:"needs,omitempty"`
	OptionalNeeds []string       `yaml:"optionalNeeds,omitempty" json:"optionalNeeds,omitempty"`
	Optional      bool           `yaml:"optional,omitempty" json:"optional,omitempty"`
	With          map[string]any `yaml:"with,omitempty" json:"with,omitempty"`
	Runtime       RuntimePolicy  `yaml:"runtime,omitempty" json:"runtime,omitempty"`
	Resources     Resources      `yaml:"resources,omitempty" json:"resources,omitempty"`
}

func Parse(data []byte) (*Workflow, error) {
	var w Workflow
	if err := yaml.Unmarshal(data, &w); err != nil {
		return nil, fmt.Errorf("parse workflow YAML: %w", err)
	}
	return &w, nil
}

func Load(path string) (*Workflow, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read workflow: %w", err)
	}
	return Parse(b)
}

func RawConfig(v map[string]any) (json.RawMessage, error) {
	if v == nil {
		return json.RawMessage(`{}`), nil
	}
	return json.Marshal(v)
}
