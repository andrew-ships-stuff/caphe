package inference

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

type Capabilities struct {
	StructuredOutput bool     `json:"structuredOutput"`
	MaxContextTokens int      `json:"maxContextTokens"`
	Models           []string `json:"models"`
}
type Request struct {
	Model            string          `json:"model"`
	SystemPrompt     string          `json:"systemPrompt"`
	UntrustedContext string          `json:"untrustedContext"`
	Schema           json.RawMessage `json:"schema"`
	MaxInputTokens   int             `json:"maxInputTokens"`
	MaxOutputTokens  int             `json:"maxOutputTokens"`
	PromptVersion    string          `json:"promptVersion"`
	SchemaVersion    string          `json:"schemaVersion"`
}
type Result struct {
	Output           json.RawMessage `json:"output"`
	Model            string          `json:"model"`
	PromptTokens     int             `json:"promptTokens"`
	CompletionTokens int             `json:"completionTokens"`
	Duration         time.Duration   `json:"duration"`
	Cached           bool            `json:"cached"`
}
type Provider interface {
	Name() string
	Available(context.Context) (bool, error)
	Capabilities(context.Context) (Capabilities, error)
	GenerateStructured(context.Context, Request) (Result, error)
}
type LlamaCPP struct {
	endpoint *url.URL
	client   *http.Client
}

func NewLlamaCPP(endpoint string, timeout time.Duration) (*LlamaCPP, error) {
	u, err := url.Parse(endpoint)
	if err != nil {
		return nil, err
	}
	if u.Scheme != "http" || !(u.Hostname() == "127.0.0.1" || u.Hostname() == "localhost" || u.Hostname() == "::1") {
		return nil, fmt.Errorf("llama.cpp endpoint must be loopback HTTP")
	}
	return &LlamaCPP{endpoint: u, client: &http.Client{Timeout: timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return fmt.Errorf("inference redirects are forbidden") }}}, nil
}
func (l *LlamaCPP) Name() string { return "llama.cpp" }
func (l *LlamaCPP) Available(ctx context.Context) (bool, error) {
	u := l.endpoint.ResolveReference(&url.URL{Path: "/health"})
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	resp, err := l.client.Do(req)
	if err != nil {
		return false, nil
	}
	defer resp.Body.Close()
	return resp.StatusCode >= 200 && resp.StatusCode < 300, nil
}
func (l *LlamaCPP) Capabilities(ctx context.Context) (Capabilities, error) {
	ok, err := l.Available(ctx)
	if err != nil || !ok {
		return Capabilities{}, err
	}
	return Capabilities{StructuredOutput: true}, nil
}
func (l *LlamaCPP) GenerateStructured(ctx context.Context, r Request) (Result, error) {
	if r.MaxInputTokens <= 0 || r.MaxOutputTokens <= 0 {
		return Result{}, fmt.Errorf("positive token budgets required")
	}
	payload := map[string]any{"model": r.Model, "messages": []map[string]string{{"role": "system", "content": r.SystemPrompt}, {"role": "user", "content": "BEGIN_UNTRUSTED_DATA\n" + r.UntrustedContext + "\nEND_UNTRUSTED_DATA"}}, "max_tokens": r.MaxOutputTokens, "temperature": 0, "response_format": map[string]any{"type": "json_schema", "json_schema": map[string]any{"name": "caphe_response", "schema": json.RawMessage(r.Schema), "strict": true}}}
	var formatted struct {
		Prompt string `json:"prompt"`
	}
	if err := l.postJSON(ctx, "/apply-template", map[string]any{"messages": payload["messages"], "add_generation_prompt": true}, &formatted); err != nil {
		return Result{}, fmt.Errorf("format input budget: %w", err)
	}
	var tokenized struct {
		Tokens []int `json:"tokens"`
	}
	if err := l.postJSON(ctx, "/tokenize", map[string]any{"content": formatted.Prompt, "add_special": true, "parse_special": true}, &tokenized); err != nil {
		return Result{}, fmt.Errorf("count input tokens: %w", err)
	}
	if len(tokenized.Tokens) == 0 || len(tokenized.Tokens) > r.MaxInputTokens {
		return Result{}, fmt.Errorf("input has %d tokens; maximum %d", len(tokenized.Tokens), r.MaxInputTokens)
	}
	b, _ := json.Marshal(payload)
	u := l.endpoint.ResolveReference(&url.URL{Path: "/v1/chat/completions"})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewReader(b))
	if err != nil {
		return Result{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	start := time.Now()
	resp, err := l.client.Do(req)
	if err != nil {
		return Result{}, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if err != nil {
		return Result{}, err
	}
	if resp.StatusCode/100 != 2 {
		return Result{}, fmt.Errorf("llama.cpp HTTP %d: %s", resp.StatusCode, string(body))
	}
	var out struct {
		Choices []struct {
			FinishReason string `json:"finish_reason"`
			Message      struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
		Usage struct {
			Prompt     int `json:"prompt_tokens"`
			Completion int `json:"completion_tokens"`
		} `json:"usage"`
		Model string `json:"model"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return Result{}, err
	}
	if len(out.Choices) != 1 {
		return Result{}, fmt.Errorf("expected one completion")
	}
	if out.Choices[0].FinishReason == "length" {
		return Result{}, fmt.Errorf("model output truncated at token limit (%d completion tokens; maximum %d); increase --max-output-tokens within the configured budget", out.Usage.Completion, r.MaxOutputTokens)
	}
	raw := json.RawMessage(out.Choices[0].Message.Content)
	if !json.Valid(raw) {
		return Result{}, fmt.Errorf("model returned invalid JSON (%d completion tokens; maximum %d)", out.Usage.Completion, r.MaxOutputTokens)
	}
	return Result{Output: raw, Model: out.Model, PromptTokens: out.Usage.Prompt, CompletionTokens: out.Usage.Completion, Duration: time.Since(start)}, nil
}

func (l *LlamaCPP) postJSON(ctx context.Context, path string, input, output any) error {
	data, err := json.Marshal(input)
	if err != nil {
		return err
	}
	u := l.endpoint.ResolveReference(&url.URL{Path: path})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := l.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("llama.cpp %s HTTP %d", path, resp.StatusCode)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 2<<20)).Decode(output)
}
