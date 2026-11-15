package githubreview

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type PublishOptions struct {
	Token       string
	APIURL      string
	SummaryOnly bool
	DryRun      bool
	MaxComments int
}

type PublishResult struct {
	SummaryAction string `json:"summaryAction"`
	InlineCreated int    `json:"inlineCreated"`
	InlineUpdated int    `json:"inlineUpdated"`
	DryRun        bool   `json:"dryRun"`
}

type publisher struct {
	client *http.Client
	base   *url.URL
	token  string
}

type githubComment struct {
	ID   int64  `json:"id"`
	Body string `json:"body"`
}

func Publish(ctx context.Context, artifact Artifact, options PublishOptions) (PublishResult, error) {
	if err := Validate(artifact, options.MaxComments); err != nil {
		return PublishResult{}, err
	}
	if options.DryRun || strings.TrimSpace(options.Token) == "" {
		return PublishResult{SummaryAction: "dry-run", DryRun: true}, nil
	}
	api := options.APIURL
	if api == "" {
		api = "https://api.github.com"
	}
	base, err := url.Parse(api)
	if err != nil || base.Scheme != "https" || base.Host == "" || base.User != nil || base.RawQuery != "" || base.Fragment != "" {
		return PublishResult{}, fmt.Errorf("GitHub API URL must be an HTTPS origin")
	}
	p := &publisher{client: &http.Client{Timeout: 30 * time.Second}, base: base, token: options.Token}
	result := PublishResult{}
	issuePath := fmt.Sprintf("/repos/%s/issues/%d/comments", artifact.Repository, artifact.PullRequest)
	var issueComments []githubComment
	if err := p.request(ctx, http.MethodGet, issuePath+"?per_page=100", nil, &issueComments); err != nil {
		return result, err
	}
	summaryMarker := fmt.Sprintf("<!-- caphe-review:%d -->", artifact.PullRequest)
	var existingSummary int64
	for _, c := range issueComments {
		if strings.Contains(c.Body, summaryMarker) {
			existingSummary = c.ID
			break
		}
	}
	if existingSummary != 0 {
		if err := p.request(ctx, http.MethodPatch, fmt.Sprintf("/repos/%s/issues/comments/%d", artifact.Repository, existingSummary), map[string]string{"body": artifact.Summary}, nil); err != nil {
			return result, err
		}
		result.SummaryAction = "updated"
	} else {
		if err := p.request(ctx, http.MethodPost, issuePath, map[string]string{"body": artifact.Summary}, nil); err != nil {
			return result, err
		}
		result.SummaryAction = "created"
	}
	if options.SummaryOnly {
		return result, nil
	}
	inlinePath := fmt.Sprintf("/repos/%s/pulls/%d/comments", artifact.Repository, artifact.PullRequest)
	var existingInline []githubComment
	if err := p.request(ctx, http.MethodGet, inlinePath+"?per_page=100", nil, &existingInline); err != nil {
		return result, err
	}
	byMarker := map[string]int64{}
	for _, c := range existingInline {
		for _, candidate := range artifact.Comments {
			marker := "<!-- caphe-finding:" + candidate.FindingID + " -->"
			if strings.Contains(c.Body, marker) {
				byMarker[candidate.FindingID] = c.ID
			}
		}
	}
	for _, c := range artifact.Comments {
		if id := byMarker[c.FindingID]; id != 0 {
			if err := p.request(ctx, http.MethodPatch, fmt.Sprintf("/repos/%s/pulls/comments/%d", artifact.Repository, id), map[string]string{"body": c.Body}, nil); err != nil {
				return result, err
			}
			result.InlineUpdated++
			continue
		}
		payload := map[string]any{"body": c.Body, "commit_id": artifact.HeadSHA, "path": c.Path, "line": c.Line, "side": c.Side}
		if err := p.request(ctx, http.MethodPost, inlinePath, payload, nil); err != nil {
			return result, err
		}
		result.InlineCreated++
	}
	return result, nil
}

func (p *publisher) request(ctx context.Context, method, path string, payload, output any) error {
	if !strings.HasPrefix(path, "/repos/") {
		return fmt.Errorf("invalid GitHub API path")
	}
	apiPath := strings.Split(path, "?")[0]
	endpoint := *p.base
	endpoint.Path = strings.TrimSuffix(p.base.Path, "/") + apiPath
	endpoint.RawQuery = func() string {
		if i := strings.IndexByte(path, '?'); i >= 0 {
			return path[i+1:]
		}
		return ""
	}()
	var body io.Reader
	if payload != nil {
		data, err := json.Marshal(payload)
		if err != nil {
			return err
		}
		body = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint.String(), body)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Authorization", "Bearer "+p.token)
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	response, err := p.client.Do(req)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, 2<<20))
	if err != nil {
		return err
	}
	if response.StatusCode/100 != 2 {
		return fmt.Errorf("GitHub API %s %s returned %d: %s", method, endpoint.Path, response.StatusCode, strings.TrimSpace(string(data)))
	}
	if output != nil && len(data) > 0 {
		if err := json.Unmarshal(data, output); err != nil {
			return fmt.Errorf("parse GitHub API response: %w", err)
		}
	}
	return nil
}
