package cluster

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type Client struct {
	endpoint string
	token    string
	http     *http.Client
}

func NewClient(endpoint, token string) (*Client, error) {
	if endpoint == "" {
		endpoint = "http://127.0.0.1:8787"
	}
	u, err := url.Parse(endpoint)
	if err != nil || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, fmt.Errorf("invalid cluster endpoint")
	}
	if u.Scheme != "https" && !(u.Scheme == "http" && isLoopbackHost(u.Hostname())) {
		return nil, fmt.Errorf("cluster endpoint must use HTTPS unless it is loopback")
	}
	return &Client{endpoint: strings.TrimRight(endpoint, "/"), token: token, http: &http.Client{Timeout: 10 * time.Minute}}, nil
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func (c *Client) Submit(ctx context.Context, sub Submission, archivePath string) (Job, error) {
	if archivePath == "" {
		var out Job
		if err := c.jsonRequest(ctx, http.MethodPost, "/v1/jobs", sub, &out); err != nil {
			return Job{}, err
		}
		return out, nil
	}
	file, err := os.Open(archivePath)
	if err != nil {
		return Job{}, err
	}
	defer file.Close()
	reader, writer := io.Pipe()
	multipartWriter := multipart.NewWriter(writer)
	go func() {
		metadata, err := multipartWriter.CreateFormField("metadata")
		if err == nil {
			err = json.NewEncoder(metadata).Encode(sub)
		}
		if err == nil {
			var archive io.Writer
			archive, err = multipartWriter.CreateFormFile("archive", filepath.Base(archivePath))
			if err == nil {
				_, err = io.Copy(archive, file)
			}
		}
		if closeErr := multipartWriter.Close(); err == nil {
			err = closeErr
		}
		_ = writer.CloseWithError(err)
	}()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint+"/v1/jobs", reader)
	if err != nil {
		return Job{}, err
	}
	req.Header.Set("Content-Type", multipartWriter.FormDataContentType())
	var out Job
	if err := c.do(req, &out); err != nil {
		return Job{}, err
	}
	return out, nil
}

func (c *Client) Get(ctx context.Context, id string) (Job, error) {
	var out Job
	if err := c.jsonRequest(ctx, http.MethodGet, "/v1/jobs/"+url.PathEscape(id), nil, &out); err != nil {
		return Job{}, err
	}
	return out, nil
}

func (c *Client) Workflows(ctx context.Context) ([]string, error) {
	var out struct {
		Workflows []string `json:"workflows"`
	}
	if err := c.jsonRequest(ctx, http.MethodGet, "/v1/workflows", nil, &out); err != nil {
		return nil, err
	}
	return out.Workflows, nil
}

func (c *Client) Download(ctx context.Context, id string, destination string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.endpoint+"/v1/jobs/"+url.PathEscape(id)+"/bundle", nil)
	if err != nil {
		return err
	}
	c.authorize(req)
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return responseError(resp)
	}
	file, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	written, copyErr := io.Copy(file, io.LimitReader(resp.Body, (128<<20)+1))
	closeErr := file.Close()
	if copyErr != nil || written > 128<<20 {
		_ = os.Remove(destination)
		if written > 128<<20 {
			return fmt.Errorf("cluster bundle exceeds download limit")
		}
		return copyErr
	}
	return closeErr
}

func (c *Client) jsonRequest(ctx context.Context, method, path string, input, output any) error {
	var body io.Reader
	if input != nil {
		data, err := json.Marshal(input)
		if err != nil {
			return err
		}
		body = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.endpoint+path, body)
	if err != nil {
		return err
	}
	if input != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return c.do(req, output)
}

func (c *Client) do(req *http.Request, output any) error {
	c.authorize(req)
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return responseError(resp)
	}
	decoder := json.NewDecoder(io.LimitReader(resp.Body, 4<<20))
	decoder.DisallowUnknownFields()
	return decoder.Decode(output)
}

func (c *Client) authorize(req *http.Request) {
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
}

func responseError(resp *http.Response) error {
	var body struct {
		Error string `json:"error"`
	}
	_ = json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&body)
	if body.Error == "" {
		body.Error = resp.Status
	}
	return fmt.Errorf("cluster API: %s", body.Error)
}
