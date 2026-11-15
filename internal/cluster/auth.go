package cluster

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"os"
)

type Authenticator struct {
	tokens   map[string]string
	insecure bool
}

type authFile struct {
	Tokens []authToken `json:"tokens"`
}

type authToken struct {
	Tenant string `json:"tenant"`
	Token  string `json:"token"`
}

func LoadAuthenticator(path string, insecure bool) (*Authenticator, error) {
	if insecure {
		return &Authenticator{insecure: true}, nil
	}
	if path == "" {
		return nil, fmt.Errorf("authentication file is required unless --insecure-no-auth is set")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	decoder := json.NewDecoder(file)
	decoder.DisallowUnknownFields()
	var config authFile
	if err := decoder.Decode(&config); err != nil {
		return nil, err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return nil, fmt.Errorf("authentication file contains trailing content")
	}
	auth := &Authenticator{tokens: map[string]string{}}
	for _, item := range config.Tokens {
		if !validTenant(item.Tenant) || len(item.Token) < 32 {
			return nil, fmt.Errorf("authentication entries require a valid tenant and token of at least 32 characters")
		}
		if _, exists := auth.tokens[item.Token]; exists {
			return nil, fmt.Errorf("duplicate authentication token")
		}
		auth.tokens[item.Token] = item.Tenant
	}
	if len(auth.tokens) == 0 {
		return nil, fmt.Errorf("authentication file contains no tokens")
	}
	return auth, nil
}

func (a *Authenticator) Authenticate(token string) (string, bool) {
	if a.insecure {
		return "development", true
	}
	for expected, tenant := range a.tokens {
		if len(token) == len(expected) && subtle.ConstantTimeCompare([]byte(token), []byte(expected)) == 1 {
			return tenant, true
		}
	}
	return "", false
}
