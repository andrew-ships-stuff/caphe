package cluster

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestJobListingIsTenantScopedAndPaginated(t *testing.T) {
	store, err := OpenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, tenant := range []string{"a", "b", "a"} {
		if _, err := store.CreateJob(tenant, Submission{}, strings.NewReader("archive"), true); err != nil {
			t.Fatal(err)
		}
	}
	auth := &Authenticator{tokens: map[string]string{"token-a": "a", "token-b": "b"}}
	server, err := NewServer(ServerConfig{Store: store, Auth: auth})
	if err != nil {
		t.Fatal(err)
	}
	request := func(query, token string, want int) JobPage {
		t.Helper()
		req := httptest.NewRequest("GET", "/v1/jobs"+query, nil)
		req.Header.Set("Authorization", "Bearer "+token)
		res := httptest.NewRecorder()
		server.http.Handler.ServeHTTP(res, req)
		if res.Code != want {
			t.Fatalf("got %d: %s", res.Code, res.Body.String())
		}
		var page JobPage
		if want == 200 {
			if err := json.Unmarshal(res.Body.Bytes(), &page); err != nil {
				t.Fatal(err)
			}
		}
		return page
	}
	first := request("?limit=1", "token-a", 200)
	if len(first.Jobs) != 1 || first.Jobs[0].Tenant != "a" || first.NextCursor == "" {
		t.Fatalf("unexpected page: %+v", first)
	}
	second := request("?limit=1&cursor="+first.NextCursor, "token-a", 200)
	if len(second.Jobs) != 1 || second.Jobs[0].Tenant != "a" || second.Jobs[0].ID == first.Jobs[0].ID || second.NextCursor != "" {
		t.Fatalf("unexpected page: %+v", second)
	}
	request("?cursor="+first.NextCursor, "token-b", 400)
	request("?limit=201", "token-a", 400)
	request("?limit=0", "token-a", 400)
	request("?cursor=../../secret", "token-a", 400)
	request("", "invalid", 401)
}
