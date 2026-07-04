package plugin

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
)

func TestTokenPermissionGroupsReadFiltersResults(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/accounts/acct-1/tokens/permission_groups" {
			t.Fatalf("path = %s", r.URL.Path)
		}
		writeJSON(t, w, cloudflareEnvelope[[]cloudflarePermissionGroup]{Success: true, Result: []cloudflarePermissionGroup{
			{ID: "pg-workers", Name: "Workers Scripts Read", Scopes: []string{"com.cloudflare.api.account"}},
			{ID: "pg-dns", Name: "DNS Read", Scopes: []string{"com.cloudflare.api.account.zone"}},
		}})
	}))
	defer server.Close()

	b, storage := testBackend(t)
	b.httpClient = server.Client()
	ctx := context.Background()
	_, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config/cloudflare",
		Storage:   storage,
		Data: map[string]interface{}{
			"api_token":  "token",
			"account_id": "acct-1",
			"base_url":   server.URL,
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "token/permission-groups",
		Storage:   storage,
		Data: map[string]interface{}{
			"name":  "workers",
			"scope": "com.cloudflare.api.account",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	groups := resp.Data["permission_groups"].([]map[string]interface{})
	if len(groups) != 1 || groups[0]["id"] != "pg-workers" {
		t.Fatalf("permission_groups = %#v", groups)
	}
}
