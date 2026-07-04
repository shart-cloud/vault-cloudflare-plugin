package plugin

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
)

func TestStaticTokenWriteReadListDeleteExistingToken(t *testing.T) {
	b, storage := testBackend(t)
	ctx := context.Background()

	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "token/static/ci",
		Storage:   storage,
		Data: map[string]interface{}{
			"token":      "static-token-value",
			"account_id": "acct-1",
			"token_id":   "tok-static",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp != nil && resp.IsError() {
		t.Fatal(resp.Error())
	}

	resp, err = b.HandleRequest(ctx, &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "token/static/ci",
		Storage:   storage,
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := resp.Data["token"]; got != "static-token-value" {
		t.Fatalf("token = %#v", got)
	}
	if got := resp.Data["managed"]; got != false {
		t.Fatalf("managed = %#v", got)
	}

	resp, err = b.HandleRequest(ctx, &logical.Request{
		Operation: logical.ListOperation,
		Path:      "token/static/",
		Storage:   storage,
	})
	if err != nil {
		t.Fatal(err)
	}
	keys := resp.Data["keys"].([]string)
	if len(keys) != 1 || keys[0] != "ci" {
		t.Fatalf("keys = %#v", keys)
	}

	_, err = b.HandleRequest(ctx, &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      "token/static/ci",
		Storage:   storage,
	})
	if err != nil {
		t.Fatal(err)
	}
	resp, err = b.HandleRequest(ctx, &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "token/static/ci",
		Storage:   storage,
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp != nil {
		t.Fatalf("expected nil response after delete, got %#v", resp)
	}
}

func TestStaticTokenCreateFromRoleStoresReturnedToken(t *testing.T) {
	var createReq cloudflareAPITokenCreateRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("method = %s, want POST", r.Method)
		}
		if r.URL.Path != "/accounts/acct-1/tokens" {
			t.Fatalf("path = %s", r.URL.Path)
		}
		if err := json.NewDecoder(r.Body).Decode(&createReq); err != nil {
			t.Fatal(err)
		}
		writeJSON(t, w, cloudflareEnvelope[cloudflareAPIToken]{Success: true, Result: cloudflareAPIToken{ID: "tok-static", Value: "created-static-value", ExpiresOn: createReq.ExpiresOn}})
	}))
	defer server.Close()

	b, storage := testBackend(t)
	b.httpClient = server.Client()
	ctx := context.Background()
	writeCloudflareTestConfig(t, b, storage, server.URL)
	writeTokenRole(t, b, storage)

	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "token/static/ci",
		Storage:   storage,
		Data: map[string]interface{}{
			"role":         "worker-read",
			"display_name": "ci static",
			"ttl":          "30m",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp != nil && resp.IsError() {
		t.Fatal(resp.Error())
	}
	if !strings.HasPrefix(createReq.Name, "vault-worker-read-ci-static-") {
		t.Fatalf("token name = %q", createReq.Name)
	}

	resp, err = b.HandleRequest(ctx, &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "token/static/ci",
		Storage:   storage,
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := resp.Data["token"]; got != "created-static-value" {
		t.Fatalf("token = %#v", got)
	}
	if got := resp.Data["token_id"]; got != "tok-static" {
		t.Fatalf("token_id = %#v", got)
	}
	if got := resp.Data["managed"]; got != true {
		t.Fatalf("managed = %#v", got)
	}
}

func TestStaticTokenDeleteCanDeleteManagedCloudflareToken(t *testing.T) {
	deleted := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			t.Fatalf("method = %s, want DELETE", r.Method)
		}
		if r.URL.Path != "/accounts/acct-1/tokens/tok-static" {
			t.Fatalf("path = %s", r.URL.Path)
		}
		deleted = true
		writeJSON(t, w, cloudflareEnvelope[json.RawMessage]{Success: true})
	}))
	defer server.Close()

	b, storage := testBackend(t)
	b.httpClient = server.Client()
	ctx := context.Background()
	writeCloudflareTestConfig(t, b, storage, server.URL)
	entry := &staticToken{Name: "ci", Token: "value", AccountID: "acct-1", TokenID: "tok-static", DeleteOnTTL: true}
	storageEntry, err := logical.StorageEntryJSON(staticTokenStoragePath("ci"), entry)
	if err != nil {
		t.Fatal(err)
	}
	if err := storage.Put(ctx, storageEntry); err != nil {
		t.Fatal(err)
	}

	_, err = b.HandleRequest(ctx, &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      "token/static/ci",
		Storage:   storage,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !deleted {
		t.Fatal("expected Cloudflare token deletion")
	}
}
