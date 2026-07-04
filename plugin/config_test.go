package plugin

import (
	"context"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
)

func testBackend(t *testing.T) (*cloudflareBackend, logical.Storage) {
	t.Helper()
	b := Backend()
	storage := &logical.InmemStorage{}
	if err := b.Setup(context.Background(), &logical.BackendConfig{StorageView: storage}); err != nil {
		t.Fatal(err)
	}
	return b, storage
}

func TestCloudflareConfigRedactsAPIToken(t *testing.T) {
	b, storage := testBackend(t)
	ctx := context.Background()

	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config/cloudflare",
		Storage:   storage,
		Data: map[string]interface{}{
			"api_token":        "super-secret-token",
			"account_id":       "account-1",
			"secrets_store_id": "store-1",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp != nil && resp.IsError() {
		t.Fatal(resp.Error().Error())
	}

	resp, err = b.HandleRequest(ctx, &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "config/cloudflare",
		Storage:   storage,
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := resp.Data["api_token"]; got != nil {
		t.Fatalf("api_token leaked in read response: %#v", got)
	}
	if got := resp.Data["api_token_set"]; got != true {
		t.Fatalf("api_token_set = %#v, want true", got)
	}
	if got := resp.Data["base_url"]; got != defaultCloudflareBaseURL {
		t.Fatalf("base_url = %#v, want %q", got, defaultCloudflareBaseURL)
	}
}

func TestCloudflareConfigRequiresAPIToken(t *testing.T) {
	b, storage := testBackend(t)

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config/cloudflare",
		Storage:   storage,
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatalf("expected missing api_token error, got %#v", resp)
	}
}

func TestSyncConfigDefaults(t *testing.T) {
	b, storage := testBackend(t)

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "config/sync",
		Storage:   storage,
	})
	if err != nil {
		t.Fatal(err)
	}

	scopes := resp.Data["default_scopes"].([]string)
	if len(scopes) != 1 || scopes[0] != "workers" {
		t.Fatalf("default_scopes = %#v, want [workers]", scopes)
	}
	if got := resp.Data["default_chunk_size_bytes"]; got != defaultChunkSizeBytes {
		t.Fatalf("default_chunk_size_bytes = %#v, want %d", got, defaultChunkSizeBytes)
	}
	if got := resp.Data["max_parts"]; got != defaultMaxParts {
		t.Fatalf("max_parts = %#v, want %d", got, defaultMaxParts)
	}
	if got := resp.Data["delete_removed_parts"]; got != true {
		t.Fatalf("delete_removed_parts = %#v, want true", got)
	}
}

func TestSyncConfigWriteAndRead(t *testing.T) {
	b, storage := testBackend(t)
	ctx := context.Background()

	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config/sync",
		Storage:   storage,
		Data: map[string]interface{}{
			"default_scopes":           []string{"workers", "ai_gateway"},
			"default_chunk_size_bytes": 32000,
			"max_parts":                5,
			"name_prefix":              "APP_",
			"name_suffix":              "_PROD",
			"delete_removed_parts":     false,
			"managed_comment_prefix":   "managed-by=test",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp != nil && resp.IsError() {
		t.Fatal(resp.Error().Error())
	}

	resp, err = b.HandleRequest(ctx, &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "config/sync",
		Storage:   storage,
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := resp.Data["default_chunk_size_bytes"]; got != 32000 {
		t.Fatalf("default_chunk_size_bytes = %#v, want 32000", got)
	}
	if got := resp.Data["delete_removed_parts"]; got != false {
		t.Fatalf("delete_removed_parts = %#v, want false", got)
	}
}
