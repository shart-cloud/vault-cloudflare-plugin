package plugin

import (
	"context"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
)

func TestSyncRuleWriteReadListDelete(t *testing.T) {
	b, storage := testBackend(t)
	ctx := context.Background()

	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "sync/rules/api-jwt",
		Storage:   storage,
		Data: map[string]interface{}{
			"vault_mount":     "kv",
			"vault_path":      "apps/api/prod/jwt",
			"vault_field":     "value",
			"cloudflare_name": "JWT_PRIVATE_KEY",
			"binding_name":    "JWT_KEY",
			"scopes":          []string{"workers"},
			"split":           "true",
			"encoding":        "base64",
			"enabled":         true,
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
		Path:      "sync/rules/api-jwt",
		Storage:   storage,
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := resp.Data["vault_mount"]; got != "kv" {
		t.Fatalf("vault_mount = %#v, want kv", got)
	}
	if got := resp.Data["split"]; got != "true" {
		t.Fatalf("split = %#v, want true", got)
	}
	if got := resp.Data["binding_name"]; got != "JWT_KEY" {
		t.Fatalf("binding_name = %#v, want JWT_KEY", got)
	}

	resp, err = b.HandleRequest(ctx, &logical.Request{
		Operation: logical.ListOperation,
		Path:      "sync/rules/",
		Storage:   storage,
	})
	if err != nil {
		t.Fatal(err)
	}
	keys := resp.Data["keys"].([]string)
	if len(keys) != 1 || keys[0] != "api-jwt" {
		t.Fatalf("keys = %#v, want [api-jwt]", keys)
	}

	_, err = b.HandleRequest(ctx, &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      "sync/rules/api-jwt",
		Storage:   storage,
	})
	if err != nil {
		t.Fatal(err)
	}

	resp, err = b.HandleRequest(ctx, &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "sync/rules/api-jwt",
		Storage:   storage,
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp != nil {
		t.Fatalf("expected nil response after delete, got %#v", resp)
	}
}

func TestSyncRuleValidation(t *testing.T) {
	b, storage := testBackend(t)

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "sync/rules/bad-rule",
		Storage:   storage,
		Data: map[string]interface{}{
			"vault_mount":     "kv",
			"vault_path":      "apps/api/prod/jwt",
			"cloudflare_name": "BAD NAME",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatalf("expected validation error, got %#v", resp)
	}

	resp, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "sync/rules/bad-binding",
		Storage:   storage,
		Data: map[string]interface{}{
			"vault_mount":     "kv",
			"vault_path":      "apps/api/prod/jwt",
			"cloudflare_name": "JWT_PRIVATE_KEY",
			"binding_name":    "1_BAD",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatalf("expected binding validation error, got %#v", resp)
	}
}
