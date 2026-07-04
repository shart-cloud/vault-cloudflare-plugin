package plugin

import (
	"context"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
)

func TestTokenRoleWriteReadListDelete(t *testing.T) {
	b, storage := testBackend(t)
	ctx := context.Background()

	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "token/roles/worker-read",
		Storage:   storage,
		Data: map[string]interface{}{
			"account_id":        "acct-1",
			"token_type":        "account",
			"permission_groups": []string{"pg-1"},
			"resources": map[string]interface{}{
				"com.cloudflare.api.account.acct-1": "*",
			},
			"default_ttl": "1h",
			"max_ttl":     "4h",
			"enabled":     true,
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
		Path:      "token/roles/worker-read",
		Storage:   storage,
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := resp.Data["default_ttl"]; got != 3600 {
		t.Fatalf("default_ttl = %#v, want 3600", got)
	}
	if got := resp.Data["max_ttl"]; got != 14400 {
		t.Fatalf("max_ttl = %#v, want 14400", got)
	}
	if got := resp.Data["name_template"]; got != defaultTokenNameTemplate {
		t.Fatalf("name_template = %#v", got)
	}

	resp, err = b.HandleRequest(ctx, &logical.Request{
		Operation: logical.ListOperation,
		Path:      "token/roles/",
		Storage:   storage,
	})
	if err != nil {
		t.Fatal(err)
	}
	keys := resp.Data["keys"].([]string)
	if len(keys) != 1 || keys[0] != "worker-read" {
		t.Fatalf("keys = %#v, want [worker-read]", keys)
	}

	_, err = b.HandleRequest(ctx, &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      "token/roles/worker-read",
		Storage:   storage,
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestTokenRoleValidation(t *testing.T) {
	b, storage := testBackend(t)

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "token/roles/bad",
		Storage:   storage,
		Data: map[string]interface{}{
			"token_type":        "account",
			"permission_groups": []string{"pg-1"},
			"resources":         map[string]interface{}{"*": "*"},
			"default_ttl":       "5h",
			"max_ttl":           "1h",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatalf("expected validation error, got %#v", resp)
	}
}
