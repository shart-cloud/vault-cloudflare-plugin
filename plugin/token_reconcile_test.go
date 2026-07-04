package plugin

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/hashicorp/vault/sdk/logical"
)

func TestTokenReconcileReportsDrift(t *testing.T) {
	now := time.Now().UTC()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Fatalf("method = %s, want GET", r.Method)
		}
		if r.URL.Path != "/accounts/acct-1/tokens" {
			t.Fatalf("path = %s", r.URL.Path)
		}
		writeJSON(t, w, cloudflareEnvelope[[]cloudflareAPIToken]{Success: true, Result: []cloudflareAPIToken{
			{ID: "tok-present", Name: "vault-worker-read-ci-1", ExpiresOn: now.Add(time.Hour).Format(time.RFC3339)},
			{ID: "tok-static", Name: "vault-worker-read-static-1", ExpiresOn: now.Add(time.Hour).Format(time.RFC3339)},
			{ID: "tok-orphan", Name: "vault-worker-read-orphan-1", ExpiresOn: now.Add(time.Hour).Format(time.RFC3339)},
			{ID: "tok-expired", Name: "vault-worker-read-old-1", ExpiresOn: now.Add(-time.Hour).Format(time.RFC3339)},
			{ID: "tok-human", Name: "human-token", ExpiresOn: now.Add(time.Hour).Format(time.RFC3339)},
		}})
	}))
	defer server.Close()

	b, storage := testBackend(t)
	b.httpClient = server.Client()
	ctx := context.Background()
	writeCloudflareTestConfig(t, b, storage, server.URL)
	if err := writeTokenState(ctx, storage, "tok-present", &tokenState{RoleName: "worker-read", AccountID: "acct-1", TokenID: "tok-present"}); err != nil {
		t.Fatal(err)
	}
	if err := writeTokenState(ctx, storage, "tok-missing", &tokenState{RoleName: "worker-read", AccountID: "acct-1", TokenID: "tok-missing"}); err != nil {
		t.Fatal(err)
	}
	staticEntry, err := logical.StorageEntryJSON(staticTokenStoragePath("ci"), &staticToken{Name: "ci", AccountID: "acct-1", TokenID: "tok-static", Token: "value", Managed: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := storage.Put(ctx, staticEntry); err != nil {
		t.Fatal(err)
	}

	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "token/reconcile",
		Storage:   storage,
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp != nil && resp.IsError() {
		t.Fatal(resp.Error())
	}
	if got := len(resp.Data["active_tokens_without_state"].([]map[string]interface{})); got != 1 {
		t.Fatalf("active_tokens_without_state len = %d, want 1", got)
	}
	if got := len(resp.Data["expired_tokens_present"].([]map[string]interface{})); got != 1 {
		t.Fatalf("expired_tokens_present len = %d, want 1", got)
	}
	if got := len(resp.Data["missing_cloudflare_tokens"].([]map[string]interface{})); got != 1 {
		t.Fatalf("missing_cloudflare_tokens len = %d, want 1", got)
	}
	if got := len(resp.Data["deleted_orphans"].([]string)); got != 0 {
		t.Fatalf("deleted_orphans len = %d, want 0", got)
	}
}

func TestTokenReconcileDeleteOrphansRequiresNonDryRun(t *testing.T) {
	b, storage := testBackend(t)
	ctx := context.Background()
	writeCloudflareTestConfig(t, b, storage, "https://example.invalid")

	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "token/reconcile",
		Storage:   storage,
		Data: map[string]interface{}{
			"delete_orphans": true,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatalf("expected dry-run guard error, got %#v", resp)
	}
}

func TestTokenReconcileDeletesOrphans(t *testing.T) {
	deleted := []string{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			writeJSON(t, w, cloudflareEnvelope[[]cloudflareAPIToken]{Success: true, Result: []cloudflareAPIToken{
				{ID: "tok-orphan", Name: "vault-worker-read-orphan-1", ExpiresOn: time.Now().UTC().Add(time.Hour).Format(time.RFC3339)},
				{ID: "tok-human", Name: "human-token", ExpiresOn: time.Now().UTC().Add(time.Hour).Format(time.RFC3339)},
			}})
		case http.MethodDelete:
			deleted = append(deleted, r.URL.Path)
			writeJSON(t, w, cloudflareEnvelope[json.RawMessage]{Success: true})
		default:
			t.Fatalf("unexpected method %s", r.Method)
		}
	}))
	defer server.Close()

	b, storage := testBackend(t)
	b.httpClient = server.Client()
	ctx := context.Background()
	writeCloudflareTestConfig(t, b, storage, server.URL)

	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "token/reconcile",
		Storage:   storage,
		Data: map[string]interface{}{
			"dry_run":        false,
			"delete_orphans": true,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp != nil && resp.IsError() {
		t.Fatal(resp.Error())
	}
	if len(deleted) != 1 || deleted[0] != "/accounts/acct-1/tokens/tok-orphan" {
		t.Fatalf("deleted = %#v", deleted)
	}
}

func TestTokenReconcileAccountIDsIncludesRoleOverrides(t *testing.T) {
	ids := tokenReconcileAccountIDs(
		&cloudflareConfig{AccountID: "acct-default"},
		map[string]*tokenState{
			"tok-1": {AccountID: "acct-state"},
		},
		[]*tokenRole{
			{AccountID: "acct-role"},
			{AccountID: "acct-default"},
		},
		map[string]*staticToken{
			"tok-static": {AccountID: "acct-static", TokenID: "tok-static"},
		},
	)
	want := []string{"acct-default", "acct-role", "acct-state", "acct-static"}
	if len(ids) != len(want) {
		t.Fatalf("ids = %#v, want %#v", ids, want)
	}
	for i := range want {
		if ids[i] != want[i] {
			t.Fatalf("ids = %#v, want %#v", ids, want)
		}
	}
}
