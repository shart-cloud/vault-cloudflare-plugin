package plugin

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
)

func TestSyncReconcileReportsDrift(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Fatalf("method = %s, want GET", r.Method)
		}
		writeJSON(t, w, cloudflareEnvelope[[]cloudflareSecret]{Success: true, Result: []cloudflareSecret{
			{ID: "id-part-1", Name: "JWT__PART_001", Comment: "managed-by=vault-cloudflare rule=jwt vault=kv/app/jwt version=6 sha256=oldhash part=1/2"},
			{ID: "id-meta", Name: "JWT__META", Comment: "managed-by=vault-cloudflare rule=jwt vault=kv/app/jwt version=7 sha256=hash7 part=meta"},
			{ID: "id-extra", Name: "JWT__PART_003", Comment: "managed-by=vault-cloudflare rule=jwt vault=kv/app/jwt version=7 sha256=hash7 part=3/2"},
			{ID: "id-orphan", Name: "ORPHAN", Comment: "managed-by=vault-cloudflare rule=gone vault=kv/old version=1 sha256=old part=single"},
		}})
	}))
	defer server.Close()

	b, storage := testBackend(t)
	b.httpClient = server.Client()
	ctx := context.Background()
	writeCloudflareTestConfig(t, b, storage, server.URL)
	writeSyncRuleForReconcile(t, b, storage)
	if err := writeSyncState(ctx, storage, "jwt", &syncState{
		VaultVersion:        7,
		SourceSHA256:        "hash7",
		CloudflareAccountID: "acct-1",
		CloudflareStoreID:   "store-1",
		CloudflareNamesToID: map[string]string{
			"JWT__PART_001": "id-part-1",
			"JWT__PART_002": "id-part-2",
			"JWT__META":     "id-meta",
		},
		Parts: 2,
	}); err != nil {
		t.Fatal(err)
	}

	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "sync/reconcile",
		Storage:   storage,
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp != nil && resp.IsError() {
		t.Fatal(resp.Error())
	}
	if got := len(resp.Data["missing_cloudflare_entries"].([]map[string]interface{})); got != 1 {
		t.Fatalf("missing_cloudflare_entries len = %d, want 1", got)
	}
	if got := len(resp.Data["managed_orphans"].([]map[string]interface{})); got != 2 {
		t.Fatalf("managed_orphans len = %d, want 2", got)
	}
	if got := len(resp.Data["stale_comments_or_versions"].([]map[string]interface{})); got != 1 {
		t.Fatalf("stale_comments_or_versions len = %d, want 1", got)
	}
	if got := len(resp.Data["chunk_issues"].([]map[string]interface{})); got != 2 {
		t.Fatalf("chunk_issues len = %d, want 2", got)
	}
}

func TestSyncReconcileDeleteOrphansRequiresNonDryRun(t *testing.T) {
	b, storage := testBackend(t)
	ctx := context.Background()
	writeCloudflareTestConfig(t, b, storage, "https://example.invalid")

	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "sync/reconcile",
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

func TestSyncReconcileDeletesOrphans(t *testing.T) {
	deleted := []string{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			writeJSON(t, w, cloudflareEnvelope[[]cloudflareSecret]{Success: true, Result: []cloudflareSecret{
				{ID: "id-orphan", Name: "ORPHAN", Comment: "managed-by=vault-cloudflare rule=gone vault=kv/old version=1 sha256=old part=single"},
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
	writeSyncRuleForReconcile(t, b, storage)

	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "sync/reconcile",
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
	if len(deleted) != 1 || deleted[0] != "/accounts/acct-1/secrets_store/stores/store-1/secrets/id-orphan" {
		t.Fatalf("deleted = %#v", deleted)
	}
}

func writeSyncRuleForReconcile(t *testing.T, b *cloudflareBackend, storage logical.Storage) {
	t.Helper()
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "sync/rules/jwt",
		Storage:   storage,
		Data: map[string]interface{}{
			"vault_mount":     "kv",
			"vault_path":      "app/jwt",
			"vault_field":     "value",
			"cloudflare_name": "JWT",
			"split":           "true",
			"encoding":        "base64",
			"enabled":         true,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp != nil && resp.IsError() {
		t.Fatal(resp.Error())
	}
}
