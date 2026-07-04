package plugin

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
)

func TestDeleteStaleRecordedSecretsOnlyDeletesOldNames(t *testing.T) {
	deletedIDs := []string{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			t.Fatalf("method = %s, want DELETE", r.Method)
		}
		deletedIDs = append(deletedIDs, r.URL.Path)
		writeJSON(t, w, cloudflareEnvelope[json.RawMessage]{Success: true})
	}))
	defer server.Close()

	client := newCloudflareClient(&cloudflareConfig{APIToken: "token", BaseURL: server.URL}, server.Client())
	deleted, err := deleteStaleRecordedSecrets(context.Background(), client, "acct", "store", map[string]string{
		"SECRET__PART_001": "id-1",
		"SECRET__PART_002": "id-2",
		"SECRET__META":     "id-meta",
	}, map[string]string{
		"SECRET__PART_001": "id-1",
		"SECRET__META":     "id-meta",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(deleted) != 1 || deleted[0] != "SECRET__PART_002" {
		t.Fatalf("deleted = %#v, want [SECRET__PART_002]", deleted)
	}
	if len(deletedIDs) != 1 || deletedIDs[0] != "/accounts/acct/secrets_store/stores/store/secrets/id-2" {
		t.Fatalf("deleted paths = %#v", deletedIDs)
	}
}

func TestSameStringSet(t *testing.T) {
	if !sameStringSet([]string{"b", "a"}, []string{"a", "b"}) {
		t.Fatal("expected same set")
	}
	if sameStringSet([]string{"a"}, []string{"a", "b"}) {
		t.Fatal("expected different set")
	}
}

func TestSyncDeleteDryRunAndConfirmation(t *testing.T) {
	b, storage := testBackend(t)
	ctx := context.Background()
	if err := writeSyncState(ctx, storage, "api", &syncState{
		CloudflareAccountID: "acct-1",
		CloudflareStoreID:   "store-1",
		CloudflareNamesToID: map[string]string{
			"API_SECRET": "id-1",
		},
	}); err != nil {
		t.Fatal(err)
	}

	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "sync/delete/api",
		Storage:   storage,
		Data: map[string]interface{}{
			"dry_run": true,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	wouldDelete := resp.Data["would_delete"].([]string)
	if len(wouldDelete) != 1 || wouldDelete[0] != "API_SECRET" {
		t.Fatalf("would_delete = %#v", wouldDelete)
	}
	state, err := readSyncState(ctx, storage, "api")
	if err != nil {
		t.Fatal(err)
	}
	if state == nil {
		t.Fatal("dry-run removed sync state")
	}

	resp, err = b.HandleRequest(ctx, &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "sync/delete/api",
		Storage:   storage,
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatalf("expected confirmation error, got %#v", resp)
	}
}

func TestSyncDeleteDeletesCloudflareEntriesAndState(t *testing.T) {
	deletedPaths := []string{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			t.Fatalf("method = %s, want DELETE", r.Method)
		}
		deletedPaths = append(deletedPaths, r.URL.Path)
		writeJSON(t, w, cloudflareEnvelope[json.RawMessage]{Success: true})
	}))
	defer server.Close()

	b, storage := testBackend(t)
	b.httpClient = server.Client()
	ctx := context.Background()
	writeCloudflareTestConfig(t, b, storage, server.URL)
	if err := writeSyncState(ctx, storage, "api", &syncState{
		CloudflareAccountID: "acct-1",
		CloudflareStoreID:   "store-1",
		CloudflareNamesToID: map[string]string{
			"API_SECRET":      "id-1",
			"API_SECRET_META": "id-meta",
		},
	}); err != nil {
		t.Fatal(err)
	}

	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "sync/delete/api",
		Storage:   storage,
		Data: map[string]interface{}{
			"delete_cloudflare_secrets": true,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp != nil && resp.IsError() {
		t.Fatal(resp.Error())
	}
	deleted := resp.Data["deleted"].([]string)
	if len(deleted) != 2 || deleted[0] != "API_SECRET" || deleted[1] != "API_SECRET_META" {
		t.Fatalf("deleted = %#v", deleted)
	}
	if len(deletedPaths) != 2 {
		t.Fatalf("deleted paths = %#v", deletedPaths)
	}
	state, err := readSyncState(ctx, storage, "api")
	if err != nil {
		t.Fatal(err)
	}
	if state != nil {
		t.Fatalf("expected sync state removal, got %#v", state)
	}
}
