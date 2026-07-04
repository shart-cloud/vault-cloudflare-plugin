package plugin

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/vault/sdk/logical"
)

func TestTokenCredsIssueAndRevoke(t *testing.T) {
	var createReq cloudflareAPITokenCreateRequest
	deleted := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost:
			if r.URL.Path != "/accounts/acct-1/tokens" {
				t.Fatalf("create path = %s", r.URL.Path)
			}
			if err := json.NewDecoder(r.Body).Decode(&createReq); err != nil {
				t.Fatal(err)
			}
			writeJSON(t, w, cloudflareEnvelope[cloudflareAPIToken]{Success: true, Result: cloudflareAPIToken{ID: "tok-1", Value: "cf-token-value", ExpiresOn: createReq.ExpiresOn}})
		case http.MethodDelete:
			if r.URL.Path != "/accounts/acct-1/tokens/tok-1" {
				t.Fatalf("delete path = %s", r.URL.Path)
			}
			deleted = true
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
	writeTokenRole(t, b, storage)

	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "token/creds/worker-read",
		Storage:   storage,
		Data: map[string]interface{}{
			"display_name": "ci job",
			"ttl":          "30m",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp == nil || resp.IsError() {
		t.Fatalf("unexpected response: %#v", resp)
	}
	if got := resp.Data["token"]; got != "cf-token-value" {
		t.Fatalf("token = %#v", got)
	}
	if resp.Secret == nil || resp.Secret.TTL != 30*time.Minute || resp.Secret.Renewable {
		t.Fatalf("secret lease = %#v", resp.Secret)
	}
	if !strings.HasPrefix(createReq.Name, "vault-worker-read-ci-job-") {
		t.Fatalf("token name = %q", createReq.Name)
	}
	if len(createReq.Policies) != 1 || createReq.Policies[0].PermissionGroups[0]["id"] != "pg-1" {
		t.Fatalf("policies = %#v", createReq.Policies)
	}

	state, err := readTokenState(ctx, storage, "tok-1")
	if err != nil {
		t.Fatal(err)
	}
	if state == nil || state.TokenID != "tok-1" || state.RoleName != "worker-read" {
		t.Fatalf("state = %#v", state)
	}
	if strings.Contains(state.TokenID+state.RoleName+state.AccountID+state.ExpiresOn, "cf-token-value") {
		t.Fatal("token value leaked into token state")
	}

	_, err = b.HandleRequest(ctx, &logical.Request{
		Operation: logical.RevokeOperation,
		Storage:   storage,
		Secret:    resp.Secret,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !deleted {
		t.Fatal("expected Cloudflare token deletion")
	}
	state, err = readTokenState(ctx, storage, "tok-1")
	if err != nil {
		t.Fatal(err)
	}
	if state != nil {
		t.Fatalf("expected token state deletion, got %#v", state)
	}
}

func TestTokenCredsRejectTTLAboveMax(t *testing.T) {
	b, storage := testBackend(t)
	ctx := context.Background()
	writeCloudflareTestConfig(t, b, storage, "https://example.invalid")
	writeTokenRole(t, b, storage)

	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "token/creds/worker-read",
		Storage:   storage,
		Data: map[string]interface{}{
			"ttl": "5h",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatalf("expected ttl validation error, got %#v", resp)
	}
}

func TestTokenCredsRenewUpdatesCloudflareToken(t *testing.T) {
	var updateReq cloudflareAPITokenCreateRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost:
			writeJSON(t, w, cloudflareEnvelope[cloudflareAPIToken]{Success: true, Result: cloudflareAPIToken{ID: "tok-1", Value: "cf-token-value"}})
		case http.MethodPut:
			if r.URL.Path != "/accounts/acct-1/tokens/tok-1" {
				t.Fatalf("update path = %s", r.URL.Path)
			}
			if err := json.NewDecoder(r.Body).Decode(&updateReq); err != nil {
				t.Fatal(err)
			}
			writeJSON(t, w, cloudflareEnvelope[cloudflareAPIToken]{Success: true, Result: cloudflareAPIToken{ID: "tok-1", ExpiresOn: updateReq.ExpiresOn}})
		default:
			t.Fatalf("unexpected method %s", r.Method)
		}
	}))
	defer server.Close()

	b, storage := testBackend(t)
	b.httpClient = server.Client()
	ctx := context.Background()
	writeCloudflareTestConfig(t, b, storage, server.URL)
	writeTokenRoleWithRenewable(t, b, storage, true)

	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "token/creds/worker-read",
		Storage:   storage,
		Data: map[string]interface{}{
			"display_name": "ci",
			"ttl":          "30m",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp == nil || resp.Secret == nil || !resp.Secret.Renewable {
		t.Fatalf("expected renewable secret, got %#v", resp)
	}
	resp.Secret.IssueTime = time.Now().UTC()
	resp.Secret.Increment = time.Hour

	renewed, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.RenewOperation,
		Storage:   storage,
		Secret:    resp.Secret,
	})
	if err != nil {
		t.Fatal(err)
	}
	if renewed == nil || renewed.Secret == nil || renewed.Secret.TTL != time.Hour || !renewed.Secret.Renewable {
		t.Fatalf("renewed secret = %#v", renewed)
	}
	if updateReq.Name == "" || updateReq.ExpiresOn == "" {
		t.Fatalf("update request = %#v", updateReq)
	}
	state, err := readTokenState(ctx, storage, "tok-1")
	if err != nil {
		t.Fatal(err)
	}
	if state == nil || state.ExpiresOn != updateReq.ExpiresOn {
		t.Fatalf("state = %#v, update = %#v", state, updateReq)
	}
}

func TestDeleteAccountTokenTreatsNotFoundAsSuccess(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		writeJSON(t, w, cloudflareEnvelope[json.RawMessage]{Success: false})
	}))
	defer server.Close()

	client := newCloudflareClient(&cloudflareConfig{APIToken: "token", BaseURL: server.URL}, server.Client())
	if err := client.deleteAccountToken(context.Background(), "acct", "missing"); err != nil {
		t.Fatal(err)
	}
}

func writeCloudflareTestConfig(t *testing.T, b *cloudflareBackend, storage logical.Storage, baseURL string) {
	t.Helper()
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config/cloudflare",
		Storage:   storage,
		Data: map[string]interface{}{
			"api_token":        "bootstrap-token",
			"account_id":       "acct-1",
			"secrets_store_id": "store-1",
			"base_url":         baseURL,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp != nil && resp.IsError() {
		t.Fatal(resp.Error())
	}
}

func writeTokenRole(t *testing.T, b *cloudflareBackend, storage logical.Storage) {
	t.Helper()
	writeTokenRoleWithRenewable(t, b, storage, false)
}

func writeTokenRoleWithRenewable(t *testing.T, b *cloudflareBackend, storage logical.Storage, renewable bool) {
	t.Helper()
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "token/roles/worker-read",
		Storage:   storage,
		Data: map[string]interface{}{
			"token_type":        "account",
			"permission_groups": []string{"pg-1"},
			"resources": map[string]interface{}{
				"com.cloudflare.api.account.acct-1": "*",
			},
			"default_ttl": "1h",
			"max_ttl":     "4h",
			"renewable":   renewable,
			"enabled":     true,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp != nil && resp.IsError() {
		t.Fatal(resp.Error())
	}
}
