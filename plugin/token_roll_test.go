package plugin

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
)

func TestTokenRollReturnsNewTokenValue(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			t.Fatalf("method = %s, want PUT", r.Method)
		}
		if r.URL.Path != "/accounts/acct-1/tokens/tok-1/value" {
			t.Fatalf("path = %s", r.URL.Path)
		}
		writeJSON(t, w, cloudflareEnvelope[cloudflareAPIToken]{Success: true, Result: cloudflareAPIToken{ID: "tok-1", Value: "new-token-value", ExpiresOn: "2026-07-04T17:00:00Z"}})
	}))
	defer server.Close()

	b, storage := testBackend(t)
	b.httpClient = server.Client()
	ctx := context.Background()
	writeCloudflareTestConfig(t, b, storage, server.URL)
	if err := writeTokenState(ctx, storage, "tok-1", &tokenState{RoleName: "worker-read", AccountID: "acct-1", TokenID: "tok-1"}); err != nil {
		t.Fatal(err)
	}

	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "token/roll/tok-1",
		Storage:   storage,
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp == nil || resp.IsError() {
		t.Fatalf("unexpected response: %#v", resp)
	}
	if got := resp.Data["token"]; got != "new-token-value" {
		t.Fatalf("token = %#v", got)
	}
	state, err := readTokenState(ctx, storage, "tok-1")
	if err != nil {
		t.Fatal(err)
	}
	if state.ExpiresOn != "2026-07-04T17:00:00Z" {
		t.Fatalf("state expires_on = %q", state.ExpiresOn)
	}
}

func TestTokenRollRejectsMissingValue(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(t, w, cloudflareEnvelope[cloudflareAPIToken]{Success: true, Result: cloudflareAPIToken{ID: "tok-1"}})
	}))
	defer server.Close()

	b, storage := testBackend(t)
	b.httpClient = server.Client()
	ctx := context.Background()
	writeCloudflareTestConfig(t, b, storage, server.URL)

	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "token/roll/tok-1",
		Storage:   storage,
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatalf("expected error response, got %#v", resp)
	}
}

func TestUpdateAccountTokenUsesPut(t *testing.T) {
	var decoded cloudflareAPITokenCreateRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			t.Fatalf("method = %s, want PUT", r.Method)
		}
		if err := json.NewDecoder(r.Body).Decode(&decoded); err != nil {
			t.Fatal(err)
		}
		writeJSON(t, w, cloudflareEnvelope[cloudflareAPIToken]{Success: true, Result: cloudflareAPIToken{ID: "tok-1", ExpiresOn: decoded.ExpiresOn}})
	}))
	defer server.Close()

	client := newCloudflareClient(&cloudflareConfig{APIToken: "token", BaseURL: server.URL}, server.Client())
	_, err := client.updateAccountToken(context.Background(), "acct", "tok-1", cloudflareAPITokenCreateRequest{Name: "name", ExpiresOn: "2026-07-04T17:00:00Z"})
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Name != "name" {
		t.Fatalf("decoded = %#v", decoded)
	}
}
