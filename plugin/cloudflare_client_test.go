package plugin

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCloudflareClientSecretsStoreRequests(t *testing.T) {
	var methods []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		methods = append(methods, r.Method)
		if got := r.Header.Get("Authorization"); got != "Bearer token-1" {
			t.Fatalf("Authorization = %q", got)
		}

		switch r.Method {
		case http.MethodGet:
			writeJSON(t, w, cloudflareEnvelope[[]cloudflareSecret]{Success: true, Result: []cloudflareSecret{{ID: "id-1", Name: "SECRET"}}})
		case http.MethodPost, http.MethodPatch:
			var req cloudflareSecretWrite
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Fatal(err)
			}
			if req.Value != "value-1" {
				t.Fatalf("value = %q, want value-1", req.Value)
			}
			writeJSON(t, w, cloudflareEnvelope[cloudflareSecret]{Success: true, Result: cloudflareSecret{ID: "id-1", Name: req.Name}})
		case http.MethodDelete:
			writeJSON(t, w, cloudflareEnvelope[json.RawMessage]{Success: true})
		default:
			t.Fatalf("unexpected method %s", r.Method)
		}
	}))
	defer server.Close()

	client := newCloudflareClient(&cloudflareConfig{APIToken: "token-1", BaseURL: server.URL}, server.Client())
	ctx := context.Background()

	secrets, err := client.listSecrets(ctx, "acct", "store")
	if err != nil {
		t.Fatal(err)
	}
	if len(secrets) != 1 || secrets[0].Name != "SECRET" {
		t.Fatalf("secrets = %#v", secrets)
	}
	if _, err := client.createSecret(ctx, "acct", "store", cloudflareSecretWrite{Name: "SECRET", Value: "value-1"}); err != nil {
		t.Fatal(err)
	}
	if _, err := client.patchSecret(ctx, "acct", "store", "id-1", cloudflareSecretWrite{Value: "value-1"}); err != nil {
		t.Fatal(err)
	}
	if err := client.deleteSecret(ctx, "acct", "store", "id-1"); err != nil {
		t.Fatal(err)
	}

	want := []string{http.MethodGet, http.MethodPost, http.MethodPatch, http.MethodDelete}
	for i := range want {
		if methods[i] != want[i] {
			t.Fatalf("methods = %#v, want %#v", methods, want)
		}
	}
}

func writeJSON(t *testing.T, w http.ResponseWriter, v any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		t.Fatal(err)
	}
}
