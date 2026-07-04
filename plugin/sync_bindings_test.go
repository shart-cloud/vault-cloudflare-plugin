package plugin

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
)

func TestBuildTerraformSecretStoreBindingsUnchunked(t *testing.T) {
	rule := &syncRule{Name: "api", VaultMount: "kv", VaultPath: "app/api", CloudflareName: "api-secret", Split: "auto", Encoding: "raw"}
	cfg := defaultSyncConfig()
	cfg.NamePrefix = "APP_"
	cfg.NameSuffix = "_PROD"
	plan, err := buildSyncPlan(rule, cfg, sourceSecret{Payload: []byte("secret-value"), Version: 1})
	if err != nil {
		t.Fatal(err)
	}

	bindings, err := buildTerraformSecretStoreBindings(rule, cfg, "store-1", plan)
	if err != nil {
		t.Fatal(err)
	}
	if len(bindings) != 1 {
		t.Fatalf("bindings = %#v", bindings)
	}
	want := map[string]interface{}{
		"name":        "APP_API_SECRET_PROD",
		"type":        terraformSecretsStoreBindingType,
		"store_id":    "store-1",
		"secret_name": "APP_api-secret_PROD",
	}
	for key, value := range want {
		if bindings[0][key] != value {
			t.Fatalf("bindings[0][%s] = %#v, want %#v", key, bindings[0][key], value)
		}
	}
}

func TestBuildTerraformSecretStoreBindingsChunkedUsesMetaAndPartBindings(t *testing.T) {
	rule := &syncRule{Name: "jwt", VaultMount: "kv", VaultPath: "app/jwt", CloudflareName: "JWT_PRIVATE_KEY", BindingName: "JWT_KEY", Split: "true", Encoding: "raw"}
	cfg := defaultSyncConfig()
	cfg.DefaultChunkSizeBytes = 4
	cfg.MaxParts = 10
	plan, err := buildSyncPlan(rule, cfg, sourceSecret{Payload: []byte("abcdef"), Version: 1})
	if err != nil {
		t.Fatal(err)
	}

	bindings, err := buildTerraformSecretStoreBindings(rule, cfg, "store-1", plan)
	if err != nil {
		t.Fatal(err)
	}
	wantNames := []string{"JWT_KEY_META", "JWT_KEY_PART_001", "JWT_KEY_PART_002"}
	wantSecrets := []string{"JWT_PRIVATE_KEY__META", "JWT_PRIVATE_KEY__PART_001", "JWT_PRIVATE_KEY__PART_002"}
	if len(bindings) != len(wantNames) {
		t.Fatalf("bindings = %#v", bindings)
	}
	for i := range wantNames {
		if bindings[i]["name"] != wantNames[i] || bindings[i]["secret_name"] != wantSecrets[i] {
			t.Fatalf("binding[%d] = %#v", i, bindings[i])
		}
		if bindings[i]["type"] != terraformSecretsStoreBindingType || bindings[i]["store_id"] != "store-1" {
			t.Fatalf("binding[%d] = %#v", i, bindings[i])
		}
	}
}

func TestBuildTerraformSecretStoreBindingsJSONRoundTrip(t *testing.T) {
	rule := &syncRule{Name: "api", VaultMount: "kv", VaultPath: "app/api", CloudflareName: "API_SECRET", Split: "auto", Encoding: "raw"}
	plan, err := buildSyncPlan(rule, defaultSyncConfig(), sourceSecret{Payload: []byte("secret-value"), Version: 1})
	if err != nil {
		t.Fatal(err)
	}
	bindings, err := buildTerraformSecretStoreBindings(rule, defaultSyncConfig(), "store-1", plan)
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(bindings)
	if err != nil {
		t.Fatal(err)
	}
	var decoded []map[string]interface{}
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if len(decoded) != 1 || decoded[0]["secret_name"] != "API_SECRET" {
		t.Fatalf("decoded = %#v", decoded)
	}
}

func TestTerraformBindingsMatchPlannedSecretNames(t *testing.T) {
	rule := &syncRule{Name: "jwt", VaultMount: "kv", VaultPath: "app/jwt", CloudflareName: "JWT_PRIVATE_KEY", Split: "true", Encoding: "raw"}
	cfg := defaultSyncConfig()
	cfg.DefaultChunkSizeBytes = 4
	cfg.MaxParts = 10
	plan, err := buildSyncPlan(rule, cfg, sourceSecret{Payload: []byte("abcdef"), Version: 1})
	if err != nil {
		t.Fatal(err)
	}
	bindings, err := buildTerraformSecretStoreBindings(rule, cfg, "store-1", plan)
	if err != nil {
		t.Fatal(err)
	}
	secretNames := make([]string, 0, len(bindings))
	for _, binding := range bindings {
		secretNames = append(secretNames, binding["secret_name"].(string))
	}
	if !sameStringSet(secretNames, plannedNames(plan)) {
		t.Fatalf("binding secret names = %#v, planned names = %#v", secretNames, plannedNames(plan))
	}
}

func TestSanitizeWorkerBindingName(t *testing.T) {
	tests := map[string]string{
		"api-secret":      "API_SECRET",
		" app.secret ":    "APP_SECRET",
		"123-token":       "_123_TOKEN",
		"***":             "SECRET",
		"JWT_PRIVATE_KEY": "JWT_PRIVATE_KEY",
	}
	for input, want := range tests {
		if got := sanitizeWorkerBindingName(input); got != want {
			t.Fatalf("sanitizeWorkerBindingName(%q) = %q, want %q", input, got, want)
		}
		if !isValidWorkerBindingName(want) {
			t.Fatalf("sanitized binding name %q is not valid", want)
		}
	}
}

func TestSyncBindingsMissingRule(t *testing.T) {
	b, storage := testBackend(t)
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "sync/bindings/missing",
		Storage:   storage,
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatalf("expected missing rule error, got %#v", resp)
	}
}
