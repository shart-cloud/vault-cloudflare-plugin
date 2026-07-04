package plugin

import (
	"encoding/json"
	"testing"
)

func TestBuildSyncPlanUnchunked(t *testing.T) {
	rule := &syncRule{Name: "api", VaultMount: "kv", VaultPath: "app/api", CloudflareName: "API_SECRET", Split: "auto", Encoding: "raw"}
	plan, err := buildSyncPlan(rule, defaultSyncConfig(), sourceSecret{Payload: []byte("secret-value"), Version: 7})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Secrets) != 1 {
		t.Fatalf("planned secrets = %d, want 1", len(plan.Secrets))
	}
	if plan.Secrets[0].Name != "API_SECRET" || plan.Secrets[0].Value != "secret-value" {
		t.Fatalf("planned secret = %#v", plan.Secrets[0])
	}
	if plan.SourceSHA256 == "" {
		t.Fatal("missing source sha256")
	}
}

func TestBuildSyncPlanChunkedWritesMetaLast(t *testing.T) {
	rule := &syncRule{Name: "jwt", VaultMount: "kv", VaultPath: "app/jwt", CloudflareName: "JWT", Split: "true", Encoding: "raw"}
	cfg := defaultSyncConfig()
	cfg.DefaultChunkSizeBytes = 4
	cfg.MaxParts = 10

	plan, err := buildSyncPlan(rule, cfg, sourceSecret{Payload: []byte("abcdef"), Version: 3})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Secrets) != 3 {
		t.Fatalf("planned secrets = %d, want 3", len(plan.Secrets))
	}
	if plan.Secrets[0].Name != "JWT__PART_001" || plan.Secrets[1].Name != "JWT__PART_002" || plan.Secrets[2].Name != "JWT__META" {
		t.Fatalf("planned names = %#v", []string{plan.Secrets[0].Name, plan.Secrets[1].Name, plan.Secrets[2].Name})
	}

	var meta chunkMetadata
	if err := json.Unmarshal([]byte(plan.Secrets[2].Value), &meta); err != nil {
		t.Fatal(err)
	}
	if meta.Format != "vault-cloudflare-secret-v1" || meta.Parts != 2 || meta.VaultVersion != 3 {
		t.Fatalf("metadata = %#v", meta)
	}
}

func TestBuildSyncPlanMaxParts(t *testing.T) {
	rule := &syncRule{Name: "jwt", VaultMount: "kv", VaultPath: "app/jwt", CloudflareName: "JWT", Split: "true", Encoding: "raw"}
	cfg := defaultSyncConfig()
	cfg.DefaultChunkSizeBytes = 2
	cfg.MaxParts = 1

	_, err := buildSyncPlan(rule, cfg, sourceSecret{Payload: []byte("abcdef"), Version: 3})
	if err == nil {
		t.Fatal("expected max_parts error")
	}
}

func TestBuildSyncPlanDefaultChunkEnvelopeFitsCloudflareLimit(t *testing.T) {
	rule := &syncRule{Name: "large", VaultMount: "kv", VaultPath: "app/large", CloudflareName: "LARGE_SECRET", Split: "auto", Encoding: "raw"}
	plan, err := buildSyncPlan(rule, defaultSyncConfig(), sourceSecret{Payload: []byte(string(make([]byte, 1500))), Version: 1})
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range plan.Secrets {
		if len(secret.Value) > cloudflareSecretValueLimit {
			t.Fatalf("%s value length = %d, limit %d", secret.Name, len(secret.Value), cloudflareSecretValueLimit)
		}
	}
}

func TestBuildSyncPlanRejectsOversizedChunkEnvelope(t *testing.T) {
	rule := &syncRule{Name: "large", VaultMount: "kv", VaultPath: "app/large", CloudflareName: "LARGE_SECRET", Split: "true", Encoding: "raw", ChunkSizeBytes: 1000, MaxParts: 10}
	_, err := buildSyncPlan(rule, defaultSyncConfig(), sourceSecret{Payload: []byte(string(make([]byte, 900))), Version: 1})
	if err == nil {
		t.Fatal("expected envelope size error")
	}
}

func TestSplitPlannedSecretsSeparatesMetadata(t *testing.T) {
	plan := &syncPlan{Secrets: []plannedSecret{
		{Name: "SECRET__PART_001"},
		{Name: "SECRET__META"},
		{Name: "SECRET__PART_002"},
	}}
	parts, meta := splitPlannedSecrets(plan)
	if len(parts) != 2 || parts[0].Name != "SECRET__PART_001" || parts[1].Name != "SECRET__PART_002" {
		t.Fatalf("parts = %#v", parts)
	}
	if len(meta) != 1 || meta[0].Name != "SECRET__META" {
		t.Fatalf("meta = %#v", meta)
	}
}
