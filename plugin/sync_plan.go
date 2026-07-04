package plugin

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
)

type sourceSecret struct {
	Payload []byte
	Version int
}

type plannedSecret struct {
	Name    string
	Value   string
	Scopes  []string
	Comment string
	Part    int
	Parts   int
}

type syncPlan struct {
	SourceSHA256 string
	VaultVersion int
	Secrets      []plannedSecret
}

type chunkMetadata struct {
	Format       string `json:"format"`
	Name         string `json:"name"`
	VaultMount   string `json:"vault_mount"`
	VaultPath    string `json:"vault_path"`
	VaultVersion int    `json:"vault_version"`
	Encoding     string `json:"encoding"`
	Parts        int    `json:"parts"`
	SHA256       string `json:"sha256"`
}

type chunkPart struct {
	Format       string `json:"format"`
	Name         string `json:"name"`
	VaultVersion int    `json:"vault_version"`
	Part         int    `json:"part"`
	Parts        int    `json:"parts"`
	Encoding     string `json:"encoding"`
	Data         string `json:"data"`
}

func buildSyncPlan(rule *syncRule, syncCfg *syncConfig, source sourceSecret) (*syncPlan, error) {
	if syncCfg == nil {
		syncCfg = defaultSyncConfig()
	}
	chunkSize := rule.ChunkSizeBytes
	if chunkSize == 0 {
		chunkSize = syncCfg.DefaultChunkSizeBytes
	}
	maxParts := rule.MaxParts
	if maxParts == 0 {
		maxParts = syncCfg.MaxParts
	}
	scopes := rule.Scopes
	if len(scopes) == 0 {
		scopes = syncCfg.DefaultScopes
	}
	baseName := syncCfg.NamePrefix + rule.CloudflareName + syncCfg.NameSuffix

	hash := sha256.Sum256(source.Payload)
	sha := hex.EncodeToString(hash[:])
	unchunkedValue := string(source.Payload)
	if rule.Encoding == "base64" {
		unchunkedValue = base64.StdEncoding.EncodeToString(source.Payload)
	}
	shouldSplit := rule.Split == "true" || (rule.Split == "auto" && len(unchunkedValue) > cloudflareSecretValueLimit)
	if !shouldSplit {
		if len(unchunkedValue) > cloudflareSecretValueLimit {
			return nil, fmt.Errorf("unchunked secret value is %d bytes, exceeds Cloudflare limit %d", len(unchunkedValue), cloudflareSecretValueLimit)
		}
		return &syncPlan{SourceSHA256: sha, VaultVersion: source.Version, Secrets: []plannedSecret{{
			Name:    baseName,
			Value:   unchunkedValue,
			Scopes:  scopes,
			Comment: syncComment(syncCfg.ManagedCommentPrefix, rule, source.Version, sha, "single"),
			Part:    1,
			Parts:   1,
		}}}, nil
	}

	if chunkSize <= 0 {
		return nil, fmt.Errorf("chunk size must be greater than zero")
	}
	encoded := base64.StdEncoding.EncodeToString(source.Payload)
	parts := splitString(encoded, chunkSize)
	if len(parts) > maxParts {
		return nil, fmt.Errorf("secret requires %d parts, exceeds max_parts %d", len(parts), maxParts)
	}

	planned := make([]plannedSecret, 0, len(parts)+1)
	for i, data := range parts {
		part := chunkPart{
			Format:       "vault-cloudflare-secret-part-v1",
			Name:         rule.CloudflareName,
			VaultVersion: source.Version,
			Part:         i + 1,
			Parts:        len(parts),
			Encoding:     "base64",
			Data:         data,
		}
		value, err := json.Marshal(part)
		if err != nil {
			return nil, err
		}
		if len(value) > cloudflareSecretValueLimit {
			return nil, fmt.Errorf("chunk part %d is %d bytes after JSON envelope, exceeds Cloudflare limit %d; reduce chunk_size_bytes", i+1, len(value), cloudflareSecretValueLimit)
		}
		planned = append(planned, plannedSecret{
			Name:    fmt.Sprintf("%s__PART_%03d", baseName, i+1),
			Value:   string(value),
			Scopes:  scopes,
			Comment: syncComment(syncCfg.ManagedCommentPrefix, rule, source.Version, sha, fmt.Sprintf("%d/%d", i+1, len(parts))),
			Part:    i + 1,
			Parts:   len(parts),
		})
	}

	meta := chunkMetadata{
		Format:       "vault-cloudflare-secret-v1",
		Name:         rule.CloudflareName,
		VaultMount:   rule.VaultMount,
		VaultPath:    rule.VaultPath,
		VaultVersion: source.Version,
		Encoding:     "base64",
		Parts:        len(parts),
		SHA256:       sha,
	}
	value, err := json.Marshal(meta)
	if err != nil {
		return nil, err
	}
	if len(value) > cloudflareSecretValueLimit {
		return nil, fmt.Errorf("chunk metadata is %d bytes after JSON envelope, exceeds Cloudflare limit %d", len(value), cloudflareSecretValueLimit)
	}
	planned = append(planned, plannedSecret{
		Name:    baseName + "__META",
		Value:   string(value),
		Scopes:  scopes,
		Comment: syncComment(syncCfg.ManagedCommentPrefix, rule, source.Version, sha, "meta"),
		Part:    0,
		Parts:   len(parts),
	})

	return &syncPlan{SourceSHA256: sha, VaultVersion: source.Version, Secrets: planned}, nil
}

func splitPlannedSecrets(plan *syncPlan) (parts []plannedSecret, meta []plannedSecret) {
	for _, secret := range plan.Secrets {
		if strings.HasSuffix(secret.Name, "__META") {
			meta = append(meta, secret)
			continue
		}
		parts = append(parts, secret)
	}
	return parts, meta
}

func splitString(value string, size int) []string {
	var parts []string
	for len(value) > size {
		parts = append(parts, value[:size])
		value = value[size:]
	}
	if value != "" || len(parts) == 0 {
		parts = append(parts, value)
	}
	return parts
}

func syncComment(prefix string, rule *syncRule, version int, sha, part string) string {
	return fmt.Sprintf("%s rule=%s vault=%s/%s version=%d sha256=%s part=%s", prefix, rule.Name, rule.VaultMount, rule.VaultPath, version, sha, part)
}
