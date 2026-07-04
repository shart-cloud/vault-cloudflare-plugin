package plugin

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const syncRuleStoragePrefix = "sync/rules/"

type syncRule struct {
	Name           string   `json:"name"`
	VaultMount     string   `json:"vault_mount"`
	VaultPath      string   `json:"vault_path"`
	VaultField     string   `json:"vault_field,omitempty"`
	CloudflareName string   `json:"cloudflare_name"`
	AccountID      string   `json:"account_id,omitempty"`
	SecretsStoreID string   `json:"secrets_store_id,omitempty"`
	Scopes         []string `json:"scopes,omitempty"`
	Split          string   `json:"split"`
	ChunkSizeBytes int      `json:"chunk_size_bytes,omitempty"`
	MaxParts       int      `json:"max_parts,omitempty"`
	Encoding       string   `json:"encoding"`
	Enabled        bool     `json:"enabled"`
}

func (b *cloudflareBackend) pathSyncRulesList() *framework.Path {
	return &framework.Path{
		Pattern: "sync/rules/?",
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ListOperation: &framework.PathOperation{Callback: b.pathSyncRulesListRead},
		},
		HelpSynopsis:    "List configured explicit sync rules.",
		HelpDescription: "Lists names of explicit sync rules stored by this mount.",
	}
}

func (b *cloudflareBackend) pathSyncRules() *framework.Path {
	return &framework.Path{
		Pattern: "sync/rules/" + framework.GenericNameRegex("name"),
		ExistenceCheck: func(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
			return storageEntryExists(ctx, req.Storage, syncRuleStoragePath(data.Get("name").(string)))
		},
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeString,
				Description: "Rule name.",
			},
			"vault_mount": {
				Type:        framework.TypeString,
				Description: "Vault KV v2 mount containing the source secret.",
			},
			"vault_path": {
				Type:        framework.TypeString,
				Description: "Vault KV v2 secret path relative to vault_mount.",
			},
			"vault_field": {
				Type:        framework.TypeString,
				Description: "Optional field selected from the KV data object.",
			},
			"cloudflare_name": {
				Type:        framework.TypeString,
				Description: "Base Cloudflare Secrets Store secret name.",
			},
			"account_id": {
				Type:        framework.TypeString,
				Description: "Cloudflare account ID override.",
			},
			"secrets_store_id": {
				Type:        framework.TypeString,
				Description: "Cloudflare Secrets Store ID override.",
			},
			"scopes": {
				Type:        framework.TypeCommaStringSlice,
				Description: "Cloudflare Secrets Store scopes override.",
			},
			"split": {
				Type:        framework.TypeString,
				Description: "Chunking mode: auto, true, or false.",
				Default:     "auto",
			},
			"chunk_size_bytes": {
				Type:        framework.TypeInt,
				Description: "Rule-specific chunk size override.",
			},
			"max_parts": {
				Type:        framework.TypeInt,
				Description: "Rule-specific maximum chunk count override.",
			},
			"encoding": {
				Type:        framework.TypeString,
				Description: "Secret payload encoding: raw or base64.",
				Default:     "raw",
			},
			"enabled": {
				Type:        framework.TypeBool,
				Description: "Whether this sync rule is enabled.",
				Default:     true,
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.CreateOperation: &framework.PathOperation{Callback: b.pathSyncRulesWrite},
			logical.UpdateOperation: &framework.PathOperation{Callback: b.pathSyncRulesWrite},
			logical.ReadOperation:   &framework.PathOperation{Callback: b.pathSyncRulesRead},
			logical.DeleteOperation: &framework.PathOperation{Callback: b.pathSyncRulesDelete},
		},
		HelpSynopsis:    "Manage an explicit sync rule.",
		HelpDescription: "Stores a rule describing how a Vault KV v2 secret should be written to Cloudflare Secrets Store.",
	}
}

func (b *cloudflareBackend) pathSyncRulesWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	rule := &syncRule{
		Name:           data.Get("name").(string),
		VaultMount:     data.Get("vault_mount").(string),
		VaultPath:      data.Get("vault_path").(string),
		VaultField:     data.Get("vault_field").(string),
		CloudflareName: data.Get("cloudflare_name").(string),
		AccountID:      data.Get("account_id").(string),
		SecretsStoreID: data.Get("secrets_store_id").(string),
		Split:          strings.ToLower(data.Get("split").(string)),
		ChunkSizeBytes: data.Get("chunk_size_bytes").(int),
		MaxParts:       data.Get("max_parts").(int),
		Encoding:       strings.ToLower(data.Get("encoding").(string)),
		Enabled:        data.Get("enabled").(bool),
	}
	if scopes, ok := data.GetOk("scopes"); ok {
		rule.Scopes = scopes.([]string)
	}

	if err := rule.validate(); err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}

	entry, err := logical.StorageEntryJSON(syncRuleStoragePath(rule.Name), rule)
	if err != nil {
		return nil, err
	}
	return nil, req.Storage.Put(ctx, entry)
}

func (b *cloudflareBackend) pathSyncRulesRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	rule, err := readSyncRule(ctx, req.Storage, data.Get("name").(string))
	if err != nil || rule == nil {
		return nil, err
	}
	return &logical.Response{Data: rule.toResponseData()}, nil
}

func (b *cloudflareBackend) pathSyncRulesDelete(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	return nil, req.Storage.Delete(ctx, syncRuleStoragePath(data.Get("name").(string)))
}

func (b *cloudflareBackend) pathSyncRulesListRead(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	names, err := req.Storage.List(ctx, syncRuleStoragePrefix)
	if err != nil {
		return nil, err
	}
	return logical.ListResponse(names), nil
}

func readSyncRule(ctx context.Context, storage logical.Storage, name string) (*syncRule, error) {
	entry, err := storage.Get(ctx, syncRuleStoragePath(name))
	if err != nil || entry == nil {
		return nil, err
	}
	var rule syncRule
	if err := entry.DecodeJSON(&rule); err != nil {
		return nil, err
	}
	return &rule, nil
}

func readAllSyncRules(ctx context.Context, storage logical.Storage) ([]*syncRule, error) {
	names, err := storage.List(ctx, syncRuleStoragePrefix)
	if err != nil {
		return nil, err
	}
	rules := make([]*syncRule, 0, len(names))
	for _, name := range names {
		rule, err := readSyncRule(ctx, storage, name)
		if err != nil {
			return nil, err
		}
		if rule != nil {
			rules = append(rules, rule)
		}
	}
	return rules, nil
}

func syncRuleStoragePath(name string) string {
	return syncRuleStoragePrefix + name
}

func (r *syncRule) validate() error {
	if strings.TrimSpace(r.Name) == "" {
		return errors.New("rule name is required")
	}
	if strings.ContainsAny(r.Name, " /") {
		return errors.New("rule name must not contain spaces or slashes")
	}
	if strings.TrimSpace(r.VaultMount) == "" {
		return errors.New("vault_mount is required")
	}
	if strings.TrimSpace(r.VaultPath) == "" {
		return errors.New("vault_path is required")
	}
	if strings.TrimSpace(r.CloudflareName) == "" {
		return errors.New("cloudflare_name is required")
	}
	if strings.Contains(r.CloudflareName, " ") {
		return errors.New("cloudflare_name must not contain spaces")
	}
	if r.Split != "auto" && r.Split != "true" && r.Split != "false" {
		return fmt.Errorf("split must be one of auto, true, or false")
	}
	if r.Encoding != "raw" && r.Encoding != "base64" {
		return fmt.Errorf("encoding must be one of raw or base64")
	}
	if r.ChunkSizeBytes < 0 {
		return errors.New("chunk_size_bytes must not be negative")
	}
	if r.MaxParts < 0 {
		return errors.New("max_parts must not be negative")
	}
	return nil
}

func (r *syncRule) toResponseData() map[string]interface{} {
	return map[string]interface{}{
		"name":             r.Name,
		"vault_mount":      r.VaultMount,
		"vault_path":       r.VaultPath,
		"vault_field":      r.VaultField,
		"cloudflare_name":  r.CloudflareName,
		"account_id":       r.AccountID,
		"secrets_store_id": r.SecretsStoreID,
		"scopes":           r.Scopes,
		"split":            r.Split,
		"chunk_size_bytes": r.ChunkSizeBytes,
		"max_parts":        r.MaxParts,
		"encoding":         r.Encoding,
		"enabled":          r.Enabled,
	}
}
