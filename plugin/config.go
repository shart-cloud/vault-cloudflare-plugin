package plugin

import (
	"context"
	"errors"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	cloudflareConfigStoragePath = "config/cloudflare"
	syncConfigStoragePath       = "config/sync"

	defaultCloudflareBaseURL    = "https://api.cloudflare.com/client/v4"
	cloudflareSecretValueLimit  = 1024
	defaultChunkSizeBytes       = 760
	defaultMaxParts             = 3
	defaultManagedCommentPrefix = "managed-by=vault-cloudflare"
)

type cloudflareConfig struct {
	APIToken       string `json:"api_token"`
	AccountID      string `json:"account_id"`
	SecretsStoreID string `json:"secrets_store_id"`
	BaseURL        string `json:"base_url"`
}

type syncConfig struct {
	DefaultScopes         []string `json:"default_scopes"`
	DefaultChunkSizeBytes int      `json:"default_chunk_size_bytes"`
	MaxParts              int      `json:"max_parts"`
	NamePrefix            string   `json:"name_prefix"`
	NameSuffix            string   `json:"name_suffix"`
	DeleteRemovedParts    bool     `json:"delete_removed_parts"`
	ManagedCommentPrefix  string   `json:"managed_comment_prefix"`
}

func (b *cloudflareBackend) pathConfigCloudflare() *framework.Path {
	return &framework.Path{
		Pattern: "config/cloudflare",
		ExistenceCheck: func(ctx context.Context, req *logical.Request, _ *framework.FieldData) (bool, error) {
			return storageEntryExists(ctx, req.Storage, cloudflareConfigStoragePath)
		},
		Fields: map[string]*framework.FieldSchema{
			"api_token": {
				Type:        framework.TypeString,
				Description: "Bootstrap Cloudflare API token.",
				DisplayAttrs: &framework.DisplayAttributes{
					Sensitive: true,
				},
			},
			"account_id": {
				Type:        framework.TypeString,
				Description: "Default Cloudflare account ID.",
			},
			"secrets_store_id": {
				Type:        framework.TypeString,
				Description: "Default Cloudflare Secrets Store ID.",
			},
			"base_url": {
				Type:        framework.TypeString,
				Description: "Cloudflare API base URL.",
				Default:     defaultCloudflareBaseURL,
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.CreateOperation: &framework.PathOperation{Callback: b.pathConfigCloudflareWrite},
			logical.UpdateOperation: &framework.PathOperation{Callback: b.pathConfigCloudflareWrite},
			logical.ReadOperation:   &framework.PathOperation{Callback: b.pathConfigCloudflareRead},
			logical.DeleteOperation: &framework.PathOperation{Callback: b.pathConfigCloudflareDelete},
		},
		HelpSynopsis:    "Configure Cloudflare API access.",
		HelpDescription: "Stores bootstrap Cloudflare API configuration. The API token is never returned by reads.",
	}
}

func (b *cloudflareBackend) pathConfigCloudflareWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	cfg, err := readCloudflareConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if cfg == nil {
		cfg = &cloudflareConfig{}
	}

	if apiToken, ok := data.GetOk("api_token"); ok {
		cfg.APIToken = apiToken.(string)
	}
	if cfg.APIToken == "" {
		return logical.ErrorResponse("api_token is required"), nil
	}

	cfg.AccountID = data.Get("account_id").(string)
	cfg.SecretsStoreID = data.Get("secrets_store_id").(string)
	cfg.BaseURL = data.Get("base_url").(string)
	if cfg.BaseURL == "" {
		cfg.BaseURL = defaultCloudflareBaseURL
	}

	entry, err := logical.StorageEntryJSON(cloudflareConfigStoragePath, cfg)
	if err != nil {
		return nil, err
	}
	return nil, req.Storage.Put(ctx, entry)
}

func (b *cloudflareBackend) pathConfigCloudflareRead(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	cfg, err := readCloudflareConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if cfg == nil {
		return &logical.Response{Data: map[string]interface{}{
			"configured":       false,
			"api_token_set":    false,
			"account_id":       "",
			"secrets_store_id": "",
			"base_url":         defaultCloudflareBaseURL,
		}}, nil
	}

	return &logical.Response{Data: map[string]interface{}{
		"configured":       cfg.APIToken != "",
		"api_token_set":    cfg.APIToken != "",
		"account_id":       cfg.AccountID,
		"secrets_store_id": cfg.SecretsStoreID,
		"base_url":         cfg.BaseURL,
	}}, nil
}

func (b *cloudflareBackend) pathConfigCloudflareDelete(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	return nil, req.Storage.Delete(ctx, cloudflareConfigStoragePath)
}

func (b *cloudflareBackend) pathConfigSync() *framework.Path {
	return &framework.Path{
		Pattern: "config/sync",
		ExistenceCheck: func(ctx context.Context, req *logical.Request, _ *framework.FieldData) (bool, error) {
			return storageEntryExists(ctx, req.Storage, syncConfigStoragePath)
		},
		Fields: map[string]*framework.FieldSchema{
			"default_scopes": {
				Type:        framework.TypeCommaStringSlice,
				Description: "Default Cloudflare Secrets Store scopes.",
			},
			"default_chunk_size_bytes": {
				Type:        framework.TypeInt,
				Description: "Default maximum payload size per Cloudflare secret entry.",
				Default:     defaultChunkSizeBytes,
			},
			"max_parts": {
				Type:        framework.TypeInt,
				Description: "Default maximum number of chunks for split secrets.",
				Default:     defaultMaxParts,
			},
			"name_prefix": {
				Type:        framework.TypeString,
				Description: "Optional prefix added to Cloudflare secret names.",
			},
			"name_suffix": {
				Type:        framework.TypeString,
				Description: "Optional suffix added to Cloudflare secret names.",
			},
			"delete_removed_parts": {
				Type:        framework.TypeBool,
				Description: "Delete stale Cloudflare chunk entries after successful sync.",
				Default:     true,
			},
			"managed_comment_prefix": {
				Type:        framework.TypeString,
				Description: "Comment prefix used to identify Cloudflare secrets managed by this plugin.",
				Default:     defaultManagedCommentPrefix,
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.CreateOperation: &framework.PathOperation{Callback: b.pathConfigSyncWrite},
			logical.UpdateOperation: &framework.PathOperation{Callback: b.pathConfigSyncWrite},
			logical.ReadOperation:   &framework.PathOperation{Callback: b.pathConfigSyncRead},
			logical.DeleteOperation: &framework.PathOperation{Callback: b.pathConfigSyncDelete},
		},
		HelpSynopsis:    "Configure default sync behavior.",
		HelpDescription: "Stores defaults used by explicit sync rules and future discovery rules.",
	}
}

func (b *cloudflareBackend) pathConfigSyncWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	cfg := defaultSyncConfig()

	if scopes, ok := data.GetOk("default_scopes"); ok {
		cfg.DefaultScopes = scopes.([]string)
	}
	cfg.DefaultChunkSizeBytes = data.Get("default_chunk_size_bytes").(int)
	cfg.MaxParts = data.Get("max_parts").(int)
	cfg.NamePrefix = data.Get("name_prefix").(string)
	cfg.NameSuffix = data.Get("name_suffix").(string)
	cfg.DeleteRemovedParts = data.Get("delete_removed_parts").(bool)
	cfg.ManagedCommentPrefix = data.Get("managed_comment_prefix").(string)

	if err := cfg.validate(); err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}

	entry, err := logical.StorageEntryJSON(syncConfigStoragePath, cfg)
	if err != nil {
		return nil, err
	}
	return nil, req.Storage.Put(ctx, entry)
}

func (b *cloudflareBackend) pathConfigSyncRead(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	cfg, err := readSyncConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if cfg == nil {
		cfg = defaultSyncConfig()
	}

	return &logical.Response{Data: map[string]interface{}{
		"default_scopes":           cfg.DefaultScopes,
		"default_chunk_size_bytes": cfg.DefaultChunkSizeBytes,
		"max_parts":                cfg.MaxParts,
		"name_prefix":              cfg.NamePrefix,
		"name_suffix":              cfg.NameSuffix,
		"delete_removed_parts":     cfg.DeleteRemovedParts,
		"managed_comment_prefix":   cfg.ManagedCommentPrefix,
	}}, nil
}

func (b *cloudflareBackend) pathConfigSyncDelete(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	return nil, req.Storage.Delete(ctx, syncConfigStoragePath)
}

func readCloudflareConfig(ctx context.Context, storage logical.Storage) (*cloudflareConfig, error) {
	entry, err := storage.Get(ctx, cloudflareConfigStoragePath)
	if err != nil || entry == nil {
		return nil, err
	}
	var cfg cloudflareConfig
	if err := entry.DecodeJSON(&cfg); err != nil {
		return nil, err
	}
	if cfg.BaseURL == "" {
		cfg.BaseURL = defaultCloudflareBaseURL
	}
	return &cfg, nil
}

func storageEntryExists(ctx context.Context, storage logical.Storage, path string) (bool, error) {
	entry, err := storage.Get(ctx, path)
	if err != nil {
		return false, err
	}
	return entry != nil, nil
}

func readSyncConfig(ctx context.Context, storage logical.Storage) (*syncConfig, error) {
	entry, err := storage.Get(ctx, syncConfigStoragePath)
	if err != nil || entry == nil {
		return nil, err
	}
	var cfg syncConfig
	if err := entry.DecodeJSON(&cfg); err != nil {
		return nil, err
	}
	if len(cfg.DefaultScopes) == 0 {
		cfg.DefaultScopes = []string{"workers"}
	}
	if cfg.DefaultChunkSizeBytes == 0 {
		cfg.DefaultChunkSizeBytes = defaultChunkSizeBytes
	}
	if cfg.MaxParts == 0 {
		cfg.MaxParts = defaultMaxParts
	}
	if cfg.ManagedCommentPrefix == "" {
		cfg.ManagedCommentPrefix = defaultManagedCommentPrefix
	}
	return &cfg, nil
}

func defaultSyncConfig() *syncConfig {
	return &syncConfig{
		DefaultScopes:         []string{"workers"},
		DefaultChunkSizeBytes: defaultChunkSizeBytes,
		MaxParts:              defaultMaxParts,
		DeleteRemovedParts:    true,
		ManagedCommentPrefix:  defaultManagedCommentPrefix,
	}
}

func (c *syncConfig) validate() error {
	if len(c.DefaultScopes) == 0 {
		return errors.New("default_scopes must include at least one scope")
	}
	if c.DefaultChunkSizeBytes <= 0 {
		return errors.New("default_chunk_size_bytes must be greater than zero")
	}
	if c.MaxParts <= 0 {
		return errors.New("max_parts must be greater than zero")
	}
	if c.ManagedCommentPrefix == "" {
		return errors.New("managed_comment_prefix must not be empty")
	}
	return nil
}
