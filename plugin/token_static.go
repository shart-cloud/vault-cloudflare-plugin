package plugin

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const staticTokenStoragePrefix = "token/static/"

type staticToken struct {
	Name        string `json:"name"`
	Token       string `json:"token"`
	AccountID   string `json:"account_id,omitempty"`
	TokenID     string `json:"token_id,omitempty"`
	RoleName    string `json:"role_name,omitempty"`
	Managed     bool   `json:"managed,omitempty"`
	CreatedAt   string `json:"created_at,omitempty"`
	ExpiresOn   string `json:"expires_on,omitempty"`
	DeleteOnTTL bool   `json:"delete_cloudflare_token_on_delete,omitempty"`
}

func (b *cloudflareBackend) pathStaticTokensList() *framework.Path {
	return &framework.Path{
		Pattern: "token/static/?",
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ListOperation: &framework.PathOperation{Callback: b.pathStaticTokensListRead},
		},
		HelpSynopsis:    "List named static Cloudflare API tokens.",
		HelpDescription: "Lists static token names stored by this mount.",
	}
}

func (b *cloudflareBackend) pathStaticTokens() *framework.Path {
	return &framework.Path{
		Pattern: "token/static/" + framework.GenericNameRegex("name"),
		ExistenceCheck: func(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
			return storageEntryExists(ctx, req.Storage, staticTokenStoragePath(data.Get("name").(string)))
		},
		Fields: map[string]*framework.FieldSchema{
			"name":         {Type: framework.TypeString, Description: "Static token name."},
			"token":        {Type: framework.TypeString, Description: "Existing Cloudflare API token value.", DisplayAttrs: &framework.DisplayAttributes{Sensitive: true}},
			"role":         {Type: framework.TypeString, Description: "Optional token role used to create and store a Cloudflare account token."},
			"ttl":          {Type: framework.TypeDurationSecond, Description: "Optional TTL for role-created static tokens."},
			"display_name": {Type: framework.TypeString, Description: "Display name inserted into the role token name template."},
			"account_id":   {Type: framework.TypeString, Description: "Cloudflare account ID for existing static token metadata."},
			"token_id":     {Type: framework.TypeString, Description: "Cloudflare token ID for existing static token metadata."},
			"expires_on":   {Type: framework.TypeString, Description: "Optional expiration timestamp for existing static token metadata."},
			"delete_cloudflare_token_on_delete": {
				Type:        framework.TypeBool,
				Description: "Delete the Cloudflare token when deleting this static token entry.",
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.CreateOperation: &framework.PathOperation{Callback: b.pathStaticTokensWrite},
			logical.UpdateOperation: &framework.PathOperation{Callback: b.pathStaticTokensWrite},
			logical.ReadOperation:   &framework.PathOperation{Callback: b.pathStaticTokensRead},
			logical.DeleteOperation: &framework.PathOperation{Callback: b.pathStaticTokensDelete},
		},
		HelpSynopsis:    "Manage a named static Cloudflare API token.",
		HelpDescription: "Stores an existing token value or creates one from a role and stores it for stable retrieval.",
	}
}

func (b *cloudflareBackend) pathStaticTokensWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	name := data.Get("name").(string)
	roleName := data.Get("role").(string)
	tokenValue := data.Get("token").(string)
	if name == "" {
		return logical.ErrorResponse("name is required"), nil
	}
	if roleName == "" && tokenValue == "" {
		return logical.ErrorResponse("token or role is required"), nil
	}
	if roleName != "" && tokenValue != "" {
		return logical.ErrorResponse("token and role are mutually exclusive"), nil
	}

	entry := &staticToken{
		Name:        name,
		Token:       tokenValue,
		AccountID:   data.Get("account_id").(string),
		TokenID:     data.Get("token_id").(string),
		ExpiresOn:   data.Get("expires_on").(string),
		DeleteOnTTL: data.Get("delete_cloudflare_token_on_delete").(bool),
		CreatedAt:   time.Now().UTC().Format(time.RFC3339),
	}
	if roleName != "" {
		created, errResp, err := b.createStaticTokenFromRole(ctx, req, data, roleName)
		if err != nil || errResp != nil {
			return errResp, err
		}
		entry = created
		entry.Name = name
		entry.DeleteOnTTL = data.Get("delete_cloudflare_token_on_delete").(bool)
	}

	storageEntry, err := logical.StorageEntryJSON(staticTokenStoragePath(name), entry)
	if err != nil {
		return nil, err
	}
	return nil, req.Storage.Put(ctx, storageEntry)
}

func (b *cloudflareBackend) createStaticTokenFromRole(ctx context.Context, req *logical.Request, data *framework.FieldData, roleName string) (*staticToken, *logical.Response, error) {
	role, err := readTokenRole(ctx, req.Storage, roleName)
	if err != nil {
		return nil, nil, err
	}
	if role == nil {
		return nil, logical.ErrorResponse("token role %q not found", roleName), nil
	}
	if !role.Enabled {
		return nil, logical.ErrorResponse("token role %q is disabled", roleName), nil
	}
	cfg, err := readCloudflareConfig(ctx, req.Storage)
	if err != nil {
		return nil, nil, err
	}
	if cfg == nil || cfg.APIToken == "" {
		return nil, logical.ErrorResponse("config/cloudflare must be configured before creating static role tokens"), nil
	}
	accountID := firstNonEmpty(role.AccountID, cfg.AccountID)
	if accountID == "" {
		return nil, logical.ErrorResponse("account_id is required on the role or config/cloudflare"), nil
	}
	ttlSeconds := role.DefaultTTL
	if requested, ok := data.GetOk("ttl"); ok && requested.(int) > 0 {
		ttlSeconds = requested.(int)
	}
	if ttlSeconds > role.MaxTTL {
		return nil, logical.ErrorResponse("requested ttl exceeds role max_ttl"), nil
	}

	now := time.Now().UTC()
	randomSuffix, err := randomHex(4)
	if err != nil {
		return nil, nil, err
	}
	expiresOn := now.Add(time.Duration(ttlSeconds) * time.Second).Format(time.RFC3339)
	request := cloudflareAPITokenCreateRequest{
		Name:      renderTokenName(role.NameTemplate, roleName, data.Get("display_name").(string), now, randomSuffix),
		Policies:  []cloudflareAPITokenPolicy{role.toCloudflarePolicy()},
		ExpiresOn: expiresOn,
	}
	if role.NotBeforeOffset > 0 {
		request.NotBefore = now.Add(time.Duration(role.NotBeforeOffset) * time.Second).Format(time.RFC3339)
	}
	if len(role.IPAllowlist) > 0 || len(role.IPDenylist) > 0 {
		request.Condition = &cloudflareAPITokenCondition{RequestIP: &cloudflareAPITokenIPCondition{In: role.IPAllowlist, NotIn: role.IPDenylist}}
	}
	token, err := newCloudflareClient(cfg, b.httpClient).createAccountToken(ctx, accountID, request)
	if err != nil {
		return nil, nil, err
	}
	if token.ID == "" || token.Value == "" {
		return nil, nil, fmt.Errorf("cloudflare token response missing token id or value")
	}
	return &staticToken{
		Token:     token.Value,
		AccountID: accountID,
		TokenID:   token.ID,
		RoleName:  roleName,
		Managed:   true,
		CreatedAt: now.Format(time.RFC3339),
		ExpiresOn: firstNonEmpty(token.ExpiresOn, expiresOn),
	}, nil, nil
}

func (b *cloudflareBackend) pathStaticTokensRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	entry, err := readStaticToken(ctx, req.Storage, data.Get("name").(string))
	if err != nil || entry == nil {
		return nil, err
	}
	return &logical.Response{Data: map[string]interface{}{
		"name":                              entry.Name,
		"token":                             entry.Token,
		"account_id":                        entry.AccountID,
		"token_id":                          entry.TokenID,
		"role":                              entry.RoleName,
		"managed":                           entry.Managed,
		"created_at":                        entry.CreatedAt,
		"expires_on":                        entry.ExpiresOn,
		"delete_cloudflare_token_on_delete": entry.DeleteOnTTL,
	}}, nil
}

func (b *cloudflareBackend) pathStaticTokensDelete(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	name := data.Get("name").(string)
	entry, err := readStaticToken(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}
	if entry != nil && entry.DeleteOnTTL && entry.AccountID != "" && entry.TokenID != "" {
		cfg, err := readCloudflareConfig(ctx, req.Storage)
		if err != nil {
			return nil, err
		}
		if cfg == nil || cfg.APIToken == "" {
			return logical.ErrorResponse("config/cloudflare must be configured before deleting Cloudflare static tokens"), nil
		}
		if err := newCloudflareClient(cfg, b.httpClient).deleteAccountToken(ctx, entry.AccountID, entry.TokenID); err != nil {
			return nil, err
		}
	}
	return nil, req.Storage.Delete(ctx, staticTokenStoragePath(name))
}

func (b *cloudflareBackend) pathStaticTokensListRead(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	names, err := req.Storage.List(ctx, staticTokenStoragePrefix)
	if err != nil {
		return nil, err
	}
	return logical.ListResponse(names), nil
}

func readStaticToken(ctx context.Context, storage logical.Storage, name string) (*staticToken, error) {
	entry, err := storage.Get(ctx, staticTokenStoragePath(name))
	if err != nil || entry == nil {
		return nil, err
	}
	var token staticToken
	if err := entry.DecodeJSON(&token); err != nil {
		return nil, err
	}
	return &token, nil
}

func readAllStaticTokens(ctx context.Context, storage logical.Storage) (map[string]*staticToken, error) {
	names, err := storage.List(ctx, staticTokenStoragePrefix)
	if err != nil {
		return nil, err
	}
	tokens := make(map[string]*staticToken, len(names))
	for _, name := range names {
		token, err := readStaticToken(ctx, storage, name)
		if err != nil {
			return nil, err
		}
		if token != nil && token.TokenID != "" {
			tokens[token.TokenID] = token
		}
	}
	return tokens, nil
}

func staticTokenStoragePath(name string) string {
	return staticTokenStoragePrefix + name
}
