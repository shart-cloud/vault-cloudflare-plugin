package plugin

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	tokenRoleStoragePrefix   = "token/roles/"
	defaultTokenNameTemplate = "vault-{{role}}-{{display_name}}-{{unix_time}}-{{random}}"
)

type tokenRole struct {
	Name             string                 `json:"name"`
	AccountID        string                 `json:"account_id,omitempty"`
	TokenType        string                 `json:"token_type"`
	PermissionGroups []string               `json:"permission_groups"`
	Resources        map[string]interface{} `json:"resources"`
	DefaultTTL       int                    `json:"default_ttl"`
	MaxTTL           int                    `json:"max_ttl"`
	NotBeforeOffset  int                    `json:"not_before_offset,omitempty"`
	IPAllowlist      []string               `json:"ip_allowlist,omitempty"`
	IPDenylist       []string               `json:"ip_denylist,omitempty"`
	NameTemplate     string                 `json:"name_template"`
	Renewable        bool                   `json:"renewable"`
	Enabled          bool                   `json:"enabled"`
}

func (b *cloudflareBackend) pathTokenRolesList() *framework.Path {
	return &framework.Path{
		Pattern: "token/roles/?",
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ListOperation: &framework.PathOperation{Callback: b.pathTokenRolesListRead},
		},
		HelpSynopsis:    "List Cloudflare token roles.",
		HelpDescription: "Lists configured roles used to issue Cloudflare account-owned API tokens.",
	}
}

func (b *cloudflareBackend) pathTokenRoles() *framework.Path {
	return &framework.Path{
		Pattern: "token/roles/" + framework.GenericNameRegex("name"),
		ExistenceCheck: func(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
			return storageEntryExists(ctx, req.Storage, tokenRoleStoragePath(data.Get("name").(string)))
		},
		Fields: map[string]*framework.FieldSchema{
			"name":              {Type: framework.TypeString, Description: "Role name."},
			"account_id":        {Type: framework.TypeString, Description: "Cloudflare account ID override."},
			"token_type":        {Type: framework.TypeString, Default: "account", Description: "Token type. MVP supports account only."},
			"permission_groups": {Type: framework.TypeCommaStringSlice, Description: "Cloudflare permission group IDs."},
			"resources":         {Type: framework.TypeMap, Description: "Cloudflare token policy resources."},
			"default_ttl":       {Type: framework.TypeDurationSecond, Description: "Default token TTL."},
			"max_ttl":           {Type: framework.TypeDurationSecond, Description: "Maximum token TTL."},
			"not_before_offset": {Type: framework.TypeDurationSecond, Description: "Optional not-before offset."},
			"ip_allowlist":      {Type: framework.TypeCommaStringSlice, Description: "Optional CIDR allowlist."},
			"ip_denylist":       {Type: framework.TypeCommaStringSlice, Description: "Optional CIDR denylist."},
			"name_template":     {Type: framework.TypeString, Default: defaultTokenNameTemplate, Description: "Template used for Cloudflare token names."},
			"renewable":         {Type: framework.TypeBool, Default: false, Description: "Whether leases for this role are renewable."},
			"enabled":           {Type: framework.TypeBool, Default: true, Description: "Whether this role can issue tokens."},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.CreateOperation: &framework.PathOperation{Callback: b.pathTokenRolesWrite},
			logical.UpdateOperation: &framework.PathOperation{Callback: b.pathTokenRolesWrite},
			logical.ReadOperation:   &framework.PathOperation{Callback: b.pathTokenRolesRead},
			logical.DeleteOperation: &framework.PathOperation{Callback: b.pathTokenRolesDelete},
		},
		HelpSynopsis:    "Manage a Cloudflare token role.",
		HelpDescription: "Stores policy and TTL settings for leased Cloudflare account-owned API tokens.",
	}
}

func (b *cloudflareBackend) pathTokenRolesWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	role := &tokenRole{
		Name:            data.Get("name").(string),
		AccountID:       data.Get("account_id").(string),
		TokenType:       strings.ToLower(data.Get("token_type").(string)),
		Resources:       data.Get("resources").(map[string]interface{}),
		DefaultTTL:      data.Get("default_ttl").(int),
		MaxTTL:          data.Get("max_ttl").(int),
		NotBeforeOffset: data.Get("not_before_offset").(int),
		NameTemplate:    data.Get("name_template").(string),
		Renewable:       data.Get("renewable").(bool),
		Enabled:         data.Get("enabled").(bool),
	}
	if groups, ok := data.GetOk("permission_groups"); ok {
		role.PermissionGroups = groups.([]string)
	}
	if allow, ok := data.GetOk("ip_allowlist"); ok {
		role.IPAllowlist = allow.([]string)
	}
	if deny, ok := data.GetOk("ip_denylist"); ok {
		role.IPDenylist = deny.([]string)
	}
	if role.NameTemplate == "" {
		role.NameTemplate = defaultTokenNameTemplate
	}

	if err := role.validate(); err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}
	entry, err := logical.StorageEntryJSON(tokenRoleStoragePath(role.Name), role)
	if err != nil {
		return nil, err
	}
	return nil, req.Storage.Put(ctx, entry)
}

func (b *cloudflareBackend) pathTokenRolesRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	role, err := readTokenRole(ctx, req.Storage, data.Get("name").(string))
	if err != nil || role == nil {
		return nil, err
	}
	return &logical.Response{Data: role.toResponseData()}, nil
}

func (b *cloudflareBackend) pathTokenRolesDelete(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	return nil, req.Storage.Delete(ctx, tokenRoleStoragePath(data.Get("name").(string)))
}

func (b *cloudflareBackend) pathTokenRolesListRead(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	names, err := req.Storage.List(ctx, tokenRoleStoragePrefix)
	if err != nil {
		return nil, err
	}
	return logical.ListResponse(names), nil
}

func readTokenRole(ctx context.Context, storage logical.Storage, name string) (*tokenRole, error) {
	entry, err := storage.Get(ctx, tokenRoleStoragePath(name))
	if err != nil || entry == nil {
		return nil, err
	}
	var role tokenRole
	if err := entry.DecodeJSON(&role); err != nil {
		return nil, err
	}
	return &role, nil
}

func tokenRoleStoragePath(name string) string {
	return tokenRoleStoragePrefix + name
}

func (r *tokenRole) validate() error {
	if strings.TrimSpace(r.Name) == "" {
		return errors.New("role name is required")
	}
	if strings.ContainsAny(r.Name, " /") {
		return errors.New("role name must not contain spaces or slashes")
	}
	if r.TokenType != "account" {
		return fmt.Errorf("token_type must be account")
	}
	if len(r.PermissionGroups) == 0 {
		return errors.New("permission_groups must include at least one permission group ID")
	}
	if len(r.Resources) == 0 {
		return errors.New("resources must include at least one Cloudflare resource selector")
	}
	if r.DefaultTTL <= 0 {
		return errors.New("default_ttl must be greater than zero")
	}
	if r.MaxTTL <= 0 {
		return errors.New("max_ttl must be greater than zero")
	}
	if r.DefaultTTL > r.MaxTTL {
		return errors.New("default_ttl must not exceed max_ttl")
	}
	if r.NameTemplate == "" {
		return errors.New("name_template must not be empty")
	}
	return nil
}

func (r *tokenRole) toResponseData() map[string]interface{} {
	return map[string]interface{}{
		"name":              r.Name,
		"account_id":        r.AccountID,
		"token_type":        r.TokenType,
		"permission_groups": r.PermissionGroups,
		"resources":         r.Resources,
		"default_ttl":       r.DefaultTTL,
		"max_ttl":           r.MaxTTL,
		"not_before_offset": r.NotBeforeOffset,
		"ip_allowlist":      r.IPAllowlist,
		"ip_denylist":       r.IPDenylist,
		"name_template":     r.NameTemplate,
		"renewable":         r.Renewable,
		"enabled":           r.Enabled,
	}
}
