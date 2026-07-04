package plugin

import (
	"context"
	"strings"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func (b *cloudflareBackend) pathTokenPermissionGroups() *framework.Path {
	return &framework.Path{
		Pattern: "token/permission-groups",
		Fields: map[string]*framework.FieldSchema{
			"account_id": {Type: framework.TypeString, Description: "Cloudflare account ID override."},
			"name":       {Type: framework.TypeString, Description: "Optional case-insensitive name substring filter."},
			"scope":      {Type: framework.TypeString, Description: "Optional scope filter."},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{Callback: b.pathTokenPermissionGroupsRead},
		},
		HelpSynopsis:    "Discover Cloudflare token permission groups.",
		HelpDescription: "Lists Cloudflare account token permission groups, optionally filtered by name or scope.",
	}
}

func (b *cloudflareBackend) pathTokenPermissionGroupsRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	cfg, err := readCloudflareConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if cfg == nil || cfg.APIToken == "" {
		return logical.ErrorResponse("config/cloudflare must be configured before permission group discovery"), nil
	}
	accountID := firstNonEmpty(data.Get("account_id").(string), cfg.AccountID)
	if accountID == "" {
		return logical.ErrorResponse("account_id is required on the request or config/cloudflare"), nil
	}

	groups, err := newCloudflareClient(cfg, b.httpClient).listPermissionGroups(ctx, accountID)
	if err != nil {
		return nil, err
	}
	nameFilter := strings.ToLower(data.Get("name").(string))
	scopeFilter := data.Get("scope").(string)
	results := make([]map[string]interface{}, 0, len(groups))
	for _, group := range groups {
		if nameFilter != "" && !strings.Contains(strings.ToLower(group.Name), nameFilter) {
			continue
		}
		if scopeFilter != "" && !containsString(group.Scopes, scopeFilter) {
			continue
		}
		results = append(results, map[string]interface{}{
			"id":     group.ID,
			"name":   group.Name,
			"scopes": group.Scopes,
		})
	}
	return &logical.Response{Data: map[string]interface{}{"permission_groups": results}}, nil
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
