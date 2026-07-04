package plugin

import (
	"context"
	"sort"
	"strings"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const tokenManagedNamePrefix = "vault-"

func (b *cloudflareBackend) pathTokenReconcile() *framework.Path {
	return &framework.Path{
		Pattern: "token/reconcile",
		Fields: map[string]*framework.FieldSchema{
			"dry_run": {
				Type:        framework.TypeBool,
				Default:     true,
				Description: "Report token drift without deleting orphaned Cloudflare tokens.",
			},
			"delete_orphans": {
				Type:        framework.TypeBool,
				Description: "Delete plugin-managed Cloudflare tokens with no matching Vault state. Requires dry_run=false.",
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{Callback: b.pathTokenReconcileWrite},
			logical.ReadOperation:   &framework.PathOperation{Callback: b.pathTokenReconcileWrite},
		},
		HelpSynopsis:    "Reconcile Cloudflare account tokens with Vault token state.",
		HelpDescription: "Reports plugin-managed Cloudflare tokens with no Vault state, expired Cloudflare tokens, and Vault token state whose Cloudflare token is missing.",
	}
}

func (b *cloudflareBackend) pathTokenReconcileWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	dryRun := data.Get("dry_run").(bool)
	deleteOrphans := data.Get("delete_orphans").(bool)
	if deleteOrphans && dryRun {
		return logical.ErrorResponse("delete_orphans requires dry_run=false"), nil
	}

	cfg, err := readCloudflareConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if cfg == nil || cfg.APIToken == "" {
		return logical.ErrorResponse("config/cloudflare must be configured before token reconciliation"), nil
	}

	states, err := readAllTokenStates(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	staticTokens, err := readAllStaticTokens(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	roles, err := readAllTokenRoles(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	accountIDs := tokenReconcileAccountIDs(cfg, states, roles, staticTokens)
	client := newCloudflareClient(cfg, b.httpClient)

	orphaned := []map[string]interface{}{}
	expired := []map[string]interface{}{}
	missing := []map[string]interface{}{}
	deletedOrphans := []string{}
	remoteByAccount := map[string]map[string]cloudflareAPIToken{}
	now := time.Now().UTC()

	for _, accountID := range accountIDs {
		tokens, err := client.listAccountTokens(ctx, accountID)
		if err != nil {
			return nil, err
		}
		byID := make(map[string]cloudflareAPIToken, len(tokens))
		for _, token := range tokens {
			byID[token.ID] = token
			_, hasLeaseState := states[token.ID]
			_, hasStaticState := staticTokens[token.ID]
			hasState := hasLeaseState || hasStaticState
			expiredToken := tokenExpired(token.ExpiresOn, now)
			managed := hasState || isManagedCloudflareToken(token)
			if managed && expiredToken {
				expired = append(expired, tokenReconcileEntry(accountID, token))
			}
			if !hasState && isManagedCloudflareToken(token) && !expiredToken {
				orphaned = append(orphaned, tokenReconcileEntry(accountID, token))
			}
			if !hasState && isManagedCloudflareToken(token) && deleteOrphans {
				if err := client.deleteAccountToken(ctx, accountID, token.ID); err != nil {
					return nil, err
				}
				deletedOrphans = append(deletedOrphans, token.ID)
			}
		}
		remoteByAccount[accountID] = byID
	}

	for tokenID, state := range states {
		if state.AccountID == "" {
			missing = append(missing, map[string]interface{}{"token_id": tokenID, "role": state.RoleName, "account_id": state.AccountID})
			continue
		}
		if _, ok := remoteByAccount[state.AccountID][tokenID]; !ok {
			missing = append(missing, map[string]interface{}{"token_id": tokenID, "role": state.RoleName, "account_id": state.AccountID})
		}
	}
	for tokenID, token := range staticTokens {
		if token.AccountID == "" || token.TokenID == "" {
			continue
		}
		if _, ok := remoteByAccount[token.AccountID][tokenID]; !ok {
			missing = append(missing, map[string]interface{}{"token_id": tokenID, "role": "static:" + token.Name, "account_id": token.AccountID})
		}
	}

	sort.Strings(deletedOrphans)
	return &logical.Response{Data: map[string]interface{}{
		"dry_run":                     dryRun,
		"active_tokens_without_state": orphaned,
		"expired_tokens_present":      expired,
		"missing_cloudflare_tokens":   missing,
		"deleted_orphans":             deletedOrphans,
	}}, nil
}

func readAllTokenStates(ctx context.Context, storage logical.Storage) (map[string]*tokenState, error) {
	names, err := storage.List(ctx, tokenStateStoragePrefix)
	if err != nil {
		return nil, err
	}
	states := make(map[string]*tokenState, len(names))
	for _, name := range names {
		state, err := readTokenState(ctx, storage, name)
		if err != nil {
			return nil, err
		}
		if state != nil {
			states[name] = state
		}
	}
	return states, nil
}

func readAllTokenRoles(ctx context.Context, storage logical.Storage) ([]*tokenRole, error) {
	names, err := storage.List(ctx, tokenRoleStoragePrefix)
	if err != nil {
		return nil, err
	}
	roles := make([]*tokenRole, 0, len(names))
	for _, name := range names {
		role, err := readTokenRole(ctx, storage, name)
		if err != nil {
			return nil, err
		}
		if role != nil {
			roles = append(roles, role)
		}
	}
	return roles, nil
}

func tokenReconcileAccountIDs(cfg *cloudflareConfig, states map[string]*tokenState, roles []*tokenRole, staticTokens map[string]*staticToken) []string {
	seen := map[string]struct{}{}
	if cfg.AccountID != "" {
		seen[cfg.AccountID] = struct{}{}
	}
	for _, state := range states {
		if state.AccountID != "" {
			seen[state.AccountID] = struct{}{}
		}
	}
	for _, role := range roles {
		if role.AccountID != "" {
			seen[role.AccountID] = struct{}{}
		}
	}
	for _, token := range staticTokens {
		if token.AccountID != "" && token.TokenID != "" {
			seen[token.AccountID] = struct{}{}
		}
	}
	ids := make([]string, 0, len(seen))
	for id := range seen {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

func tokenReconcileEntry(accountID string, token cloudflareAPIToken) map[string]interface{} {
	return map[string]interface{}{
		"account_id": accountID,
		"token_id":   token.ID,
		"name":       token.Name,
		"expires_on": token.ExpiresOn,
		"managed":    isManagedCloudflareToken(token),
	}
}

func tokenExpired(expiresOn string, now time.Time) bool {
	if expiresOn == "" {
		return false
	}
	expiresAt, err := time.Parse(time.RFC3339, expiresOn)
	if err != nil {
		return false
	}
	return !expiresAt.After(now)
}

func isManagedCloudflareToken(token cloudflareAPIToken) bool {
	return token.ID != "" && strings.HasPrefix(token.Name, tokenManagedNamePrefix)
}
