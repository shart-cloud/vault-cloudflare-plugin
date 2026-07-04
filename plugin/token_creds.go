package plugin

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	cloudflareTokenSecretType = "cloudflare_account_token"
	tokenStateStoragePrefix   = "state/tokens/"
)

type tokenState struct {
	RoleName  string `json:"role_name"`
	AccountID string `json:"account_id"`
	TokenID   string `json:"token_id"`
	TokenName string `json:"token_name,omitempty"`
	IssuedAt  string `json:"issued_at"`
	ExpiresOn string `json:"expires_on"`
}

func (b *cloudflareBackend) cloudflareTokenSecret() *framework.Secret {
	return &framework.Secret{
		Type: cloudflareTokenSecretType,
		Fields: map[string]*framework.FieldSchema{
			"account_id": {Type: framework.TypeString},
			"token_id":   {Type: framework.TypeString},
			"role_name":  {Type: framework.TypeString},
			"expires_on": {Type: framework.TypeString},
		},
		Renew:  b.pathTokenCredsRenew,
		Revoke: b.pathTokenCredsRevoke,
	}
}

func (b *cloudflareBackend) pathTokenCreds() *framework.Path {
	return &framework.Path{
		Pattern: "token/creds/" + framework.GenericNameRegex("name"),
		Fields: map[string]*framework.FieldSchema{
			"name":         {Type: framework.TypeString, Description: "Role name."},
			"display_name": {Type: framework.TypeString, Description: "Display name inserted into the token name template."},
			"ttl":          {Type: framework.TypeDurationSecond, Description: "Optional requested TTL, capped by role max_ttl."},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{Callback: b.pathTokenCredsWrite},
			logical.ReadOperation:   &framework.PathOperation{Callback: b.pathTokenCredsWrite},
		},
		HelpSynopsis:    "Issue a leased Cloudflare account-owned API token.",
		HelpDescription: "Creates a Cloudflare account token from a configured role and returns the token value once with a Vault lease.",
	}
}

func (b *cloudflareBackend) pathTokenCredsWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	roleName := data.Get("name").(string)
	role, err := readTokenRole(ctx, req.Storage, roleName)
	if err != nil {
		return nil, err
	}
	if role == nil {
		return logical.ErrorResponse("token role %q not found", roleName), nil
	}
	if !role.Enabled {
		return logical.ErrorResponse("token role %q is disabled", roleName), nil
	}

	cfg, err := readCloudflareConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if cfg == nil || cfg.APIToken == "" {
		return logical.ErrorResponse("config/cloudflare must be configured before issuing tokens"), nil
	}
	accountID := firstNonEmpty(role.AccountID, cfg.AccountID)
	if accountID == "" {
		return logical.ErrorResponse("account_id is required on the role or config/cloudflare"), nil
	}

	ttlSeconds := role.DefaultTTL
	if requested, ok := data.GetOk("ttl"); ok && requested.(int) > 0 {
		ttlSeconds = requested.(int)
	}
	if ttlSeconds > role.MaxTTL {
		return logical.ErrorResponse("requested ttl exceeds role max_ttl"), nil
	}

	now := time.Now().UTC()
	randomSuffix, err := randomHex(4)
	if err != nil {
		return nil, err
	}
	expiresOn := now.Add(time.Duration(ttlSeconds) * time.Second).Format(time.RFC3339)
	tokenName := renderTokenName(role.NameTemplate, roleName, data.Get("display_name").(string), now, randomSuffix)
	request := cloudflareAPITokenCreateRequest{
		Name:      tokenName,
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
		return nil, err
	}
	if token.ID == "" || token.Value == "" {
		return nil, fmt.Errorf("cloudflare token response missing token id or value")
	}

	state := &tokenState{
		RoleName:  roleName,
		AccountID: accountID,
		TokenID:   token.ID,
		TokenName: tokenName,
		IssuedAt:  now.Format(time.RFC3339),
		ExpiresOn: expiresOn,
	}
	if err := writeTokenState(ctx, req.Storage, token.ID, state); err != nil {
		return nil, err
	}

	resp := b.Secret(cloudflareTokenSecretType).Response(map[string]interface{}{
		"token":      token.Value,
		"token_id":   token.ID,
		"account_id": accountID,
		"expires_on": expiresOn,
	}, map[string]interface{}{
		"account_id": accountID,
		"token_id":   token.ID,
		"role_name":  roleName,
		"token_name": tokenName,
		"expires_on": expiresOn,
	})
	resp.Secret.TTL = time.Duration(ttlSeconds) * time.Second
	resp.Secret.MaxTTL = time.Duration(role.MaxTTL) * time.Second
	resp.Secret.Renewable = role.Renewable
	if request.NotBefore != "" {
		resp.Data["not_before"] = request.NotBefore
	}
	return resp, nil
}

func (b *cloudflareBackend) pathTokenCredsRenew(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	if req.Secret == nil {
		return nil, fmt.Errorf("missing secret metadata")
	}
	accountID, _ := req.Secret.InternalData["account_id"].(string)
	tokenID, _ := req.Secret.InternalData["token_id"].(string)
	roleName, _ := req.Secret.InternalData["role_name"].(string)
	tokenName, _ := req.Secret.InternalData["token_name"].(string)
	if accountID == "" || tokenID == "" || roleName == "" {
		return nil, fmt.Errorf("missing account_id, token_id, or role_name in lease metadata")
	}

	role, err := readTokenRole(ctx, req.Storage, roleName)
	if err != nil {
		return nil, err
	}
	if role == nil {
		return logical.ErrorResponse("token role %q not found", roleName), nil
	}
	if !role.Enabled {
		return logical.ErrorResponse("token role %q is disabled", roleName), nil
	}
	if !role.Renewable {
		return logical.ErrorResponse("token role %q is not renewable", roleName), nil
	}
	cfg, err := readCloudflareConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if cfg == nil || cfg.APIToken == "" {
		return logical.ErrorResponse("config/cloudflare must be configured before renewing tokens"), nil
	}
	state, err := readTokenState(ctx, req.Storage, tokenID)
	if err != nil {
		return nil, err
	}
	if state != nil && state.TokenName != "" {
		tokenName = state.TokenName
	}
	if tokenName == "" {
		tokenName = "vault-" + roleName + "-" + tokenID
	}

	now := time.Now().UTC()
	ttl := req.Secret.Increment
	if ttl <= 0 {
		ttl = time.Duration(role.DefaultTTL) * time.Second
	}
	if ttl > time.Duration(role.MaxTTL)*time.Second {
		ttl = time.Duration(role.MaxTTL) * time.Second
	}
	if !req.Secret.IssueTime.IsZero() {
		remaining := req.Secret.IssueTime.Add(time.Duration(role.MaxTTL) * time.Second).Sub(now)
		if remaining <= 0 {
			return logical.ErrorResponse("lease has reached role max_ttl"), nil
		}
		if ttl > remaining {
			ttl = remaining
		}
	}

	expiresOn := now.Add(ttl).Format(time.RFC3339)
	request := cloudflareAPITokenCreateRequest{
		Name:      tokenName,
		Policies:  []cloudflareAPITokenPolicy{role.toCloudflarePolicy()},
		ExpiresOn: expiresOn,
	}
	if role.NotBeforeOffset > 0 {
		request.NotBefore = now.Add(time.Duration(role.NotBeforeOffset) * time.Second).Format(time.RFC3339)
	}
	if len(role.IPAllowlist) > 0 || len(role.IPDenylist) > 0 {
		request.Condition = &cloudflareAPITokenCondition{RequestIP: &cloudflareAPITokenIPCondition{In: role.IPAllowlist, NotIn: role.IPDenylist}}
	}
	if _, err := newCloudflareClient(cfg, b.httpClient).updateAccountToken(ctx, accountID, tokenID, request); err != nil {
		return nil, err
	}

	if state == nil {
		state = &tokenState{RoleName: roleName, AccountID: accountID, TokenID: tokenID, TokenName: tokenName}
	}
	state.ExpiresOn = expiresOn
	if err := writeTokenState(ctx, req.Storage, tokenID, state); err != nil {
		return nil, err
	}

	resp := &logical.Response{Secret: req.Secret}
	resp.Secret.TTL = ttl
	resp.Secret.MaxTTL = time.Duration(role.MaxTTL) * time.Second
	resp.Secret.Renewable = true
	resp.Secret.InternalData["expires_on"] = expiresOn
	return resp, nil
}

func (b *cloudflareBackend) pathTokenCredsRevoke(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	if req.Secret == nil {
		return nil, fmt.Errorf("missing secret metadata")
	}
	accountID, _ := req.Secret.InternalData["account_id"].(string)
	tokenID, _ := req.Secret.InternalData["token_id"].(string)
	if accountID == "" || tokenID == "" {
		return nil, fmt.Errorf("missing account_id or token_id in lease metadata")
	}
	cfg, err := readCloudflareConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if cfg == nil || cfg.APIToken == "" {
		return nil, fmt.Errorf("config/cloudflare must be configured before revoking tokens")
	}
	if err := newCloudflareClient(cfg, b.httpClient).deleteAccountToken(ctx, accountID, tokenID); err != nil {
		return nil, err
	}
	return nil, req.Storage.Delete(ctx, tokenStateStoragePrefix+tokenID)
}

func (r *tokenRole) toCloudflarePolicy() cloudflareAPITokenPolicy {
	groups := make([]map[string]string, 0, len(r.PermissionGroups))
	for _, id := range r.PermissionGroups {
		groups = append(groups, map[string]string{"id": id})
	}
	return cloudflareAPITokenPolicy{
		Effect:           "allow",
		PermissionGroups: groups,
		Resources:        r.Resources,
	}
}

func renderTokenName(template, roleName, displayName string, now time.Time, randomSuffix string) string {
	if displayName == "" {
		displayName = "default"
	}
	replacer := strings.NewReplacer(
		"{{role}}", roleName,
		"{{display_name}}", sanitizeTokenNamePart(displayName),
		"{{unix_time}}", fmt.Sprintf("%d", now.Unix()),
		"{{timestamp}}", now.Format(time.RFC3339),
		"{{random}}", randomSuffix,
	)
	return replacer.Replace(template)
}

func randomHex(bytesLen int) (string, error) {
	value := make([]byte, bytesLen)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return hex.EncodeToString(value), nil
}

func sanitizeTokenNamePart(value string) string {
	value = strings.TrimSpace(value)
	value = strings.ReplaceAll(value, " ", "-")
	if value == "" {
		return "default"
	}
	return value
}

func writeTokenState(ctx context.Context, storage logical.Storage, tokenID string, state *tokenState) error {
	entry, err := logical.StorageEntryJSON(tokenStateStoragePrefix+tokenID, state)
	if err != nil {
		return err
	}
	return storage.Put(ctx, entry)
}

func readTokenState(ctx context.Context, storage logical.Storage, tokenID string) (*tokenState, error) {
	entry, err := storage.Get(ctx, tokenStateStoragePrefix+tokenID)
	if err != nil || entry == nil {
		return nil, err
	}
	var state tokenState
	if err := entry.DecodeJSON(&state); err != nil {
		return nil, err
	}
	return &state, nil
}
