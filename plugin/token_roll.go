package plugin

import (
	"context"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func (b *cloudflareBackend) pathTokenRoll() *framework.Path {
	return &framework.Path{
		Pattern: "token/roll/" + framework.GenericNameRegex("token_id"),
		Fields: map[string]*framework.FieldSchema{
			"token_id":   {Type: framework.TypeString, Description: "Cloudflare token ID."},
			"account_id": {Type: framework.TypeString, Description: "Cloudflare account ID override."},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{Callback: b.pathTokenRollWrite},
		},
		HelpSynopsis:    "Roll a Cloudflare API token value.",
		HelpDescription: "Calls Cloudflare to roll an account token value and returns the new token value once.",
	}
}

func (b *cloudflareBackend) pathTokenRollWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	tokenID := data.Get("token_id").(string)
	cfg, err := readCloudflareConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if cfg == nil || cfg.APIToken == "" {
		return logical.ErrorResponse("config/cloudflare must be configured before rolling tokens"), nil
	}
	state, err := readTokenState(ctx, req.Storage, tokenID)
	if err != nil {
		return nil, err
	}
	accountID := firstNonEmpty(data.Get("account_id").(string), cfg.AccountID)
	if state != nil {
		accountID = firstNonEmpty(data.Get("account_id").(string), state.AccountID, cfg.AccountID)
	}
	if accountID == "" {
		return logical.ErrorResponse("account_id is required on the request, token state, or config/cloudflare"), nil
	}
	token, err := newCloudflareClient(cfg, b.httpClient).rollAccountTokenValue(ctx, accountID, tokenID)
	if err != nil {
		return nil, err
	}
	if token.Value == "" {
		return logical.ErrorResponse("cloudflare token roll response missing token value"), nil
	}
	respData := map[string]interface{}{
		"token":      token.Value,
		"token_id":   firstNonEmpty(token.ID, tokenID),
		"account_id": accountID,
	}
	if token.ExpiresOn != "" {
		respData["expires_on"] = token.ExpiresOn
		if state != nil {
			state.ExpiresOn = token.ExpiresOn
			_ = writeTokenState(ctx, req.Storage, tokenID, state)
		}
	}
	return &logical.Response{Data: respData}, nil
}
