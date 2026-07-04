package plugin

import (
	"context"
	"net/http"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b := Backend()
	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}
	return b, nil
}

type cloudflareBackend struct {
	*framework.Backend
	httpClient *http.Client
}

func Backend() *cloudflareBackend {
	b := &cloudflareBackend{httpClient: http.DefaultClient}
	b.Backend = &framework.Backend{
		Help:        backendHelp,
		BackendType: logical.TypeLogical,
		PathsSpecial: &logical.Paths{
			SealWrapStorage: []string{
				"config/cloudflare",
				"token/static/",
			},
		},
	}

	b.Paths = []*framework.Path{
		b.pathConfigCloudflare(),
		b.pathConfigSync(),
		b.pathSyncRulesList(),
		b.pathSyncRules(),
		b.pathSyncBindings(),
		b.pathSyncRunAll(),
		b.pathSyncRunRule(),
		b.pathSyncStatus(),
		b.pathSyncDelete(),
		b.pathSyncReconcile(),
		b.pathTokenRolesList(),
		b.pathTokenRoles(),
		b.pathTokenPermissionGroups(),
		b.pathTokenCreds(),
		b.pathTokenRoll(),
		b.pathStaticTokensList(),
		b.pathStaticTokens(),
		b.pathTokenReconcile(),
	}
	b.Secrets = []*framework.Secret{
		b.cloudflareTokenSecret(),
	}

	return b
}

const backendHelp = `
Cloudflare secrets engine.

This plugin syncs selected Vault KV v2 secrets into Cloudflare Secrets Store and
issues leased Cloudflare account-owned API tokens.
`
