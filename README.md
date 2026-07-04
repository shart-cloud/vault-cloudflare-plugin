# Vault Plugin Secrets Cloudflare

Vault secrets engine for Cloudflare runtime secrets and account-owned API tokens.

This project implements the MVP described in `SPEC.md`:

- Configure Cloudflare bootstrap API access.
- Configure default sync behavior.
- Store explicit KV v2 to Cloudflare Secrets Store sync rules.
- Run one sync rule or all enabled explicit sync rules.
- Store sync status and delete recorded Cloudflare sync entries.
- Store Cloudflare API token roles.
- Issue leased Cloudflare account-owned API tokens.
- Revoke Cloudflare API tokens when Vault leases are revoked.
- Discover Cloudflare token permission groups.

## Build

```sh
go test ./...
go build -o vault-plugin-secrets-cloudflare .
```

## CI/CD

GitHub Actions runs tests and validates the GoReleaser configuration on pushes and pull requests to `main` or `master`.

Tagged releases create Linux `amd64` and `arm64` binary archives, SHA-256 checksums, a GitHub Release, and a multi-arch GHCR image:

```sh
git tag v0.1.0
git push origin v0.1.0
```

The container image is published as:

```text
ghcr.io/<owner>/<repo>:v0.1.0
ghcr.io/<owner>/<repo>:v0
ghcr.io/<owner>/<repo>:v0.1
ghcr.io/<owner>/<repo>:latest
```

GoReleaser uses `Dockerfile.goreleaser`, which expects the prebuilt plugin binary in the release build context and packages it in a distroless runtime image.

## Vault Registration

Example local registration flow:

```sh
SHA256=$(sha256sum vault-plugin-secrets-cloudflare | cut -d ' ' -f1)

vault plugin register \
  -sha256="$SHA256" \
  -command="vault-plugin-secrets-cloudflare" \
  secret \
  vault-plugin-secrets-cloudflare

vault secrets enable \
  -path=cloudflare \
  -plugin-name=vault-plugin-secrets-cloudflare \
  plugin
```

The binary must be available in Vault's configured plugin directory.

## Configure Cloudflare

The bootstrap token must have the Cloudflare permissions needed for the workflows used:

- `Account Secrets Store Edit` and `Account Secrets Store Read` for sync.
- `API Tokens Write` and `API Tokens Read` for leased token creation and permission group discovery.

```sh
vault write cloudflare/config/cloudflare \
  api_token="$CLOUDFLARE_API_TOKEN" \
  account_id="$CLOUDFLARE_ACCOUNT_ID" \
  secrets_store_id="$CLOUDFLARE_SECRETS_STORE_ID"
```

The configured API token is never returned by reads:

```sh
vault read cloudflare/config/cloudflare
```

## Configure Sync Defaults

```sh
vault write cloudflare/config/sync \
  default_scopes="workers" \
  default_chunk_size_bytes=760 \
  max_parts=3 \
  delete_removed_parts=true
```

Cloudflare Secrets Store values are limited to 1024 bytes. For chunked secrets, `default_chunk_size_bytes` is the maximum base64 `data` field size before it is wrapped in the JSON part envelope. The default is intentionally conservative so the final JSON value stays under the Cloudflare limit.

## Create A Sync Rule

The source must be a KV v2 secret. The plugin reads it through Vault as:

```text
{vault_mount}/data/{vault_path}
```

The current implementation uses Vault's `ExtendedSystemView.ForwardGenericRequest` to read across mounts. Deployments where that system view is unavailable cannot run sync rules yet; token issuance and config paths are unaffected.

Example source secret:

```sh
vault kv put kv/apps/api/prod/jwt_private_key value=@jwt.pem
```

Example sync rule:

```sh
vault write cloudflare/sync/rules/api-jwt \
  vault_mount=kv \
  vault_path=apps/api/prod/jwt_private_key \
  vault_field=value \
  cloudflare_name=JWT_PRIVATE_KEY \
  scopes="workers" \
  split=auto \
  encoding=raw \
  enabled=true
```

Run one rule:

```sh
vault write cloudflare/sync/run/api-jwt
```

Dry-run one rule:

```sh
vault write cloudflare/sync/run/api-jwt dry_run=true
```

Run all enabled explicit rules:

```sh
vault write cloudflare/sync/run
```

Run all enabled rules with a prefix:

```sh
vault write cloudflare/sync/run rule_prefix=api-
```

Read status:

```sh
vault read cloudflare/sync/status/api-jwt
```

Delete Cloudflare entries recorded for a rule:

```sh
vault write cloudflare/sync/delete/api-jwt dry_run=true
vault write cloudflare/sync/delete/api-jwt delete_cloudflare_secrets=true
```

This does not delete the Vault source secret or the sync rule.

Reconcile sync rules, stored plugin state, and Cloudflare metadata:

```sh
vault read cloudflare/sync/reconcile
vault write cloudflare/sync/reconcile dry_run=true
```

Delete managed Cloudflare secrets that have no matching rule/state:

```sh
vault write cloudflare/sync/reconcile dry_run=false delete_orphans=true
```

Reconciliation reports missing Cloudflare entries, managed orphan entries, stale comments or versions, and chunk part drift.

## Chunked Secrets

When chunking is enabled, parts are written before metadata:

```text
JWT_PRIVATE_KEY__PART_001
JWT_PRIVATE_KEY__PART_002
JWT_PRIVATE_KEY__META
```

Each part and metadata entry uses the JSON envelope described in `SPEC.md` so Workers can reject mixed versions or invalid hashes.

## Token Permission Groups

Discover permission group IDs before creating roles:

```sh
vault read cloudflare/token/permission-groups name=workers
vault read cloudflare/token/permission-groups scope=com.cloudflare.api.account
```

Roles should store permission group IDs, not names.

## Create A Token Role

```sh
vault write cloudflare/token/roles/worker-read \
  token_type=account \
  permission_groups="<permission_group_id>" \
  resources='{"com.cloudflare.api.account.<account_id>":"*"}' \
  default_ttl=1h \
  max_ttl=4h \
  enabled=true
```

The default token name template is `vault-{{role}}-{{display_name}}-{{unix_time}}-{{random}}`. Supported template values are `{{role}}`, `{{display_name}}`, `{{unix_time}}`, `{{timestamp}}`, and `{{random}}`.

Issue a leased token:

```sh
vault write cloudflare/token/creds/worker-read display_name=ci ttl=30m
```

The response includes the Cloudflare token value once. The plugin stores token ID, account ID, role name, issue time, and expiration only.

When the Vault lease is revoked or expires, Vault calls the plugin revoke callback and the plugin deletes the Cloudflare token.

Reconcile issued token state with Cloudflare:

```sh
vault read cloudflare/token/reconcile
vault write cloudflare/token/reconcile dry_run=true
```

Delete plugin-managed Cloudflare tokens that have no matching Vault token state:

```sh
vault write cloudflare/token/reconcile dry_run=false delete_orphans=true
```

Reconciliation reports active plugin-managed tokens without Vault state, expired managed tokens still present in Cloudflare, and Vault token state whose Cloudflare token is missing.

## Deferred

The following are still deferred from the MVP or not yet implemented:

- KV metadata discovery scans.
- Worker binding generation.
- Automatic Worker deployment updates.
- Token lease renewal.
- Cloudflare user-owned token creation.
- Root credential rotation automation.
