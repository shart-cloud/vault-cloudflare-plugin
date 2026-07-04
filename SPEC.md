# Cloudflare Vault Secrets Engine Specification

## Overview

This specification describes a Vault plugin that integrates HashiCorp Vault with Cloudflare for two related workflows:

1. Sync selected static or semi-static Vault secrets into Cloudflare Secrets Store for runtime use by Workers, AI Gateway, and other Cloudflare integrations.
2. Create, lease, rotate, and revoke Cloudflare account-owned API tokens for agents, services, and optionally humans.

Vault remains the source of truth. Cloudflare receives derived runtime credentials or synchronized secret values.

## Goals

- Sync the latest version of selected Vault KV v2 secrets into Cloudflare Secrets Store.
- Support explicit sync configuration and optional Vault metadata/tag-based selection.
- Support large secret values by splitting them across multiple Cloudflare Secrets Store entries.
- Preserve integrity for chunked secrets using metadata, versioning, and checksums.
- Create short-lived Cloudflare account-owned API tokens from Vault roles.
- Revoke Cloudflare API tokens when Vault leases expire or are manually revoked.
- Keep Cloudflare bootstrap credentials stored only in Vault plugin configuration.
- Avoid storing Cloudflare secret values after write, except where Vault already stores the source secret.

## Non-Goals

- Replacing Vault as the primary secret manager.
- Reading secret values back from Cloudflare Secrets Store. Cloudflare does not expose stored secret values after creation.
- Providing transactional multi-secret updates in Cloudflare Secrets Store. The plugin must handle eventual consistency.
- Automatically updating Worker bindings unless explicitly added later.
- Supporting arbitrary Cloudflare products before they are supported by Secrets Store scopes.

## External APIs

### Cloudflare Secrets Store

Relevant endpoints:

- `GET /accounts/{account_id}/secrets_store/stores`
- `GET /accounts/{account_id}/secrets_store/stores/{store_id}`
- `POST /accounts/{account_id}/secrets_store/stores`
- `GET /accounts/{account_id}/secrets_store/stores/{store_id}/secrets`
- `GET /accounts/{account_id}/secrets_store/stores/{store_id}/secrets/{secret_id}`
- `POST /accounts/{account_id}/secrets_store/stores/{store_id}/secrets`
- `PATCH /accounts/{account_id}/secrets_store/stores/{store_id}/secrets/{secret_id}`
- `DELETE /accounts/{account_id}/secrets_store/stores/{store_id}/secrets/{secret_id}`

Required Cloudflare permission:

- `Account Secrets Store Edit` for create, update, and delete.
- `Account Secrets Store Read` for listing and metadata reads.

### Cloudflare Account Tokens

Relevant endpoints:

- `GET /accounts/{account_id}/tokens`
- `POST /accounts/{account_id}/tokens`
- `GET /accounts/{account_id}/tokens/{token_id}`
- `PUT /accounts/{account_id}/tokens/{token_id}`
- `DELETE /accounts/{account_id}/tokens/{token_id}`
- `PUT /accounts/{account_id}/tokens/{token_id}/value`
- `GET /accounts/{account_id}/tokens/permission_groups`

Required Cloudflare permission:

- `API Tokens Write` for token creation, update, deletion, and rolling.
- `API Tokens Read` for token and permission group discovery.

Cloudflare requires an initial API token created through the dashboard using the `Create additional tokens` template before tokens can be created through the API.

## Vault Mount

The plugin should be mounted as a Vault secrets engine, for example:

```sh
vault secrets enable -path=cloudflare vault-plugin-secrets-cloudflare
```

All paths below are relative to the mount path.

## Configuration Paths

### `config/cloudflare`

Stores Cloudflare API configuration.

Write fields:

- `api_token` string, required, sensitive. Bootstrap Cloudflare API token.
- `account_id` string, optional default account ID.
- `secrets_store_id` string, optional default Secrets Store ID.
- `base_url` string, optional. Defaults to `https://api.cloudflare.com/client/v4`.

Read fields:

- `account_id`
- `secrets_store_id`
- `base_url`
- `configured` boolean
- `api_token_set` boolean

The raw `api_token` must never be returned by read operations.

### `config/sync`

Stores default sync behavior.

Fields:

- `default_scopes` array of strings. Defaults to `["workers"]`.
- `default_chunk_size_bytes` integer. Defaults to a conservative value below Cloudflare's documented limit.
- `max_parts` integer. Defaults to `3`.
- `name_prefix` string, optional.
- `name_suffix` string, optional.
- `delete_removed_parts` boolean. Defaults to `true`.
- `managed_comment_prefix` string. Defaults to `managed-by=vault-cloudflare`.

## Sync Engine

### Source Model

The sync engine reads secrets from Vault KV v2.

Supported source formats:

- A single key from a KV v2 secret, such as `value`.
- A whole KV object serialized as JSON.
- A named field selected per sync rule.

The source secret's latest version is used unless a version is explicitly pinned.

### Selection Modes

#### Explicit Rules

Explicit rules are the preferred MVP selection mechanism.

Path:

```text
sync/rules/{name}
```

Fields:

- `vault_mount` string, required. Example: `kv`.
- `vault_path` string, required. Example: `apps/api/prod/stripe`.
- `vault_field` string, optional. If omitted, the whole data object is serialized as JSON.
- `cloudflare_name` string, required. Base Cloudflare secret name.
- `account_id` string, optional. Falls back to `config/cloudflare`.
- `secrets_store_id` string, optional. Falls back to `config/cloudflare`.
- `scopes` array of strings, optional. Defaults to `config/sync.default_scopes`.
- `split` boolean, optional. Defaults to `auto` behavior when value exceeds `chunk_size_bytes`.
- `chunk_size_bytes` integer, optional.
- `max_parts` integer, optional.
- `encoding` string, optional. Allowed values: `raw`, `base64`. Defaults to `base64` for chunked secrets and `raw` for unchunked secrets.
- `enabled` boolean. Defaults to `true`.

#### Metadata-Based Rules

Metadata/tag selection is optional because Vault KV v2 custom metadata is not globally queryable like an indexed tag system.

The sync engine may scan configured prefixes and inspect KV v2 `custom_metadata`.

Path:

```text
sync/discovery/{name}
```

Fields:

- `vault_mount` string, required.
- `prefix` string, required.
- `metadata_selector` map, required. Example: `{ "cloudflare-sync": "true" }`.
- `default_scopes` array of strings, optional.
- `enabled` boolean. Defaults to `true`.

Supported KV v2 metadata keys:

- `cloudflare-sync=true`
- `cloudflare-name=NAME`
- `cloudflare-scopes=workers,ai_gateway`
- `cloudflare-field=value`
- `cloudflare-split=true|false|auto`
- `cloudflare-chunk-size=NUMBER`

### Sync Operations

#### `sync/run/{rule_name}`

Runs one explicit sync rule.

Response fields:

- `rule_name`
- `vault_path`
- `vault_version`
- `cloudflare_names`
- `created`
- `updated`
- `deleted`
- `unchanged`
- `sha256`
- `warnings`

#### `sync/run`

Runs all enabled explicit rules and enabled discovery rules.

Optional fields:

- `dry_run` boolean
- `force` boolean
- `rule_prefix` string

#### `sync/status/{rule_name}`

Returns last sync state for a rule.

State fields:

- `last_run_at`
- `last_success_at`
- `last_error`
- `last_vault_version`
- `last_sha256`
- `cloudflare_secret_ids`
- `cloudflare_names`

#### `sync/delete/{rule_name}`

Deletes Cloudflare entries managed by the rule.

Fields:

- `delete_cloudflare_secrets` boolean, required.
- `dry_run` boolean, optional.

This must not delete the Vault source secret.

### Cloudflare Name Strategy

For unchunked secrets:

```text
{cloudflare_name}
```

For chunked secrets:

```text
{cloudflare_name}__META
{cloudflare_name}__PART_001
{cloudflare_name}__PART_002
{cloudflare_name}__PART_003
```

Secret names must not contain spaces. The plugin should validate names before writing to Cloudflare.

### Cloudflare Comment Strategy

Each managed Cloudflare secret should include a comment with enough metadata to identify ownership without exposing secret values.

Example:

```text
managed-by=vault-cloudflare rule=api-jwt vault=kv/apps/api/prod/jwt version=17 sha256=abc123 part=1/3
```

The sync engine should only modify Cloudflare secrets that are either recorded in plugin state or have the configured managed comment prefix.

### Create-or-Patch Algorithm

For each sync operation:

1. Read the latest Vault KV v2 metadata and data.
2. Extract the selected field or serialize the object.
3. Encode and chunk if needed.
4. Compute SHA-256 over the canonical source payload before chunking.
5. List Cloudflare Secrets Store metadata and resolve names to IDs.
6. Create missing entries.
7. Patch existing entries whose desired value, scopes, or comment changed.
8. For chunked secrets, write part entries first and metadata last.
9. Delete stale extra parts if `delete_removed_parts=true`.
10. Persist sync state in Vault plugin storage.

Because Cloudflare secret values are write-only, the plugin cannot compare remote secret values directly. It must compare against Vault-side sync state, Vault version, source hash, Cloudflare metadata, and explicit force flags.

### Chunking Format

Chunking exists to support secrets larger than a configured Cloudflare single-secret threshold and to provide predictable Worker runtime behavior.

The metadata secret value must be JSON:

```json
{
  "format": "vault-cloudflare-secret-v1",
  "name": "JWT_PRIVATE_KEY",
  "vault_mount": "kv",
  "vault_path": "apps/api/prod/jwt_private_key",
  "vault_version": 17,
  "encoding": "base64",
  "parts": 3,
  "sha256": "..."
}
```

Each part secret value should be JSON:

```json
{
  "format": "vault-cloudflare-secret-part-v1",
  "name": "JWT_PRIVATE_KEY",
  "vault_version": 17,
  "part": 1,
  "parts": 3,
  "encoding": "base64",
  "data": "..."
}
```

Workers must read `__META`, read all expected parts, verify matching version and part count, concatenate `data`, decode if needed, and verify `sha256` before use.

### Chunking Consistency

Cloudflare Secrets Store does not provide multi-secret transactions. The plugin must reduce inconsistency risk by:

- Writing all part entries before writing `__META`.
- Including `vault_version` and `sha256` in metadata.
- Including `vault_version`, `part`, and `parts` in every part.
- Requiring runtime consumers to reject mixed versions or invalid hashes.
- Optionally deleting stale parts only after the new metadata is written.

### Worker Binding Implications

Cloudflare Workers require explicit Secrets Store bindings. If a secret may use up to three parts, deployments should bind all expected names:

```toml
[[secrets_store_secrets]]
binding = "JWT_PRIVATE_KEY_META"
store_id = "<STORE_ID>"
secret_name = "JWT_PRIVATE_KEY__META"

[[secrets_store_secrets]]
binding = "JWT_PRIVATE_KEY_PART_001"
store_id = "<STORE_ID>"
secret_name = "JWT_PRIVATE_KEY__PART_001"

[[secrets_store_secrets]]
binding = "JWT_PRIVATE_KEY_PART_002"
store_id = "<STORE_ID>"
secret_name = "JWT_PRIVATE_KEY__PART_002"

[[secrets_store_secrets]]
binding = "JWT_PRIVATE_KEY_PART_003"
store_id = "<STORE_ID>"
secret_name = "JWT_PRIVATE_KEY__PART_003"
```

The plugin may later generate binding snippets, but automatic Worker deployment is not part of the MVP.

## API Token Creator

### Role Model

Path:

```text
token/roles/{name}
```

Fields:

- `account_id` string, optional. Defaults to `config/cloudflare.account_id`.
- `token_type` string. MVP supports `account` only.
- `permission_groups` array of strings, required. Cloudflare permission group IDs.
- `resources` map, required. Cloudflare token policy resources.
- `default_ttl` duration, required.
- `max_ttl` duration, required.
- `not_before_offset` duration, optional.
- `ip_allowlist` array of CIDRs, optional.
- `ip_denylist` array of CIDRs, optional.
- `name_template` string, optional. Defaults to `vault-{{role}}-{{display_name}}-{{unix_time}}`.
- `renewable` boolean. Defaults to `false`.
- `enabled` boolean. Defaults to `true`.

### Create Credentials

Path:

```text
token/creds/{role_name}
```

The plugin creates an account-owned Cloudflare API token using:

```text
POST /accounts/{account_id}/tokens
```

The Cloudflare `expires_on` value must be no later than the Vault lease expiration.

Response fields:

- `token` string, sensitive. Returned once.
- `token_id` string.
- `account_id` string.
- `expires_on` timestamp.
- `not_before` timestamp, optional.
- `lease_id` string.

The Vault lease metadata must include:

- `account_id`
- `token_id`
- `role_name`
- `expires_on`

### Revoke Credentials

On lease revocation, the plugin calls:

```text
DELETE /accounts/{account_id}/tokens/{token_id}
```

Revocation must be idempotent. A missing or already-deleted token should be treated as success.

### Renew Credentials

If `renewable=true`, renewal may update `expires_on` using:

```text
PUT /accounts/{account_id}/tokens/{token_id}
```

Renewal must never exceed the role's `max_ttl`.

MVP recommendation: keep token leases non-renewable and issue replacement tokens instead.

### Roll Token Value

Path:

```text
token/roll/{token_id}
```

Optional administrative endpoint that calls:

```text
PUT /accounts/{account_id}/tokens/{token_id}/value
```

This returns a new token value once. This should be restricted to administrators.

### Permission Group Discovery

Path:

```text
token/permission-groups
```

Calls:

```text
GET /accounts/{account_id}/tokens/permission_groups
```

Optional filters:

- `name`
- `scope`

Roles should store permission group IDs, not names, because Cloudflare permission names are cosmetic and may change.

## Internal State

The plugin should store state in Vault's logical storage.

### Sync Rule State

Key:

```text
state/sync/{rule_name}
```

Fields:

- `last_run_at`
- `last_success_at`
- `last_error`
- `vault_mount`
- `vault_path`
- `vault_field`
- `vault_version`
- `source_sha256`
- `cloudflare_account_id`
- `cloudflare_store_id`
- `cloudflare_names_to_ids`
- `parts`

### Token Lease State

Vault lease metadata should be sufficient for revocation. Additional state may be stored for audit or debugging:

```text
state/tokens/{token_id}
```

Fields:

- `role_name`
- `account_id`
- `token_id`
- `issued_at`
- `expires_on`
- `lease_id`

The token value must not be stored outside Vault's normal response and audit redaction paths.

## Security Requirements

- Mark `api_token`, generated API tokens, and synchronized secret payloads as sensitive.
- Never log Cloudflare token values or Vault secret values.
- Never return configured Cloudflare bootstrap tokens from read paths.
- Support Cloudflare API token authentication with bearer tokens. Avoid global API keys except for explicit compatibility mode.
- Validate Cloudflare secret names before write.
- Restrict sync/delete operations with Vault ACL policies.
- Restrict token role creation to administrators.
- Use least privilege Cloudflare bootstrap credentials where possible.
- Prefer account-owned Cloudflare API tokens for automation.
- For human access, rely on Vault audit logs for attribution.

## Failure Handling

### Sync Failures

- Partial Cloudflare writes must be recorded in sync state.
- `sync/status/{rule_name}` must show the last error.
- Re-running sync must converge to the desired state.
- If metadata write fails after parts were written, runtime consumers should continue using the old metadata version.
- If stale part deletion fails, the next sync should retry deletion.

### Token Failures

- If token creation succeeds but Vault response fails, the plugin may orphan a Cloudflare token. A reconciliation endpoint should list and optionally delete plugin-managed tokens.
- If token revocation fails due to Cloudflare unavailability, Vault should surface the revocation error so operators can retry.
- If token revocation returns not found, treat as success.

## Reconciliation

### `sync/reconcile`

Compares Vault sync rules, plugin state, and Cloudflare metadata.

Reports:

- Managed Cloudflare secrets with no matching Vault rule.
- Vault rules with missing Cloudflare entries.
- Cloudflare entries with stale comments or versions.
- Chunked secrets with missing or extra parts.

Optional fields:

- `dry_run` boolean. Defaults to `true`.
- `delete_orphans` boolean. Defaults to `false`.

### `token/reconcile`

Lists Cloudflare account tokens matching the plugin's naming/comment conventions and compares them with Vault lease state.

Reports:

- Active tokens with no Vault lease.
- Expired tokens still present in Cloudflare.
- Vault leases whose Cloudflare token is missing.

Optional fields:

- `dry_run` boolean. Defaults to `true`.
- `delete_orphans` boolean. Defaults to `false`.

## MVP Scope

The first implementation should include:

- `config/cloudflare`
- `config/sync`
- Explicit sync rules under `sync/rules/{name}`
- `sync/run/{rule_name}`
- `sync/run`
- `sync/status/{rule_name}`
- Create-or-patch Cloudflare Secrets Store entries
- Chunking with `__META` and `__PART_NNN`
- Account token roles under `token/roles/{name}`
- `token/creds/{role_name}` with Vault leases
- Lease revocation that deletes Cloudflare account tokens
- Permission group discovery
- Token reconciliation under `token/reconcile`

Defer until after MVP:

- KV metadata discovery scans.
- Worker binding generation.
- Automatic Worker deployment updates.
- Token lease renewal.
- Cloudflare user-owned token creation.
- Root credential rotation automation.

## Example Sync Rule

```json
{
  "vault_mount": "kv",
  "vault_path": "apps/api/prod/jwt_private_key",
  "vault_field": "value",
  "cloudflare_name": "JWT_PRIVATE_KEY",
  "scopes": ["workers"],
  "split": true,
  "chunk_size_bytes": 48000,
  "max_parts": 3,
  "encoding": "base64",
  "enabled": true
}
```

## Example Token Role

```json
{
  "account_id": "<account_id>",
  "token_type": "account",
  "permission_groups": [
    "<workers_scripts_read_permission_group_id>"
  ],
  "resources": {
    "com.cloudflare.api.account.<account_id>": "*"
  },
  "default_ttl": "1h",
  "max_ttl": "4h",
  "ip_allowlist": ["203.0.113.10/32"],
  "renewable": false,
  "enabled": true
}
```

## Open Questions

- Should the plugin support only KV v2, or should it also read from other Vault engines through Vault's internal request router?
- Should chunked part values be raw strings for simplicity or JSON envelopes for stronger validation? This spec recommends JSON envelopes.
- Should stale Cloudflare secrets be deleted automatically or require explicit `sync/delete` / reconciliation approval?
- Should sync be event-driven through Vault plugin event notifications where available, or periodic/manual only for OSS compatibility?
- Should Worker runtime reassembly helpers be shipped in this repository as TypeScript utilities?
