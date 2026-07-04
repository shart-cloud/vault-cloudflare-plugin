# Terraform Worker Secrets Store Example

This example keeps Cloudflare runtime secret values out of Terraform state.
Terraform manages Worker infrastructure and Secrets Store bindings; Vault remains
the source of truth for secret values.

## Flow

1. CI obtains a short-lived Cloudflare API token from Vault:

   ```sh
   export CLOUDFLARE_API_TOKEN="$(
     vault write -field=token cloudflare/token/creds/terraform-worker-deployer \
       display_name=terraform \
       ttl=30m
   )"
   ```

2. Terraform writes a Vault sync rule.
3. Terraform triggers `vault write cloudflare/sync/run/api-jwt`.
4. Terraform reads `cloudflare/sync/bindings/api-jwt` for binding metadata.
5. Terraform deploys the Worker with `secrets_store_secret` bindings.

The `sync/bindings` response includes only binding names, store IDs, and
Cloudflare secret names. It does not include secret values.

## Run

```sh
terraform init
terraform apply \
  -var account_id="$CLOUDFLARE_ACCOUNT_ID" \
  -var secrets_store_id="$CLOUDFLARE_SECRETS_STORE_ID"
```

The Vault provider uses `VAULT_ADDR` and `VAULT_TOKEN`. The Cloudflare provider
uses `CLOUDFLARE_API_TOKEN`.
