#!/usr/bin/env bash
set -euo pipefail
: "${VAULT_IMAGE:?Set VAULT_IMAGE to the image under test}"
container="vault-plugin-smoke-${GITHUB_RUN_ID:-$$}"
trap 'docker rm -f "$container" >/dev/null 2>&1 || true' EXIT

docker run --detach --name "$container" --cap-add IPC_LOCK \
  -e VAULT_DEV_ROOT_TOKEN_ID=smoke-test-only \
  -e VAULT_DEV_LISTEN_ADDRESS=127.0.0.1:8200 \
  "$VAULT_IMAGE" server -dev -dev-no-store-token -dev-plugin-dir=/vault/plugins

vault_cli() {
  docker exec -e VAULT_ADDR=http://127.0.0.1:8200 \
    -e VAULT_TOKEN=smoke-test-only "$container" vault "$@"
}
ready=false
for attempt in {1..30}; do
  if vault_cli status >/dev/null 2>&1; then ready=true; break; fi
  sleep 1
done
if [ "$ready" != true ]; then docker logs "$container"; exit 1; fi
vault_cli version | grep -F 'Vault v2.2.1 '

for engine in openrouter cloudflare; do
  plugin="vault-plugin-secrets-$engine"
  checksum="$(docker exec "$container" sha256sum "/vault/plugins/$plugin")"
  checksum="${checksum%% *}"
  vault_cli plugin register -sha256="$checksum" -command="$plugin" secret "$plugin"
  vault_cli secrets enable -path="$engine" -plugin-name="$plugin" plugin
done
vault_cli kv put secret/smoke value=roundtrip
test "$(vault_cli kv get -field=value secret/smoke)" = roundtrip
vault_cli secrets list
