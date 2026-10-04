#!/bin/sh
# Create a LibreNMS API token for the admin user and store it in .env as
# LIBRENMS_API_TOKEN (used by `make sync-librenms`).
set -eu
cd "$(dirname "$0")/.."
compose="${COMPOSE:-docker compose}"
user=$(scripts/env-get.sh LIBRENMS_ADMIN_USER admin)

output=$($compose exec -T librenms lnms api:token-create "$user" --name switch-mgmt 2>&1) || {
  echo "$output"
  echo "Could not create a token. Does the user '$user' exist? Create it with: make librenms-admin" >&2
  exit 1
}
token=$(printf '%s\n' "$output" | grep -E '^[0-9]+\|[A-Za-z0-9]+$' | tail -n 1)
if [ -z "$token" ]; then
  echo "$output"
  echo "Could not find the token in the output above; paste it into .env as LIBRENMS_API_TOKEN" >&2
  exit 1
fi
scripts/env-set.sh LIBRENMS_API_TOKEN "$token"
echo "Stored a new API token for '$user' in .env (LIBRENMS_API_TOKEN)."
