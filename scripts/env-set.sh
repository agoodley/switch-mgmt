#!/bin/sh
# Set KEY=VALUE in .env (replacing any existing line).  Usage: scripts/env-set.sh KEY VALUE
set -eu
key="$1"
value="$2"
file="${ENV_FILE:-.env}"
tmp="$file.tmp.$$"
touch "$file"
grep -v -E "^${key}=" "$file" > "$tmp" || true
printf '%s=%s\n' "$key" "$value" >> "$tmp"
chmod 600 "$tmp"
mv "$tmp" "$file"
