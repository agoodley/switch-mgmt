#!/bin/sh
# Print one value from .env without shell-evaluating the file (passwords may
# contain $, ; or spaces).  Usage: scripts/env-get.sh KEY [default]
key="$1"
default="${2:-}"
file="${ENV_FILE:-.env}"
value=""
if [ -f "$file" ]; then
  value=$(grep -E "^${key}=" "$file" | tail -n 1 | cut -d= -f2-)
fi
# strip one level of surrounding quotes
case "$value" in
  \"*\") value=${value#\"}; value=${value%\"} ;;
  \'*\') value=${value#\'}; value=${value%\'} ;;
esac
printf '%s' "${value:-$default}"
