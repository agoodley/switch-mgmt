#!/bin/bash
# Entry point wrapper for the Oxidized container:
#  1. run Oxidized as the host user (PUID/PGID), so it can read router.json
#     and known_hosts, which only their owner may read;
#  2. use the shared known_hosts (data/ssh) for strict host key checking;
#  3. render the Oxidized config from config.erb + environment (.env), so the
#     switch credentials never live in a file in the repository;
#  4. wait until `make sync-oxidized` has written at least one switch to
#     router.json (Oxidized exits when its source is empty);
#  5. hand over to the image's normal process supervisor.
set -euo pipefail

conf_dir=/home/oxidized/.config/oxidized
router=/etc/switch-mgmt/router.json

if [[ -n "${PUID:-}" && "$(id -u oxidized)" != "$PUID" ]]; then
  groupmod -o -g "${PGID:-$PUID}" oxidized
  usermod -o -u "$PUID" -g "${PGID:-$PUID}" oxidized
fi

mkdir -p /etc/ssh
ln -sf /etc/switch-mgmt-ssh/known_hosts /etc/ssh/ssh_known_hosts

mkdir -p "$conf_dir"
(umask 077 && ruby -rerb -rjson -e 'print ERB.new(File.read(ARGV[0]), trim_mode: "-").result' \
  /opt/switch-mgmt/config.erb > "$conf_dir/config")
chown -R oxidized:oxidized "$conf_dir"

waited=0
until ruby -rjson -e 'exit(JSON.parse(File.read(ARGV[0])).any? ? 0 : 1)' "$router" 2>/dev/null; do
  if (( waited % 300 == 0 )); then
    echo "oxidized: no switches in $router yet - run 'make sync-oxidized'"
  fi
  sleep 10
  waited=$((waited + 10))
done

exec "$@"
