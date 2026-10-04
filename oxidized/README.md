# Oxidized device list

`router.json` in this directory is generated from the Ansible inventory by
`make sync-oxidized` and read by the Oxidized container (mounted read-only at
`/etc/switch-mgmt`).  It is git-ignored; do not edit it by hand.

The Oxidized configuration itself is rendered from `docker/oxidized/config.erb`
when the container starts, with the credentials from `.env`.
