#!/bin/sh
# Everything the toolbox writes (reports, backups, router.json, known_hosts)
# can contain network details or secrets: readable by its owner only.
umask 077
exec "$@"
