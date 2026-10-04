# Config snippets

Fixes that are not spanning-tree specific go here as plain IOS config, written
exactly as it appears in `show running-config` (top-level lines unindented,
sub-commands indented one space).  Snippets are Jinja2 templates, so inventory
variables are available (`{{ inventory_hostname }}`, `{{ site }}`, host_vars ...).

```bash
make deploy SNIPPET=snippets/examples/errdisable-recovery.cfg.j2 SITE=hq CHECK=1   # dry run, shows the commands
make deploy SNIPPET=snippets/examples/errdisable-recovery.cfg.j2 SITE=hq           # one switch, 25 %, then the rest
```

Only lines missing from the running-config are sent, every switch is backed up
to `backups/` first, and the rollout stops at the first failure.  Try a new
snippet against the lab first (`make lab-up`, then `INVENTORY=inventory-lab`).
