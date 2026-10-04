# netaudit

Spanning-tree audit, remediation planning, CDP discovery and a lab simulator
for Cisco IOS / IOS-XE switches.  Used by the Ansible playbooks in this
repository; see the top-level README.

```
netaudit analyze RUN_DIR            # parse raw outputs, write report.html / plan.json
netaudit discover --seed IP --site hq --credentials ansible/inventory/credentials.yml --out ansible/inventory/sites/hq.yml
netaudit known-hosts 10.10.0.1 10.10.0.2:2222   # record SSH host keys (trust on first use), report changed ones
netaudit credentials-import passwords.csv --file ansible/inventory/credentials.yml
netaudit lab generate --out DIR     # simulated outputs, no SSH needed
netaudit lab serve                  # simulated switches over SSH (ports 2201+)
```
