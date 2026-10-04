# Per-switch settings

One file per switch, named after its inventory name, e.g. `hq-acc-07.yml`:

```yaml
# a port with a small desk switch that cannot be removed yet
stp_edge_exclude: [Gi1/0/24]
# this switch must never become root
stp_priority: 61440
```

Any variable from `roles/switch_mgmt_defaults/defaults/main.yml` can be set
here; host values win over the site file and `group_vars/switches.yml`.
