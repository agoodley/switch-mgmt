# Spanning-tree runbook

This explains what the audit report's findings mean, what the remediation
plan does about them, and how to deal by hand with the ones it leaves alone.
The commands and workflow are in the [README](../README.md).

## The design the plan moves you towards

* **One root bridge per site, at the core.** The switch with `stp_role:
  root_primary` gets priority 4096 for every VLAN, `root_secondary` gets 8192.
  Left alone, every switch has 32768 and the one with the lowest MAC address
  (usually the oldest switch in the building) becomes root, so traffic between
  access switches takes odd paths through it.
* **Optionally, access switches at 61440** (`stp_priority_other: 61440`), so
  none of them can become root even when both cores are down.
* **Rapid-PVST+ everywhere.** It reconverges in about a second instead of
  30–50 s. PVST+ and Rapid-PVST+ interoperate, but every port facing a PVST+
  switch falls back to the slow timers.
* **Edge ports with PortFast and BPDU Guard.** A host port then forwards
  immediately, never causes a topology change, and shuts itself down if a
  switch is plugged in. `errdisable recovery cause bpduguard` (300 s) brings
  it back once the switch is removed.
* **Few VLANs per trunk.** With PVST+ each VLAN is a spanning-tree
  instance, and many Catalyst access switches (2960 family, for example)
  support only 128. VLANs beyond the limit run with no spanning tree at all.
* Optional extras: **Root Guard** on the cores' downlinks
  (`stp_rootguard_downlinks`), so nothing downstream can take over as root;
  **Loop Guard** (`stp_loopguard_default`) and **UDLD** on fibre uplinks
  against unidirectional links (example snippets in `ansible/snippets/examples/`).

## Findings, by report category

### root-bridge

| Finding | Meaning and fix |
| --- | --- |
| *Root bridge is X, expected Y* | Fixed by the plan (priority from `stp_role`). |
| *Root bridge `<mac>` is not an audited switch* | The root is outside the inventory: a switch you have not added, another site bridged over the WAN, or a rogue switch. Starting at any switch, run `show spanning-tree vlan N` and follow the *Root port* to the next switch (`show cdp neighbors <port> detail`) until you reach it. |
| *Switches disagree about the root bridge* | The VLAN is split into separate spanning trees: a trunk does not carry the VLAN, or a link is blocked as inconsistent. Check `show interfaces trunk` on the links between the two halves. |
| *No root bridge is designated* | Set `stp_role: root_primary` / `root_secondary` on the core pair. |
| *If X fails, Y would become root instead of Z* | The backup root is not the second-best priority. Set `stp_role: root_secondary`, or lower the other switch's priority. |

### stp-mode

*Mixed spanning-tree modes* is fixed by the plan (`spanning-tree mode
rapid-pvst`). Changing the mode restarts spanning tree on that switch: expect
a few seconds of disruption per switch, so apply in a maintenance window.
Switches running **MST** are a blocker. Moving to or from MST needs a region
design (name, revision, VLAN-to-instance map) and is left to you.

### topology-change

Each time a non-edge port goes up or down, the switch sends a topology change
(TC). Every switch in the VLAN then flushes its MAC address table quickly and
floods unknown traffic until it has learned the addresses again. A steady
stream of TCs looks like random slowness and packet loss.

The report follows the TC counters back to their source:
`show spanning-tree detail` on each switch says how many TCs it has seen, when
the last one arrived, and on which port ("from GigabitEthernet1/0/49"). The
audit hops to the switch on that port and repeats until it reaches the switch
where the port itself changed state.

| Origin | What to do |
| --- | --- |
| an access port | A host (PC, printer, phone) bouncing its link on a port without PortFast. The plan adds PortFast. If the host flaps constantly, look at the cable, NIC and power-saving settings too. |
| a switch-to-switch link | The link itself goes up and down. Check `show interfaces <port>` (CRC errors, resets), the optics, and enable UDLD on fibre. |
| *external* | The TCs come from beyond the audited switches. Audit the neighbour too. |

When the previous run is at least 30 minutes old, the audit compares the
counters with it and reports the current rate instead of lifetime totals. A
re-audit some hours after `make apply` shows whether the TCs have really
stopped.

*N access ports transitioned to forwarding 100+ times* lists hosts that flap a
lot. PortFast stops the TCs, but the host still has a problem.

### edge-ports

| Finding | Meaning and fix |
| --- | --- |
| *N access ports lack PortFast and/or BPDU Guard* | Fixed by the plan. |
| *Access ports have a switch or bridge behind them* | Something running spanning tree is plugged into a user port: a desk switch, a bridged VM host, a meeting-room box. The plan deliberately leaves these ports alone, because BPDU Guard would shut them and cut off the users behind them. Decide per port: remove the device, replace it with a dumb (non-STP) switch, make it an official switch with a proper uplink, or keep it and add the port to `stp_edge_exclude`. |
| *BPDU Filter enabled* | BPDU Filter turns spanning tree off on the port, so a loop through it is never blocked. Remove it (`no spanning-tree bpdufilter`) unless you know exactly why it is there. |
| *Connected ports have no explicit switchport mode* | The port negotiates trunking with DTP. Set `switchport mode access` (or trunk) explicitly. Only explicit access ports get hardened. |

### inconsistent-ports

The switch is blocking the port for that VLAN on purpose, to prevent a loop or
a takeover. `show spanning-tree inconsistentports` lists them.

| Type | Cause and fix |
| --- | --- |
| **PVID** | Native-VLAN mismatch on a trunk: each end tags a different VLAN as native. Set the same `switchport trunk native vlan N` on both ends. CDP also logs `%CDP-4-NATIVE_VLAN_MISMATCH`. |
| **ROOT** | Root Guard received a better BPDU: something downstream claims to be root. Find it and fix its priority. The port recovers by itself once the BPDUs stop. |
| **LOOP** | Loop Guard stopped receiving BPDUs on a blocking port: probably a unidirectional link. Check the fibre, optics and UDLD. |
| **TYPE** | A PVST BPDU arrived on an access port, or a trunk faces an access port. Make both ends agree. |

### errdisable

`show interfaces status err-disabled` gives the reason. Fix the cause first,
then `shutdown` / `no shutdown` on the port (or wait for err-disable recovery,
if it is configured for that reason). For a port shut by BPDU Guard, the cause
is a switch behind it (see edge-ports above).

### loop

*Access ports blocking* means a redundant path exists through host ports: a
loop through a desk switch, a PC bridging two NICs, two wall sockets patched
together. Spanning tree is containing it. Find what is attached to the ports
listed.

### logs

| Message | Meaning |
| --- | --- |
| `%SW_MATM-4-MACFLAP_NOTIF` | The same MAC address keeps moving between two ports: a loop, or a dual-homed server with mismatched NIC teaming. The ports are in the message. Look at what connects them. |
| `%SPANTREE-2-BLOCK_BPDUGUARD`, `%PM-4-ERR_DISABLE` | BPDU Guard shut a port (see errdisable). |
| `%CDP-4-NATIVE_VLAN_MISMATCH` | See PVID above. |
| `%SPANTREE-5-ROOTCHANGE` | The root bridge changed. Expected right after `make apply`. At any other time, find out why (a core rebooted, a new switch with a better priority). |
| `%LINK-3-UPDOWN` (many) | Interfaces flapping. The usual source of topology changes. |

After `make sync`, LibreNMS raises an alert as these arrive for MAC flapping,
BPDU/Root/Loop Guard blocks, other inconsistencies (PVID, type, EtherChannel
misconfiguration, loopback), root changes and err-disabled ports. An alert
transport must be configured for the alerts to reach anyone.

### trunks

| Finding | Fix |
| --- | --- |
| *Native VLAN mismatch* | Same native VLAN on both ends. |
| *Trunk connected to an access port* | Make both ends trunk (or both access). |
| *Allowed VLANs differ* | A VLAN is carried on one side only, which can split that VLAN's spanning tree. Make the lists match. |

### config

| Finding | Fix |
| --- | --- |
| *No automatic recovery for BPDU Guard* | Fixed by the plan (`errdisable recovery cause bpduguard`). |
| *Spanning tree disabled for VLAN(s)* | `no spanning-tree vlan N` means loops in those VLANs are never blocked. Remove it unless the VLAN really cannot loop. |
| *Extended system ID is disabled* | Re-enable `spanning-tree extend system-id`. Priorities then work per VLAN as expected. |
| *Legacy UplinkFast/BackboneFast* | Not needed with Rapid-PVST+. Remove after the migration. |
| *N PVST instances active* | Near or over the platform limit. Prune unused VLANs from trunks (`switchport trunk allowed vlan ...`). |
| *Path cost method differs* | Mixed short/long costs give wrong path choices. Set `stp_pathcost_method: long` (the plan applies it everywhere). |
| *Non-default STP timers on the root bridge* | Timers set on the root are pushed to the whole VLAN. Go back to the defaults unless there is a documented reason. |

### collection

*No data collected* means the switch could not be logged into. The reason is
in `reports/<run>/raw/<switch>.json` (`errors`). *Commands not supported* is
normal for some commands on old images (LLDP disabled, no MST). The rest of
the audit still works.

## Maintenance window checklist

1. **Before:** `make audit SITE=x`, read the report, resolve any plan
   blockers. Then `make plan SITE=x` and review the commands for the cores and
   one access switch. Make sure you have console or out-of-band access to the
   core switches.
2. **During:** `make apply SITE=x`. The canary switch goes first. Check that
   its users are fine before pressing Enter for the next batch. Watch
   LibreNMS for the cores while they are changed.
3. **If a switch fails its checks**, the rollout stops and prints the
   rollback commands and the backup path. The failed switch's config was not
   saved, so a `reload` also brings it back. Full configs are in
   `backups/<site>/` and in Oxidized.
4. **After:** `make audit SITE=x` straight away (roots, modes, edge ports),
   and again a few hours later (topology-change rates). Then work through the
   report's *Manual actions*.

## Useful commands on a switch

```
show spanning-tree root                                    root bridge and root port per VLAN
show spanning-tree summary                                 mode, guards, port counts, root-for list
show spanning-tree detail | include ieee|rstp|occurr|from  TC counters and where the last one came from
show spanning-tree inconsistentports                       ports blocked as inconsistent
show interfaces status err-disabled                        err-disabled ports and the reason
show errdisable recovery                                   which causes recover automatically
show mac address-table address <mac>                       where a host is learned
show cdp neighbors <port> detail                           what is on a port
show logging | include SPANTREE|MACFLAP|ERR_DISABLE        recent STP events
```
