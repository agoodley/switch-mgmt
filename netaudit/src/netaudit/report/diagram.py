"""Draw a VLAN's spanning tree as a self-contained SVG (and as Mermaid for Markdown).

Layout: the root bridge sits on the left, every switch is placed one column to
the right of the switch its root port leads to.  Forwarding (tree) links are
solid, blocked links dashed.  No external tools are needed.
"""

from __future__ import annotations

from html import escape

from ..analysis.topology import Topology, VlanView
from ..util import short_interface

COL_W = 230
ROW_H = 50
NODE_W = 160
NODE_H = 38
PAD = 24


def _children(view: VlanView) -> dict[str, list[str]]:
    children: dict[str, list[str]] = {}
    for host, node in view.tree.items():
        parent = node.parent
        if parent is None:
            continue
        children.setdefault(parent, []).append(host)
    for kids in children.values():
        kids.sort()
    return children


def layout(view: VlanView) -> dict[str, tuple[float, float, int]]:
    """Return node -> (x, y, depth).  External parents become their own nodes."""
    children = _children(view)
    roots = sorted(
        {h for h, n in view.tree.items() if n.parent is None}
        | {n.parent for n in view.tree.values() if n.parent and n.parent.startswith("external:")}
    )
    # nodes whose parent is not in the tree (inconsistent snapshot) become roots too
    known = set(view.tree) | set(roots)
    for host, node in view.tree.items():
        if node.parent and node.parent not in known:
            roots.append(host)
    positions: dict[str, tuple[float, float, int]] = {}
    row = 0

    def place(node: str, depth: int, trail: set[str]) -> float:
        nonlocal row
        kids = [k for k in children.get(node, []) if k not in trail and k not in positions]
        if not kids:
            y = row
            row += 1
        else:
            ys = [place(k, depth + 1, trail | {node}) for k in kids]
            y = (ys[0] + ys[-1]) / 2
        positions[node] = (PAD + depth * COL_W, PAD + y * ROW_H, depth)
        return y

    for root in roots:
        if root not in positions:
            place(root, 0, set())
    for host in view.tree:  # anything unreachable (loops in bad data)
        if host not in positions:
            positions[host] = (PAD, PAD + row * ROW_H, 0)
            row += 1
    return positions


def svg(topology: Topology, view: VlanView, max_nodes: int = 400) -> str:
    if not view.tree or len(view.tree) > max_nodes:
        return ""
    pos = layout(view)
    width = max(x for x, _, _ in pos.values()) + NODE_W + PAD
    height = max(y for _, y, _ in pos.values()) + NODE_H + PAD
    parts = [
        f'<svg class="stp-tree" viewBox="0 0 {width:.0f} {height:.0f}" width="{width:.0f}" height="{height:.0f}" '
        f'role="img" aria-label="Spanning tree for {escape(view.instance)}" xmlns="http://www.w3.org/2000/svg">'
    ]
    # tree edges
    for host, node in view.tree.items():
        if not node.parent or node.parent not in pos or host not in pos:
            continue
        x1, y1, _ = pos[node.parent]
        x2, y2, _ = pos[host]
        sx, sy = x1 + NODE_W, y1 + NODE_H / 2
        ex, ey = x2, y2 + NODE_H / 2
        mid = (sx + ex) / 2
        tip = f"{node.parent.removeprefix('external:')} {short_interface(node.parent_port or '')} -> {host} {short_interface(node.via_port or '')} (root port)"
        parts.append(
            f'<path class="edge fwd" d="M{sx:.0f},{sy:.0f} C{mid:.0f},{sy:.0f} {mid:.0f},{ey:.0f} {ex:.0f},{ey:.0f}">'
            f"<title>{escape(tip)}</title></path>"
        )
    # blocked links: from the designated end to the blocking end, with a marker at the blocking port
    drawn = set()
    for host, port, other, other_name in view.blocked_links:
        if host not in pos:
            continue
        target = other if other in pos else None
        key = tuple(sorted((host, target or other_name or "?")))
        if key in drawn:
            continue
        drawn.add(key)
        hx, hy, hdepth = pos[host]
        tip = f"{host} {short_interface(port)} is blocking (alternate port) towards {target or other_name or 'unknown'}"
        if target is None:
            sx, sy = hx + NODE_W, hy + NODE_H / 2
            parts.append(f'<path class="edge blk" d="M{sx:.0f},{sy:.0f} l36,0"><title>{escape(tip)}</title></path>')
            parts.append(
                f'<g class="blkmark" transform="translate({sx + 4:.0f},{sy:.0f})"><title>{escape(tip)}</title><circle r="4"/></g>'
            )
            continue
        ox, oy, odepth = pos[target]
        if odepth == hdepth:
            # same column: arc on the right-hand side
            sx, sy = ox + NODE_W, oy + NODE_H / 2
            ex, ey = hx + NODE_W, hy + NODE_H / 2
            bulge = 34 + abs(ey - sy) * 0.08
            d = f"M{sx:.0f},{sy:.0f} C{sx + bulge:.0f},{sy:.0f} {ex + bulge:.0f},{ey:.0f} {ex:.0f},{ey:.0f}"
            mark = (ex + 5, ey)
        else:
            (px, py), (cx, cy) = ((ox, oy), (hx, hy)) if odepth < hdepth else ((hx, hy), (ox, oy))
            sx, sy = px + NODE_W, py + NODE_H / 2
            ex, ey = cx, cy + NODE_H / 2
            mid = (sx + ex) / 2
            d = f"M{sx:.0f},{sy:.0f} C{mid:.0f},{sy:.0f} {mid:.0f},{ey:.0f} {ex:.0f},{ey:.0f}"
            mark = (ex - 5, ey) if odepth < hdepth else (sx + 5, sy)
        parts.append(f'<path class="edge blk" d="{d}"><title>{escape(tip)}</title></path>')
        parts.append(
            f'<g class="blkmark" transform="translate({mark[0]:.0f},{mark[1]:.0f})"><title>{escape(tip)}</title><circle r="4"/></g>'
        )
    # nodes
    for name, (x, y, _) in pos.items():
        classes = ["node"]
        label = name
        sub = ""
        if name.startswith("external:"):
            classes.append("external")
            label = name.removeprefix("external:")
            sub = "not audited"
        else:
            state = view.switches.get(name)
            if state is not None and state.is_root:
                classes.append("root")
                sub = "ROOT"
            elif state is not None:
                sub = f"cost {state.root_cost}" if state.root_cost is not None else ""
            if name == view.expected_root:
                classes.append("expected")
                sub = "ROOT (intended)" if "root" in classes else (sub + " · intended root").strip(" ·")
            if state is not None and state.blocked_ports:
                classes.append("has-blocked")
        tip = label
        state = view.switches.get(name)
        if state is not None:
            tip += f"\nbridge priority {state.bridge_priority} {state.bridge_mac}"
            if state.root_port:
                tip += f"\nroot port {short_interface(state.root_port)}"
            if state.blocked_ports:
                tip += "\nblocking: " + ", ".join(short_interface(p) for p in state.blocked_ports)
        parts.append(
            f'<g class="{" ".join(classes)}" transform="translate({x:.0f},{y:.0f})"><title>{escape(tip)}</title>'
            f'<rect width="{NODE_W}" height="{NODE_H}" rx="6"/>'
            f'<text x="10" y="15" class="label">{escape(label[:22])}</text>'
            f'<text x="10" y="30" class="sub">{escape(sub)}</text></g>'
        )
    parts.append("</svg>")
    return "".join(parts)


def mermaid(view: VlanView) -> str:
    def ident(name: str) -> str:
        return "n_" + "".join(c if c.isalnum() else "_" for c in name)

    lines = ["graph LR"]
    for host, node in sorted(view.tree.items()):
        label = host + (" (root)" if node.parent is None else "")
        lines.append(f'  {ident(host)}["{label}"]')
        if node.parent:
            parent_label = node.parent.removeprefix("external:")
            if node.parent.startswith("external:"):
                lines.append(f'  {ident(node.parent)}["{parent_label} (not audited)"]')
            lines.append(f"  {ident(node.parent)} --> {ident(host)}")
    seen = set()
    for host, port, other, _ in view.blocked_links:
        if other and other in view.tree:
            key = tuple(sorted((host, other)))
            if key in seen:
                continue
            seen.add(key)
            lines.append(f"  {ident(host)} -. BLK {short_interface(port)} .- {ident(other)}")
    return "\n".join(lines)
