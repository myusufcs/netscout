"""Pembangun topologi: SVG (digambar sendiri) dan Graphviz DOT."""
from __future__ import annotations

import math
from pathlib import Path

from .model import Host, Inventory

W, H = 1100, 760
COLORS = {
    "router": "#7dd3fc", "switch": "#a78bfa", "server": "#86efac",
    "printer": "#fcd34d", "host": "#c9d1d9", "unknown": "#6b7280",
}


def default_gateway(route_path: str = "/proc/net/route") -> str:
    """Ambil gateway default dari /proc/net/route (tanpa perintah tambahan)."""
    p = Path(route_path)
    if not p.is_file():
        return ""
    for i, line in enumerate(p.read_text(errors="replace").splitlines()):
        if i == 0:
            continue
        parts = line.split()
        if len(parts) < 3 or parts[1] != "00000000":
            continue
        try:
            raw = int(parts[2], 16)
        except ValueError:
            continue
        return ".".join(str((raw >> (8 * k)) & 0xFF) for k in range(4))
    return ""


def _short(text: str, n: int = 22) -> str:
    text = (text or "").strip().replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    return text if len(text) <= n else text[: n - 1] + "…"


def to_dot(inv: Inventory) -> str:
    """Sumber Graphviz (tidak butuh binary `dot`) — bisa dirender di mana pun."""
    lines = ["graph netscout {", '  graph [overlap=false, splines=true, bgcolor="#0f1115"];',
             '  node [shape=box, style="rounded,filled", fontname="Helvetica", '
             'fontcolor="#e6e6e6", color="#242a33", fontsize=10];',
             '  edge [color="#3b4553"];']
    gw = inv.gateway or "GATEWAY"
    lines.append(f'  "{gw}" [label="gateway\\n{gw}", fillcolor="#1d4ed8", fontcolor=white];')
    for h in inv.hosts:
        if h.ip == inv.gateway:
            continue
        label = f"{h.label}\\n{h.ip}"
        if h.mac:
            label += f"\\n{h.mac}"
        color = COLORS.get(h.kind.value, "#6b7280")
        lines.append(f'  "{h.ip}" [label="{label}", fillcolor="{color[:7]}22", '
                     f'color="{color}"];')
        lines.append(f'  "{gw}" -- "{h.ip}";')
    lines.append("}")
    return "\n".join(lines)


def to_svg(inv: Inventory) -> str:
    """Gambar topologi sederhana: gateway di tengah, host mengelilinginya."""
    hosts = [h for h in inv.hosts if h.ip != inv.gateway]
    gw = inv.gateway or "gateway"
    cx, cy = W / 2, H / 2
    n = max(len(hosts), 1)
    radius = min(W, H) * 0.34 if n <= 8 else min(W, H) * 0.40

    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" '
        f'viewBox="0 0 {W} {H}" font-family="Helvetica, Arial, sans-serif">',
        f'<rect width="{W}" height="{H}" fill="#0f1115"/>',
        f'<text x="24" y="36" fill="#e6e6e6" font-size="18" font-weight="bold">'
        f'Topologi — {_short(inv.target_spec, 40)}</text>',
        f'<text x="24" y="58" fill="#8b93a1" font-size="12">{len(inv.hosts)} host hidup '
        f'dari {inv.scanned} alamat dipindai · {inv.finished}</text>',
    ]

    positions: list[tuple[Host, float, float]] = []
    for i, h in enumerate(hosts):
        angle = (2 * math.pi * i / n) - math.pi / 2
        x = cx + radius * math.cos(angle)
        y = cy + radius * math.sin(angle)
        positions.append((h, x, y))
        parts.append(f'<line x1="{cx:.0f}" y1="{cy:.0f}" x2="{x:.0f}" y2="{y:.0f}" '
                     f'stroke="#2c3542" stroke-width="1.5"/>')

    parts.append(f'<circle cx="{cx:.0f}" cy="{cy:.0f}" r="34" fill="#1d4ed8" '
                 f'stroke="#3b82f6" stroke-width="2"/>')
    parts.append(f'<text x="{cx:.0f}" y="{cy + 4:.0f}" fill="#ffffff" font-size="13" '
                 f'text-anchor="middle">gateway</text>')
    parts.append(f'<text x="{cx:.0f}" y="{cy + 50:.0f}" fill="#8b93a1" font-size="11" '
                 f'text-anchor="middle">{_short(gw, 18)}</text>')

    for h, x, y in positions:
        color = COLORS.get(h.kind.value, "#6b7280")
        r = 22 if h.kind.value in ("router", "switch") else 18
        parts.append(f'<circle cx="{x:.0f}" cy="{y:.0f}" r="{r}" fill="{color}" '
                     f'fill-opacity="0.18" stroke="{color}" stroke-width="1.6"/>')
        parts.append(f'<text x="{x:.0f}" y="{y + 4:.0f}" fill="{color}" font-size="11" '
                     f'text-anchor="middle">{h.kind.symbol}</text>')
        parts.append(f'<text x="{x:.0f}" y="{y + r + 14:.0f}" fill="#e6e6e6" font-size="11" '
                     f'text-anchor="middle">{_short(h.label, 20)}</text>')
        parts.append(f'<text x="{x:.0f}" y="{y + r + 27:.0f}" fill="#8b93a1" font-size="10" '
                     f'text-anchor="middle">{h.ip}</text>')

    # legenda
    lx, ly = 24, H - 24 * len(COLORS) - 10
    parts.append(f'<text x="{lx}" y="{ly - 8}" fill="#8b93a1" font-size="11">Keterangan:</text>')
    for i, (kind, color) in enumerate(COLORS.items()):
        y = ly + i * 22
        parts.append(f'<circle cx="{lx + 6}" cy="{y}" r="6" fill="{color}" '
                     f'fill-opacity="0.25" stroke="{color}"/>')
        parts.append(f'<text x="{lx + 20}" y="{y + 4}" fill="#c9d1d9" font-size="11">{kind}</text>')

    parts.append("</svg>")
    return "\n".join(parts)
