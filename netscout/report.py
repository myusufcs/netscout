"""Penyusun laporan netscout: teks, Markdown, JSON, CSV."""
from __future__ import annotations

import csv
import datetime as dt
import io
import json
from pathlib import Path

from .model import Inventory


def to_text(inv: Inventory) -> str:
    bar = "=" * 96
    L = [bar, f"  INVENTARIS JARINGAN — {inv.target_spec}", bar]
    L.append(f"waktu     : {inv.started} → {inv.finished}")
    L.append(f"dipindai  : {inv.scanned} alamat · hidup {len(inv.hosts)}")
    if inv.gateway:
        L.append(f"gateway   : {inv.gateway}")
    if inv.community:
        L.append(f"SNMP      : community {inv.community!r}")
    ringkas = " · ".join(f"{k} {len(v)}" for k, v in inv.by_kind().items())
    L.append(f"komposisi : {ringkas or '—'}")
    L.append("")
    L.append(f"  {'IP':<16}{'MAC':<19}{'VEN':<14}{'JENIS':<9}{'NAMA':<20}DESKRIPSI")
    L.append("-" * 96)
    for kind, hosts in inv.by_kind().items():
        for h in hosts:
            nama = (h.sys_name or h.ptr or "—")[:19]
            desc = (h.sys_descr or h.note or "")[:30]
            L.append(f"{h.kind.symbol} {h.ip:<15}{(h.mac or '—'):<19}"
                     f"{(h.vendor or '—')[:13]:<14}{kind:<9}{nama:<20}{desc}")
    if inv.errors:
        L.append("\nCATATAN / ERROR")
        L.append("-" * 96)
        for e in inv.errors:
            L.append(f"  {e}")
    return "\n".join(L)


def to_markdown(inv: Inventory) -> str:
    L = [f"# Inventaris jaringan — `{inv.target_spec}`", ""]
    L.append(f"- **Waktu**: {inv.started} → {inv.finished}")
    L.append(f"- **Dipindai**: {inv.scanned} alamat, **{len(inv.hosts)} host hidup**")
    if inv.gateway:
        L.append(f"- **Gateway**: `{inv.gateway}`")
    L.append("")
    L.append("## Komposisi")
    L.append("")
    L.append("| Jenis | Jumlah |")
    L.append("|---|---|")
    for k, v in inv.by_kind().items():
        L.append(f"| {k} | {len(v)} |")
    L.append("")
    L.append("## Host")
    L.append("")
    L.append("| IP | MAC | Vendor | Jenis | Nama | Deskripsi | Uptime | Port terbuka |")
    L.append("|---|---|---|---|---|---|---|---|")
    for h in inv.hosts:
        L.append(f"| `{h.ip}` | {h.mac or '—'} | {h.vendor or '—'} | {h.kind.value} | "
                 f"{h.sys_name or h.ptr or '—'} | {(h.sys_descr or '')[:60]} | "
                 f"{h.uptime or '—'} | "
                 f"{', '.join(str(p) for p in h.open_ports) or '—'} |")
    if inv.errors:
        L.append("")
        L.append("## Catatan")
        L.append("")
        for e in inv.errors:
            L.append(f"- {e}")
    return "\n".join(L)


def to_json(inv: Inventory) -> str:
    return json.dumps(inv.as_dict(), indent=2, ensure_ascii=False)


def to_csv(inv: Inventory) -> str:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["ip", "mac", "vendor", "jenis", "nama", "ptr", "uptime",
                "jumlah_interface", "ip_tambahan", "port_terbuka", "snmp", "deskripsi"])
    for h in inv.hosts:
        w.writerow([h.ip, h.mac, h.vendor, h.kind.value, h.sys_name, h.ptr, h.uptime,
                    h.interfaces, " ".join(h.ips), " ".join(str(p) for p in h.open_ports),
                    "ya" if h.snmp_ok else "tidak", h.sys_descr])
    return buf.getvalue()


def write(outdir: Path, inv: Inventory, formats: list[str],
          svg: str | None = None, dot: str | None = None) -> list[Path]:
    outdir.mkdir(parents=True, exist_ok=True)
    stamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    safe = "".join(c if c.isalnum() or c in ".-" else "-" for c in inv.target_spec)
    base = f"netscout-{safe}-{stamp}"
    written: list[Path] = []
    for fmt, renderer, ext in (("text", to_text, "txt"), ("md", to_markdown, "md"),
                               ("json", to_json, "json"), ("csv", to_csv, "csv")):
        if fmt in formats:
            p = outdir / f"{base}.{ext}"
            p.write_text(renderer(inv), encoding="utf-8")
            written.append(p)
    if svg:
        p = outdir / f"{base}-topologi.svg"
        p.write_text(svg, encoding="utf-8")
        written.append(p)
    if dot:
        p = outdir / f"{base}-topologi.dot"
        p.write_text(dot, encoding="utf-8")
        written.append(p)
    return written
