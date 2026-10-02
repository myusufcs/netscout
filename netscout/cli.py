"""CLI netscout.

    python3 -m netscout scan 192.168.1.0/24
    python3 -m netscout scan 192.168.1.1-254 --community public --ports 22,80,443
    python3 -m netscout scan 10.0.0.0/29 --no-snmp --out laporan
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import socket
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from . import __version__, snmp, topology
from . import report as report_mod
from .discovery import expand_targets, load_oui, parse_arp, sweep, vendor_of
from .model import Host, Inventory, guess_kind
from .util import tcp_open


def enrich(host: str, community: str | None, arp: dict, oui: dict,
           ports: list[int], timeout: float) -> Host:
    h = Host(ip=host)
    try:
        h.ptr = socket.gethostbyaddr(host)[0]
    except Exception:                      # noqa: BLE001
        h.ptr = ""
    h.mac = arp.get(host, "")
    h.vendor = vendor_of(h.mac, oui) if h.mac else ""

    if ports:
        with ThreadPoolExecutor(max_workers=len(ports)) as pool:
            results = list(pool.map(lambda p: (p, tcp_open(host, p, timeout)), ports))
        h.open_ports = sorted(p for p, ok in results if ok)

    if community:
        try:
            base = snmp.get(host, community, list(snmp.OID.values()), timeout=timeout)
            values = {oid: val for oid, val in base}
            h.sys_descr = str(values.get(snmp.OID["sysDescr"], "") or "")[:160]
            h.sys_name = str(values.get(snmp.OID["sysName"], "") or "")[:80]
            h.uptime = snmp.uptime_text(values.get(snmp.OID["sysUpTime"]))
            h.snmp_ok = bool(h.sys_descr or h.sys_name)
            rows = snmp.walk(host, community, snmp.OID_IF_TABLE, max_rows=64, timeout=timeout)
            h.interfaces = len({oid for oid, _ in rows if ".1.2.2.1.2." in oid})
            addr_rows = snmp.walk(host, community, snmp.OID_IP_ADDR_TABLE,
                                  max_rows=32, timeout=timeout)
            h.ips = sorted({str(v) for oid, v in addr_rows
                            if oid.startswith("1.3.6.1.2.1.4.20.1.1.") and "." in str(v)})
        except snmp.SnmpError as exc:
            h.note = str(exc)[:120]
        except Exception as exc:           # noqa: BLE001
            h.note = f"{type(exc).__name__}: {exc}"[:120]

    h.kind = guess_kind(h.sys_descr, h.vendor, h.open_ports, h.sys_name or h.ptr)
    return h


def cmd_scan(args) -> int:
    targets = expand_targets(args.spec)
    if not targets:
        print("tidak ada target yang bisa dipindai", file=sys.stderr)
        return 2

    inv = Inventory(target_spec=args.spec, community=args.community or "",
                    started=dt.datetime.now().isoformat(timespec="seconds"),
                    scanned=len(targets), gateway=topology.default_gateway())

    if not args.quiet:
        print(f"memindai {len(targets)} alamat (ICMP, {args.workers} paralel)...", file=sys.stderr)

    alive = sweep(targets, workers=args.workers, timeout=args.ping_timeout,
                  progress=(lambda h: print(f"  hidup: {h}", file=sys.stderr))
                  if not args.quiet else None)

    arp = parse_arp() if not args.no_arp else {}
    oui = load_oui(args.oui)
    ports = [int(p) for p in args.ports.split(",")] if args.ports else []

    if not args.quiet:
        print(f"{len(alive)} host hidup — mengumpulkan detail...", file=sys.stderr)

    with ThreadPoolExecutor(max_workers=min(16, max(1, args.workers))) as pool:
        inv.hosts = list(pool.map(
            lambda h: enrich(h, args.community, arp, oui, ports, args.timeout), alive))

    if not inv.hosts:
        inv.errors.append("tidak ada host yang merespons ICMP — cek rentang, firewall, "
                          "atau jalankan dari jaringan yang sama")
    inv.finished = dt.datetime.now().isoformat(timespec="seconds")

    if args.json and not args.out:
        print(report_mod.to_json(inv))
    elif not args.out:
        print(report_mod.to_text(inv))

    if args.out:
        formats = [f.strip() for f in (args.format or "text,md,json,csv").split(",") if f.strip()]
        svg = topology.to_svg(inv) if "svg" in formats or "all" in formats else None
        dot = topology.to_dot(inv) if "dot" in formats or "all" in formats else None
        for p in report_mod.write(Path(args.out).expanduser(), inv, formats, svg, dot):
            print(f"  -> {p}")
    if args.svg and not args.out:
        print(topology.to_svg(inv))
    return 0 if inv.hosts else 1


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="netscout",
        description="Inventaris & topologi jaringan (ping sweep + SNMP + tabel ARP)")
    ap.add_argument("--version", action="version", version=f"netscout {__version__}")
    sub = ap.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan", help="pindai rentang dan susun inventaris")
    s.add_argument("spec", help="CIDR (192.168.1.0/24), rentang (192.168.1.1-254), atau daftar")
    s.add_argument("--community", default="public",
                   help="community SNMP (kosongkan dengan --no-snmp)")
    s.add_argument("--no-snmp", action="store_true")
    s.add_argument("--no-arp", action="store_true", help="jangan baca tabel ARP")
    s.add_argument("--oui", help="berkas OUI IEEE (opsional, untuk nama vendor lengkap)")
    s.add_argument("--ports", help="port TCP yang dicek, mis. 22,80,443")
    s.add_argument("--workers", type=int, default=64)
    s.add_argument("--ping-timeout", type=int, default=1)
    s.add_argument("--timeout", type=float, default=2.0, help="timeout SNMP/TCP")
    s.add_argument("--out", help="folder laporan")
    s.add_argument("--format", help="text,md,json,csv,svg,dot (default semua)")
    s.add_argument("--json", action="store_true")
    s.add_argument("--svg", action="store_true", help="cetak SVG topologi ke stdout")
    s.add_argument("--quiet", action="store_true")
    return ap


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.no_snmp:
        args.community = ""
    return cmd_scan(args)


if __name__ == "__main__":
    raise SystemExit(main())
