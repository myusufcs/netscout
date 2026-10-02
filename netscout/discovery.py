"""Penemuan host: daftar alamat, ping, tabel ARP, dan vendor dari OUI MAC."""
from __future__ import annotations

import ipaddress
import re
import shutil
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

# tabel OUI ringkas — vendor umum di jaringan kantor/rumah
OUI: dict[str, str] = {
    "00000C": "Cisco", "000142": "Cisco", "001A2F": "Cisco", "001B0C": "Cisco",
    "001E13": "Cisco", "00235E": "Cisco", "0024C4": "Cisco", "0050E2": "Cisco",
    "000C29": "VMware", "005056": "VMware", "080027": "VirtualBox",
    "525400": "QEMU/KVM", "00155D": "Hyper-V",
    "001B21": "Intel", "3C970E": "Intel", "7CB27D": "Intel", "8C1645": "Intel",
    "000D3A": "Microsoft", "0017FA": "Microsoft", "281878": "Microsoft",
    "001E58": "D-Link", "1CBDB9": "D-Link", "340804": "D-Link",
    "00265A": "D-Link", "001CF0": "D-Link",
    "001377": "Samsung", "002454": "Samsung", "5C0A5B": "Samsung",
    "0017C8": "Kyocera", "3C2AF4": "Brother", "0021CC": "Brother",
    "00074D": "Zebra", "001B78": "HP", "3464A9": "HP", "9457A5": "HP",
    "B0A5A9": "HP", "001A4B": "HP", "3C4A92": "HP",
    "002248": "Microsoft", "001143": "Dell", "14FEB5": "Dell", "B8AC6F": "Dell",
    "00188B": "Dell", "F8BC12": "Dell",
    "000C42": "Routerboard/MikroTik", "4C5E0C": "Routerboard/MikroTik",
    "6C3B6B": "Routerboard/MikroTik", "DC2C6E": "Routerboard/MikroTik",
    "74ACB9": "Ubiquiti", "0418D6": "Ubiquiti", "245A4C": "Ubiquiti",
    "002722": "Ubiquiti", "788A20": "Ubiquiti",
    "001CDF": "Belkin", "944452": "Belkin", "080086": "Netgear",
    "0026F2": "Netgear", "A040A0": "Netgear", "9C3DCF": "Netgear",
    "50C7BF": "TP-Link", "A42BB0": "TP-Link", "C46E1F": "TP-Link",
    "F4EC38": "TP-Link", "9C5322": "Compal", "00259C": "Cisco-Linksys",
    "002369": "Cisco-Linksys", "48F8B3": "Linksys/Cisco",
    "B827EB": "Raspberry Pi", "DCA632": "Raspberry Pi", "E45F01": "Raspberry Pi",
    "00155F": "Xiaomi", "64CC2E": "Xiaomi", "78DDBB": "Xiaomi",
    "0C8910": "Xiaomi", "7C9EBD": "Huawei", "48DB50": "Huawei",
    "00259E": "Huawei", "5C7D5E": "Huawei", "0022A1": "ZTE",
    "344B50": "ZTE", "5CE28C": "ZTE", "001E40": "Shanghai Dare",
    "A4C138": "Aruba", "6CF37F": "Aruba", "186472": "Aruba",
    "0018A4": "ASUSTek", "2C56DC": "ASUSTek", "704D7B": "ASUSTek",
    "0019E0": "TP-Link", "647002": "TP-Link", "0C8268": "TP-Link",
}


def load_oui(path: str | Path | None = None) -> dict[str, str]:
    """Muat tabel OUI dari berkas IEEE (opsional); gabung dengan tabel bawaan."""
    table = dict(OUI)
    p = Path(path) if path else Path("/usr/share/ieee-data/oui.txt")
    if p.is_file():
        pattern = re.compile(r"^([0-9A-F]{2}-[0-9A-F]{2}-[0-9A-F]{2})\s+\(hex\)\s+(.+)$")
        for line in p.read_text(errors="replace").splitlines():
            m = pattern.match(line.strip())
            if m:
                table.setdefault(m.group(1).replace("-", ""), m.group(2).strip())
    return table


def vendor_of(mac: str, table: dict[str, str] | None = None) -> str:
    if not mac or mac in ("—", ""):
        return ""
    prefix = mac.replace(":", "").replace("-", "").upper()[:6]
    return (table or OUI).get(prefix, "tidak dikenal")


def expand_targets(spec: str) -> list[str]:
    """Terima CIDR, rentang a-b, atau daftar IP dipisah koma."""
    out: list[str] = []
    for item in str(spec).split(","):
        item = item.strip()
        if not item:
            continue
        if "/" in item:
            net = ipaddress.ip_network(item, strict=False)
            out += [str(h) for h in net.hosts()]
        elif "-" in item:
            # mendukung "10.0.0.1-4" maupun "10.0.0.1-10.0.0.4"
            start_s, _, end_s = item.partition("-")
            start_s, end_s = start_s.strip(), end_s.strip()
            try:
                start = ipaddress.ip_address(start_s)
                if "." in end_s:
                    end = ipaddress.ip_address(end_s)
                else:
                    end = ipaddress.ip_address(
                        ".".join(start_s.split(".")[:3] + [end_s]))
                out += [str(ipaddress.ip_address(i))
                        for i in range(int(start), int(end) + 1)]
            except ValueError:
                continue
        else:
            try:
                out.append(str(ipaddress.ip_address(item)))
            except ValueError:
                out.append(item)          # biarkan hostname lewat
    seen, uniq = set(), []
    for h in out:
        if h not in seen:
            seen.add(h)
            uniq.append(h)
    return uniq


def ping(host: str, timeout: int = 1) -> bool:
    if not shutil.which("ping"):
        return False
    try:
        p = subprocess.run(["ping", "-c", "1", "-W", str(timeout), "-n", host],
                           capture_output=True, text=True, timeout=timeout + 3)
        return p.returncode == 0
    except Exception:                      # noqa: BLE001
        return False


def sweep(hosts: list[str], workers: int = 64, timeout: int = 1,
          progress=None) -> list[str]:
    """Ping paralel; kembalikan daftar host yang hidup."""
    alive: list[str] = []
    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        futs = {pool.submit(ping, h, timeout): h for h in hosts}
        for fut in as_completed(futs):
            h = futs[fut]
            try:
                ok = fut.result()
            except Exception:              # noqa: BLE001
                ok = False
            if ok:
                alive.append(h)
                if progress:
                    progress(h)
    return sorted(alive, key=lambda x: tuple(int(p) for p in x.split("."))
                  if x.count(".") == 3 else (x,))


def parse_arp(path: str | Path = "/proc/net/arp") -> dict[str, str]:
    """Baca tabel ARP: {ip: mac}. Format: IPaddress HWtype Flags HWaddress Mask Device."""
    table: dict[str, str] = {}
    p = Path(path)
    if not p.is_file():
        return table
    for i, line in enumerate(p.read_text(errors="replace").splitlines()):
        if i == 0:
            continue
        parts = line.split()
        if len(parts) >= 4 and parts[3] != "00:00:00:00:00:00":
            table[parts[0]] = parts[3].lower()
    return table
