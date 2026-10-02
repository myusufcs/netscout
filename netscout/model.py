"""Model inventaris: host, tautan, dan hasil pemindaian."""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from enum import Enum


class Kind(str, Enum):
    ROUTER = "router"
    SWITCH = "switch"
    SERVER = "server"
    PRINTER = "printer"
    HOST = "host"
    UNKNOWN = "unknown"

    @property
    def symbol(self) -> str:
        return {"router": "🛰️", "switch": "🔀", "server": "🖥️", "printer": "🖨️",
                "host": "💻", "unknown": "❔"}[self.value]


def guess_kind(descr: str, vendor: str, open_ports: list[int], name: str = "") -> Kind:
    text = f"{descr} {vendor} {name}".lower()
    if any(k in text for k in ("routeros", "cisco ios", "router", "gateway", "mikrotik")):
        return Kind.ROUTER
    if any(k in text for k in ("switch", "catalyst", "procurve")):
        return Kind.SWITCH
    if any(k in text for k in ("printer", "jetdirect", "laserjet")):
        return Kind.PRINTER
    if any(k in text for k in ("linux", "windows server", "ubuntu", "debian", "vmware esxi")):
        return Kind.SERVER
    if 8080 in open_ports or 9100 in open_ports:
        return Kind.PRINTER
    if 22 in open_ports or 3389 in open_ports or 80 in open_ports or 443 in open_ports:
        return Kind.SERVER
    return Kind.HOST if descr or vendor else Kind.UNKNOWN


@dataclass
class Host:
    ip: str
    mac: str = ""
    vendor: str = ""
    ptr: str = ""                 # reverse DNS
    kind: Kind = Kind.UNKNOWN
    sys_descr: str = ""
    sys_name: str = ""
    uptime: str = ""
    interfaces: int = 0
    ips: list[str] = field(default_factory=list)
    open_ports: list[int] = field(default_factory=list)
    snmp_ok: bool = False
    note: str = ""

    @property
    def label(self) -> str:
        return self.sys_name or self.ptr or self.ip

    def as_dict(self) -> dict:
        d = asdict(self)
        d["kind"] = self.kind.value
        return d


@dataclass
class Inventory:
    target_spec: str = ""
    started: str = ""
    finished: str = ""
    scanned: int = 0
    gateway: str = ""
    community: str = ""
    hosts: list[Host] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def by_kind(self) -> dict[str, list[Host]]:
        out: dict[str, list[Host]] = {}
        for h in self.hosts:
            out.setdefault(h.kind.value, []).append(h)
        return {k: sorted(v, key=lambda x: tuple(int(p) for p in x.ip.split("."))
                          if x.ip.count(".") == 3 else (0,)) for k, v in sorted(out.items())}

    def as_dict(self) -> dict:
        return {
            "target": self.target_spec,
            "started": self.started,
            "finished": self.finished,
            "scanned": self.scanned,
            "gateway": self.gateway,
            "community": self.community,
            "summary": {k: len(v) for k, v in self.by_kind().items()},
            "hosts": [h.as_dict() for h in self.hosts],
            "errors": self.errors,
        }
