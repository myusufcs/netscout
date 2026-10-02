"""Utilitas jaringan kecil (tanpa dependensi)."""
from __future__ import annotations

import socket


def tcp_open(host: str, port: int, timeout: float = 2.0) -> bool:
    s = socket.socket()
    s.settimeout(timeout)
    try:
        s.connect((host, port))
        return True
    except Exception:                      # noqa: BLE001
        return False
    finally:
        s.close()
