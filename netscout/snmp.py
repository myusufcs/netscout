"""SNMPv2c minimal — encoder/decoder BER/ASN.1 + GET & WALK, tanpa dependensi.

Cukup untuk kebutuhan inventaris: sysDescr, sysName, sysUpTime, ifTable, dan
ipAddrTable. Sengaja tidak mendukung SNMPv3 (enkripsi) karena itu butuh protokol
jauh lebih besar — dan untuk inventaris, v2c di jaringan internal sudah memadai.
"""
from __future__ import annotations

import random
import socket

# ---------------------------------------------------------------- tag ASN.1
T_INTEGER = 0x02
T_OCTET = 0x04
T_NULL = 0x05
T_OID = 0x06
T_SEQ = 0x30
T_IPADDR = 0x40
T_COUNTER32 = 0x41
T_GAUGE32 = 0x42
T_TIMETICKS = 0x43
T_OPAQUE = 0x44
T_COUNTER64 = 0x46
T_NOSUCH = 0x80
T_ENDOFMIB = 0x82

PDU_GET = 0xA0
PDU_GETNEXT = 0xA1
PDU_RESPONSE = 0xA2

SNMP_VERSION_2C = 1

# OID yang dipakai untuk inventaris
OID = {
    "sysDescr": "1.3.6.1.2.1.1.1.0",
    "sysObjectID": "1.3.6.1.2.1.1.2.0",
    "sysUpTime": "1.3.6.1.2.1.1.3.0",
    "sysContact": "1.3.6.1.2.1.1.4.0",
    "sysName": "1.3.6.1.2.1.1.5.0",
    "sysLocation": "1.3.6.1.2.1.1.6.0",
}
OID_IF_TABLE = "1.3.6.1.2.1.2.2"
OID_IP_ADDR_TABLE = "1.3.6.1.2.1.4.20"


class SnmpError(Exception):
    """Kegagalan protokol SNMP."""


# ---------------------------------------------------------------- encoder

def _len_bytes(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(raw)]) + raw


def tlv(tag: int, payload: bytes) -> bytes:
    return bytes([tag]) + _len_bytes(len(payload)) + payload


def enc_int(value: int, tag: int = T_INTEGER) -> bytes:
    if value == 0:
        raw = b"\x00"
    else:
        length = (value.bit_length() + 8) // 8          # +1 byte untuk tanda
        raw = value.to_bytes(length, "big", signed=True)
        while len(raw) > 1 and raw[0] == 0 and raw[1] < 0x80:
            raw = raw[1:]
    return tlv(tag, raw)


def enc_str(value: str | bytes, tag: int = T_OCTET) -> bytes:
    raw = value.encode() if isinstance(value, str) else value
    return tlv(tag, raw)


def enc_null() -> bytes:
    return tlv(T_NULL, b"")


def enc_oid(oid: str, tag: int = T_OID) -> bytes:
    parts = [int(x) for x in oid.strip(".").split(".")]
    if len(parts) < 2:
        raise SnmpError(f"OID tidak valid: {oid}")
    body = bytearray([parts[0] * 40 + parts[1]])
    for num in parts[2:]:
        if num < 0:
            raise SnmpError("sub-identifier OID tidak boleh negatif")
        chunk = [num & 0x7F]
        num >>= 7
        while num:
            chunk.append((num & 0x7F) | 0x80)
            num >>= 7
        body.extend(reversed(chunk))
    return tlv(tag, bytes(body))


def build_request(community: str, oids: list[str], request_id: int | None = None,
                  pdu_tag: int = PDU_GET) -> tuple[bytes, int]:
    rid = request_id if request_id is not None else random.randint(1, 2**31 - 1)
    varbinds = b"".join(tlv(T_SEQ, enc_oid(o) + enc_null()) for o in oids)
    pdu = tlv(pdu_tag, enc_int(rid) + enc_int(0) + enc_int(0) + tlv(T_SEQ, varbinds))
    msg = tlv(T_SEQ, enc_int(SNMP_VERSION_2C) + enc_str(community) + pdu)
    return msg, rid


# ---------------------------------------------------------------- decoder

def _read_tlv(data: bytes, pos: int = 0) -> tuple[int, bytes, int]:
    if pos + 2 > len(data):
        raise SnmpError("paket terpotong saat membaca tag/panjang")
    tag = data[pos]
    pos += 1
    first = data[pos]
    pos += 1
    if first & 0x80:
        n = first & 0x7F
        if n == 0 or pos + n > len(data):
            raise SnmpError("panjang BER tidak valid")
        length = int.from_bytes(data[pos:pos + n], "big")
        pos += n
    else:
        length = first
    end = pos + length
    if end > len(data):
        raise SnmpError("isi TLV melebihi panjang paket")
    return tag, data[pos:end], end


def dec_int(payload: bytes) -> int:
    return int.from_bytes(payload, "big", signed=True)


def dec_oid(payload: bytes) -> str:
    if not payload:
        raise SnmpError("OID kosong")
    first = payload[0]
    parts = [first // 40, first % 40]
    val = 0
    for byte in payload[1:]:
        val = (val << 7) | (byte & 0x7F)
        if not byte & 0x80:
            parts.append(val)
            val = 0
    return ".".join(str(p) for p in parts)


def dec_value(tag: int, payload: bytes):
    if tag == T_INTEGER or tag in (T_COUNTER32, T_GAUGE32, T_TIMETICKS, T_COUNTER64):
        return dec_int(payload)
    if tag == T_OCTET:
        try:
            return payload.decode("utf-8")
        except UnicodeDecodeError:
            return payload.hex()
    if tag == T_OID:
        return dec_oid(payload)
    if tag == T_IPADDR and len(payload) == 4:
        return ".".join(str(b) for b in payload)
    if tag == T_NULL:
        return None
    if tag == T_NOSUCH:
        return "noSuchObject"
    if tag == T_ENDOFMIB:
        return "endOfMibView"
    return payload.hex()


def parse_response(data: bytes, expect_id: int | None = None) -> list[tuple[str, object]]:
    """Urai paket respons SNMP menjadi [(oid, nilai)]."""
    tag, msg, _ = _read_tlv(data)
    if tag != T_SEQ:
        raise SnmpError(f"paket bukan SEQUENCE (tag {tag:#x})")
    pos = 0
    _, _, pos = _read_tlv(msg, pos)                       # version
    _, _, pos = _read_tlv(msg, pos)                       # community
    pdu_tag, pdu, _ = _read_tlv(msg, pos)
    if pdu_tag not in (PDU_RESPONSE,):
        raise SnmpError(f"bukan paket respons (tag {pdu_tag:#x})")

    pos = 0
    _, rid_raw, pos = _read_tlv(pdu, pos)
    rid = dec_int(rid_raw)
    _, err_status_raw, pos = _read_tlv(pdu, pos)
    err_status = dec_int(err_status_raw)
    _, err_index, pos = _read_tlv(pdu, pos)
    if err_status:
        raise SnmpError(f"error-status={err_status} index={dec_int(err_index)}")

    _, vbs, pos = _read_tlv(pdu, pos)
    out: list[tuple[str, object]] = []
    vpos = 0
    while vpos < len(vbs):
        _, vb, vpos = _read_tlv(vbs, vpos)
        ipos = 0
        _, oid_raw, ipos = _read_tlv(vb, ipos)
        vtag, vraw, _ = _read_tlv(vb, ipos)
        out.append((dec_oid(oid_raw), dec_value(vtag, vraw)))
    return out


# ---------------------------------------------------------------- transport

def get(host: str, community: str, oids: list[str], timeout: float = 2.0,
        retries: int = 1) -> list[tuple[str, object]]:
    msg, rid = build_request(community, oids, pdu_tag=PDU_GET)
    return _exchange(host, msg, rid, timeout, retries)


def get_next(host: str, community: str, oid: str, timeout: float = 2.0,
             retries: int = 1) -> list[tuple[str, object]]:
    msg, rid = build_request(community, [oid], pdu_tag=PDU_GETNEXT)
    return _exchange(host, msg, rid, timeout, retries)


def _exchange(host: str, msg: bytes, rid: int, timeout: float, retries: int):
    last: Exception | None = None
    for _ in range(retries + 1):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        try:
            sock.sendto(msg, (host, 161))
            data, _ = sock.recvfrom(65535)
            return parse_response(data, rid)
        except socket.timeout as exc:
            last = SnmpError(f"timeout ke {host}:161 (community salah / SNMP mati?)")
            last.__cause__ = exc
        except OSError as exc:
            last = SnmpError(f"gagal kirim ke {host}:161: {exc}")
        finally:
            sock.close()
    raise last or SnmpError("gagal menghubungi host")


def walk(host: str, community: str, base_oid: str, max_rows: int = 256,
         timeout: float = 2.0) -> list[tuple[str, object]]:
    """Telusuri subtree OID dengan GETNEXT berulang."""
    rows: list[tuple[str, object]] = []
    current = base_oid
    prefix = base_oid.rstrip(".") + "."
    while len(rows) < max_rows:
        try:
            result = get_next(host, community, current, timeout=timeout)
        except SnmpError:
            break
        if not result:
            break
        oid, value = result[0]
        if not oid.startswith(prefix) and oid != base_oid:
            break
        if value in ("endOfMibView", "noSuchObject"):
            break
        rows.append((oid, value))
        current = oid
    return rows


def uptime_text(ticks: int | None) -> str:
    """TimeTicks (1/100 detik) menjadi teks yang mudah dibaca."""
    if not isinstance(ticks, int):
        return "—"
    secs = ticks // 100
    d, rem = divmod(secs, 86400)
    h, rem = divmod(rem, 3600)
    m, s = divmod(rem, 60)
    if d:
        return f"{d} hari {h} jam"
    if h:
        return f"{h} jam {m} menit"
    if m:
        return f"{m} menit {s} detik"
    return f"{s} detik"


def mac_from_bytes(value) -> str:
    if isinstance(value, str) and len(value) == 12 and all(c in "0123456789abcdef" for c in value):
        return ":".join(value[i:i + 2] for i in range(0, 12, 2))
    return str(value)


def pack_probe(community: str = "public") -> bytes:
    """Paket siap-kirim untuk uji cepat (dipakai test tanpa jaringan nyata)."""
    return build_request(community, [OID["sysDescr"]])[0]
