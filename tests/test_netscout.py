"""Uji netscout: codec SNMP, penemuan, topologi, laporan, dan CLI.

Sebagian besar test berjalan tanpa jaringan. Satu smoke test memakai 127.0.0.1.
"""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from netscout import report as report_mod, snmp, topology              # noqa: E402
from netscout.discovery import (expand_targets, load_oui, parse_arp,    # noqa: E402
                                vendor_of)
from netscout.model import Host, Inventory, Kind, guess_kind            # noqa: E402


def build_response(community: str, rid: int, pairs: list[tuple[str, int, bytes]]) -> bytes:
    """Bangun paket respons SNMP untuk menguji parser."""
    vbs = b"".join(snmp.tlv(snmp.T_SEQ, snmp.enc_oid(o) + snmp.tlv(t, v)) for o, t, v in pairs)
    pdu = snmp.tlv(0xA2, snmp.enc_int(rid) + snmp.enc_int(0) + snmp.enc_int(0)
                   + snmp.tlv(snmp.T_SEQ, vbs))
    return snmp.tlv(snmp.T_SEQ, snmp.enc_int(1) + snmp.enc_str(community) + pdu)


class TestSnmpCodec(unittest.TestCase):
    def test_oid_roundtrip(self):
        for oid in ("1.3.6.1.2.1.1.1.0", "1.3.6.1.4.1.9.1", "1.3.6.1.2.1.2.2.1.2.1",
                    "1.3.6.1.4.1.14988.1.1.1.3.0"):
            tag, payload, _ = snmp._read_tlv(snmp.enc_oid(oid))
            self.assertEqual(tag, snmp.T_OID)
            self.assertEqual(snmp.dec_oid(payload), oid)

    def test_integer_roundtrip(self):
        for n in (0, 1, 127, 128, 255, 256, 4095, 65535, 2 ** 31 - 1):
            _, payload, _ = snmp._read_tlv(snmp.enc_int(n))
            self.assertEqual(snmp.dec_int(payload), n, n)

    def test_dec_value(self):
        self.assertEqual(snmp.dec_value(snmp.T_OCTET, b"RouterOS 7.1"), "RouterOS 7.1")
        self.assertEqual(snmp.dec_value(snmp.T_IPADDR, b"\xc0\xa8\x01\x01"), "192.168.1.1")
        self.assertIsNone(snmp.dec_value(snmp.T_NULL, b""))
        self.assertEqual(snmp.dec_value(snmp.T_NOSUCH, b""), "noSuchObject")
        self.assertEqual(snmp.dec_value(snmp.T_ENDOFMIB, b""), "endOfMibView")
        self.assertEqual(snmp.dec_value(snmp.T_COUNTER32, b"\x00\x00\x01\x00"), 256)

    def test_nilai_biner_bukan_utf8_jadi_hex(self):
        nilai = snmp.dec_value(snmp.T_OCTET, b"\xff\xfe\x00")
        self.assertTrue(all(c in "0123456789abcdef" for c in nilai))

    def test_build_request_struktur(self):
        msg, rid = snmp.build_request("rahasia", [snmp.OID["sysDescr"]])
        _, body, _ = snmp._read_tlv(msg)
        pos = 0
        _, ver, pos = snmp._read_tlv(body, pos)
        _, comm, pos = snmp._read_tlv(body, pos)
        pdu_tag, pdu, _ = snmp._read_tlv(body, pos)
        self.assertEqual(snmp.dec_int(ver), 1)
        self.assertEqual(comm, b"rahasia")
        self.assertEqual(pdu_tag, snmp.PDU_GET)
        _, pdu_rid, _ = snmp._read_tlv(pdu, 0)
        self.assertEqual(snmp.dec_int(pdu_rid), rid)

    def test_parse_response(self):
        data = build_response("public", 4242, [
            (snmp.OID["sysDescr"], snmp.T_OCTET, b"Linux router 6.1"),
            (snmp.OID["sysUpTime"], snmp.T_TIMETICKS, (123456).to_bytes(3, "big")),
            (snmp.OID["sysName"], snmp.T_OCTET, b"gw-utama"),
        ])
        rows = dict(snmp.parse_response(data, 4242))
        self.assertEqual(rows[snmp.OID["sysDescr"]], "Linux router 6.1")
        self.assertEqual(rows[snmp.OID["sysName"]], "gw-utama")
        self.assertEqual(rows[snmp.OID["sysUpTime"]], 123456)

    def test_parse_response_error_status(self):
        vbs = snmp.tlv(snmp.T_SEQ, snmp.tlv(snmp.T_SEQ,
                                            snmp.enc_oid("1.3.6.1.2.1.1.1.0") + snmp.enc_null()))
        pdu = snmp.tlv(0xA2, snmp.enc_int(7) + snmp.enc_int(2) + snmp.enc_int(1)
                       + snmp.tlv(snmp.T_SEQ, vbs))
        data = snmp.tlv(snmp.T_SEQ, snmp.enc_int(1) + snmp.enc_str("public") + pdu)
        with self.assertRaises(snmp.SnmpError):
            snmp.parse_response(data)

    def test_paket_rusak_melempar_rapi(self):
        with self.assertRaises(snmp.SnmpError):
            snmp.parse_response(b"\x30\x05\x02")
        with self.assertRaises(snmp.SnmpError):
            snmp._read_tlv(b"\x30")

    def test_uptime_text(self):
        self.assertEqual(snmp.uptime_text(100), "1 detik")          # 100 ticks = 1s
        self.assertIn("jam", snmp.uptime_text(100 * 3600 * 5))
        self.assertIn("hari", snmp.uptime_text(100 * 86400 * 3))
        self.assertEqual(snmp.uptime_text(None), "—")
        self.assertEqual(snmp.uptime_text("x"), "—")

    def test_mac_from_bytes(self):
        self.assertEqual(snmp.mac_from_bytes("aabbccddeeff"), "aa:bb:cc:dd:ee:ff")
        self.assertEqual(snmp.mac_from_bytes("bukan-mac"), "bukan-mac")


class TestDiscovery(unittest.TestCase):
    def test_expand_cidr(self):
        ips = expand_targets("192.168.10.0/30")
        self.assertEqual(ips, ["192.168.10.1", "192.168.10.2"])

    def test_expand_rentang(self):
        self.assertEqual(expand_targets("10.0.0.1-4"),
                         ["10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4"])
        self.assertEqual(expand_targets("10.0.0.1-10.0.0.3"),
                         ["10.0.0.1", "10.0.0.2", "10.0.0.3"])

    def test_expand_daftar_dan_dedupe(self):
        self.assertEqual(expand_targets("1.1.1.1, 1.1.1.1 ,8.8.8.8"), ["1.1.1.1", "8.8.8.8"])

    def test_hostname_dibiarkan(self):
        self.assertEqual(expand_targets("router.internal"), ["router.internal"])

    def test_vendor_of(self):
        self.assertEqual(vendor_of("B8:27:EB:11:22:33"), "Raspberry Pi")
        self.assertEqual(vendor_of("00:0C:29:AA:BB:CC"), "VMware")
        self.assertEqual(vendor_of("").__len__(), 0)
        self.assertEqual(vendor_of("FF:FF:FF:FF:FF:FF"), "tidak dikenal")

    def test_parse_arp(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "arp"
            p.write_text(
                "IP address       HW type     Flags       HW address            Mask     Device\n"
                "192.168.1.1      0x1         0x2         b8:27:eb:11:22:33     *        eth0\n"
                "192.168.1.9      0x1         0x0         00:00:00:00:00:00     *        eth0\n"
                "192.168.1.7      0x1         0x2         aa:bb:cc:dd:ee:ff     *        wlan0\n")
            table = parse_arp(p)
            self.assertEqual(table["192.168.1.1"], "b8:27:eb:11:22:33")
            self.assertNotIn("192.168.1.9", table)
            self.assertEqual(table["192.168.1.7"], "aa:bb:cc:dd:ee:ff")

    def test_load_oui_berkas_tidak_ada_tetap_jalan(self):
        self.assertIn("B827EB", load_oui("/tidak/ada/oui.txt"))


class TestModel(unittest.TestCase):
    def test_guess_kind(self):
        self.assertIs(guess_kind("RouterOS 7.1", "MikroTik", []), Kind.ROUTER)
        self.assertIs(guess_kind("Linux server 6.1", "Dell", [22]), Kind.SERVER)
        self.assertIs(guess_kind("", "Brother", [9100]), Kind.PRINTER)
        self.assertIs(guess_kind("", "", []), Kind.UNKNOWN)
        self.assertIs(guess_kind("", "Xiaomi", []), Kind.HOST)

    def test_by_kind_dan_serialisasi(self):
        inv = Inventory(target_spec="uji", scanned=2)
        inv.hosts = [Host(ip="10.0.0.2", kind=Kind.HOST),
                     Host(ip="10.0.0.1", kind=Kind.ROUTER)]
        kinds = inv.by_kind()
        self.assertIn("router", kinds)
        self.assertEqual(kinds["router"][0].ip, "10.0.0.1")
        d = inv.as_dict()
        self.assertEqual(d["summary"]["router"], 1)
        json.dumps(d)


class TestTopology(unittest.TestCase):
    def _inv(self) -> Inventory:
        inv = Inventory(target_spec="10.0.0.0/29", gateway="10.0.0.1", finished="t")
        inv.hosts = [
            Host(ip="10.0.0.1", kind=Kind.ROUTER, sys_name="gw", mac="aa:bb:cc:dd:ee:01"),
            Host(ip="10.0.0.2", kind=Kind.HOST, sys_name="pc-1", mac="aa:bb:cc:dd:ee:02"),
            Host(ip="10.0.0.3", kind=Kind.PRINTER, sys_name="prn", mac="aa:bb:cc:dd:ee:03"),
        ]
        return inv

    def test_gateway_dari_proc_route(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "route"
            p.write_text(
                "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\n"
                "wlp3s0\t00000000\t0101A8C0\t0003\t0\t0\t600\t00000000\t0\t0\n"
                "wlp3s0\t0001A8C0\t00000000\t0001\t0\t0\t600\t00FFFFFF\t0\t0\n")
            self.assertEqual(topology.default_gateway(p), "192.168.1.1")
        self.assertEqual(topology.default_gateway("/tidak/ada"), "")

    def test_dot_memuat_semua_node(self):
        dot = topology.to_dot(self._inv())
        self.assertIn("10.0.0.2", dot)
        self.assertIn('"10.0.0.1" -- "10.0.0.2"', dot)
        self.assertTrue(dot.startswith("graph netscout"))

    def test_svg_valid_dan_memuat_host(self):
        svg = topology.to_svg(self._inv())
        self.assertTrue(svg.startswith("<svg"))
        self.assertTrue(svg.rstrip().endswith("</svg>"))
        for ip in ("10.0.0.2", "10.0.0.3"):
            self.assertIn(ip, svg)
        self.assertIn("gateway", svg)


class TestReport(unittest.TestCase):
    def _inv(self) -> Inventory:
        inv = Inventory(target_spec="10.0.0.0/29", started="a", finished="b",
                        scanned=6, gateway="10.0.0.1", community="public")
        inv.hosts = [Host(ip="10.0.0.2", mac="aa:bb:cc:dd:ee:02", vendor="Dell",
                          sys_name="pc-1", kind=Kind.SERVER, uptime="2 jam 3 menit",
                          open_ports=[22, 443])]
        return inv

    def test_text(self):
        t = report_mod.to_text(self._inv())
        self.assertIn("INVENTARIS JARINGAN", t)
        self.assertIn("pc-1", t)

    def test_markdown(self):
        md = report_mod.to_markdown(self._inv())
        self.assertIn("| IP | MAC |", md)
        self.assertIn("`10.0.0.2`", md)

    def test_json(self):
        d = json.loads(report_mod.to_json(self._inv()))
        self.assertEqual(d["summary"]["server"], 1)

    def test_csv(self):
        import csv as _csv
        import io
        rows = list(_csv.DictReader(io.StringIO(report_mod.to_csv(self._inv()))))
        self.assertEqual(rows[0]["ip"], "10.0.0.2")
        self.assertEqual(rows[0]["port_terbuka"], "22 443")

    def test_write_termasuk_topologi(self):
        with tempfile.TemporaryDirectory() as td:
            files = report_mod.write(Path(td), self._inv(), ["text", "md", "json", "csv"],
                                     svg="<svg></svg>", dot="graph {}")
            names = {f.suffix for f in files}
            self.assertIn(".svg", names)
            self.assertIn(".dot", names)
            self.assertEqual(len(files), 6)


class TestCli(unittest.TestCase):
    def test_scan_localhost(self):
        with tempfile.TemporaryDirectory() as td:
            code = __import__("netscout.cli", fromlist=["main"]).main(
                ["scan", "127.0.0.1", "--no-snmp", "--out", td,
                 "--format", "json,svg,dot", "--quiet"])
            data = json.loads(next(Path(td).glob("netscout-*.json")).read_text())
            self.assertEqual(len(data["hosts"]), 1)
            self.assertEqual(data["hosts"][0]["ip"], "127.0.0.1")
            self.assertEqual(code, 0)

    def test_rentang_kosong_tetap_menghasilkan_laporan(self):
        with tempfile.TemporaryDirectory() as td:
            from netscout.cli import main
            code = main(["scan", "192.0.2.251-252", "--no-snmp", "--out", td,
                         "--format", "json", "--quiet", "--ping-timeout", "1"])
            data = json.loads(next(Path(td).glob("netscout-*.json")).read_text())
            self.assertEqual(data["scanned"], 2)
            self.assertIsInstance(data["hosts"], list)
            self.assertIn(code, (0, 1))


if __name__ == "__main__":
    unittest.main(verbosity=2)
