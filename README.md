# netscout

**Inventaris & topologi jaringan** dari terminal — ping sweep, identitas perangkat lewat SNMP,
MAC/vendor dari tabel ARP, lalu inventaris + **diagram topologi**.

Tidak ada dependensi: **SNMPv2c-nya ditulis dari nol** (encoder/decoder BER/ASN.1) dan
diagram SVG-nya digambar sendiri — tanpa `pysnmp`, tanpa `graphviz`.

[![CI](https://github.com/myusufcs/netscout/actions/workflows/ci.yml/badge.svg)](https://github.com/myusufcs/netscout/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![Zero deps](https://img.shields.io/badge/dependencies-none-success)
![License](https://img.shields.io/badge/license-MIT-green)

---

## Kenapa ini ada

Pertanyaan "ada perangkat apa saja di jaringan ini?" biasanya dijawab dengan buka spreadsheet
manual, atau `nmap -sn` lalu disalin tangan. `netscout` menjawabnya sekali jalan: siapa yang
hidup, MAC & vendornya siapa, jenisnya apa, dan bagaimana topologinya — lalu menyimpannya
sebagai CSV/JSON supaya bisa dibandingkan dari waktu ke waktu.

## Keluaran contoh

```
$ netscout scan 192.168.10.0/29 --community public --ports 22,80,443
memindai 6 alamat (ICMP, 64 paralel)...
  hidup: 192.168.10.1
  hidup: 192.168.10.2
  hidup: 192.168.10.5
================================================================================
  INVENTARIS JARINGAN — 192.168.10.0/29
================================================================================
dipindai  : 6 alamat · hidup 3
gateway   : 192.168.10.1
SNMP      : community 'public'
komposisi : host 1 · printer 1 · router 1

  IP              MAC                VEN            JENIS    NAMA              DESKRIPSI
--------------------------------------------------------------------------------
🛰️ 192.168.10.1   74:ac:b9:11:22:33  Ubiquiti       router   gw-utama          EdgeRouter X 2.0.9
💻 192.168.10.2   b8:27:eb:44:55:66  Raspberry Pi   host     pi-dashboard      Linux 6.1.21 raspberrypi
🖨️ 192.168.10.5   3c:2a:f4:99:88:77  Brother        printer  prn-lantai2       Brother NC-8100w
```

Hasilnya ditulis ke `--out` sebagai **teks + Markdown + JSON + CSV**, plus:

- `*-topologi.svg` — diagram siap dibuka di browser (gateway di tengah, host mengelilinginya,
  warna per jenis perangkat)
- `*-topologi.dot` — sumber Graphviz, kalau mau dirender sendiri dengan `dot`

> Contoh di atas dirender dari lingkungan lab; jalankan di jaringan milik Anda sendiri.

## Instalasi & pemakaian

Zero dependency — cukup standard library Python 3.10+ (`ping` dari sistem untuk ICMP).

```bash
git clone https://github.com/myusufcs/netscout
cd netscout

python3 -m netscout scan 192.168.1.0/24                          # seluruh subnet
python3 -m netscout scan 192.168.1.1-254 --ports 22,80,443       # rentang alamat
python3 -m netscout scan 192.168.1.10,192.168.1.20 --no-snmp     # host tertentu
python3 -m netscout scan 10.0.0.0/24 --community rahasia \
    --out laporan --format text,csv,json,svg,dot
```

| Opsi | Arti |
|---|---|
| `--community` | Community SNMP (default `public`) |
| `--no-snmp` | Lewati SNMP (ping + ARP saja) |
| `--no-arp` | Jangan baca tabel ARP |
| `--ports 22,80,443` | Sekalian cek port TCP |
| `--oui FILE` | Pakai berkas OUI IEEE lengkap (mis. `/usr/share/ieee-data/oui.txt`) |
| `--workers N` | Paralelisme ping (default 64) |

## Bagaimana SNMP-nya bekerja

`snmp.py` mengimplementasikan protokol yang diperlukan saja — cukup untuk inventaris:

1. **Encoder BER** — OID (varint base-128), INTEGER, OCTET STRING, NULL, dan struktur PDU.
2. **Decoder** — TLV dengan panjang pendek/panjang, lalu nilai: `OctetString`, `Integer32`,
   `Counter32`, `TimeTicks`, `IpAddress`, `NULL`, `noSuchObject`, `endOfMibView`.
3. **Operasi** — `GET` (satu kali untuk sysDescr/sysName/sysUpTime) dan `GETNEXT` berulang
   untuk menelusuri tabel (`ifTable`, `ipAddrTable`).

SNMPv3 tidak didukung — itu memerlukan protokol jauh lebih besar (USM, enkripsi). Untuk
inventaris di jaringan internal, v2c memadai; dan sejak awal tool ini menandai dengan jelas
kalau perangkat tidak menjawab SNMP (kolom keterangan) alih-alih menebak.

## Desain

```
netscout/
  cli.py        # alur: expand target -> sweep -> enrich -> inventaris -> laporan
  snmp.py       # SNMPv2c dari nol (BER/ASN.1, GET, GETNEXT)
  discovery.py  # CIDR/rentang, ping sweep paralel, tabel ARP, vendor OUI
  topology.py   # gateway default (/proc/net/route), SVG digambar sendiri, DOT
  model.py      # Host/Inventory + tebakan jenis perangkat
  report.py     # teks / Markdown / JSON / CSV (+ SVG & DOT)
  util.py       # cek port TCP
```

Semua bagian yang berisi logika murni — codec SNMP, parsing ARP, ekspansi CIDR, pembuat
SVG/DOT — dipisah dari I/O sehingga bisa diuji **tanpa jaringan** (29 test, satu di antaranya
memakai `127.0.0.1`).

## Batasan yang jujur

- **Hanya perangkat yang merespons ICMP** yang ditemukan. Host dengan firewall ICMP akan
  terlewat — untuk itu perlu pemindaian ARP aktif (butuh hak akses lebih) atau fitur
  dari perangkat jaringan itu sendiri.
- Informasi MAC/vendor hanya tersedia untuk host di **segmen lokal yang sama**, karena
  berasal dari tabel ARP. Host di balik router tidak akan punya MAC.
- Vendor berasal dari tabel OUI bawaan (ringkas). Pakai `--oui` dengan berkas IEEE lengkap
  untuk akurasi penuh — dan ingat, OUI menunjukkan pemilik blok MAC, bukan selalu pabrikan
  perangkat akhir (VM akan tampil sebagai VMware/Hyper-V).
- Tebakan "jenis perangkat" heuristik dari sysDescr/port. Router dengan SNMP mati tetap
  terlihat seperti host biasa.
- **SNMPv2c mengirim community dalam bentuk teks polos.** Jangan pakai tool ini di jaringan
  yang tidak Anda percaya, dan jangan kirim community produksi lewat tautan publik.

## Etika & izin

Tool ini untuk **jaringan yang Anda kelola sendiri**. Memindai jaringan orang lain tanpa izin
bisa melanggar hukum dan kebijakan. Jalankan dari dalam jaringan yang sama, dan simpan
hasilnya dengan aman — inventaris jaringan adalah peta yang menarik bagi penyerang.

## Uji

```bash
python3 -m unittest discover -s tests -v     # 29 test
```

## Lisensi

MIT — lihat [LICENSE](LICENSE). Copyright (c) 2026 M Yusuf Chairul Saleh.
