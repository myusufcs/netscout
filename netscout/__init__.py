"""netscout — inventaris & topologi jaringan.

Penemuan host (ping sweep), pengayaan identitas lewat SNMP, MAC/vendor dari tabel ARP,
lalu inventaris + diagram topologi.

SNMPv2c diimplementasikan sendiri di `snmp.py` (BER/ASN.1) supaya tidak butuh
dependensi eksternal.
"""
__version__ = "0.1.0"
