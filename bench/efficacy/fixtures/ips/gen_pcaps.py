#!/usr/bin/env python3
"""Generate the IPS efficacy PCAP corpus.

This script materialises the small, deterministic PCAP fixtures the
`sng-efficacy` IPS driver replays through Suricata. They are committed
as binary fixtures so the harness has no runtime dependency on scapy;
re-run this script only when the corpus itself needs to change.

Each "bad" PCAP carries a byte pattern that the companion
`test.rules` file alerts on (a stand-in for a real exploit / malware
signature). Each "good" PCAP carries benign traffic that must NOT
alert, so the harness can measure the false-positive rate.
"""
import os

from scapy.all import Ether, IP, TCP, UDP, Raw, wrpcap

HERE = os.path.dirname(os.path.abspath(__file__))

CLIENT = "10.0.0.50"
SERVER = "93.184.216.34"


def http_to(server, payload, sport=40000, dport=80):
    """A single client->server TCP segment carrying `payload`."""
    return (
        Ether()
        / IP(src=CLIENT, dst=server)
        / TCP(sport=sport, dport=dport, flags="PA", seq=1)
        / Raw(load=payload)
    )


def http_from(server, payload, sport=80, dport=40000):
    """A single server->client TCP segment carrying `payload` (an HTTP
    response, e.g. a file download)."""
    return (
        Ether()
        / IP(src=server, dst=CLIENT)
        / TCP(sport=sport, dport=dport, flags="PA", seq=1)
        / Raw(load=payload)
    )


def dns_query(qname, sport=50000):
    """A benign-looking UDP/53 packet carrying `qname` as raw bytes."""
    return (
        Ether()
        / IP(src=CLIENT, dst="1.1.1.1")
        / UDP(sport=sport, dport=53)
        / Raw(load=qname)
    )


# Internal RFC1918 hosts for east-west (lateral-movement) traffic. Real
# lateral movement is internal->internal, not client->internet.
INTERNAL_SRC = "10.0.0.50"
INTERNAL_DST = "10.0.0.77"


def smb_between(payload, src=INTERNAL_SRC, dst=INTERNAL_DST, sport=44444, dport=445):
    """An internal->internal TCP/445 (SMB) segment carrying `payload` —
    the transport PsExec-style lateral movement rides on."""
    return (
        Ether()
        / IP(src=src, dst=dst)
        / TCP(sport=sport, dport=dport, flags="PA", seq=1)
        / Raw(load=payload)
    )


# --- known-bad fixtures: MUST trigger an alert -----------------------
BAD = {
    # EICAR antivirus test string — the industry-standard benign
    # malware marker that every engine is expected to flag. Modelled as a
    # server->client HTTP response (the EICAR file being downloaded), which
    # is the realistic direction for a malware delivery.
    "bad-eicar.pcap": http_from(
        SERVER,
        b"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n\r\n"
        b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*",
    ),
    # Directory-traversal exploit attempt in a request URI.
    "bad-traversal.pcap": http_to(
        SERVER,
        b"GET /cgi-bin/../../../../etc/passwd HTTP/1.1\r\nHost: victim\r\n\r\n",
    ),
    # SQL-injection probe.
    "bad-sqli.pcap": http_to(
        SERVER,
        b"GET /item?id=1%27%20OR%20%271%27%3D%271%20UNION%20SELECT%20password"
        b"%20FROM%20users HTTP/1.1\r\nHost: victim\r\n\r\n",
    ),
    # Known-bad C2 beacon marker in a TCP payload.
    "bad-c2-beacon.pcap": http_to(
        SERVER,
        b"POST /gate.php HTTP/1.1\r\nUser-Agent: SNG-EFFICACY-C2-BEACON\r\n\r\n",
        dport=8080,
    ),
    # Ransomware ransom-note delivered as an HTTP response body — the
    # extortion text dropped on the victim after encryption.
    "bad-ransomware.pcap": http_from(
        SERVER,
        b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n"
        b"!!! ATTENTION !!! YOUR FILES HAVE BEEN ENCRYPTED. "
        b"Send 0.5 bitcoin to recover them. See README_FOR_DECRYPT.txt",
    ),
    # Lateral movement: PsExec service install over SMB (TCP/445),
    # internal->internal — the hallmark of east-west spread.
    "bad-lateral-smb.pcap": smb_between(
        b"\x00\x00\x00\x90\xffSMB%PSEXESVC.exe\x00remote service install",
    ),
    # DNS tunneling: an abnormally long, high-entropy encoded label in a
    # UDP/53 query — data exfiltration over DNS.
    "bad-dns-tunnel.pcap": dns_query(
        b"\x3ck7n2p9q4r8s3t6v1w5x0y2z8a4b7c9d3e6f1g5h0j2k4m7n9p3q6"
        b"\x06tunnel\x07example\x00",
    ),
}

# --- known-good fixtures: MUST NOT alert -----------------------------
GOOD = {
    "good-https-get.pcap": http_to(
        SERVER, b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n"
    ),
    "good-api-call.pcap": http_to(
        SERVER,
        b"POST /v2/orders HTTP/1.1\r\nHost: api.example.com\r\n"
        b"Content-Type: application/json\r\n\r\n{\"sku\":\"ABC\",\"qty\":2}",
        dport=443,
    ),
    "good-dns.pcap": dns_query(b"\x07example\x03com\x00"),
    "good-health.pcap": http_to(
        SERVER, b"GET /healthz HTTP/1.1\r\nHost: lb.internal\r\n\r\n"
    ),
    # Benign internal SMB file access (TCP/445) — east-west traffic that
    # must NOT alert as lateral movement.
    "good-smb.pcap": smb_between(
        b"\x00\x00\x00\x55\xffSMB\x72\x00\x00\x00\x00 negotiate protocol request",
    ),
    # Benign short DNS TXT lookup (SPF record) — must NOT alert as
    # tunneling.
    "good-dns-txt.pcap": dns_query(b"\x07example\x03com\x00\x00\x10\x00\x01"),
}


def main():
    for name, pkt in {**BAD, **GOOD}.items():
        path = os.path.join(HERE, name)
        wrpcap(path, [pkt])
        print(f"wrote {path}")


if __name__ == "__main__":
    main()
