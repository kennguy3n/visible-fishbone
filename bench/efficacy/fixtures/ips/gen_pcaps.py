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


def dns_query(qname, sport=50000):
    """A benign-looking UDP/53 packet carrying `qname` as raw bytes."""
    return (
        Ether()
        / IP(src=CLIENT, dst="1.1.1.1")
        / UDP(sport=sport, dport=53)
        / Raw(load=qname)
    )


# --- known-bad fixtures: MUST trigger an alert -----------------------
BAD = {
    # EICAR antivirus test string — the industry-standard benign
    # malware marker that every engine is expected to flag.
    "bad-eicar.pcap": http_to(
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
}


def main():
    for name, pkt in {**BAD, **GOOD}.items():
        path = os.path.join(HERE, name)
        wrpcap(path, [pkt])
        print(f"wrote {path}")


if __name__ == "__main__":
    main()
