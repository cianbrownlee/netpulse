#!/usr/bin/env python3
"""Writes fuzz/corpus/dns/: hand-made DNS messages that start the DNS fuzzer on the shapes the
sample captures don't have (AAAA records, CNAME chains, mDNS announcements, several answers).

Usage: make_dns_seeds.py [OUT_DIR]   (default: fuzz/corpus/dns next to this script)
"""

import ipaddress
import os
import struct
import sys


def name(text):
    out = b""
    for label in text.split("."):
        out += bytes([len(label)]) + label.encode()
    return out + b"\0"


def pointer(offset):
    return struct.pack("!H", 0xC000 | offset)


def header(flags, questions, answers, ident=0x1234):
    return struct.pack("!HHHHHH", ident, flags, questions, answers, 0, 0)


def record(owner, rtype, data, klass=1, ttl=300):
    return owner + struct.pack("!HHIH", rtype, klass, ttl, len(data)) + data


def a(text):
    return ipaddress.IPv4Address(text).packed


def aaaa(text):
    return ipaddress.IPv6Address(text).packed


def seeds():
    question = name("www.example.com") + struct.pack("!HH", 1, 1)  # starts at offset 12

    yield "a_answer", header(0x8180, 1, 1) + question + record(pointer(12), 1, a("192.0.2.10"))

    q6 = name("www.example.com") + struct.pack("!HH", 28, 1)
    yield "aaaa_answer", header(0x8180, 1, 1) + q6 + record(pointer(12), 28, aaaa("2001:db8::10"))

    yield "several_answers", header(0x8180, 1, 3) + question + b"".join(
        record(pointer(12), 1, a("192.0.2.%d" % i)) for i in (1, 2, 3))

    # www.example.com is a CNAME for edge.cdn.example.net, which has the address; the A
    # record's owner is a pointer into the CNAME's data.
    cname_data_offset = 12 + len(question) + 2 + 10  # after the CNAME record's owner + fixed fields
    cname_data = name("edge.cdn")[:-1] + name("example.net")
    yield "cname_chain", (header(0x8180, 1, 2) + question + record(pointer(12), 5, cname_data)
                          + record(pointer(cname_data_offset), 1, a("192.0.2.20")))

    # mDNS: no question; the device announces its own name, with the cache-flush bit set.
    yield "mdns_announcement", (header(0x8400, 0, 2, ident=0)
                                + record(name("living-room-tv.local"), 1, a("192.168.1.50"), klass=0x8001, ttl=120)
                                + record(pointer(12), 28, aaaa("2001:db8:1::50"), klass=0x8001, ttl=120))

    # A refusal and a query: neither may produce names.
    yield "nxdomain", header(0x8183, 1, 0) + question
    yield "query", header(0x0100, 1, 0) + question


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                                              "corpus", "dns")
    os.makedirs(out, exist_ok=True)
    for label, message in seeds():
        with open(os.path.join(out, label + ".bin"), "wb") as f:
            f.write(message)


if __name__ == "__main__":
    main()
