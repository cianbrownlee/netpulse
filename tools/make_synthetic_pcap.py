#!/usr/bin/env python3
"""Write sample_pcaps/synthetic.pcap: a small, deterministic capture with known contents.

The frames are assembled here, independently of the C++ parser, so replaying this file
through NetPulse is an end-to-end check that the pipeline counts what is actually there.
The expected totals are printed at the end; tests/CMake's replay test checks them.

Mix of traffic (64 frames):
  TCP  40  - an HTTPS download (handshake, data, ACKs) and a short HTTP exchange, one frame
             of which carries an 802.1Q VLAN tag
  UDP  16  - a DNS query/response and a steady call-like stream from a second device
  ICMP  2  - an echo request/reply (counted as "other IPv4")
  non-IPv4 3 - two ARP frames and one IPv6 frame
  malformed 3 - a runt frame, an IPv4 header with IHL 3, a TCP header with data offset 2

Large frames are stored truncated to 96 bytes (as a header-only capture would) with their
real on-the-wire length recorded, which exercises wire length > captured length.

Usage: python3 tools/make_synthetic_pcap.py [output_path]
"""

import struct
import sys
from pathlib import Path

SNAPLEN = 96

LAPTOP = (192, 168, 1, 14)
TV = (192, 168, 1, 31)
WEB = (93, 184, 216, 34)
CDN = (151, 101, 1, 69)
DNS = (8, 8, 8, 8)
TURN = (142, 250, 1, 1)
ONE = (1, 1, 1, 1)

SYN, ACK, PSH, FIN = 0x02, 0x10, 0x08, 0x01


def ethernet(ethertype, vlan=None):
    header = bytes.fromhex("020000000002" "020000000001")
    if vlan is not None:
        header += struct.pack("!HH", 0x8100, vlan)
    return header + struct.pack("!H", ethertype)


def ipv4(src, dst, proto, payload_len, ihl=5):
    total = ihl * 4 + payload_len
    header = struct.pack("!BBHHHBBH4s4s", (4 << 4) | ihl, 0, total, 0x1234, 0x4000, 64, proto, 0,
                         bytes(src), bytes(dst))
    return header


def tcp(sport, dport, flags, data_offset=5):
    return struct.pack("!HHIIBBHHH", sport, dport, 1000, 2000, data_offset << 4, flags, 65535, 0, 0)


def udp(sport, dport, payload_len):
    return struct.pack("!HHHH", sport, dport, 8 + payload_len, 0)


def tcp_frame(src, sport, dst, dport, flags, payload_len=0, vlan=None):
    return (ethernet(0x0800, vlan) + ipv4(src, dst, 6, 20 + payload_len) + tcp(sport, dport, flags)
            + b"\xab" * payload_len)


def udp_frame(src, sport, dst, dport, payload_len):
    return (ethernet(0x0800) + ipv4(src, dst, 17, 8 + payload_len) + udp(sport, dport, payload_len)
            + b"\xab" * payload_len)


def build_frames():
    frames = []  # (label, bytes)

    # HTTPS download: laptop:51000 <-> web:443 (35 frames)
    frames.append(("tcp", tcp_frame(LAPTOP, 51000, WEB, 443, SYN)))
    frames.append(("tcp", tcp_frame(WEB, 443, LAPTOP, 51000, SYN | ACK)))
    frames.append(("tcp", tcp_frame(LAPTOP, 51000, WEB, 443, ACK)))
    for i in range(25):
        frames.append(("tcp", tcp_frame(WEB, 443, LAPTOP, 51000, ACK | PSH, 1460)))
        if i % 4 == 3:
            frames.append(("tcp", tcp_frame(LAPTOP, 51000, WEB, 443, ACK)))
    frames.append(("tcp", tcp_frame(LAPTOP, 51000, WEB, 443, ACK)))  # 3 + 25 + 6 + 1 = 35

    # Short HTTP exchange: laptop:51002 <-> cdn:80 (5 frames, one VLAN-tagged)
    frames.append(("tcp", tcp_frame(LAPTOP, 51002, CDN, 80, ACK | PSH, 120)))
    frames.append(("tcp", tcp_frame(CDN, 80, LAPTOP, 51002, ACK | PSH, 600, vlan=10)))
    frames.append(("tcp", tcp_frame(LAPTOP, 51002, CDN, 80, ACK)))
    frames.append(("tcp", tcp_frame(LAPTOP, 51002, CDN, 80, FIN | ACK)))
    frames.append(("tcp", tcp_frame(CDN, 80, LAPTOP, 51002, FIN | ACK)))

    # DNS: laptop:50000 <-> 8.8.8.8:53 (2 frames)
    frames.append(("udp", udp_frame(LAPTOP, 50000, DNS, 53, 30)))
    frames.append(("udp", udp_frame(DNS, 53, LAPTOP, 50000, 46)))

    # Call-like stream: tv:40000 <-> turn:3478, small regular packets both ways (14 frames)
    for i in range(14):
        if i % 2 == 0:
            frames.append(("udp", udp_frame(TV, 40000, TURN, 3478, 160)))
        else:
            frames.append(("udp", udp_frame(TURN, 3478, TV, 40000, 160)))

    # ICMP echo request/reply (2 frames)
    icmp = struct.pack("!BBHHH", 8, 0, 0, 1, 1) + b"\x00" * 32
    frames.append(("other_ipv4", ethernet(0x0800) + ipv4(LAPTOP, ONE, 1, len(icmp)) + icmp))
    reply = struct.pack("!BBHHH", 0, 0, 0, 1, 1) + b"\x00" * 32
    frames.append(("other_ipv4", ethernet(0x0800) + ipv4(ONE, LAPTOP, 1, len(reply)) + reply))

    # Non-IPv4: ARP request, ARP reply, one IPv6 frame (3 frames)
    arp = bytes(28)
    frames.append(("non_ipv4", ethernet(0x0806) + arp))
    frames.append(("non_ipv4", ethernet(0x0806) + arp))
    frames.append(("non_ipv4", ethernet(0x86DD) + bytes(40)))

    # Malformed (3 frames)
    frames.append(("malformed", bytes(10)))  # runt: shorter than an Ethernet header
    bad_ihl = bytearray(ipv4(LAPTOP, WEB, 6, 20))
    bad_ihl[0] = (4 << 4) | 3
    frames.append(("malformed", ethernet(0x0800) + bytes(bad_ihl) + tcp(1, 2, ACK)))
    frames.append(("malformed", ethernet(0x0800) + ipv4(LAPTOP, WEB, 6, 20)
                   + tcp(51003, 443, ACK, data_offset=2)))

    return frames


def main():
    out = Path(sys.argv[1]) if len(sys.argv) > 1 else (
        Path(__file__).resolve().parent.parent / "sample_pcaps" / "synthetic.pcap")
    frames = build_frames()

    with out.open("wb") as f:
        # Classic pcap global header: magic, v2.4, UTC, sigfigs 0, snaplen, LINKTYPE_ETHERNET
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, SNAPLEN, 1))
        ts_us = 1_700_000_000 * 1_000_000
        for _, frame in frames:
            captured = frame[:SNAPLEN]
            f.write(struct.pack("<IIII", ts_us // 1_000_000, ts_us % 1_000_000,
                                len(captured), len(frame)))
            f.write(captured)
            ts_us += 150_000  # spread over ~10 s so replay shows a real throughput shape

    counts = {}
    for label, _ in frames:
        counts[label] = counts.get(label, 0) + 1
    total_bytes = sum(len(frame) for _, frame in frames)
    print(f"wrote {out} ({out.stat().st_size} bytes on disk)")
    print(f"packets={len(frames)} bytes={total_bytes} tcp={counts.get('tcp', 0)} "
          f"udp={counts.get('udp', 0)} other_ipv4={counts.get('other_ipv4', 0)} "
          f"non_ipv4={counts.get('non_ipv4', 0)} malformed={counts.get('malformed', 0)}")


if __name__ == "__main__":
    main()
