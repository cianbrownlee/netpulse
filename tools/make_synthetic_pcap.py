#!/usr/bin/env python3
"""Write NetPulse's deterministic test captures into sample_pcaps/.

The frames are assembled here, independently of the C++ parser, so replaying these files
through NetPulse is an end-to-end check that the pipeline sees what is actually there.
Expected results are printed at the end; CMake's replay tests check them.

synthetic.pcap: parser and counting coverage (64 frames over ~10 s):
  TCP  40  - an HTTPS download (handshake, data, ACKs) and a short HTTP exchange, one frame
             of which carries an 802.1Q VLAN tag
  UDP  16  - a DNS query/response and a steady call-like stream from a second device
  ICMP  2  - an echo request/reply (counted as "other IPv4")
  non-IPv4 3 - two ARP frames and one IPv6 frame
  malformed 3 - a runt frame, an IPv4 header with IHL 3, a TCP header with data offset 2

Large frames are stored truncated to 96 bytes (as a header-only capture would) with their
real on-the-wire length recorded, which exercises wire length > captured length.

traffic_mix.pcap: classifier and status coverage (~70 s), one of each traffic pattern:
  streaming      HTTPS, ~1.5 MB bursts every 5 s, download only        (t = 0..56 s)
  call           UDP 3478, ~200-byte packets both ways, 10/s each way    (t = 2..62 s)
  browsing       8 short HTTPS exchanges of ~50 kB with different hosts
  background     DNS lookups to the router before each page
  other          an interactive SSH session, small packets every 2 s
  file transfer  continuous ~10 MB/s HTTPS download                     (t = 60..70 s)
The download at the end is far above the laptop's own average, so the status line should
read "using a lot more data than usual". Large segments are recorded the way Linux captures
show them with receive offload (GRO): one ~60 kB record standing for many wire packets.

Usage: python3 tools/make_synthetic_pcap.py [output_dir]
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


LAN_ROUTER = (192, 168, 1, 1)
PHONE = (192, 168, 1, 40)
VIDEO = (198, 51, 100, 20)
SSH_HOST = (198, 51, 100, 77)
CALL_RELAY = (203, 0, 113, 50)
MIRROR = (203, 0, 113, 80)


def segment(src, sport, dst, dport, proto, payload_len, flags=ACK):
    """Headers of one packet (or one GRO-merged segment) and its full on-the-wire length."""
    if proto == 6:
        headers = ethernet(0x0800) + ipv4(src, dst, 6, 20 + payload_len) + tcp(sport, dport, flags)
    else:
        headers = (ethernet(0x0800) + ipv4(src, dst, 17, 8 + payload_len)
                   + udp(sport, dport, payload_len))
    return headers, len(headers) + payload_len


def build_traffic_mix():
    records = []  # (seconds from start, header bytes, wire length)

    def add(t, *args, **kwargs):
        headers, wire = segment(*args, **kwargs)
        records.append((t, headers, wire))

    # Streaming: a 25-segment burst (~1.5 MB) every 5 s, an ACK every 5 segments.
    for burst in range(12):
        start = burst * 5 + 0.1
        for i in range(25):
            t = start + i * 0.03
            add(t, VIDEO, 443, LAPTOP, 52000, 6, 60_000)
            if i % 5 == 4:
                add(t + 0.001, LAPTOP, 52000, VIDEO, 443, 6, 0)

    # Call: 10 packets a second each way for 60 s.
    for i in range(600):
        t = 2.0 + i * 0.1
        add(t, PHONE, 40000, CALL_RELAY, 3478, 17, 172)
        add(t + 0.05, CALL_RELAY, 3478, PHONE, 40000, 17, 172)

    # Browsing: a DNS lookup, then a short HTTPS exchange with a different host each time.
    for n, start in enumerate([3, 8, 15, 22, 30, 37, 44, 51]):
        host, port = (151, 101, 10 + n, 5), 53000 + n
        add(start, LAPTOP, 50000, LAN_ROUTER, 53, 17, 30)
        add(start + 0.02, LAN_ROUTER, 53, LAPTOP, 50000, 17, 60)
        add(start + 0.05, LAPTOP, port, host, 443, 6, 0, flags=SYN)
        add(start + 0.07, host, 443, LAPTOP, port, 6, 0, flags=SYN | ACK)
        add(start + 0.08, LAPTOP, port, host, 443, 6, 0)
        add(start + 0.10, LAPTOP, port, host, 443, 6, 600, flags=ACK | PSH)
        for i in range(6):
            add(start + 0.15 + i * 0.02, host, 443, LAPTOP, port, 6, 8_000)
        add(start + 0.30, LAPTOP, port, host, 443, 6, 0)

    # Interactive SSH: keystrokes and echoes every 2 s.
    for i in range(35):
        t = 1.0 + i * 2
        add(t, LAPTOP, 54000, SSH_HOST, 22, 6, 48, flags=ACK | PSH)
        add(t + 0.05, SSH_HOST, 22, LAPTOP, 54000, 6, 96, flags=ACK | PSH)

    # File transfer: a continuous ~10 MB/s download for the last 10 s.
    i = 0
    while 60.0 + i * 0.006 < 70.0:
        t = 60.0 + i * 0.006
        add(t, MIRROR, 443, LAPTOP, 55000, 6, 60_000)
        if i % 10 == 9:
            add(t + 0.001, LAPTOP, 55000, MIRROR, 443, 6, 0)
        i += 1

    records.sort(key=lambda r: r[0])
    return records


def write_pcap(path, records):
    """records: (seconds from start, frame bytes from Ethernet onward, wire length)."""
    with path.open("wb") as f:
        # Classic pcap global header: magic, v2.4, UTC, sigfigs 0, snaplen, LINKTYPE_ETHERNET
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, SNAPLEN, 1))
        start_us = 1_700_000_000 * 1_000_000
        for t, frame, wire in records:
            ts_us = start_us + round(t * 1_000_000)
            captured = frame[:SNAPLEN]
            f.write(struct.pack("<IIII", ts_us // 1_000_000, ts_us % 1_000_000,
                                len(captured), wire))
            f.write(captured)


def main():
    out_dir = Path(sys.argv[1]) if len(sys.argv) > 1 else (
        Path(__file__).resolve().parent.parent / "sample_pcaps")

    # synthetic.pcap: one frame every 150 ms, so replay shows a real throughput shape.
    frames = build_frames()
    synthetic = out_dir / "synthetic.pcap"
    write_pcap(synthetic, [(i * 0.15, frame, len(frame)) for i, (_, frame) in enumerate(frames)])

    counts = {}
    for label, _ in frames:
        counts[label] = counts.get(label, 0) + 1
    total_bytes = sum(len(frame) for _, frame in frames)
    print(f"wrote {synthetic} ({synthetic.stat().st_size} bytes on disk)")
    print(f"  packets={len(frames)} bytes={total_bytes} tcp={counts.get('tcp', 0)} "
          f"udp={counts.get('udp', 0)} other_ipv4={counts.get('other_ipv4', 0)} "
          f"non_ipv4={counts.get('non_ipv4', 0)} malformed={counts.get('malformed', 0)}")

    mix = build_traffic_mix()
    traffic_mix = out_dir / "traffic_mix.pcap"
    write_pcap(traffic_mix, mix)
    print(f"wrote {traffic_mix} ({traffic_mix.stat().st_size} bytes on disk)")
    print(f"  records={len(mix)} wire_bytes={sum(w for _, _, w in mix)}")
    print("  expect: categories: streaming=1 browsing=8 calls-gaming=1 file-transfer=1 other=1")
    print("  expect: status: device-above-usual")


if __name__ == "__main__":
    main()
