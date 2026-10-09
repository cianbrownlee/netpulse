#!/usr/bin/env python3
"""Write NetPulse's deterministic test captures into sample_pcaps/.

The frames are assembled here, independently of the C++ parser, so replaying these files
through NetPulse is an end-to-end check that the pipeline sees what is actually there.
Expected results are printed at the end; CMake's replay tests check them.

synthetic.pcap: parser and counting coverage (72 frames over ~11 s):
  IPv4: an HTTPS download (handshake, data, ACKs) and a short HTTP exchange, one frame of
        which carries an 802.1Q VLAN tag; a DNS query/response; a steady call-like UDP stream
        from a second device; an ICMP echo request/reply
  IPv6: an HTTPS exchange, a DNS query/response, ICMPv6 neighbor solicitation, mDNS behind a
        hop-by-hop extension header, and a later fragment (no transport header)
  non-IP: two ARP frames
  malformed: a runt frame, an IPv4 header with IHL 3, a TCP header with data offset 2

Large frames are stored truncated to 96 bytes (as a header-only capture would) with their
real on-the-wire length recorded, which exercises wire length > captured length.

traffic_mix.pcap: classifier and status coverage (~70 s), one of each traffic pattern:
  streaming      HTTPS, ~1.5 MB bursts every 5 s, download only        (t = 0..56 s)
  call           UDP 3478, ~200-byte packets both ways, 10/s each way    (t = 2..62 s)
  browsing       8 short HTTPS exchanges of ~50 kB with different hosts
  background     DNS lookups to the router before each page, with real answers naming the
                 hosts (and the video, call and download servers), for --dns-names
  other          an interactive SSH session, small packets every 2 s
  file transfer  continuous ~10 MB/s HTTPS download                     (t = 60..70 s)
The download at the end is far above the laptop's own average, so the status line should
read "using a lot more data than usual". Large segments are recorded the way Linux captures
show them with receive offload (GRO): one ~60 kB record standing for many wire packets.

Usage: python3 tools/make_synthetic_pcap.py [output_dir]
"""

import ipaddress
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


def v6(text):
    return ipaddress.IPv6Address(text).packed


def ipv6(src, dst, next_header, payload_len):
    return struct.pack("!IHBB16s16s", 6 << 28, payload_len, next_header, 64, src, dst)


def tcp6_frame(src, sport, dst, dport, flags, payload_len=0):
    return (ethernet(0x86DD) + ipv6(src, dst, 6, 20 + payload_len) + tcp(sport, dport, flags)
            + b"\xab" * payload_len)


def udp6_frame(src, sport, dst, dport, payload_len):
    return (ethernet(0x86DD) + ipv6(src, dst, 17, 8 + payload_len) + udp(sport, dport, payload_len)
            + b"\xab" * payload_len)


LAPTOP6 = v6("2001:db8:1::14")
WEB6 = v6("2606:2800:220:1:248:1893:25c8:1946")
DNS6 = v6("2001:4860:4860::8888")
LAPTOP_LL = v6("fe80::14")
SOLICITED_NODE = v6("ff02::1:ff00:1")
MDNS6 = v6("ff02::fb")


def build_frames():
    # (label, frame bytes, (src, sport, dst, dport, protocol) for IP frames NetPulse should
    # count as conversations, else None). The tuples let main() work out the expected number of
    # flows and hosts here, independently of NetPulse.
    frames = []

    def tcp4(src, sport, dst, dport, flags, payload_len=0, vlan=None):
        frames.append(("tcp", tcp_frame(src, sport, dst, dport, flags, payload_len, vlan),
                       (bytes(src), sport, bytes(dst), dport, 6)))

    def udp4(src, sport, dst, dport, payload_len):
        frames.append(("udp", udp_frame(src, sport, dst, dport, payload_len),
                       (bytes(src), sport, bytes(dst), dport, 17)))

    # HTTPS download: laptop:51000 <-> web:443 (35 frames)
    tcp4(LAPTOP, 51000, WEB, 443, SYN)
    tcp4(WEB, 443, LAPTOP, 51000, SYN | ACK)
    tcp4(LAPTOP, 51000, WEB, 443, ACK)
    for i in range(25):
        tcp4(WEB, 443, LAPTOP, 51000, ACK | PSH, 1460)
        if i % 4 == 3:
            tcp4(LAPTOP, 51000, WEB, 443, ACK)
    tcp4(LAPTOP, 51000, WEB, 443, ACK)  # 3 + 25 + 6 + 1 = 35

    # Short HTTP exchange: laptop:51002 <-> cdn:80 (5 frames, one VLAN-tagged)
    tcp4(LAPTOP, 51002, CDN, 80, ACK | PSH, 120)
    tcp4(CDN, 80, LAPTOP, 51002, ACK | PSH, 600, vlan=10)
    tcp4(LAPTOP, 51002, CDN, 80, ACK)
    tcp4(LAPTOP, 51002, CDN, 80, FIN | ACK)
    tcp4(CDN, 80, LAPTOP, 51002, FIN | ACK)

    # DNS: laptop:50000 <-> 8.8.8.8:53 (2 frames)
    udp4(LAPTOP, 50000, DNS, 53, 30)
    udp4(DNS, 53, LAPTOP, 50000, 46)

    # Call-like stream: tv:40000 <-> turn:3478, small regular packets both ways (14 frames)
    for i in range(14):
        if i % 2 == 0:
            udp4(TV, 40000, TURN, 3478, 160)
        else:
            udp4(TURN, 3478, TV, 40000, 160)

    # ICMP echo request/reply (2 frames)
    icmp = struct.pack("!BBHHH", 8, 0, 0, 1, 1) + b"\x00" * 32
    frames.append(("other_ip", ethernet(0x0800) + ipv4(LAPTOP, ONE, 1, len(icmp)) + icmp,
                   (bytes(LAPTOP), 0, bytes(ONE), 0, 1)))
    reply = struct.pack("!BBHHH", 0, 0, 0, 1, 1) + b"\x00" * 32
    frames.append(("other_ip", ethernet(0x0800) + ipv4(ONE, LAPTOP, 1, len(reply)) + reply,
                   (bytes(ONE), 0, bytes(LAPTOP), 0, 1)))

    # IPv6 (9 frames): an HTTPS exchange, a DNS lookup, neighbor discovery, mDNS behind a
    # hop-by-hop extension header, and the second piece of a fragmented datagram.
    for src, sport, dst, dport, flags, size in [
            (LAPTOP6, 51010, WEB6, 443, SYN, 0), (WEB6, 443, LAPTOP6, 51010, SYN | ACK, 0),
            (LAPTOP6, 51010, WEB6, 443, ACK, 0), (WEB6, 443, LAPTOP6, 51010, ACK | PSH, 1200)]:
        frames.append(("tcp", tcp6_frame(src, sport, dst, dport, flags, size),
                       (src, sport, dst, dport, 6)))
    frames.append(("udp", udp6_frame(LAPTOP6, 50001, DNS6, 53, 30), (LAPTOP6, 50001, DNS6, 53, 17)))
    frames.append(("udp", udp6_frame(DNS6, 53, LAPTOP6, 50001, 60), (DNS6, 53, LAPTOP6, 50001, 17)))
    solicitation = struct.pack("!BBHI16s", 135, 0, 0, 0, LAPTOP6)  # ICMPv6 type 135
    frames.append(("other_ip", ethernet(0x86DD) + ipv6(LAPTOP_LL, SOLICITED_NODE, 58,
                                                         len(solicitation)) + solicitation,
                   (LAPTOP_LL, 0, SOLICITED_NODE, 0, 58)))
    hop_by_hop = struct.pack("!BB6s", 17, 0, bytes(6))  # next header UDP, 8 bytes long
    frames.append(("udp", ethernet(0x86DD) + ipv6(LAPTOP_LL, MDNS6, 0, 8 + 8 + 40) + hop_by_hop
                   + udp(5353, 5353, 40) + bytes(40), (LAPTOP_LL, 5353, MDNS6, 5353, 17)))
    fragment = struct.pack("!BBHI", 17, 0, (185 << 3), 0xCAFE)  # offset 1480 bytes, last piece
    frames.append(("other_ip", ethernet(0x86DD) + ipv6(DNS6, LAPTOP6, 44, 8 + 100) + fragment
                   + bytes(100), (DNS6, 0, LAPTOP6, 0, 17)))

    # Non-IP: ARP request and reply (2 frames)
    arp = bytes(28)
    frames.append(("non_ip", ethernet(0x0806) + arp, None))
    frames.append(("non_ip", ethernet(0x0806) + arp, None))

    # Malformed (3 frames)
    frames.append(("malformed", bytes(10), None))  # runt: shorter than an Ethernet header
    bad_ihl = bytearray(ipv4(LAPTOP, WEB, 6, 20))
    bad_ihl[0] = (4 << 4) | 3
    frames.append(("malformed", ethernet(0x0800) + bytes(bad_ihl) + tcp(1, 2, ACK), None))
    frames.append(("malformed", ethernet(0x0800) + ipv4(LAPTOP, WEB, 6, 20)
                   + tcp(51003, 443, ACK, data_offset=2), None))

    return frames


def dns_response(name, addresses):
    """A DNS answer: one question for `name`, one A record per IPv4 address (as tuples)."""
    labels = b"".join(bytes([len(part)]) + part.encode() for part in name.split(".")) + b"\0"
    message = struct.pack("!HHHHHH", 0x4242, 0x8180, 1, len(addresses), 0, 0)
    message += labels + struct.pack("!HH", 1, 1)
    for address in addresses:
        # Owner name as a compression pointer to the question (offset 12).
        message += struct.pack("!HHHIH", 0xC00C, 1, 1, 300, 4) + bytes(address)
    return message


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
    records = []  # (seconds from start, frame bytes, wire length[, bytes to keep])

    def add(t, *args, **kwargs):
        headers, wire = segment(*args, **kwargs)
        records.append((t, headers, wire))

    def dns_answer(t, client, client_port, name, addresses):
        message = dns_response(name, addresses)
        frame = (ethernet(0x0800) + ipv4(LAN_ROUTER, client, 17, 8 + len(message))
                 + udp(53, client_port, len(message)) + message)
        records.append((t, frame, len(frame), 512))

    # The names behind the conversations below, as the devices' DNS lookups were answered.
    # With --dns-names these turn the video and the call into known-service matches.
    dns_answer(0.05, LAPTOP, 50000, "rr4---sn-ab5l6nzr.googlevideo.com", [VIDEO])
    dns_answer(1.95, PHONE, 50001, "turn.zoom.us", [CALL_RELAY])
    dns_answer(59.95, LAPTOP, 50000, "downloads.example.org", [MIRROR])

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
        dns_answer(start + 0.02, LAPTOP, 50000, f"www.site{n}.example", [host])
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
    """records: (seconds from start, frame bytes from Ethernet onward, wire length[, bytes to
    keep, default SNAPLEN])."""
    with path.open("wb") as f:
        # Classic pcap global header: magic, v2.4, UTC, sigfigs 0, snaplen, LINKTYPE_ETHERNET
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 512, 1))
        start_us = 1_700_000_000 * 1_000_000
        for record in records:
            t, frame, wire = record[:3]
            keep = record[3] if len(record) > 3 else SNAPLEN
            ts_us = start_us + round(t * 1_000_000)
            captured = frame[:keep]
            f.write(struct.pack("<IIII", ts_us // 1_000_000, ts_us % 1_000_000,
                                len(captured), wire))
            f.write(captured)


def main():
    out_dir = Path(sys.argv[1]) if len(sys.argv) > 1 else (
        Path(__file__).resolve().parent.parent / "sample_pcaps")

    # synthetic.pcap: one frame every 150 ms, so replay shows a real throughput shape.
    frames = build_frames()
    synthetic = out_dir / "synthetic.pcap"
    write_pcap(synthetic, [(i * 0.15, frame, len(frame)) for i, (_, frame, _) in enumerate(frames)])

    counts = {}
    for label, _, _ in frames:
        counts[label] = counts.get(label, 0) + 1
    total_bytes = sum(len(frame) for _, frame, _ in frames)
    conversations = [meta for _, _, meta in frames if meta]
    flows = {(meta[4],) + tuple(sorted([(meta[0], meta[1]), (meta[2], meta[3])]))
             for meta in conversations}
    hosts = {meta[0] for meta in conversations} | {meta[2] for meta in conversations}
    ipv6_packets = sum(1 for meta in conversations if len(meta[0]) == 16)
    print(f"wrote {synthetic} ({synthetic.stat().st_size} bytes on disk)")
    print(f"  expect: summary: packets={len(frames)} bytes={total_bytes} tcp={counts.get('tcp', 0)} "
          f"udp={counts.get('udp', 0)} other_ip={counts.get('other_ip', 0)} "
          f"non_ip={counts.get('non_ip', 0)} malformed={counts.get('malformed', 0)} "
          f"ipv6={ipv6_packets} flows={len(flows)} hosts={len(hosts)} missed=0")

    mix = build_traffic_mix()
    traffic_mix = out_dir / "traffic_mix.pcap"
    write_pcap(traffic_mix, mix)
    print(f"wrote {traffic_mix} ({traffic_mix.stat().st_size} bytes on disk)")
    print(f"  records={len(mix)} wire_bytes={sum(record[2] for record in mix)}")
    print("  expect: categories: streaming=1 browsing=8 calls-gaming=1 file-transfer=1 other=1")
    print("  expect: status: device-above-usual")
    print("  expect with --dns-names: streaming and calls/gaming as [known-domain match]")


if __name__ == "__main__":
    main()
