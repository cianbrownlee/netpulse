#include "parse/packet_parser.hpp"

#include <algorithm>

namespace netpulse {

namespace {

// Assemble big-endian fields byte by byte. Casting the buffer to a struct pointer instead would
// be undefined behavior (alignment, strict aliasing) and endian-dependent.
std::uint16_t read_be16(std::span<const std::uint8_t> b, std::size_t offset) {
    return static_cast<std::uint16_t>((b[offset] << 8) | b[offset + 1]);
}

std::uint32_t read_be32(std::span<const std::uint8_t> b, std::size_t offset) {
    return (std::uint32_t{b[offset]} << 24) | (std::uint32_t{b[offset + 1]} << 16) |
           (std::uint32_t{b[offset + 2]} << 8) | std::uint32_t{b[offset + 3]};
}

}  // namespace

std::optional<EthernetHeader> parse_ethernet(std::span<const std::uint8_t> bytes) {
    // dst MAC (6) | src MAC (6) | EtherType (2)
    if (bytes.size() < kEthernetHeaderLength) return std::nullopt;

    EthernetHeader eth;
    eth.ethertype = read_be16(bytes, 12);
    eth.header_length = kEthernetHeaderLength;

    // 802.1Q: a 4-byte tag (TPID 0x8100, then TCI) sits before the real EtherType.
    if (eth.ethertype == kEtherTypeVlan) {
        if (bytes.size() < kEthernetHeaderLength + kVlanTagLength) return std::nullopt;
        eth.ethertype = read_be16(bytes, 16);
        eth.header_length += kVlanTagLength;
    }
    return eth;
}

std::optional<Ipv4Header> parse_ipv4(std::span<const std::uint8_t> bytes) {
    if (bytes.size() < kIpv4MinHeaderLength) return std::nullopt;

    const std::uint8_t version = bytes[0] >> 4;
    const std::size_t header_length = std::size_t{bytes[0] & 0x0Fu} * 4;
    if (version != 4) return std::nullopt;
    if (header_length < kIpv4MinHeaderLength) return std::nullopt;  // IHL < 5 is invalid
    if (bytes.size() < header_length) return std::nullopt;          // options cut off

    Ipv4Header ip;
    ip.header_length = header_length;
    ip.total_length = read_be16(bytes, 2);
    if (ip.total_length < header_length) return std::nullopt;  // claims less than its own header

    const std::uint16_t flags_and_offset = read_be16(bytes, 6);
    ip.is_later_fragment = (flags_and_offset & 0x1FFF) != 0;
    ip.protocol = bytes[9];
    ip.src = read_be32(bytes, 12);
    ip.dst = read_be32(bytes, 16);
    return ip;
}

std::optional<TcpHeader> parse_tcp(std::span<const std::uint8_t> bytes) {
    if (bytes.size() < kTcpMinHeaderLength) return std::nullopt;

    TcpHeader tcp;
    tcp.src_port = read_be16(bytes, 0);
    tcp.dst_port = read_be16(bytes, 2);
    tcp.header_length = static_cast<std::size_t>(bytes[12] >> 4) * 4;
    tcp.flags = bytes[13];
    if (tcp.header_length < kTcpMinHeaderLength) return std::nullopt;  // data offset < 5
    if (bytes.size() < tcp.header_length) return std::nullopt;         // options cut off
    return tcp;
}

std::optional<UdpHeader> parse_udp(std::span<const std::uint8_t> bytes) {
    if (bytes.size() < kUdpHeaderLength) return std::nullopt;

    UdpHeader udp;
    udp.src_port = read_be16(bytes, 0);
    udp.dst_port = read_be16(bytes, 2);
    udp.length = read_be16(bytes, 4);
    if (udp.length < kUdpHeaderLength) return std::nullopt;
    return udp;
}

const char* to_string(PacketKind kind) {
    switch (kind) {
        case PacketKind::Tcp: return "TCP";
        case PacketKind::Udp: return "UDP";
        case PacketKind::OtherIpv4: return "Other IPv4";
        case PacketKind::NonIpv4: return "Non-IPv4";
        case PacketKind::Malformed: return "Malformed";
    }
    return "?";
}

PacketInfo parse_packet(std::span<const std::uint8_t> frame) {
    PacketInfo info;  // kind defaults to Malformed

    const auto eth = parse_ethernet(frame);
    if (!eth) return info;
    info.ethertype = eth->ethertype;
    if (eth->ethertype != kEtherTypeIpv4) {
        info.kind = PacketKind::NonIpv4;
        return info;
    }

    const auto ip_bytes = frame.subspan(eth->header_length);
    const auto ip = parse_ipv4(ip_bytes);
    if (!ip) return info;
    info.ip_protocol = ip->protocol;
    info.src_ip = IpAddress::v4(ip->src);
    info.dst_ip = IpAddress::v4(ip->dst);
    info.kind = PacketKind::OtherIpv4;
    if (ip->is_later_fragment) return info;

    // Bound the transport header by what the IP header says the packet holds, so Ethernet
    // padding on short frames is never mistaken for header bytes. If the capture was cut short
    // (snaplen), what we actually have is the tighter bound.
    const std::size_t transport_offset = ip->header_length;
    const std::size_t transport_length =
        std::min<std::size_t>(ip_bytes.size(), ip->total_length) - transport_offset;
    const auto transport = ip_bytes.subspan(transport_offset, transport_length);

    if (ip->protocol == kIpProtoTcp) {
        const auto tcp = parse_tcp(transport);
        if (!tcp) {
            info.kind = PacketKind::Malformed;
            return info;
        }
        info.kind = PacketKind::Tcp;
        info.src_port = tcp->src_port;
        info.dst_port = tcp->dst_port;
        info.tcp_flags = tcp->flags;
    } else if (ip->protocol == kIpProtoUdp) {
        const auto udp = parse_udp(transport);
        if (!udp) {
            info.kind = PacketKind::Malformed;
            return info;
        }
        info.kind = PacketKind::Udp;
        info.src_port = udp->src_port;
        info.dst_port = udp->dst_port;
    }
    return info;
}

}  // namespace netpulse
