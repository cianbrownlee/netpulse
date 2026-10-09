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
        case PacketKind::OtherIp: return "Other IP";
        case PacketKind::NonIp: return "Non-IP";
        case PacketKind::Malformed: return "Malformed";
    }
    return "?";
}

std::optional<Ipv6Header> parse_ipv6(std::span<const std::uint8_t> bytes) {
    // version/class/flow (4) | payload length (2) | next header (1) | hop limit (1) |
    // source (16) | destination (16)
    if (bytes.size() < kIpv6HeaderLength) return std::nullopt;
    if ((bytes[0] >> 4) != 6) return std::nullopt;

    Ipv6Header ip;
    ip.payload_length = read_be16(bytes, 4);
    IpAddress::Bytes address{};
    std::copy_n(bytes.begin() + 8, 16, address.begin());
    ip.src = IpAddress::v6(address);
    std::copy_n(bytes.begin() + 24, 16, address.begin());
    ip.dst = IpAddress::v6(address);

    // Walk the extension-header chain to the transport header. Every step is bounds-checked,
    // and the chain length is capped, because a crafted packet can make it arbitrarily long.
    std::uint8_t next = bytes[6];
    std::size_t offset = kIpv6HeaderLength;
    for (int seen = 0;; ++seen) {
        std::size_t length = 0;
        switch (next) {
            case kIpv6HopByHop:
            case kIpv6Routing:
            case kIpv6DestinationOptions:
            case kIpv6Mobility:
            case kIpv6Hip:
            case kIpv6Shim6:
                // Next header (1) | length in 8-byte units, not counting the first 8 (1) | ...
                if (bytes.size() < offset + 2) return std::nullopt;
                length = (std::size_t{bytes[offset + 1]} + 1) * 8;
                break;
            case kIpv6Authentication:
                // Same layout, but the length is in 4-byte units, not counting the first 8.
                if (bytes.size() < offset + 2) return std::nullopt;
                length = (std::size_t{bytes[offset + 1]} + 2) * 4;
                break;
            case kIpv6Fragment:
                // Next header (1) | reserved (1) | offset (13 bits) + flags (3) | id (4)
                length = 8;
                break;
            default:
                // A transport header (TCP, UDP, ICMPv6...) or something not walked into: ESP
                // (encrypted from here on) or "no next header".
                ip.protocol = next;
                ip.header_length = offset;
                if (ip.payload_length != 0 && kIpv6HeaderLength + ip.payload_length < offset) {
                    return std::nullopt;  // headers claim more than the packet holds
                }
                return ip;
        }
        if (seen >= kMaxIpv6ExtensionHeaders) return std::nullopt;
        if (bytes.size() < offset + length) return std::nullopt;  // cut off
        if (next == kIpv6Fragment && (read_be16(bytes, offset + 2) >> 3) != 0) {
            ip.is_later_fragment = true;  // no transport header in this piece
            ip.protocol = bytes[offset];
            ip.header_length = offset + length;
            return ip;
        }
        next = bytes[offset];
        offset += length;
    }
}

namespace {

// Fills in TCP or UDP fields from the transport header, or marks the packet malformed. Other
// IP protocols leave the packet as OtherIp.
void parse_transport(PacketInfo& info, std::span<const std::uint8_t> transport) {
    if (info.ip_protocol == kIpProtoTcp) {
        const auto tcp = parse_tcp(transport);
        if (!tcp) {
            info.kind = PacketKind::Malformed;
            return;
        }
        info.kind = PacketKind::Tcp;
        info.src_port = tcp->src_port;
        info.dst_port = tcp->dst_port;
        info.tcp_flags = tcp->flags;
    } else if (info.ip_protocol == kIpProtoUdp) {
        const auto udp = parse_udp(transport);
        if (!udp) {
            info.kind = PacketKind::Malformed;
            return;
        }
        info.kind = PacketKind::Udp;
        info.src_port = udp->src_port;
        info.dst_port = udp->dst_port;
    }
}

}  // namespace

PacketInfo parse_packet(std::span<const std::uint8_t> frame) {
    PacketInfo info;  // kind defaults to Malformed

    const auto eth = parse_ethernet(frame);
    if (!eth) return info;
    info.ethertype = eth->ethertype;
    const auto ip_bytes = frame.subspan(eth->header_length);

    if (eth->ethertype == kEtherTypeIpv4) {
        const auto ip = parse_ipv4(ip_bytes);
        if (!ip) return info;
        info.ip_version = 4;
        info.ip_protocol = ip->protocol;
        info.src_ip = IpAddress::v4(ip->src);
        info.dst_ip = IpAddress::v4(ip->dst);
        info.kind = PacketKind::OtherIp;
        if (ip->is_later_fragment) return info;

        // Bound the transport header by what the IP header says the packet holds, so Ethernet
        // padding on short frames is never mistaken for header bytes. If the capture was cut
        // short (snaplen), what we actually have is the tighter bound.
        const std::size_t end = std::min<std::size_t>(ip_bytes.size(), ip->total_length);
        parse_transport(info, ip_bytes.subspan(ip->header_length, end - ip->header_length));
        return info;
    }

    if (eth->ethertype == kEtherTypeIpv6) {
        const auto ip = parse_ipv6(ip_bytes);
        if (!ip) return info;
        info.ip_version = 6;
        info.ip_protocol = ip->protocol;
        info.src_ip = ip->src;
        info.dst_ip = ip->dst;
        info.kind = PacketKind::OtherIp;
        if (ip->is_later_fragment) return info;

        // Same bound as IPv4, from the payload length. Zero means a jumbogram (or a bogus
        // header); then all we can go by is what was captured.
        const std::size_t end =
            ip->payload_length == 0
                ? ip_bytes.size()
                : std::min<std::size_t>(ip_bytes.size(), kIpv6HeaderLength + ip->payload_length);
        if (end < ip->header_length) {
            info.kind = PacketKind::Malformed;
            return info;
        }
        parse_transport(info, ip_bytes.subspan(ip->header_length, end - ip->header_length));
        return info;
    }

    info.kind = PacketKind::NonIp;
    return info;
}

}  // namespace netpulse
