#include "util/net.hpp"

namespace netpulse {

namespace {

constexpr IpAddress v4(std::uint8_t a, std::uint8_t b, std::uint8_t c, std::uint8_t d) {
    return IpAddress::v4(a, b, c, d);
}

constexpr IpAddress v6_prefix(std::uint8_t first, std::uint8_t second = 0) {
    IpAddress::Bytes b{};
    b[0] = first;
    b[1] = second;
    return IpAddress::v6(b);
}

constexpr IpAddress kV6Loopback = [] {
    IpAddress::Bytes b{};
    b[15] = 1;
    return IpAddress::v6(b);
}();

}  // namespace

bool is_private(const IpAddress& ip) {
    if (ip.is_v4()) {
        return ip.in_prefix(v4(10, 0, 0, 0), 8) ||       // RFC 1918
               ip.in_prefix(v4(172, 16, 0, 0), 12) ||    // RFC 1918
               ip.in_prefix(v4(192, 168, 0, 0), 16) ||   // RFC 1918
               ip.in_prefix(v4(127, 0, 0, 0), 8) ||      // loopback
               ip.in_prefix(v4(169, 254, 0, 0), 16) ||   // link-local
               ip.in_prefix(v4(100, 64, 0, 0), 10);      // carrier-grade NAT
    }
    return ip.in_prefix(v6_prefix(0xFC), 7) ||          // unique local addresses
           ip.in_prefix(v6_prefix(0xFE, 0x80), 10) ||   // link-local
           ip == kV6Loopback;
}

bool is_local(const IpAddress& ip) { return is_private(ip) || is_group_or_unspecified(ip); }

bool is_group_or_unspecified(const IpAddress& ip) {
    if (ip.is_v4()) {
        return ip.in_prefix(v4(0, 0, 0, 0), 8) ||  // "this network" (e.g. DHCP's 0.0.0.0)
               // Multicast: in practice, local discovery traffic (SSDP, mDNS, IGMP) that never
               // leaves the network, even though the range isn't private in the RFC 1918 sense.
               ip.in_prefix(v4(224, 0, 0, 0), 4) ||
               ip == v4(255, 255, 255, 255);        // limited broadcast
    }
    return ip.in_prefix(v6_prefix(0xFF), 8) ||  // multicast (IPv6 has no broadcast)
           ip == IpAddress{};                    // unspecified (::), e.g. duplicate-address checks
}

std::string ip_protocol_name(std::uint8_t protocol) {
    switch (protocol) {
        case 1: return "ICMP";
        case 2: return "IGMP";
        case 6: return "TCP";
        case 17: return "UDP";
        case 47: return "GRE";
        case 50: return "ESP";
        case 58: return "ICMPv6";
        default: return "IP proto " + std::to_string(protocol);
    }
}

}  // namespace netpulse
