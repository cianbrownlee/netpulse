#include "util/net.hpp"

namespace netpulse {

namespace {

constexpr std::uint32_t ip(std::uint8_t a, std::uint8_t b, std::uint8_t c, std::uint8_t d) {
    return (std::uint32_t{a} << 24) | (std::uint32_t{b} << 16) | (std::uint32_t{c} << 8) | d;
}

constexpr bool in_prefix(std::uint32_t addr, std::uint32_t network, int prefix_len) {
    const std::uint32_t mask = prefix_len == 0 ? 0 : ~std::uint32_t{0} << (32 - prefix_len);
    return (addr & mask) == (network & mask);
}

}  // namespace

std::string ipv4_to_string(std::uint32_t addr) {
    return std::to_string(addr >> 24) + '.' + std::to_string((addr >> 16) & 0xFF) + '.' +
           std::to_string((addr >> 8) & 0xFF) + '.' + std::to_string(addr & 0xFF);
}

bool is_local_ipv4(std::uint32_t addr) {
    return in_prefix(addr, ip(10, 0, 0, 0), 8) ||       // RFC 1918
           in_prefix(addr, ip(172, 16, 0, 0), 12) ||    // RFC 1918
           in_prefix(addr, ip(192, 168, 0, 0), 16) ||   // RFC 1918
           in_prefix(addr, ip(127, 0, 0, 0), 8) ||      // loopback
           in_prefix(addr, ip(169, 254, 0, 0), 16) ||   // link-local
           in_prefix(addr, ip(100, 64, 0, 0), 10) ||    // carrier-grade NAT
           in_prefix(addr, ip(0, 0, 0, 0), 8) ||        // "this network" (e.g. DHCP's 0.0.0.0)
           // Multicast: in practice, local discovery traffic (SSDP, mDNS, IGMP) that never
           // leaves the network, even though the range isn't private in the RFC 1918 sense.
           in_prefix(addr, ip(224, 0, 0, 0), 4) ||
           addr == ip(255, 255, 255, 255);              // limited broadcast
}

std::string ip_protocol_name(std::uint8_t protocol) {
    switch (protocol) {
        case 1: return "ICMP";
        case 2: return "IGMP";
        case 6: return "TCP";
        case 17: return "UDP";
        default: return "IP proto " + std::to_string(protocol);
    }
}

}  // namespace netpulse
