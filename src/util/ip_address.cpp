#include "util/ip_address.hpp"

#include <arpa/inet.h>

namespace netpulse {

bool IpAddress::in_prefix(const IpAddress& network, int bits) const {
    // IPv4 prefixes count from the start of the IPv4 part (byte 12 of the mapped form).
    const int start_bit = is_v4() ? 96 : 0;
    const int end_bit = start_bit + bits;
    for (int bit = start_bit; bit < end_bit; ++bit) {
        const auto byte = static_cast<std::size_t>(bit / 8);
        const int mask = 0x80 >> (bit % 8);
        if ((bytes_[byte] & mask) != (network.bytes_[byte] & mask)) return false;
    }
    return true;
}

std::string IpAddress::to_string() const {
    if (is_v4()) {
        const std::uint32_t v = v4_value();
        return std::to_string(v >> 24) + '.' + std::to_string((v >> 16) & 0xFF) + '.' +
               std::to_string((v >> 8) & 0xFF) + '.' + std::to_string(v & 0xFF);
    }
    // inet_ntop implements the RFC 5952 canonical form: lowercase hex, no leading zeros, and the
    // longest run of zero groups collapsed to "::".
    char text[INET6_ADDRSTRLEN];
    if (inet_ntop(AF_INET6, bytes_.data(), text, sizeof text) == nullptr) return "?";
    return text;
}

}  // namespace netpulse
