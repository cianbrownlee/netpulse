#include "util/local_networks.hpp"

#include <arpa/inet.h>

#include <algorithm>
#include <charconv>

#include "util/net.hpp"

namespace netpulse {

namespace {

// Clears every bit after the first `bits` bits of the address (counted within its family).
IpAddress mask_to_prefix(const IpAddress& address, int bits) {
    IpAddress::Bytes bytes = address.bytes();
    const int start = address.is_v4() ? 96 : 0;
    for (int bit = start + bits; bit < 128; ++bit) {
        bytes[static_cast<std::size_t>(bit / 8)] &= static_cast<std::uint8_t>(~(0x80 >> (bit % 8)));
    }
    return IpAddress::v6(bytes);  // IPv4-mapped bytes stay IPv4-mapped
}

std::optional<IpAddress> parse_address(const std::string& text) {
    std::uint8_t v4[4];
    if (inet_pton(AF_INET, text.c_str(), v4) == 1) return IpAddress::v4(v4[0], v4[1], v4[2], v4[3]);
    IpAddress::Bytes v6{};
    if (inet_pton(AF_INET6, text.c_str(), v6.data()) == 1) return IpAddress::v6(v6);
    return std::nullopt;
}

}  // namespace

std::optional<IpPrefix> IpPrefix::parse(std::string_view text) {
    const auto slash = text.find('/');
    const auto address = parse_address(std::string(text.substr(0, slash)));
    if (!address) return std::nullopt;

    const int max_bits = address->is_v4() ? 32 : 128;
    int bits = max_bits;
    if (slash != std::string_view::npos) {
        const auto digits = text.substr(slash + 1);
        const auto [end, error] = std::from_chars(digits.data(), digits.data() + digits.size(), bits);
        if (error != std::errc{} || end != digits.data() + digits.size()) return std::nullopt;
        if (bits < 0 || bits > max_bits) return std::nullopt;
    }
    return IpPrefix{mask_to_prefix(*address, bits), bits};
}

std::optional<IpPrefix> IpPrefix::from_netmask(const IpAddress& address, const IpAddress& netmask) {
    if (address.is_v4() != netmask.is_v4()) return std::nullopt;
    const int start = address.is_v4() ? 96 : 0;
    int bits = 0;
    bool in_ones = true;
    for (int bit = start; bit < 128; ++bit) {
        const bool one = (netmask.bytes()[static_cast<std::size_t>(bit / 8)] & (0x80 >> (bit % 8))) != 0;
        if (one && !in_ones) return std::nullopt;  // ones after a zero: not a prefix mask
        if (one) ++bits;
        else in_ones = false;
    }
    return IpPrefix{mask_to_prefix(address, bits), bits};
}

void LocalNetworks::add(const IpPrefix& prefix) {
    const bool duplicate = std::any_of(prefixes_.begin(), prefixes_.end(), [&](const IpPrefix& p) {
        return p.network == prefix.network && p.bits == prefix.bits;
    });
    if (!duplicate) prefixes_.push_back(prefix);
}

bool LocalNetworks::contains(const IpAddress& ip) const {
    return std::any_of(prefixes_.begin(), prefixes_.end(),
                       [&](const IpPrefix& p) { return p.contains(ip); });
}

bool LocalNetworks::is_local(const IpAddress& ip) const {
    return netpulse::is_local(ip) || contains(ip);
}

bool LocalNetworks::is_device(const IpAddress& ip) const {
    if (is_group_or_unspecified(ip)) return false;
    return is_private(ip) || contains(ip);
}

std::string LocalNetworks::to_string() const {
    std::string out;
    for (const auto& p : prefixes_) {
        if (!out.empty()) out += ", ";
        out += p.to_string();
    }
    return out;
}

const LocalNetworks& no_local_networks() {
    static const LocalNetworks none;
    return none;
}

}  // namespace netpulse
