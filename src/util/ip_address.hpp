#pragma once

#include <array>
#include <compare>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <functional>
#include <string>

namespace netpulse {

// An IPv4 or IPv6 address.
//
// IPv4 addresses are stored in IPv4-mapped IPv6 form (::ffff:a.b.c.d, RFC 4291 section
// 2.5.5.2), so one 16-byte value represents both families: no variant, no branching to compare
// or hash. Ordering is plain byte order, which for IPv4 is the same as numeric order.
class IpAddress {
public:
    using Bytes = std::array<std::uint8_t, 16>;

    constexpr IpAddress() = default;  // :: (the unspecified address)

    // From a 32-bit value in host byte order, e.g. 0xC0A8010E for 192.168.1.14.
    static constexpr IpAddress v4(std::uint32_t value) {
        IpAddress a;
        a.bytes_[10] = 0xFF;
        a.bytes_[11] = 0xFF;
        a.bytes_[12] = static_cast<std::uint8_t>(value >> 24);
        a.bytes_[13] = static_cast<std::uint8_t>(value >> 16);
        a.bytes_[14] = static_cast<std::uint8_t>(value >> 8);
        a.bytes_[15] = static_cast<std::uint8_t>(value);
        return a;
    }
    static constexpr IpAddress v4(std::uint8_t a, std::uint8_t b, std::uint8_t c, std::uint8_t d) {
        return v4((std::uint32_t{a} << 24) | (std::uint32_t{b} << 16) | (std::uint32_t{c} << 8) | d);
    }
    // From 16 bytes in network order, as they appear in an IPv6 header.
    static constexpr IpAddress v6(const Bytes& bytes) {
        IpAddress a;
        a.bytes_ = bytes;
        return a;
    }

    constexpr bool is_v4() const {
        for (std::size_t i = 0; i < 10; ++i) {
            if (bytes_[i] != 0) return false;
        }
        return bytes_[10] == 0xFF && bytes_[11] == 0xFF;
    }
    // The IPv4 address as a host-order integer. Only meaningful when is_v4().
    constexpr std::uint32_t v4_value() const {
        return (std::uint32_t{bytes_[12]} << 24) | (std::uint32_t{bytes_[13]} << 16) |
               (std::uint32_t{bytes_[14]} << 8) | std::uint32_t{bytes_[15]};
    }
    constexpr const Bytes& bytes() const { return bytes_; }

    // Whether the first `bits` bits of this address match `network` (same family assumed:
    // for IPv4 the bits count from the start of the IPv4 address, as in 192.168.0.0/16).
    bool in_prefix(const IpAddress& network, int bits) const;

    constexpr auto operator<=>(const IpAddress&) const = default;
    constexpr bool operator==(const IpAddress&) const = default;

    // "192.168.1.14", or RFC 5952 text for IPv6 ("2001:db8::1").
    std::string to_string() const;

private:
    Bytes bytes_{};
};

namespace detail {
// splitmix64 finalizer: spreads keys that differ only in a few bits across all 64.
constexpr std::uint64_t mix64(std::uint64_t x) {
    x ^= x >> 30;
    x *= 0xbf58476d1ce4e5b9ULL;
    x ^= x >> 27;
    x *= 0x94d049bb133111ebULL;
    x ^= x >> 31;
    return x;
}

// Hashes run several times per packet, so they fold words together with a cheap multiply-xor
// and pay for one full mix64 at the end. (Byte order doesn't matter for a hash, so the words
// are plain native-endian loads.)
inline constexpr std::uint64_t kFold = 0x9e3779b97f4a7c15ULL;

inline std::uint64_t word(const IpAddress& a, std::size_t index) {
    std::uint64_t w;
    std::memcpy(&w, a.bytes().data() + 8 * index, sizeof w);
    return w;
}

inline std::uint64_t fold(std::uint64_t h, const IpAddress& a) {
    h = (h * kFold) ^ word(a, 0);
    return (h * kFold) ^ word(a, 1);
}
}  // namespace detail

}  // namespace netpulse

template <>
struct std::hash<netpulse::IpAddress> {
    std::size_t operator()(const netpulse::IpAddress& a) const noexcept {
        return static_cast<std::size_t>(netpulse::detail::mix64(netpulse::detail::fold(0, a)));
    }
};
