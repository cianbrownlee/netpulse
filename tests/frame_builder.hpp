#pragma once

// Builds raw Ethernet frames byte by byte for parser and aggregator tests. Written separately
// from the parser (big-endian writes here, big-endian reads there) so a shared misconception
// about the wire format would have to be made twice to go unnoticed.

#include <arpa/inet.h>

#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <initializer_list>
#include <optional>
#include <vector>

#include "util/ip_address.hpp"

namespace netpulse::test {

using Bytes = std::vector<std::uint8_t>;

constexpr IpAddress ip(std::uint8_t a, std::uint8_t b, std::uint8_t c, std::uint8_t d) {
    return IpAddress::v4(a, b, c, d);
}

// IPv6 from its text form, e.g. ip6("2001:db8::1").
inline IpAddress ip6(const char* text) {
    IpAddress::Bytes bytes{};
    if (inet_pton(AF_INET6, text, bytes.data()) != 1) throw std::invalid_argument(text);
    return IpAddress::v6(bytes);
}

inline void put16(Bytes& out, std::uint16_t v) {
    out.push_back(static_cast<std::uint8_t>(v >> 8));
    out.push_back(static_cast<std::uint8_t>(v));
}

inline void put32(Bytes& out, std::uint32_t v) {
    put16(out, static_cast<std::uint16_t>(v >> 16));
    put16(out, static_cast<std::uint16_t>(v));
}

inline Bytes concat(std::initializer_list<Bytes> parts) {
    Bytes out;
    for (const auto& p : parts) out.insert(out.end(), p.begin(), p.end());
    return out;
}

inline Bytes ethernet(std::uint16_t ethertype, std::optional<std::uint16_t> vlan_id = {}) {
    Bytes out = {0x02, 0x00, 0x00, 0x00, 0x00, 0x02,   // dst MAC
                 0x02, 0x00, 0x00, 0x00, 0x00, 0x01};  // src MAC
    if (vlan_id) {
        put16(out, 0x8100);
        put16(out, *vlan_id);
    }
    put16(out, ethertype);
    return out;
}

// Knobs for building unusual or deliberately broken IPv4 headers, e.g.
//   ipv4(src, dst, 6, 20, Ipv4Options{}.ihl(4))
struct Ipv4Options {
    std::size_t options_length = 0;     // multiple of 4, up to 40
    std::uint16_t flags_and_offset = 0;
    std::uint8_t version = 4;
    std::optional<std::uint8_t> ihl_override;
    std::optional<std::uint16_t> total_length_override;

    Ipv4Options& options(std::size_t bytes) { options_length = bytes; return *this; }
    Ipv4Options& fragment(std::uint16_t v) { flags_and_offset = v; return *this; }
    Ipv4Options& ip_version(std::uint8_t v) { version = v; return *this; }
    Ipv4Options& ihl(std::uint8_t v) { ihl_override = v; return *this; }
    Ipv4Options& total_length(std::uint16_t v) { total_length_override = v; return *this; }
};

inline Bytes ipv4(const IpAddress& src, const IpAddress& dst, std::uint8_t protocol,
                  std::size_t payload_length, Ipv4Options o = {}) {
    const std::size_t header_length = 20 + o.options_length;
    const auto ihl = o.ihl_override.value_or(static_cast<std::uint8_t>(header_length / 4));
    Bytes out;
    out.push_back(static_cast<std::uint8_t>((o.version << 4) | (ihl & 0x0F)));
    out.push_back(0);  // DSCP/ECN
    put16(out, o.total_length_override.value_or(
                   static_cast<std::uint16_t>(header_length + payload_length)));
    put16(out, 0x1234);  // identification
    put16(out, o.flags_and_offset);
    out.push_back(64);  // TTL
    out.push_back(protocol);
    put16(out, 0);  // checksum (not validated by NetPulse)
    put32(out, src.v4_value());
    put32(out, dst.v4_value());
    out.insert(out.end(), o.options_length, 0x01);  // NOP options
    return out;
}

inline Bytes tcp(std::uint16_t src_port, std::uint16_t dst_port, std::uint8_t flags = 0x10,
                 std::size_t options_length = 0, std::optional<std::uint8_t> offset_override = {}) {
    const auto offset =
        offset_override.value_or(static_cast<std::uint8_t>((20 + options_length) / 4));
    Bytes out;
    put16(out, src_port);
    put16(out, dst_port);
    put32(out, 1000);  // sequence
    put32(out, 2000);  // acknowledgment
    out.push_back(static_cast<std::uint8_t>(offset << 4));
    out.push_back(flags);
    put16(out, 65535);  // window
    put16(out, 0);      // checksum
    put16(out, 0);      // urgent pointer
    out.insert(out.end(), options_length, 0x01);
    return out;
}

inline Bytes udp(std::uint16_t src_port, std::uint16_t dst_port, std::size_t payload_length,
                 std::optional<std::uint16_t> length_override = {}) {
    Bytes out;
    put16(out, src_port);
    put16(out, dst_port);
    put16(out, length_override.value_or(static_cast<std::uint16_t>(8 + payload_length)));
    put16(out, 0);
    return out;
}

inline Bytes payload(std::size_t n) { return Bytes(n, 0xAB); }

// IPv6 fixed header. `payload_length` covers everything after these 40 bytes, including any
// extension headers.
inline Bytes ipv6(const IpAddress& src, const IpAddress& dst, std::uint8_t next_header,
                  std::size_t payload_length, std::uint8_t version = 6) {
    Bytes out;
    out.push_back(static_cast<std::uint8_t>(version << 4));  // traffic class / flow label: 0
    out.push_back(0);
    out.push_back(0);
    out.push_back(0);
    put16(out, static_cast<std::uint16_t>(payload_length));
    out.push_back(next_header);
    out.push_back(64);  // hop limit
    out.insert(out.end(), src.bytes().begin(), src.bytes().end());
    out.insert(out.end(), dst.bytes().begin(), dst.bytes().end());
    return out;
}

// A generic IPv6 extension header (hop-by-hop, routing, destination options) of `length` bytes,
// a multiple of 8.
inline Bytes ext_header(std::uint8_t next_header, std::size_t length) {
    Bytes out(length, 0x01);  // padding options
    out[0] = next_header;
    out[1] = static_cast<std::uint8_t>(length / 8 - 1);
    return out;
}

// IPv6 fragment header: `offset_units` is the fragment offset in 8-byte units.
inline Bytes fragment_header(std::uint8_t next_header, std::uint16_t offset_units, bool more) {
    Bytes out = {next_header, 0};
    put16(out, static_cast<std::uint16_t>((offset_units << 3) | (more ? 1 : 0)));
    put32(out, 0xCAFE);  // identification
    return out;
}

inline Bytes tcp6_frame(const IpAddress& src, std::uint16_t sport, const IpAddress& dst,
                        std::uint16_t dport, std::size_t payload_length = 0,
                        std::uint8_t flags = 0x10) {
    return concat({ethernet(0x86DD), ipv6(src, dst, 6, 20 + payload_length),
                   tcp(sport, dport, flags), payload(payload_length)});
}

inline Bytes udp6_frame(const IpAddress& src, std::uint16_t sport, const IpAddress& dst,
                        std::uint16_t dport, std::size_t payload_length = 0) {
    return concat({ethernet(0x86DD), ipv6(src, dst, 17, 8 + payload_length),
                   udp(sport, dport, payload_length), payload(payload_length)});
}

inline Bytes tcp_frame(const IpAddress& src, std::uint16_t sport, const IpAddress& dst,
                       std::uint16_t dport, std::size_t payload_length = 0,
                       std::uint8_t flags = 0x10) {
    return concat({ethernet(0x0800), ipv4(src, dst, 6, 20 + payload_length),
                   tcp(sport, dport, flags), payload(payload_length)});
}

inline Bytes udp_frame(const IpAddress& src, std::uint16_t sport, const IpAddress& dst,
                       std::uint16_t dport, std::size_t payload_length = 0) {
    return concat({ethernet(0x0800), ipv4(src, dst, 17, 8 + payload_length),
                   udp(sport, dport, payload_length), payload(payload_length)});
}

}  // namespace netpulse::test
