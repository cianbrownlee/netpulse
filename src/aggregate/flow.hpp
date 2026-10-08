#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>

#include "parse/packet_parser.hpp"

namespace netpulse {

using Clock = std::chrono::steady_clock;

// Identifies one conversation by its 5-tuple. The key is canonical: endpoint A is always the
// lower (ip, port) pair, so packets in both directions of the same conversation land on the
// same key. That matches what a "flow" means to a reader ("this laptop talking to that
// server"), and later lets the classifier ask direction questions (one-way bulk transfer vs.
// a bidirectional call) from a single entry.
struct FlowKey {
    std::uint32_t ip_a = 0;
    std::uint32_t ip_b = 0;
    std::uint16_t port_a = 0;
    std::uint16_t port_b = 0;
    std::uint8_t protocol = 0;

    bool operator==(const FlowKey&) const = default;
};

struct FlowStats {
    std::uint64_t packets = 0;
    std::uint64_t bytes = 0;
    std::uint64_t bytes_a_to_b = 0;
    std::uint64_t bytes_b_to_a = 0;
    Clock::time_point first_seen{};
    Clock::time_point last_seen{};
};

struct DirectedFlowKey {
    FlowKey key;
    bool a_to_b = true;  // false if the packet travels from endpoint B to endpoint A
};

// Only meaningful for IPv4 packets. Ports are zero for protocols without them (ICMP, fragments).
inline DirectedFlowKey make_flow_key(const PacketInfo& p) {
    const bool src_is_a =
        p.src_ip < p.dst_ip || (p.src_ip == p.dst_ip && p.src_port <= p.dst_port);
    DirectedFlowKey d;
    d.a_to_b = src_is_a;
    d.key.protocol = p.ip_protocol;
    if (src_is_a) {
        d.key.ip_a = p.src_ip;
        d.key.port_a = p.src_port;
        d.key.ip_b = p.dst_ip;
        d.key.port_b = p.dst_port;
    } else {
        d.key.ip_a = p.dst_ip;
        d.key.port_a = p.dst_port;
        d.key.ip_b = p.src_ip;
        d.key.port_b = p.src_port;
    }
    return d;
}

}  // namespace netpulse

template <>
struct std::hash<netpulse::FlowKey> {
    std::size_t operator()(const netpulse::FlowKey& k) const noexcept {
        // Pack the 13 bytes of key into two words, then mix (splitmix64 finalizer) so that
        // keys differing only in low bits still spread across buckets.
        std::uint64_t h = (std::uint64_t{k.ip_a} << 32) | k.ip_b;
        h ^= mix((std::uint64_t{k.port_a} << 32) | (std::uint64_t{k.port_b} << 16) | k.protocol);
        return static_cast<std::size_t>(mix(h));
    }

private:
    static std::uint64_t mix(std::uint64_t x) noexcept {
        x ^= x >> 30;
        x *= 0xbf58476d1ce4e5b9ULL;
        x ^= x >> 27;
        x *= 0x94d049bb133111ebULL;
        x ^= x >> 31;
        return x;
    }
};
