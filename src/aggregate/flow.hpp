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
    IpAddress ip_a;
    IpAddress ip_b;
    std::uint16_t port_a = 0;
    std::uint16_t port_b = 0;
    std::uint8_t protocol = 0;

    bool operator==(const FlowKey&) const = default;
};

// Whole-second index of a time point, used to count distinct active seconds.
inline std::int64_t second_index(Clock::time_point t) {
    return std::chrono::duration_cast<std::chrono::seconds>(t.time_since_epoch()).count();
}

struct FlowStats {
    std::uint64_t packets = 0;
    std::uint64_t bytes = 0;
    std::uint64_t bytes_a_to_b = 0;
    std::uint64_t bytes_b_to_a = 0;
    Clock::time_point first_seen{};
    Clock::time_point last_seen{};

    // How many distinct whole seconds carried traffic. Set against the flow's lifetime this
    // is a duty cycle, which separates a continuous transfer (~100%) from the on/off bursts of
    // video streaming, without storing any per-second history.
    std::uint32_t active_seconds = 0;
    std::int64_t last_active_second = -1;

    // Smoothed recent rate, maintained by Aggregator::build_snapshot.
    double current_bps = 0;
    std::uint64_t bytes_at_last_tick = 0;

    double duty_cycle() const {
        const std::int64_t lifetime = second_index(last_seen) - second_index(first_seen) + 1;
        return lifetime <= 0 ? 0.0 : static_cast<double>(active_seconds) / static_cast<double>(lifetime);
    }
    std::chrono::duration<double> duration() const { return last_seen - first_seen; }
};

struct DirectedFlowKey {
    FlowKey key;
    bool a_to_b = true;  // false if the packet travels from endpoint B to endpoint A
};

// Only meaningful for IP packets. Ports are zero for protocols without them (ICMP, fragments).
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
        // Fold both addresses and the ports/protocol together, then one splitmix64 finalizer
        // so keys differing only in a few low bits (sequential ephemeral ports) still spread.
        using netpulse::detail::fold;
        using netpulse::detail::kFold;
        std::uint64_t h = fold(fold(0, k.ip_a), k.ip_b);
        h = (h * kFold) ^ ((std::uint64_t{k.port_a} << 32) | (std::uint64_t{k.port_b} << 16) | k.protocol);
        return static_cast<std::size_t>(netpulse::detail::mix64(h));
    }
};
