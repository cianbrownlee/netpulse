#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <unordered_map>

#include "aggregate/flow.hpp"
#include "aggregate/snapshot.hpp"
#include "aggregate/throughput_window.hpp"
#include "parse/packet_parser.hpp"

namespace netpulse {

struct HostStats {
    std::uint64_t packets = 0;
    std::uint64_t bytes = 0;
    Clock::time_point first_seen{};
    Clock::time_point last_seen{};
};

// Turns a stream of parsed packets into running statistics.
//
// Deliberately single-threaded and clock-free: it is owned by exactly one thread (the
// aggregator thread in the pipeline) and every method takes time as an argument. All the
// concurrency lives in the pipeline around it, which keeps this logic plain and unit-testable.
class Aggregator {
public:
    struct Config {
        std::size_t window_seconds = 60;
        // Flows with no packets for this long are forgotten, so a long-running session's
        // memory tracks *active* connections rather than every connection ever seen.
        std::chrono::seconds flow_idle_timeout{120};
        std::size_t top_n = 10;
    };

    Aggregator();
    explicit Aggregator(Config config);

    // `wire_length` is the frame's full on-the-wire size, which can exceed the captured bytes.
    void ingest(const PacketInfo& info, std::uint32_t wire_length, Clock::time_point t);

    // Advances the throughput window, expires idle flows, and copies out the top-N views.
    // Host names and capture health are left empty; the pipeline fills those in.
    Snapshot build_snapshot(Clock::time_point now);

    void expire_idle_flows(Clock::time_point now);

    const std::unordered_map<FlowKey, FlowStats>& flows() const { return flows_; }
    const std::unordered_map<std::uint32_t, HostStats>& hosts() const { return hosts_; }
    const TrafficCounter& total() const { return total_; }

private:
    TrafficCounter& counter_for(PacketKind kind);
    void credit_host(std::uint32_t ip, std::uint32_t bytes, Clock::time_point t);

    Config config_;
    TrafficCounter total_, tcp_, udp_, other_ipv4_, non_ipv4_, malformed_;
    ThroughputWindow throughput_;
    std::unordered_map<FlowKey, FlowStats> flows_;
    std::unordered_map<std::uint32_t, HostStats> hosts_;
    Clock::time_point last_expiry_{};
};

}  // namespace netpulse
