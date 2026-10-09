#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <unordered_map>

#include "aggregate/flow.hpp"
#include "aggregate/observed_names.hpp"
#include "aggregate/snapshot.hpp"
#include "aggregate/throughput_window.hpp"
#include "parse/packet_parser.hpp"
#include "util/local_networks.hpp"

namespace netpulse {

struct HostStats {
    std::uint64_t packets = 0;
    std::uint64_t bytes = 0;
    Clock::time_point first_seen{};
    Clock::time_point last_seen{};
    double current_bps = 0;  // smoothed recent rate
    std::uint64_t bytes_at_last_tick = 0;
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
        // Smoothing for "current" rates (exponentially weighted, this time constant): long
        // enough that one burst doesn't look like a trend, short enough to feel live.
        std::chrono::seconds rate_time_constant{3};
        std::size_t rate_leaders = 5;
        // Conversations listed for each top talker (HostRow::flows).
        std::size_t host_flows = 10;
        // Networks that count as "your side" in addition to private address ranges.
        LocalNetworks local_networks;
        // Read the answers in DNS/mDNS responses to learn names for addresses (--dns-names).
        bool observe_dns = false;
    };

    Aggregator();
    explicit Aggregator(Config config);

    // `wire_length` is the frame's full on-the-wire size, which can exceed the captured bytes.
    void ingest(const PacketInfo& info, std::uint32_t wire_length, Clock::time_point t);

    // Advances the throughput window, updates smoothed rates, expires idle flows, and copies
    // out the top-N views. Names, categories, capture health and status are left for the
    // pipeline to fill in.
    Snapshot build_snapshot(Clock::time_point now);

    void expire_idle_flows(Clock::time_point now);

    const std::unordered_map<FlowKey, FlowStats>& flows() const { return flows_; }
    const std::unordered_map<IpAddress, HostStats>& hosts() const { return hosts_; }
    const TrafficCounter& total() const { return total_; }
    const ObservedNames& observed_names() const { return observed_names_; }

private:
    TrafficCounter& counter_for(PacketKind kind);
    void credit_host(const IpAddress& ip, std::uint32_t bytes, Clock::time_point t);
    void update_rates(Clock::time_point now);
    HostRow host_row(const IpAddress& ip, const HostStats& h, Clock::time_point now) const;
    FlowRow flow_row(const FlowKey& key, const FlowStats& stats) const;
    void add_host_flows(std::vector<HostRow>& hosts) const;

    Config config_;
    TrafficCounter total_, tcp_, udp_, other_ip_, non_ip_, malformed_;
    TrafficCounter ipv4_, ipv6_;
    ThroughputWindow throughput_;
    std::unordered_map<FlowKey, FlowStats> flows_;
    std::unordered_map<IpAddress, HostStats> hosts_;
    Clock::time_point last_expiry_{};
    ObservedNames observed_names_;

    bool rates_started_ = false;
    Clock::time_point last_tick_{};
    double total_current_bps_ = 0;
    std::uint64_t total_bytes_at_last_tick_ = 0;
};

}  // namespace netpulse
