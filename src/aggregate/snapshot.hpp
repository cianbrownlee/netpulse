#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "aggregate/category.hpp"
#include "aggregate/flow.hpp"
#include "aggregate/status.hpp"

namespace netpulse {

struct TrafficCounter {
    std::uint64_t packets = 0;
    std::uint64_t bytes = 0;
};

// Where reverse-DNS stands for an address. NoName (looked up, nothing published) is different
// from Unknown (not looked up yet, still pending, or resolution switched off): only the former
// means "this address has no name".
enum class NameState : std::uint8_t { Unknown, Named, NoName };

struct HostRow {
    std::uint32_t ip = 0;
    std::string name;          // reverse-DNS name; empty unless name_state is Named
    NameState name_state = NameState::Unknown;
    bool is_local = false;     // private/LAN address rather than an internet one
    std::uint64_t packets = 0; // sent + received
    std::uint64_t bytes = 0;   // sent + received
    double current_bps = 0;    // smoothed rate over the last few seconds
    double average_bps = 0;    // average since first seen
    Clock::duration seen_for{};
};

struct FlowRow {
    FlowKey key;
    FlowStats stats;
    std::string name_a;
    std::string name_b;
    NameState name_state_a = NameState::Unknown;
    NameState name_state_b = NameState::Unknown;
    Category category = Category::Other;
    ClassMethod method = ClassMethod::None;
    std::string reason;  // why the classifier chose `category`, in plain language
};

struct CategoryRow {
    Category category = Category::Other;
    std::uint64_t bytes = 0;  // across active conversations
    std::size_t flows = 0;
    ClassMethod main_method = ClassMethod::None;  // the method behind most of these bytes
    std::string explanation;
};

// How well capture is keeping up. Packets can be lost in two places, and both are reported
// rather than hidden: in the kernel (libpcap's ring buffer overflowed before we read it) and
// in NetPulse's own queue (the aggregator fell behind the capture thread).
struct CaptureHealth {
    std::uint64_t captured = 0;      // packets libpcap handed to us
    std::uint64_t queue_drops = 0;   // ...that we then had to drop because the queue was full
    std::uint64_t kernel_drops = 0;  // never reached us at all
    std::uint64_t interface_drops = 0;

    std::uint64_t missed() const { return queue_drops + kernel_drops; }
    double missed_fraction() const {
        const std::uint64_t seen = captured + kernel_drops;
        return seen == 0 ? 0.0 : static_cast<double>(missed()) / static_cast<double>(seen);
    }
};

// An immutable, self-contained picture of the traffic at one moment. Built by the aggregator
// thread and handed to the UI thread whole, so the UI never touches live aggregator state.
struct Snapshot {
    Clock::duration uptime{};

    TrafficCounter total;
    TrafficCounter tcp;
    TrafficCounter udp;
    TrafficCounter other_ipv4;
    TrafficCounter non_ipv4;
    TrafficCounter malformed;

    double bytes_per_second = 0;   // last complete second
    double packets_per_second = 0;
    double current_bps = 0;        // smoothed over the last few seconds
    std::vector<std::uint64_t> byte_history;  // per second, oldest first

    std::vector<HostRow> top_hosts;     // by total bytes, descending
    std::vector<HostRow> rate_leaders;  // by current rate, descending (feeds the status checks)
    std::vector<FlowRow> top_flows;     // by total bytes, descending
    std::optional<FlowRow> busiest_flow;  // highest current rate
    std::size_t active_flows = 0;
    std::size_t known_hosts = 0;

    std::vector<CategoryRow> categories;  // shown categories with traffic, by bytes descending
    std::uint64_t background_bytes = 0;

    CaptureHealth health;
    Status status;
};

}  // namespace netpulse
