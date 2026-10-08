#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <vector>

namespace netpulse {

// Bytes and packets per second over a trailing window of whole seconds (default 60).
//
// A cumulative average (total bytes / uptime) would flatten every burst and idle period into
// one meaningless number; this keeps the recent shape of the traffic, which is what both the
// "current throughput" readout and the sparkline need.
//
// Time is passed in explicitly rather than read from a clock, so the window is deterministic
// and testable.
class ThroughputWindow {
public:
    using Clock = std::chrono::steady_clock;

    explicit ThroughputWindow(std::size_t window_seconds = 60);

    void add(Clock::time_point t, std::uint64_t bytes);

    // Rolls the window forward to `now`, zero-filling idle seconds. Call before reading so
    // that a quiet network reads as zero instead of as the last busy second.
    void advance_to(Clock::time_point now);

    // Rates over the most recent *complete* second. The in-progress second is excluded:
    // a quarter of the way into a second it would under-report by roughly 4x.
    double bytes_per_second() const;
    double packets_per_second() const;

    // Complete-second byte totals, oldest first. Always window_seconds() entries long.
    std::vector<std::uint64_t> byte_history() const;

    std::size_t window_seconds() const { return window_seconds_; }

private:
    struct Bucket {
        std::uint64_t bytes = 0;
        std::uint64_t packets = 0;
    };

    std::int64_t second_of(Clock::time_point t) const;
    const Bucket* bucket_for(std::int64_t second) const;

    std::size_t window_seconds_;
    std::vector<Bucket> ring_;  // window_seconds_ complete seconds + 1 in progress
    bool started_ = false;
    Clock::time_point origin_{};
    std::int64_t current_second_ = 0;
};

}  // namespace netpulse
