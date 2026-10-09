#pragma once

#include <chrono>
#include <cstdint>
#include <deque>

#include "aggregate/snapshot.hpp"
#include "aggregate/status.hpp"
#include "util/local_networks.hpp"

namespace netpulse {

// Tunable thresholds for the status checks. Starting points, to be tuned against real traffic.
struct StatusThresholds {
    double above_usual_factor = 3.0;  // current rate vs. the device's own average
    double new_device_share = 0.30;   // of current total traffic
    double unnamed_share = 0.50;      // of current total traffic
    double drop_fraction = 0.01;      // of packets over the recent window

    // Ratios mean nothing when traffic is light: 3x of almost nothing is still almost nothing.
    double min_rate_bps = 100'000;
    // Learn what "usual" looks like before comparing against it. Also stops every device from
    // counting as "new" in the first minute of a session.
    std::chrono::seconds warm_up{60};
    std::chrono::seconds new_device_window{60};       // "just appeared" means within this
    std::chrono::seconds unnamed_min_duration{10};    // a brief burst isn't "most of your traffic"
    std::chrono::seconds drop_window{5};
    std::uint64_t drop_min_packets = 200;             // too few packets: no meaningful rate
    // Once shown, a message stays up at least this long after its condition clears, so the
    // headline doesn't flicker on and off around a threshold.
    std::chrono::seconds hold{10};
};

// Decides the status line from successive snapshots.
//
// Checks, in priority order (the first that holds wins; messages never stack):
//   1. NetPulse is missing more than 1% of packets. First because when the tool is falling
//      behind, every other number on screen is less trustworthy.
//   2. A device is moving more than 3x its own average.
//   3. A device that just appeared is taking more than 30% of traffic.
//   4. One conversation with an address that has no reverse-DNS name is taking more than 50%.
//
// Time comes from Snapshot::uptime, so the tracker is deterministic and works the same for
// live capture and replay.
class StatusTracker {
public:
    explicit StatusTracker(StatusThresholds thresholds = {}, LocalNetworks local = {});

    Status update(const Snapshot& snapshot);

private:
    struct HealthSample {
        Clock::duration at{};
        std::uint64_t seen = 0;
        std::uint64_t missed = 0;
        std::uint64_t queue_drops = 0;
        std::uint64_t kernel_drops = 0;
    };

    Status evaluate(const Snapshot& s);
    std::optional<Status> check_capture_health(const Snapshot& s);
    std::optional<Status> check_device_above_usual(const Snapshot& s) const;
    std::optional<Status> check_new_device(const Snapshot& s) const;
    std::optional<Status> check_unnamed_destination(const Snapshot& s) const;

    StatusThresholds t_;
    LocalNetworks local_;  // which addresses are devices on your side
    std::deque<HealthSample> health_;
    Status shown_;
    Clock::duration last_true_{};  // when the shown heads-up condition last held
};

}  // namespace netpulse
