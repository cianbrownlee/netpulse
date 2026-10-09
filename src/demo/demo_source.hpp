#pragma once

#include <atomic>
#include <chrono>
#include <cstdint>
#include <optional>
#include <string>

#include "capture/packet_source.hpp"

namespace netpulse {

// Simulated traffic from a small household, for `netpulse --demo`: try the dashboard without
// capture permissions, a Linux box, or interesting traffic of your own.
//
// The packets are real Ethernet frames that go through the same parser, aggregator, classifier
// and status checks as captured ones. They follow a script: a TV streaming over IPv6, a laptop
// watching video over QUIC and browsing, a phone on a call, a gaming PC playing and then
// starting a big download, plus the background chatter (DNS answers, mDNS announcements, NTP,
// ARP) that names everything. All addresses come from the ranges reserved for documentation
// (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24, 2001:db8::/32), so none of them is anyone's
// real server.
//
// Like a replay, the source runs on its own clock (the timestamps it gives packets). It
// generates `preroll` seconds instantly, so the dashboard opens with a full minute of history
// and the status checks past their warm-up, then continues in real time.
class DemoSource final : public PacketSource {
public:
    struct Options {
        std::chrono::seconds preroll{75};
        // Pace packets in real time after the pre-roll. Off: generate as fast as possible.
        bool realtime = true;
        // Stop after this much simulated time; unset runs until stop().
        std::optional<std::chrono::seconds> duration;
        std::uint32_t seed = 7;
    };

    // Simulated seconds at which the gaming PC's big download starts (it repeats every
    // kDownloadPeriod), so tests and docs can refer to the scripted event.
    static constexpr int kDownloadStart = 85;
    static constexpr int kDownloadLength = 40;
    static constexpr int kDownloadPeriod = 180;

    DemoSource() : DemoSource(Options{}) {}
    explicit DemoSource(Options options);

    void run(BoundedQueue<CapturedPacket>& queue) override;
    void stop() override { stop_.store(true); }

    CaptureCounters counters() const override;
    std::optional<std::string> error() const override { return std::nullopt; }
    bool is_offline() const override { return true; }  // its own clock, like a replay
    bool is_demo() const override { return true; }
    const std::string& description() const override { return description_; }
    LocalNetworks local_networks() const override;

private:
    Options options_;
    std::atomic<bool> stop_{false};
    std::atomic<std::uint64_t> produced_{0};
    std::string description_ = "demo household";
};

}  // namespace netpulse
