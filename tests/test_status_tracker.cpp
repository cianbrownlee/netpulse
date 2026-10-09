#include <catch2/catch_test_macros.hpp>
#include <chrono>
#include <string>

#include "aggregate/status_tracker.hpp"
#include "frame_builder.hpp"

using namespace netpulse;
using netpulse::test::ip;
using namespace std::chrono_literals;

namespace {

Snapshot at(Clock::duration uptime, double total_bps) {
    Snapshot s;
    s.uptime = uptime;
    s.current_bps = total_bps;
    return s;
}

HostRow device(const IpAddress& addr, double current, double average, Clock::duration seen_for) {
    HostRow h;
    h.ip = addr;
    h.current_bps = current;
    h.average_bps = average;
    h.seen_for = seen_for;
    return h;
}

// Laptop downloading from a server whose reverse-DNS lookup came back empty.
FlowRow unnamed_flow(double current, Clock::duration lifetime, NameState remote_state) {
    FlowRow f;
    f.key.ip_a = ip(192, 168, 1, 14);  // numerically lower, so endpoint A
    f.key.port_a = 51000;
    f.key.ip_b = ip(203, 0, 113, 9);
    f.key.port_b = 443;
    f.key.protocol = 6;
    f.stats.first_seen = Clock::time_point{} + 1000s;
    f.stats.last_seen = f.stats.first_seen + lifetime;
    f.stats.current_bps = current;
    f.name_state_b = remote_state;
    return f;
}

const IpAddress kLaptop = ip(192, 168, 1, 14);

}  // namespace

TEST_CASE("quiet traffic reads as normal, with an explanation", "[status]") {
    StatusTracker tracker;
    const Status s = tracker.update(at(5min, 20'000));
    CHECK(s.kind == StatusKind::Normal);
    CHECK_FALSE(s.heads_up());
    CHECK(s.headline == "Everything looks normal");
    CHECK(s.explanation.find("not a security scan") != std::string::npos);
}

TEST_CASE("a device far above its own average gets a heads-up", "[status]") {
    StatusTracker tracker;
    Snapshot s = at(10min, 1'200'000);
    s.rate_leaders = {device(kLaptop, 1'000'000, 100'000, 10min)};
    const Status st = tracker.update(s);
    CHECK(st.kind == StatusKind::DeviceAboveUsual);
    CHECK(st.headline.find("192.168.1.14") != std::string::npos);
    CHECK(st.explanation.find("10x") != std::string::npos);
}

TEST_CASE("above-usual needs history, real volume, and a device on your side", "[status]") {
    SECTION("still in the warm-up") {
        StatusTracker tracker;
        Snapshot s = at(30s, 1'200'000);
        s.rate_leaders = {device(kLaptop, 1'000'000, 100'000, 30s)};
        CHECK(tracker.update(s).kind == StatusKind::Normal);
    }
    SECTION("ratio is high but the traffic is tiny") {
        StatusTracker tracker;
        Snapshot s = at(10min, 60'000);
        s.rate_leaders = {device(kLaptop, 50'000, 2'000, 10min)};
        CHECK(tracker.update(s).kind == StatusKind::Normal);
    }
    SECTION("an internet server is not 'a device'") {
        StatusTracker tracker;
        Snapshot s = at(10min, 1'200'000);
        s.rate_leaders = {device(ip(93, 184, 216, 34), 1'000'000, 100'000, 10min)};
        CHECK(tracker.update(s).kind == StatusKind::Normal);
    }
}

TEST_CASE("a device that just appeared and dominates traffic gets a heads-up", "[status]") {
    StatusTracker tracker;
    Snapshot s = at(5min, 1'000'000);
    s.rate_leaders = {device(ip(192, 168, 1, 77), 800'000, 800'000, 20s)};
    const Status st = tracker.update(s);
    CHECK(st.kind == StatusKind::NewDeviceHeavy);
    CHECK(st.headline.find("a new device (192.168.1.77)") != std::string::npos);
}

TEST_CASE("at the start of a session, nothing counts as a new device", "[status]") {
    StatusTracker tracker;
    Snapshot s = at(40s, 1'000'000);
    s.rate_leaders = {device(ip(192, 168, 1, 77), 800'000, 800'000, 40s)};
    CHECK(tracker.update(s).kind == StatusKind::Normal);
}

TEST_CASE("most traffic to an address with no name is worth noticing", "[status]") {
    StatusTracker tracker;
    Snapshot s = at(5min, 1'000'000);
    s.busiest_flow = unnamed_flow(900'000, 30s, NameState::NoName);
    const Status st = tracker.update(s);
    CHECK(st.kind == StatusKind::UnnamedDestination);
    CHECK(st.explanation.find("203.0.113.9") != std::string::npos);
}

TEST_CASE("unnamed-destination needs a finished lookup and a sustained flow", "[status]") {
    SECTION("lookup still pending is not 'no name'") {
        StatusTracker tracker;
        Snapshot s = at(5min, 1'000'000);
        s.busiest_flow = unnamed_flow(900'000, 30s, NameState::Unknown);
        CHECK(tracker.update(s).kind == StatusKind::Normal);
    }
    SECTION("a brief burst") {
        StatusTracker tracker;
        Snapshot s = at(5min, 1'000'000);
        s.busiest_flow = unnamed_flow(900'000, 3s, NameState::NoName);
        CHECK(tracker.update(s).kind == StatusKind::Normal);
    }
    SECTION("not most of the traffic") {
        StatusTracker tracker;
        Snapshot s = at(5min, 1'000'000);
        s.busiest_flow = unnamed_flow(400'000, 30s, NameState::NoName);
        CHECK(tracker.update(s).kind == StatusKind::Normal);
    }
}

TEST_CASE("NetPulse falling behind is reported first, as a note about the tool", "[status]") {
    StatusTracker tracker;
    Snapshot s0 = at(10min, 1'200'000);
    s0.rate_leaders = {device(kLaptop, 1'000'000, 100'000, 10min)};  // would also trigger
    tracker.update(s0);

    Snapshot s1 = s0;
    s1.uptime = 10min + 5s;
    s1.health.captured = 10'000;
    s1.health.queue_drops = 400;
    s1.health.kernel_drops = 100;  // 500 of 10,100 seen: ~5%
    const Status st = tracker.update(s1);
    CHECK(st.kind == StatusKind::ToolFallingBehind);
    CHECK(st.explanation.find("about the tool, not your network") != std::string::npos);
}

TEST_CASE("drop rate uses a recent window and needs enough packets", "[status]") {
    StatusTracker tracker;
    Snapshot s = at(1min, 0);
    s.health.captured = 50;
    s.health.queue_drops = 10;  // 20%, but of only 60 packets
    CHECK(tracker.update(s).kind == StatusKind::Normal);

    // Old losses age out of the window: a burst of drops long ago doesn't keep the note up.
    StatusTracker t2;
    Snapshot early = at(1min, 0);
    t2.update(early);
    Snapshot lossy = at(1min + 5s, 0);
    lossy.health.captured = 10'000;
    lossy.health.queue_drops = 1'000;
    CHECK(t2.update(lossy).kind == StatusKind::ToolFallingBehind);
    for (int i = 1; i <= 30; ++i) {  // 30 s of clean capture afterwards
        Snapshot clean = lossy;
        clean.uptime = 1min + 5s + std::chrono::seconds(i);
        clean.health.captured = 10'000 + 1'000ull * static_cast<unsigned>(i);
        t2.update(clean);
    }
    Snapshot later = lossy;
    later.uptime = 1min + 36s;
    later.health.captured = 41'000;
    CHECK(t2.update(later).kind == StatusKind::Normal);
}

TEST_CASE("a heads-up stays up briefly after its condition clears", "[status]") {
    StatusTracker tracker;
    Snapshot busy = at(10min, 1'200'000);
    busy.rate_leaders = {device(kLaptop, 1'000'000, 100'000, 10min)};
    REQUIRE(tracker.update(busy).kind == StatusKind::DeviceAboveUsual);

    Snapshot calm = at(10min + 4s, 20'000);
    CHECK(tracker.update(calm).kind == StatusKind::DeviceAboveUsual);  // held

    calm.uptime = 10min + 11s;
    CHECK(tracker.update(calm).kind == StatusKind::Normal);  // hold expired
}

TEST_CASE("devices with public IPv6 addresses count once their network is known",
          "[status][ipv6][local]") {
    const IpAddress laptop6 = netpulse::test::ip6("2601:600:8a00:1234::14");
    Snapshot s = at(10min, 1'200'000);
    s.rate_leaders = {device(laptop6, 1'000'000, 100'000, 10min)};

    StatusTracker unaware;
    CHECK(unaware.update(s).kind == StatusKind::Normal);  // looks like an internet server

    LocalNetworks home;
    home.add(*IpPrefix::parse("2601:600:8a00:1234::/64"));
    StatusTracker aware(StatusThresholds{}, home);
    const Status st = aware.update(s);
    CHECK(st.kind == StatusKind::DeviceAboveUsual);
    CHECK(st.headline.find("2601:600:8a00:1234::14") != std::string::npos);
}
