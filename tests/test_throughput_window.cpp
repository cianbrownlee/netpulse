#include <catch2/catch_test_macros.hpp>
#include <chrono>

#include "aggregate/throughput_window.hpp"

using netpulse::ThroughputWindow;
using namespace std::chrono_literals;

namespace {
const ThroughputWindow::Clock::time_point t0 = ThroughputWindow::Clock::time_point{} + 1000s;
}

TEST_CASE("a fresh window reads zero", "[throughput]") {
    ThroughputWindow w(60);
    CHECK(w.bytes_per_second() == 0.0);
    CHECK(w.packets_per_second() == 0.0);
    const auto history = w.byte_history();
    CHECK(history.size() == 60);
    for (auto v : history) CHECK(v == 0);
}

TEST_CASE("rate reflects the last complete second only", "[throughput]") {
    ThroughputWindow w(60);
    w.add(t0, 1000);
    w.add(t0 + 300ms, 500);
    w.add(t0 + 900ms, 500);

    // Still inside second 0: nothing is complete yet.
    w.advance_to(t0 + 950ms);
    CHECK(w.bytes_per_second() == 0.0);

    // Second 1 in progress: second 0 is complete and counted; second 1's bytes are not.
    w.add(t0 + 1200ms, 99999);
    w.advance_to(t0 + 1500ms);
    CHECK(w.bytes_per_second() == 2000.0);
    CHECK(w.packets_per_second() == 3.0);
}

TEST_CASE("idle seconds read as zero instead of repeating the last busy one", "[throughput]") {
    ThroughputWindow w(60);
    w.add(t0, 5000);
    w.advance_to(t0 + 1500ms);
    CHECK(w.bytes_per_second() == 5000.0);

    w.advance_to(t0 + 5500ms);  // four quiet seconds later
    CHECK(w.bytes_per_second() == 0.0);

    const auto history = w.byte_history();  // seconds -55 .. 4
    REQUIRE(history.size() == 60);
    CHECK(history[55] == 5000);  // second 0
    CHECK(history[56] == 0);
    CHECK(history[59] == 0);
}

TEST_CASE("history is ordered oldest to newest", "[throughput]") {
    ThroughputWindow w(5);
    for (int s = 0; s < 5; ++s) w.add(t0 + std::chrono::seconds(s), static_cast<std::uint64_t>(s + 1) * 100);
    w.advance_to(t0 + 5s);
    const auto history = w.byte_history();
    REQUIRE(history.size() == 5);
    CHECK(history == std::vector<std::uint64_t>{100, 200, 300, 400, 500});
}

TEST_CASE("data older than the window falls out", "[throughput]") {
    ThroughputWindow w(5);
    w.add(t0, 777);
    w.advance_to(t0 + 3s);
    CHECK(w.byte_history()[2] == 777);

    w.advance_to(t0 + 6s);  // second 0 is now 6 seconds old: outside a 5-second window
    for (auto v : w.byte_history()) CHECK(v == 0);

    // A gap much longer than the ring must not leave stale buckets behind either.
    w.add(t0 + 7s, 1);
    w.advance_to(t0 + 500s);
    for (auto v : w.byte_history()) CHECK(v == 0);
}

TEST_CASE("a slightly late packet is credited to its own second", "[throughput]") {
    ThroughputWindow w(60);
    w.add(t0, 100);
    w.advance_to(t0 + 2100ms);
    w.add(t0 + 1500ms, 40);  // stamped during second 1, counted during second 2
    w.advance_to(t0 + 2200ms);
    CHECK(w.bytes_per_second() == 40.0);  // second 1
    const auto history = w.byte_history();
    CHECK(history[58] == 100);  // second 0
    CHECK(history[59] == 40);   // second 1
}
