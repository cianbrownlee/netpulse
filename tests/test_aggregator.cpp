#include <catch2/catch_test_macros.hpp>
#include <chrono>

#include "aggregate/aggregator.hpp"
#include "frame_builder.hpp"

using namespace netpulse;
using namespace netpulse::test;
using namespace std::chrono_literals;

namespace {

const Clock::time_point t0 = Clock::time_point{} + 1000s;
const std::uint32_t kLaptop = ip(192, 168, 1, 14);
const std::uint32_t kTv = ip(192, 168, 1, 31);
const std::uint32_t kServer = ip(93, 184, 216, 34);

void ingest_frame(Aggregator& agg, const Bytes& frame, std::uint32_t wire_length,
                  Clock::time_point t) {
    agg.ingest(parse_packet(std::span<const std::uint8_t>(frame)), wire_length, t);
}

}  // namespace

TEST_CASE("packets in both directions accumulate into one flow", "[aggregate]") {
    Aggregator agg;
    ingest_frame(agg, tcp_frame(kLaptop, 51000, kServer, 443), 100, t0);
    ingest_frame(agg, tcp_frame(kServer, 443, kLaptop, 51000), 1500, t0 + 10ms);
    ingest_frame(agg, tcp_frame(kServer, 443, kLaptop, 51000), 1500, t0 + 20ms);

    REQUIRE(agg.flows().size() == 1);
    const FlowStats& f = agg.flows().begin()->second;
    CHECK(f.packets == 3);
    CHECK(f.bytes == 3100);
    // 93.184.216.34 is numerically lower than 192.168.1.14, so the server is endpoint A and
    // server -> laptop is the A-to-B direction.
    CHECK(f.bytes_a_to_b == 3000);
    CHECK(f.bytes_b_to_a == 100);
    CHECK(f.first_seen == t0);
    CHECK(f.last_seen == t0 + 20ms);
}

TEST_CASE("totals and per-protocol counters use on-the-wire length", "[aggregate]") {
    Aggregator agg;
    ingest_frame(agg, tcp_frame(kLaptop, 1, kServer, 443), 1514, t0);
    ingest_frame(agg, udp_frame(kLaptop, 2, ip(8, 8, 8, 8), 53), 80, t0);
    ingest_frame(agg, concat({ethernet(kEtherTypeArp), payload(28)}), 60, t0);
    ingest_frame(agg, Bytes{0x01, 0x02, 0x03}, 3, t0);  // malformed

    const Snapshot s = agg.build_snapshot(t0 + 1s);
    CHECK(s.total.packets == 4);
    CHECK(s.total.bytes == 1514 + 80 + 60 + 3);
    CHECK(s.tcp.packets == 1);
    CHECK(s.tcp.bytes == 1514);
    CHECK(s.udp.bytes == 80);
    CHECK(s.non_ipv4.packets == 1);
    CHECK(s.malformed.packets == 1);
}

TEST_CASE("non-IPv4 and malformed packets never create flows or hosts", "[aggregate]") {
    Aggregator agg;
    ingest_frame(agg, concat({ethernet(kEtherTypeIpv6), payload(40)}), 80, t0);
    ingest_frame(agg, Bytes(10, 0xFF), 10, t0);
    CHECK(agg.flows().empty());
    CHECK(agg.hosts().empty());
    CHECK(agg.total().packets == 2);
}

TEST_CASE("hosts are credited for traffic they send and receive", "[aggregate]") {
    Aggregator agg;
    ingest_frame(agg, tcp_frame(kLaptop, 1, kServer, 443), 100, t0);
    ingest_frame(agg, tcp_frame(kServer, 443, kLaptop, 1), 900, t0);
    ingest_frame(agg, udp_frame(kTv, 5, kServer, 6), 50, t0);

    CHECK(agg.hosts().at(kLaptop).bytes == 1000);
    CHECK(agg.hosts().at(kServer).bytes == 1050);
    CHECK(agg.hosts().at(kTv).bytes == 50);
}

TEST_CASE("snapshot top-N is sorted by bytes and capped", "[aggregate]") {
    Aggregator::Config config;
    config.top_n = 2;
    Aggregator agg(config);
    ingest_frame(agg, udp_frame(ip(10, 0, 0, 1), 1, ip(10, 0, 0, 9), 9), 100, t0);
    ingest_frame(agg, udp_frame(ip(10, 0, 0, 2), 2, ip(10, 0, 0, 9), 9), 300, t0);
    ingest_frame(agg, udp_frame(ip(10, 0, 0, 3), 3, ip(10, 0, 0, 9), 9), 200, t0);

    const Snapshot s = agg.build_snapshot(t0 + 1s);
    REQUIRE(s.top_flows.size() == 2);
    CHECK(s.top_flows[0].stats.bytes == 300);
    CHECK(s.top_flows[1].stats.bytes == 200);

    REQUIRE(s.top_hosts.size() == 2);
    CHECK(s.top_hosts[0].ip == ip(10, 0, 0, 9));  // party to every flow: 600 bytes
    CHECK(s.top_hosts[0].bytes == 600);
    CHECK(s.top_hosts[0].is_local);
    CHECK(s.top_hosts[1].ip == ip(10, 0, 0, 2));

    CHECK(s.active_flows == 3);
    CHECK(s.known_hosts == 4);
}

TEST_CASE("idle flows expire, active ones stay", "[aggregate]") {
    Aggregator::Config config;
    config.flow_idle_timeout = 120s;
    Aggregator agg(config);
    ingest_frame(agg, tcp_frame(kLaptop, 1, kServer, 443), 100, t0);
    ingest_frame(agg, tcp_frame(kLaptop, 2, kServer, 443), 100, t0 + 100s);

    agg.expire_idle_flows(t0 + 150s);  // first flow idle 150s, second idle 50s
    REQUIRE(agg.flows().size() == 1);
    CHECK(agg.flows().begin()->first.port_b == 2);  // the laptop's side of the newer flow

    // Cumulative totals are history, not live state: expiry never rewinds them.
    CHECK(agg.total().packets == 2);
}

TEST_CASE("snapshot carries current throughput and history", "[aggregate]") {
    Aggregator agg;
    ingest_frame(agg, tcp_frame(kLaptop, 1, kServer, 443), 1000, t0);
    ingest_frame(agg, tcp_frame(kLaptop, 1, kServer, 443), 1000, t0 + 500ms);

    const Snapshot s = agg.build_snapshot(t0 + 1200ms);
    CHECK(s.bytes_per_second == 2000.0);
    CHECK(s.packets_per_second == 2.0);
    REQUIRE(s.byte_history.size() == 60);
    CHECK(s.byte_history.back() == 2000);
}
