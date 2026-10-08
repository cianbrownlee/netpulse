#include <catch2/catch_test_macros.hpp>
#include <chrono>

#include "frame_builder.hpp"
#include "util/format.hpp"
#include "util/net.hpp"

using namespace netpulse;
using netpulse::test::ip;
using namespace std::chrono_literals;

TEST_CASE("byte counts read at human scale", "[format]") {
    CHECK(format_bytes(0) == "0 B");
    CHECK(format_bytes(999) == "999 B");
    CHECK(format_bytes(1000) == "1.0 kB");
    CHECK(format_bytes(12'400'000) == "12.4 MB");
    CHECK(format_bytes(123'456'789) == "123 MB");
    CHECK(format_bytes(2'500'000'000.0) == "2.5 GB");
    CHECK(format_rate(12'400'000) == "12.4 MB/s");
}

TEST_CASE("counts get thousands separators", "[format]") {
    CHECK(format_count(0) == "0");
    CHECK(format_count(12) == "12");
    CHECK(format_count(123) == "123");
    CHECK(format_count(1234) == "1,234");
    CHECK(format_count(12345) == "12,345");
    CHECK(format_count(123456) == "123,456");
    CHECK(format_count(1234567) == "1,234,567");
}

TEST_CASE("durations and percentages", "[format]") {
    CHECK(format_duration(45s) == "45 s");
    CHECK(format_duration(14min + 20s) == "14 min");
    CHECK(format_duration(2h + 5min) == "2 h 05 min");
    CHECK(format_percent(0.5) == "50%");
    CHECK(format_percent(0.0123, 2) == "1.23%");
}

TEST_CASE("IPv4 helpers", "[format][net]") {
    CHECK(ipv4_to_string(ip(192, 168, 1, 14)) == "192.168.1.14");
    CHECK(ipv4_to_string(0) == "0.0.0.0");

    CHECK(is_local_ipv4(ip(192, 168, 1, 14)));
    CHECK(is_local_ipv4(ip(10, 1, 2, 3)));
    CHECK(is_local_ipv4(ip(172, 20, 169, 233)));  // WSL2's NAT range
    CHECK_FALSE(is_local_ipv4(ip(172, 32, 0, 1)));  // just outside 172.16/12
    CHECK_FALSE(is_local_ipv4(ip(8, 8, 8, 8)));

    CHECK(ip_protocol_name(6) == "TCP");
    CHECK(ip_protocol_name(17) == "UDP");
    CHECK(ip_protocol_name(47) == "IP proto 47");
}
