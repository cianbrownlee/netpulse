#include <catch2/catch_test_macros.hpp>
#include <chrono>

#include "frame_builder.hpp"
#include "util/format.hpp"
#include "util/net.hpp"

using namespace netpulse;
using netpulse::test::ip;
using netpulse::test::ip6;
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

TEST_CASE("IP addresses: IPv4 and IPv6 in one type", "[net][ip]") {
    const IpAddress laptop = ip(192, 168, 1, 14);
    CHECK(laptop.is_v4());
    CHECK(laptop.v4_value() == 0xC0A8010Eu);
    CHECK(laptop.to_string() == "192.168.1.14");
    CHECK(ip(0, 0, 0, 0).to_string() == "0.0.0.0");

    const IpAddress doc = ip6("2001:db8::1");
    CHECK_FALSE(doc.is_v4());
    CHECK_FALSE(doc == laptop);
    CHECK(std::hash<IpAddress>{}(laptop) == std::hash<IpAddress>{}(ip(192, 168, 1, 14)));

    // IPv4 orders numerically, as the canonical flow key relies on.
    CHECK(ip(93, 184, 216, 34) < ip(192, 168, 1, 14));
    CHECK(ip(10, 0, 0, 9) < ip(10, 0, 0, 10));
}

TEST_CASE("IPv6 text is RFC 5952 canonical", "[net][ip]") {
    CHECK(ip6("2001:0DB8:0000:0000:0000:0000:0000:0001").to_string() == "2001:db8::1");
    CHECK(ip6("fe80::1").to_string() == "fe80::1");
    CHECK(ip6("::1").to_string() == "::1");
    CHECK(ip6("::").to_string() == "::");
    // Only runs of two or more zero groups collapse, and only the first of equal runs.
    CHECK(ip6("2001:db8:0:1:1:1:1:1").to_string() == "2001:db8:0:1:1:1:1:1");
    CHECK(ip6("2001:db8:0:0:1:0:0:1").to_string() == "2001:db8::1:0:0:1");
}

TEST_CASE("local and private ranges", "[net][ip]") {
    CHECK(is_local(ip(192, 168, 1, 14)));
    CHECK(is_local(ip(10, 1, 2, 3)));
    CHECK(is_local(ip(172, 20, 169, 233)));   // WSL2's NAT range
    CHECK_FALSE(is_local(ip(172, 32, 0, 1)));  // just outside 172.16/12
    CHECK_FALSE(is_local(ip(8, 8, 8, 8)));

    // Discovery and broadcast traffic stays on the local network.
    CHECK(is_local(ip(239, 255, 255, 250)));  // SSDP
    CHECK(is_local(ip(224, 0, 0, 251)));      // mDNS
    CHECK(is_local(ip(255, 255, 255, 255)));
    CHECK(is_local(ip(0, 0, 0, 0)));
    CHECK_FALSE(is_local(ip(223, 255, 255, 255)));  // just below multicast
    CHECK_FALSE(is_private(ip(239, 255, 255, 250)));  // local, but not a device

    // IPv6.
    CHECK(is_private(ip6("fd12:3456:789a::1")));  // unique local
    CHECK(is_private(ip6("fe80::1c2b:3cff:fe4d:5e6f")));  // link-local
    CHECK(is_private(ip6("::1")));
    CHECK_FALSE(is_private(ip6("2001:db8::1")));
    CHECK_FALSE(is_private(ip6("2606:4700::6810:84e5")));  // a public (Cloudflare) address
    CHECK(is_local(ip6("ff02::fb")));  // mDNS multicast
    CHECK(is_local(ip6("::")));
    CHECK_FALSE(is_private(ip6("ff02::fb")));
}

TEST_CASE("protocol names", "[net]") {
    CHECK(ip_protocol_name(6) == "TCP");
    CHECK(ip_protocol_name(17) == "UDP");
    CHECK(ip_protocol_name(58) == "ICMPv6");
    CHECK(ip_protocol_name(47) == "GRE");
    CHECK(ip_protocol_name(99) == "IP proto 99");
}

TEST_CASE("network-sourced text is made terminal-safe", "[format]") {
    CHECK(printable("www.example.com") == "www.example.com");
    CHECK(printable("evil\x1b[2J.com") == "evil?[2J.com");
    CHECK(printable(std::string("a\0b", 3)) == "a?b");
    CHECK(printable("caf\xc3\xa9") == "caf??");
}
