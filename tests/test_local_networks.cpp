#include <catch2/catch_test_macros.hpp>

#include "frame_builder.hpp"
#include "util/local_networks.hpp"

using namespace netpulse;
using netpulse::test::ip;
using netpulse::test::ip6;

TEST_CASE("prefixes parse from text, with host bits cleared", "[local]") {
    const auto lan = IpPrefix::parse("192.168.1.14/24");
    REQUIRE(lan);
    CHECK(lan->to_string() == "192.168.1.0/24");
    CHECK(lan->contains(ip(192, 168, 1, 200)));
    CHECK_FALSE(lan->contains(ip(192, 168, 2, 1)));

    const auto home6 = IpPrefix::parse("2001:db8:1:0:abcd::1/64");
    REQUIRE(home6);
    CHECK(home6->to_string() == "2001:db8:1::/64");
    CHECK(home6->contains(ip6("2001:db8:1::14")));
    CHECK_FALSE(home6->contains(ip6("2001:db8:2::14")));

    // A bare address is a single host.
    const auto host = IpPrefix::parse("10.0.0.5");
    REQUIRE(host);
    CHECK(host->bits == 32);
    CHECK(host->contains(ip(10, 0, 0, 5)));
    CHECK_FALSE(host->contains(ip(10, 0, 0, 6)));
}

TEST_CASE("bad prefixes are rejected", "[local]") {
    CHECK_FALSE(IpPrefix::parse("192.168.1.0/33"));
    CHECK_FALSE(IpPrefix::parse("2001:db8::/129"));
    CHECK_FALSE(IpPrefix::parse("192.168.1.0/"));
    CHECK_FALSE(IpPrefix::parse("192.168.1.0/2x"));
    CHECK_FALSE(IpPrefix::parse("not-an-address/24"));
    CHECK_FALSE(IpPrefix::parse(""));
}

TEST_CASE("an IPv4 prefix never matches an IPv6 address and vice versa", "[local]") {
    const auto everything4 = IpPrefix::parse("0.0.0.0/0");
    REQUIRE(everything4);
    CHECK(everything4->contains(ip(8, 8, 8, 8)));
    CHECK_FALSE(everything4->contains(ip6("2001:db8::1")));

    const auto everything6 = IpPrefix::parse("::/0");
    REQUIRE(everything6);
    CHECK(everything6->contains(ip6("2001:db8::1")));
    CHECK_FALSE(everything6->contains(ip(8, 8, 8, 8)));
}

TEST_CASE("prefixes come from interface netmasks", "[local]") {
    const auto v4 = IpPrefix::from_netmask(ip(172, 20, 169, 233), ip(255, 255, 240, 0));
    REQUIRE(v4);
    CHECK(v4->to_string() == "172.20.160.0/20");  // WSL2's NAT network

    const auto v6 = IpPrefix::from_netmask(ip6("2601:600:8a00:1234:5678:9abc:def0:1"),
                                           ip6("ffff:ffff:ffff:ffff::"));
    REQUIRE(v6);
    CHECK(v6->to_string() == "2601:600:8a00:1234::/64");

    // Not a prefix mask (ones after a zero), or mixed families: no prefix.
    CHECK_FALSE(IpPrefix::from_netmask(ip(10, 0, 0, 1), ip(255, 0, 255, 0)));
    CHECK_FALSE(IpPrefix::from_netmask(ip(10, 0, 0, 1), ip6("ffff::")));
}

TEST_CASE("local networks make public IPv6 home addresses local devices", "[local][ipv6]") {
    LocalNetworks home;
    home.add(*IpPrefix::parse("2601:600:8a00:1234::/64"));
    home.add(*IpPrefix::parse("2601:600:8a00:1234::/64"));  // duplicates are ignored
    CHECK(home.prefixes().size() == 1);

    const IpAddress laptop = ip6("2601:600:8a00:1234::14");
    CHECK(home.is_device(laptop));
    CHECK(home.is_local(laptop));
    CHECK_FALSE(no_local_networks().is_device(laptop));  // the address alone looks public

    // Private ranges are always local; group addresses never name a device.
    CHECK(home.is_device(ip(192, 168, 1, 14)));
    CHECK(home.is_local(ip6("ff02::fb")));
    CHECK_FALSE(home.is_device(ip6("ff02::fb")));
    CHECK_FALSE(home.is_device(ip(255, 255, 255, 255)));
    CHECK_FALSE(home.is_local(ip6("2606:4700::6810:84e5")));
    CHECK(home.to_string() == "2601:600:8a00:1234::/64");
}
