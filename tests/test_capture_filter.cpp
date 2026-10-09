#include <catch2/catch_test_macros.hpp>
#include <cstdint>
#include <span>

#include "bpf_interpreter.hpp"
#include "capture/capture_filter.hpp"
#include "frame_builder.hpp"
#include "parse/packet_parser.hpp"

using namespace netpulse;
using namespace netpulse::test;

namespace {

std::uint32_t keep(const std::vector<BpfInstruction>& program, const Bytes& frame) {
    return run_bpf(program, std::span<const std::uint8_t>(frame));
}

const IpAddress kLaptop = ip(192, 168, 1, 14);
const IpAddress kResolver = ip(8, 8, 8, 8);

}  // namespace

TEST_CASE("by default every packet is cut to the snaplen", "[filter]") {
    const auto program = build_capture_filter(192, 0);
    CHECK(program.size() == 1);
    CHECK(keep(program, udp_frame(kResolver, 53, kLaptop, 50000, 300)) == 192);
    CHECK(keep(program, Bytes(10, 0)) == 192);  // even runts: the one-instruction filter reads nothing
}

TEST_CASE("with DNS names on, only DNS and mDNS responses keep more", "[filter]") {
    const auto program = build_capture_filter(192, 512);

    CHECK(keep(program, udp_frame(kResolver, 53, kLaptop, 50000, 300)) == 512);       // DNS answer
    CHECK(keep(program, udp_frame(ip(192, 168, 1, 31), 5353, ip(224, 0, 0, 251), 5353, 80)) == 512);
    CHECK(keep(program, udp_frame(kLaptop, 50000, kResolver, 53, 30)) == 192);       // the query
    CHECK(keep(program, tcp_frame(kResolver, 53, kLaptop, 50000, 300)) == 192);      // DNS over TCP
    CHECK(keep(program, tcp_frame(ip(93, 184, 216, 34), 443, kLaptop, 51000)) == 192);
    CHECK(keep(program, concat({ethernet(kEtherTypeArp), payload(28)})) == 192);
}

TEST_CASE("the IPv4 header length is honored when finding the UDP port", "[filter]") {
    const auto program = build_capture_filter(192, 512);
    // 12 bytes of IP options push the UDP header back; port 53 must still be found.
    const Bytes with_options = concat({ethernet(kEtherTypeIpv4),
                                       ipv4(kResolver, kLaptop, 17, 8 + 40, Ipv4Options{}.options(12)),
                                       udp(53, 50000, 40), payload(40)});
    CHECK(keep(program, with_options) == 512);
}

TEST_CASE("later IPv4 fragments never count as DNS", "[filter]") {
    const auto program = build_capture_filter(192, 512);
    // Payload bytes that happen to sit where a UDP source port of 53 would be.
    const Bytes later = concat({ethernet(kEtherTypeIpv4),
                                ipv4(kResolver, kLaptop, 17, 40, Ipv4Options{}.fragment(185)),
                                Bytes{0x00, 0x35}, payload(38)});
    CHECK(keep(program, later) == 192);
}

TEST_CASE("IPv6 DNS responses keep more, when UDP follows the fixed header", "[filter][ipv6]") {
    const auto program = build_capture_filter(192, 512);
    const IpAddress laptop6 = ip6("2001:db8:1::14");
    const IpAddress resolver6 = ip6("2001:4860:4860::8888");
    CHECK(keep(program, udp6_frame(resolver6, 53, laptop6, 50000, 300)) == 512);
    CHECK(keep(program, udp6_frame(laptop6, 50000, resolver6, 53, 30)) == 192);

    // Documented limitation: behind an extension header, the filter doesn't look.
    const Bytes behind_extension = concat({ethernet(kEtherTypeIpv6),
                                           ipv6(resolver6, laptop6, kIpv6HopByHop, 8 + 8 + 40),
                                           ext_header(kIpProtoUdp, 8), udp(53, 50000, 40), payload(40)});
    CHECK(keep(program, behind_extension) == 192);
}

TEST_CASE("documented limitations of the longer filter", "[filter]") {
    const auto program = build_capture_filter(192, 512);
    // VLAN-tagged frames aren't inspected: no extra bytes, but nothing lost either.
    const Bytes tagged = concat({ethernet(kEtherTypeIpv4, 10), ipv4(kResolver, kLaptop, 17, 8 + 40),
                                 udp(53, 50000, 40), payload(40)});
    CHECK(keep(program, tagged) == 192);
    // A runt IPv4 frame too short for the fields checked is dropped (BPF's out-of-bounds rule).
    const Bytes runt = concat({ethernet(kEtherTypeIpv4), Bytes{0x45, 0x00}});
    CHECK(keep(program, runt) == 0);
}
