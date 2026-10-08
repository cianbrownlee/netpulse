#include <catch2/catch_test_macros.hpp>
#include <unordered_map>
#include <unordered_set>

#include "aggregate/flow.hpp"
#include "frame_builder.hpp"

using namespace netpulse;
using netpulse::test::ip;

namespace {

PacketInfo tcp_packet(std::uint32_t src, std::uint16_t sport, std::uint32_t dst,
                      std::uint16_t dport) {
    PacketInfo p;
    p.kind = PacketKind::Tcp;
    p.ip_protocol = kIpProtoTcp;
    p.src_ip = src;
    p.src_port = sport;
    p.dst_ip = dst;
    p.dst_port = dport;
    return p;
}

}  // namespace

TEST_CASE("both directions of a conversation share one flow key", "[flow]") {
    const auto out = make_flow_key(tcp_packet(ip(192, 168, 1, 14), 51000, ip(93, 184, 216, 34), 443));
    const auto back = make_flow_key(tcp_packet(ip(93, 184, 216, 34), 443, ip(192, 168, 1, 14), 51000));

    CHECK(out.key == back.key);
    CHECK(out.a_to_b != back.a_to_b);
    CHECK(std::hash<FlowKey>{}(out.key) == std::hash<FlowKey>{}(back.key));
}

TEST_CASE("endpoint A is the lower (ip, port) pair", "[flow]") {
    const auto d = make_flow_key(tcp_packet(ip(10, 0, 0, 9), 80, ip(10, 0, 0, 2), 5555));
    CHECK(d.key.ip_a == ip(10, 0, 0, 2));
    CHECK(d.key.port_a == 5555);
    CHECK(d.key.ip_b == ip(10, 0, 0, 9));
    CHECK(d.key.port_b == 80);
    CHECK_FALSE(d.a_to_b);

    // Same address on both ends (loopback): ports break the tie.
    const auto loop = make_flow_key(tcp_packet(ip(127, 0, 0, 1), 9000, ip(127, 0, 0, 1), 3000));
    CHECK(loop.key.port_a == 3000);
    CHECK_FALSE(loop.a_to_b);
}

TEST_CASE("different ports, protocols or peers are different flows", "[flow]") {
    const auto base = make_flow_key(tcp_packet(ip(10, 0, 0, 1), 1000, ip(10, 0, 0, 2), 443)).key;

    auto other_port = make_flow_key(tcp_packet(ip(10, 0, 0, 1), 1001, ip(10, 0, 0, 2), 443)).key;
    auto other_peer = make_flow_key(tcp_packet(ip(10, 0, 0, 1), 1000, ip(10, 0, 0, 3), 443)).key;
    PacketInfo as_udp = tcp_packet(ip(10, 0, 0, 1), 1000, ip(10, 0, 0, 2), 443);
    as_udp.ip_protocol = kIpProtoUdp;
    auto other_proto = make_flow_key(as_udp).key;

    CHECK_FALSE(base == other_port);
    CHECK_FALSE(base == other_peer);
    CHECK_FALSE(base == other_proto);
}

TEST_CASE("flow key hash spreads sequential ports across buckets", "[flow]") {
    // Ephemeral ports are often sequential; a weak hash would cluster them.
    std::unordered_set<std::size_t> hashes;
    for (std::uint16_t port = 50000; port < 51000; ++port) {
        hashes.insert(std::hash<FlowKey>{}(
            make_flow_key(tcp_packet(ip(192, 168, 1, 14), port, ip(1, 1, 1, 1), 443)).key));
    }
    CHECK(hashes.size() == 1000);

    std::unordered_map<FlowKey, int> map;
    map[make_flow_key(tcp_packet(ip(1, 1, 1, 1), 1, ip(2, 2, 2, 2), 2)).key] = 7;
    CHECK(map.at(make_flow_key(tcp_packet(ip(2, 2, 2, 2), 2, ip(1, 1, 1, 1), 1)).key) == 7);
}
