#include <catch2/catch_test_macros.hpp>
#include <random>

#include "frame_builder.hpp"
#include "parse/packet_parser.hpp"

using namespace netpulse;
using namespace netpulse::test;

namespace {

PacketInfo parse(const Bytes& frame) { return parse_packet(std::span<const std::uint8_t>(frame)); }

const IpAddress kLaptop = ip(192, 168, 1, 14);
const IpAddress kServer = ip(93, 184, 216, 34);

}  // namespace

TEST_CASE("TCP frame parses through every layer", "[parse]") {
    const auto info = parse(tcp_frame(kLaptop, 51000, kServer, 443, 100,
                                      tcp_flags::kSyn | tcp_flags::kAck));
    CHECK(info.kind == PacketKind::Tcp);
    CHECK(info.ethertype == kEtherTypeIpv4);
    CHECK(info.ip_protocol == kIpProtoTcp);
    CHECK(info.src_ip == kLaptop);
    CHECK(info.dst_ip == kServer);
    CHECK(info.src_port == 51000);
    CHECK(info.dst_port == 443);
    CHECK(info.tcp_flags == (tcp_flags::kSyn | tcp_flags::kAck));
}

TEST_CASE("UDP frame parses through every layer", "[parse]") {
    const auto info = parse(udp_frame(kLaptop, 50000, ip(8, 8, 8, 8), 53, 40));
    CHECK(info.kind == PacketKind::Udp);
    CHECK(info.ip_protocol == kIpProtoUdp);
    CHECK(info.dst_ip == ip(8, 8, 8, 8));
    CHECK(info.src_port == 50000);
    CHECK(info.dst_port == 53);
}

TEST_CASE("multi-byte fields are read as big-endian", "[parse]") {
    // 443 = 0x01BB: read little-endian it would come out as 0xBB01 = 47873.
    const auto info = parse(tcp_frame(ip(1, 2, 3, 4), 443, ip(10, 20, 30, 40), 8080));
    CHECK(info.src_port == 443);
    CHECK(info.dst_port == 8080);
    CHECK(info.src_ip == IpAddress::v4(0x01020304u));
    CHECK(info.dst_ip == IpAddress::v4(0x0A141E28u));
}

TEST_CASE("802.1Q VLAN tag is skipped to find the real EtherType", "[parse]") {
    const Bytes frame = concat({ethernet(kEtherTypeIpv4, 42), ipv4(kLaptop, kServer, 6, 20),
                                tcp(1234, 443)});
    const auto eth = parse_ethernet(frame);
    REQUIRE(eth);
    CHECK(eth->header_length == 18);
    CHECK(eth->ethertype == kEtherTypeIpv4);
    CHECK(parse(frame).kind == PacketKind::Tcp);
}

TEST_CASE("non-IP frames are classified, not rejected", "[parse]") {
    const auto arp = parse(concat({ethernet(kEtherTypeArp), payload(28)}));
    CHECK(arp.kind == PacketKind::NonIp);
    CHECK(arp.ethertype == kEtherTypeArp);
    CHECK(arp.ip_version == 0);

    const auto lldp = parse(concat({ethernet(0x88CC), payload(40)}));
    CHECK(lldp.kind == PacketKind::NonIp);
}

TEST_CASE("IPv4 without TCP/UDP is OtherIp and keeps its addresses", "[parse]") {
    const auto icmp = parse(concat({ethernet(kEtherTypeIpv4), ipv4(kLaptop, kServer, 1, 8),
                                    payload(8)}));
    CHECK(icmp.kind == PacketKind::OtherIp);
    CHECK(icmp.ip_version == 4);
    CHECK(icmp.ip_protocol == kIpProtoIcmp);
    CHECK(icmp.src_ip == kLaptop);
    CHECK(icmp.dst_ip == kServer);
}

TEST_CASE("IP fragments: only the first one carries a transport header", "[parse]") {
    // More-fragments flag set, offset 0: the first fragment has the UDP header.
    const Bytes first = concat({ethernet(kEtherTypeIpv4),
                                ipv4(kLaptop, kServer, 17, 8 + 100, Ipv4Options{}.fragment(0x2000)),
                                udp(5000, 6000, 100), payload(100)});
    CHECK(parse(first).kind == PacketKind::Udp);

    // Offset 185 (x8 = 1480 bytes in): payload only, no UDP header to read.
    const Bytes later = concat({ethernet(kEtherTypeIpv4),
                                ipv4(kLaptop, kServer, 17, 100, Ipv4Options{}.fragment(185)),
                                payload(100)});
    const auto info = parse(later);
    CHECK(info.kind == PacketKind::OtherIp);
    CHECK(info.ip_protocol == kIpProtoUdp);
    CHECK(info.src_port == 0);
}

// ---------------------------------------------------------------------------------------------
// IPv6
// ---------------------------------------------------------------------------------------------

namespace {
const IpAddress kLaptop6 = ip6("2001:db8:1::14");
const IpAddress kServer6 = ip6("2606:2800:220:1:248:1893:25c8:1946");
}  // namespace

TEST_CASE("IPv6 TCP and UDP parse through every layer", "[parse][ipv6]") {
    const auto tcp6 = parse(tcp6_frame(kLaptop6, 51000, kServer6, 443, 100,
                                       tcp_flags::kSyn | tcp_flags::kAck));
    CHECK(tcp6.kind == PacketKind::Tcp);
    CHECK(tcp6.ip_version == 6);
    CHECK(tcp6.ethertype == kEtherTypeIpv6);
    CHECK(tcp6.src_ip == kLaptop6);
    CHECK(tcp6.dst_ip == kServer6);
    CHECK(tcp6.src_port == 51000);
    CHECK(tcp6.dst_port == 443);
    CHECK(tcp6.tcp_flags == (tcp_flags::kSyn | tcp_flags::kAck));

    const auto udp6 = parse(udp6_frame(kLaptop6, 50000, ip6("2001:4860:4860::8888"), 53, 30));
    CHECK(udp6.kind == PacketKind::Udp);
    CHECK(udp6.dst_port == 53);
    CHECK(udp6.dst_ip.to_string() == "2001:4860:4860::8888");
}

TEST_CASE("IPv6 extension headers are walked to the transport header", "[parse][ipv6]") {
    // Hop-by-hop (8 bytes) -> destination options (16 bytes) -> TCP.
    const Bytes headers = concat({ext_header(kIpv6DestinationOptions, 8), ext_header(kIpProtoTcp, 16)});
    const Bytes frame = concat({ethernet(kEtherTypeIpv6),
                                ipv6(kLaptop6, kServer6, kIpv6HopByHop, headers.size() + 20),
                                headers, tcp(1111, 443)});
    const auto ip = parse_ipv6(std::span<const std::uint8_t>(frame).subspan(14));
    REQUIRE(ip);
    CHECK(ip->header_length == 40 + 8 + 16);
    CHECK(ip->protocol == kIpProtoTcp);

    const auto info = parse(frame);
    CHECK(info.kind == PacketKind::Tcp);
    CHECK(info.src_port == 1111);
}

TEST_CASE("IPv6 fragments: only the first one carries a transport header", "[parse][ipv6]") {
    const Bytes first = concat({ethernet(kEtherTypeIpv6),
                                ipv6(kLaptop6, kServer6, kIpv6Fragment, 8 + 8 + 100),
                                fragment_header(kIpProtoUdp, 0, true), udp(5000, 6000, 100),
                                payload(100)});
    CHECK(parse(first).kind == PacketKind::Udp);

    const Bytes later = concat({ethernet(kEtherTypeIpv6),
                                ipv6(kLaptop6, kServer6, kIpv6Fragment, 8 + 100),
                                fragment_header(kIpProtoUdp, 185, false), payload(100)});
    const auto info = parse(later);
    CHECK(info.kind == PacketKind::OtherIp);
    CHECK(info.ip_protocol == kIpProtoUdp);
    CHECK(info.src_port == 0);
    CHECK(info.src_ip == kLaptop6);
}

TEST_CASE("ICMPv6 and encrypted ESP end the walk as Other IP", "[parse][ipv6]") {
    const auto icmp6 = parse(concat({ethernet(kEtherTypeIpv6),
                                     ipv6(ip6("fe80::1"), ip6("ff02::1:ff00:14"), kIpProtoIcmpv6, 32),
                                     payload(32)}));
    CHECK(icmp6.kind == PacketKind::OtherIp);
    CHECK(icmp6.ip_protocol == kIpProtoIcmpv6);
    CHECK(icmp6.ip_version == 6);

    const auto esp = parse(concat({ethernet(kEtherTypeIpv6),
                                   ipv6(kLaptop6, kServer6, 50, 64), payload(64)}));
    CHECK(esp.kind == PacketKind::OtherIp);
    CHECK(esp.ip_protocol == 50);
}

TEST_CASE("every truncated prefix of an IPv6 frame is rejected without crashing",
          "[parse][ipv6][malformed]") {
    const Bytes frame = tcp6_frame(kLaptop6, 51000, kServer6, 443);  // 14 + 40 + 20 = 74 bytes
    REQUIRE(frame.size() == 74);
    for (std::size_t len = 0; len < frame.size(); ++len) {
        INFO("prefix length " << len);
        const Bytes prefix(frame.begin(), frame.begin() + static_cast<std::ptrdiff_t>(len));
        CHECK(parse(prefix).kind == PacketKind::Malformed);
    }
    CHECK(parse(frame).kind == PacketKind::Tcp);
}

TEST_CASE("inconsistent or hostile IPv6 headers are rejected", "[parse][ipv6][malformed]") {
    SECTION("IPv6 EtherType, but not version 6 inside") {
        const Bytes frame = concat({ethernet(kEtherTypeIpv6),
                                    ipv6(kLaptop6, kServer6, kIpProtoTcp, 20, 4), tcp(1, 2)});
        CHECK(parse(frame).kind == PacketKind::Malformed);
    }
    SECTION("an extension header claiming more bytes than were captured") {
        Bytes hop = ext_header(kIpProtoTcp, 8);
        hop[1] = 20;  // claims (20 + 1) * 8 = 168 bytes
        const Bytes frame = concat({ethernet(kEtherTypeIpv6),
                                    ipv6(kLaptop6, kServer6, kIpv6HopByHop, 8 + 20), hop, tcp(1, 2)});
        CHECK(parse(frame).kind == PacketKind::Malformed);
    }
    SECTION("a chain longer than any real packet needs") {
        Bytes chain;
        for (int i = 0; i < 12; ++i) {
            const Bytes h = ext_header(i == 11 ? kIpProtoTcp : kIpv6DestinationOptions, 8);
            chain.insert(chain.end(), h.begin(), h.end());
        }
        const Bytes frame = concat({ethernet(kEtherTypeIpv6),
                                    ipv6(kLaptop6, kServer6, kIpv6DestinationOptions, chain.size() + 20),
                                    chain, tcp(1, 2)});
        CHECK(parse(frame).kind == PacketKind::Malformed);
    }
    SECTION("payload length shorter than the extension headers") {
        const Bytes frame = concat({ethernet(kEtherTypeIpv6),
                                    ipv6(kLaptop6, kServer6, kIpv6HopByHop, 4),
                                    ext_header(kIpProtoTcp, 8), tcp(1, 2)});
        CHECK(parse(frame).kind == PacketKind::Malformed);
    }
    SECTION("payload length too short for the TCP header that follows") {
        Bytes frame = concat({ethernet(kEtherTypeIpv6), ipv6(kLaptop6, kServer6, kIpProtoTcp, 10),
                              tcp(1, 2)});
        CHECK(parse(frame).kind == PacketKind::Malformed);
    }
}

TEST_CASE("an IPv6 payload length of zero falls back to what was captured", "[parse][ipv6]") {
    // Zero is what jumbograms (and some offloaded captures) carry in the fixed header.
    const Bytes frame = concat({ethernet(kEtherTypeIpv6), ipv6(kLaptop6, kServer6, kIpProtoTcp, 0),
                                tcp(1234, 443)});
    CHECK(parse(frame).kind == PacketKind::Tcp);
}

TEST_CASE("IPv4 header options shift the transport header", "[parse]") {
    const Bytes frame = concat({ethernet(kEtherTypeIpv4),
                                ipv4(kLaptop, kServer, 6, 20, Ipv4Options{}.options(12)),
                                tcp(1111, 2222)});
    const auto ip_header = parse_ipv4(std::span<const std::uint8_t>(frame).subspan(14));
    REQUIRE(ip_header);
    CHECK(ip_header->header_length == 32);

    const auto info = parse(frame);
    CHECK(info.kind == PacketKind::Tcp);
    CHECK(info.src_port == 1111);
    CHECK(info.dst_port == 2222);
}

TEST_CASE("TCP options are accounted for in the header length", "[parse]") {
    const Bytes segment = tcp(1, 2, 0x10, 12);
    const auto header = parse_tcp(segment);
    REQUIRE(header);
    CHECK(header->header_length == 32);
}

TEST_CASE("every truncated prefix of a frame is rejected without crashing", "[parse][malformed]") {
    const Bytes frame = tcp_frame(kLaptop, 51000, kServer, 443);  // 14 + 20 + 20 = 54 bytes
    REQUIRE(frame.size() == 54);
    for (std::size_t len = 0; len < frame.size(); ++len) {
        INFO("prefix length " << len);
        const Bytes prefix(frame.begin(), frame.begin() + static_cast<std::ptrdiff_t>(len));
        CHECK(parse(prefix).kind == PacketKind::Malformed);
    }
    CHECK(parse(frame).kind == PacketKind::Tcp);
}

TEST_CASE("inconsistent IPv4 headers are rejected", "[parse][malformed]") {
    SECTION("wrong version") {
        const Bytes frame = concat({ethernet(kEtherTypeIpv4),
                                    ipv4(kLaptop, kServer, 6, 20, Ipv4Options{}.ip_version(6)), tcp(1, 2)});
        CHECK(parse(frame).kind == PacketKind::Malformed);
    }
    SECTION("IHL below the 5-word minimum") {
        const Bytes frame = concat({ethernet(kEtherTypeIpv4),
                                    ipv4(kLaptop, kServer, 6, 20, Ipv4Options{}.ihl(4)), tcp(1, 2)});
        CHECK(parse(frame).kind == PacketKind::Malformed);
    }
    SECTION("IHL claims options that were cut off") {
        // IHL 15 = 60-byte header, but only 20 header bytes + nothing else are present.
        const Bytes frame = concat({ethernet(kEtherTypeIpv4),
                                    ipv4(kLaptop, kServer, 6, 0, Ipv4Options{}.ihl(15))});
        CHECK(parse(frame).kind == PacketKind::Malformed);
    }
    SECTION("total length smaller than the header itself") {
        const Bytes frame =
            concat({ethernet(kEtherTypeIpv4),
                    ipv4(kLaptop, kServer, 6, 20, Ipv4Options{}.total_length(12)), tcp(1, 2)});
        CHECK(parse(frame).kind == PacketKind::Malformed);
    }
}

TEST_CASE("inconsistent transport headers are rejected", "[parse][malformed]") {
    SECTION("TCP data offset below 5") {
        const Bytes frame = concat({ethernet(kEtherTypeIpv4), ipv4(kLaptop, kServer, 6, 20),
                                    tcp(1, 2, 0x10, 0, 3)});
        CHECK(parse(frame).kind == PacketKind::Malformed);
    }
    SECTION("TCP options cut off") {
        // Data offset says 32 bytes of header, only the first 20 are present.
        const Bytes frame = concat({ethernet(kEtherTypeIpv4), ipv4(kLaptop, kServer, 6, 20),
                                    tcp(1, 2, 0x10, 0, 8)});
        CHECK(parse(frame).kind == PacketKind::Malformed);
    }
    SECTION("UDP length field below the header size") {
        const Bytes frame = concat({ethernet(kEtherTypeIpv4), ipv4(kLaptop, kServer, 17, 8),
                                    udp(1, 2, 0, 4)});
        CHECK(parse(frame).kind == PacketKind::Malformed);
    }
}

TEST_CASE("transport header is bounded by IPv4 total length, not frame length", "[parse]") {
    // Ethernet pads short frames to 60 bytes. Here the IP packet claims only 10 bytes of TCP,
    // and the padding after it must not be read as the rest of a TCP header.
    Bytes frame = concat({ethernet(kEtherTypeIpv4),
                          ipv4(kLaptop, kServer, 6, 10, Ipv4Options{}.total_length(30)),
                          tcp(1, 2)});
    frame.resize(std::max<std::size_t>(frame.size(), 60), 0);
    CHECK(parse(frame).kind == PacketKind::Malformed);

    // Padding after a complete, short UDP datagram is harmless.
    Bytes padded_udp = udp_frame(kLaptop, 1000, kServer, 2000, 4);
    padded_udp.resize(60, 0);
    CHECK(parse(padded_udp).kind == PacketKind::Udp);
}

TEST_CASE("snaplen-truncated packets still parse when the headers are intact", "[parse]") {
    // The packet claims 1500 bytes, but only the 54 header bytes were captured.
    const Bytes frame = concat({ethernet(kEtherTypeIpv4), ipv4(kLaptop, kServer, 6, 1480),
                                tcp(51000, 443)});
    CHECK(parse(frame).kind == PacketKind::Tcp);
}

TEST_CASE("random garbage never crashes the parser", "[parse][malformed]") {
    // Run under the CI AddressSanitizer job, any out-of-bounds read here fails the build.
    std::mt19937 rng(12345);
    std::uniform_int_distribution<int> len_dist(0, 128);
    std::uniform_int_distribution<int> byte_dist(0, 255);
    for (int i = 0; i < 20000; ++i) {
        Bytes frame(static_cast<std::size_t>(len_dist(rng)));
        for (auto& b : frame) b = static_cast<std::uint8_t>(byte_dist(rng));
        // Bias toward reaching the deeper layers: make most frames claim IPv4 or IPv6, and
        // for IPv6 an extension header often enough to exercise the chain walk.
        if (frame.size() >= 15 && i % 4 == 1) {
            frame[12] = 0x08;
            frame[13] = 0x00;
            frame[14] = static_cast<std::uint8_t>(0x40 | (frame[14] & 0x0F));
        } else if (frame.size() >= 21 && i % 4 >= 2) {
            frame[12] = 0x86;
            frame[13] = 0xDD;
            frame[14] = static_cast<std::uint8_t>(0x60 | (frame[14] & 0x0F));
            if (i % 4 == 3) {
                static constexpr std::uint8_t kChain[] = {0, 43, 44, 51, 60, 6, 17};
                frame[20] = kChain[static_cast<std::size_t>(byte_dist(rng)) % 7];
            }
        }
        (void)parse(frame);
    }
    SUCCEED();
}
