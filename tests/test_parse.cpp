#include <catch2/catch_test_macros.hpp>
#include <random>

#include "frame_builder.hpp"
#include "parse/packet_parser.hpp"

using namespace netpulse;
using namespace netpulse::test;

namespace {

PacketInfo parse(const Bytes& frame) { return parse_packet(std::span<const std::uint8_t>(frame)); }

const std::uint32_t kLaptop = ip(192, 168, 1, 14);
const std::uint32_t kServer = ip(93, 184, 216, 34);

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
    CHECK(info.src_ip == 0x01020304u);
    CHECK(info.dst_ip == 0x0A141E28u);
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

TEST_CASE("non-IPv4 frames are classified, not rejected", "[parse]") {
    const auto arp = parse(concat({ethernet(kEtherTypeArp), payload(28)}));
    CHECK(arp.kind == PacketKind::NonIpv4);
    CHECK(arp.ethertype == kEtherTypeArp);

    const auto ipv6 = parse(concat({ethernet(kEtherTypeIpv6), payload(40)}));
    CHECK(ipv6.kind == PacketKind::NonIpv4);
    CHECK(ipv6.ethertype == kEtherTypeIpv6);
}

TEST_CASE("IPv4 without TCP/UDP is OtherIpv4 and keeps its addresses", "[parse]") {
    const auto icmp = parse(concat({ethernet(kEtherTypeIpv4), ipv4(kLaptop, kServer, 1, 8),
                                    payload(8)}));
    CHECK(icmp.kind == PacketKind::OtherIpv4);
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
    CHECK(info.kind == PacketKind::OtherIpv4);
    CHECK(info.ip_protocol == kIpProtoUdp);
    CHECK(info.src_port == 0);
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
        // Bias toward reaching the deeper layers: make most frames claim IPv4.
        if (frame.size() >= 15 && i % 4 != 0) {
            frame[12] = 0x08;
            frame[13] = 0x00;
            frame[14] = static_cast<std::uint8_t>(0x40 | (frame[14] & 0x0F));
        }
        (void)parse(frame);
    }
    SUCCEED();
}
