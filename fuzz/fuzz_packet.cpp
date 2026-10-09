// Fuzz target: an arbitrary frame through the packet parser and the aggregator, as the pipeline
// runs them with --dns-names on (so DNS answers in the frame are parsed too).
//
// Beyond "no crash and no sanitizer report", it checks the promises the rest of NetPulse relies
// on: ports only on TCP/UDP, the UDP payload view inside the frame, and the IP version matching
// the EtherType.

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <span>

#include "aggregate/aggregator.hpp"
#include "fuzz_check.hpp"
#include "parse/packet_parser.hpp"

using namespace netpulse;

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    const std::span<const std::uint8_t> frame(data, size);
    const PacketInfo info = parse_packet(frame);

    const bool transport = info.kind == PacketKind::Tcp || info.kind == PacketKind::Udp;
    if (!transport) FUZZ_CHECK(info.src_port == 0 && info.dst_port == 0 && info.tcp_flags == 0);
    if (info.kind != PacketKind::Udp) FUZZ_CHECK(info.udp_payload.empty());
    if (!info.udp_payload.empty()) {
        FUZZ_CHECK(info.udp_payload.data() >= data);
        FUZZ_CHECK(info.udp_payload.data() + info.udp_payload.size() <= data + size);
    }
    if (info.is_ip()) {
        FUZZ_CHECK((info.ip_version == 4 && info.ethertype == kEtherTypeIpv4) ||
                   (info.ip_version == 6 && info.ethertype == kEtherTypeIpv6));
        if (info.ip_version == 4) FUZZ_CHECK(info.src_ip.is_v4() && info.dst_ip.is_v4());
    }
    if (info.kind == PacketKind::NonIp) {
        FUZZ_CHECK(info.ethertype != kEtherTypeIpv4 && info.ethertype != kEtherTypeIpv6);
    }

    Aggregator::Config config;
    config.observe_dns = true;
    Aggregator aggregator(config);
    const auto t = Clock::time_point{} + std::chrono::seconds(10);
    aggregator.ingest(info, static_cast<std::uint32_t>(size), t);
    const Snapshot s = aggregator.build_snapshot(t + std::chrono::seconds(1));
    FUZZ_CHECK(s.total.packets == 1);
    FUZZ_CHECK(s.active_flows == (info.is_ip() ? 1u : 0u));
    return 0;
}
