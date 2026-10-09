// Fuzz target, differential: the kernel capture filter (classic BPF, run by the test
// interpreter) against the C++ parser, on the same frame.
//
// They are two independent implementations of "is this a DNS or mDNS answer?": the filter decides
// in the kernel how many bytes to keep, the parser decides what NetPulse thinks it captured.
// For every frame the parser accepts as IP, they must agree:
//
//   - the filter keeps the larger DNS length exactly when the parser sees UDP from port 53 or
//     5353, in the cases the filter is documented to inspect (no VLAN tag; for IPv6, UDP right
//     after the fixed header);
//   - otherwise it keeps the normal length: no payload beyond headers for anything else.
//
// For frames the parser rejects, the filter may only return one of its two lengths, or 0 (the
// kernel's out-of-bounds rule, which drops the frame).

#include <cstddef>
#include <cstdint>
#include <span>

#include "bpf_interpreter.hpp"
#include "capture/capture_filter.hpp"
#include "fuzz_check.hpp"
#include "parse/packet_parser.hpp"

using namespace netpulse;

namespace {

constexpr unsigned kSnaplen = 192;
constexpr unsigned kDnsSnaplen = 512;

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    static const auto program = build_capture_filter(kSnaplen, kDnsSnaplen);
    static const auto plain = build_capture_filter(kSnaplen, 0);
    const std::span<const std::uint8_t> frame(data, size);

    FUZZ_CHECK(test::run_bpf(plain, frame) == kSnaplen);  // without --dns-names: always headers only

    const std::uint32_t keep = test::run_bpf(program, frame);
    FUZZ_CHECK(keep == 0 || keep == kSnaplen || keep == kDnsSnaplen);

    const PacketInfo info = parse_packet(frame);
    if (info.kind == PacketKind::NonIp) FUZZ_CHECK(keep == kSnaplen);
    if (!info.is_ip()) return 0;

    const bool tagged = size >= 14 && data[12] == 0x81 && data[13] == 0x00;
    const bool udp_follows_ipv6_header = size > 20 && data[20] == kIpProtoUdp;
    const bool inspected = !tagged && (info.ip_version == 4 || udp_follows_ipv6_header);
    const bool dns_answer =
        info.kind == PacketKind::Udp && (info.src_port == 53 || info.src_port == 5353);
    FUZZ_CHECK(keep == (inspected && dns_answer ? kDnsSnaplen : kSnaplen));
    return 0;
}
