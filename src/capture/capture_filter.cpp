#include "capture/capture_filter.hpp"

#include <cstdint>

namespace netpulse {

namespace {

using namespace bpf;

BpfInstruction stmt(std::uint16_t code, std::uint32_t k) { return BpfInstruction{code, 0, 0, k}; }

BpfInstruction jump(std::uint16_t code, std::uint32_t k, std::uint8_t jt, std::uint8_t jf) {
    return BpfInstruction{code, jt, jf, k};
}

}  // namespace

std::vector<BpfInstruction> build_capture_filter(unsigned snaplen, unsigned dns_snaplen) {
    if (dns_snaplen == 0) return {stmt(kRet | kConst, snaplen)};

    // Offsets are from the start of the Ethernet frame. Jump offsets (jt/jf) count instructions
    // to skip after the current one; the target of each is noted alongside.
    return {
        /*  0 */ stmt(kLd | kHalf | kAbs, 12),                  // EtherType
        /*  1 */ jump(kJmp | kJeq | kConst, 0x0800, 1, 0),      // IPv4 -> 3, else -> 2
        /*  2 */ jump(kJmp | kJeq | kConst, 0x86DD, 8, 14),     // IPv6 -> 11, else -> 17
        // IPv4
        /*  3 */ stmt(kLd | kByte | kAbs, 23),                  // protocol
        /*  4 */ jump(kJmp | kJeq | kConst, 17, 0, 12),         // UDP -> 5, else -> 17
        /*  5 */ stmt(kLd | kHalf | kAbs, 20),                  // flags + fragment offset
        /*  6 */ jump(kJmp | kJset | kConst, 0x1FFF, 10, 0),    // later fragment -> 17
        /*  7 */ stmt(kLdx | kByte | kMsh, 14),                 // X = IPv4 header length
        /*  8 */ stmt(kLd | kHalf | kInd, 14),                  // UDP source port
        /*  9 */ jump(kJmp | kJeq | kConst, 53, 6, 0),          // DNS -> 16, else -> 10
        /* 10 */ jump(kJmp | kJeq | kConst, 5353, 5, 6),        // mDNS -> 16, else -> 17
        // IPv6
        /* 11 */ stmt(kLd | kByte | kAbs, 20),                  // next header
        /* 12 */ jump(kJmp | kJeq | kConst, 17, 0, 4),          // UDP -> 13, else -> 17
        /* 13 */ stmt(kLd | kHalf | kAbs, 54),                  // UDP source port
        /* 14 */ jump(kJmp | kJeq | kConst, 53, 1, 0),          // DNS -> 16, else -> 15
        /* 15 */ jump(kJmp | kJeq | kConst, 5353, 0, 1),        // mDNS -> 16, else -> 17
        /* 16 */ stmt(kRet | kConst, dns_snaplen),
        /* 17 */ stmt(kRet | kConst, snaplen),
    };
}

}  // namespace netpulse
