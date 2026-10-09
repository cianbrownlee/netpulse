#include "capture/capture_filter.hpp"

#include <cstdint>

namespace netpulse {

namespace {

sock_filter stmt(std::uint16_t code, std::uint32_t k) { return sock_filter{code, 0, 0, k}; }

sock_filter jump(std::uint16_t code, std::uint32_t k, std::uint8_t jt, std::uint8_t jf) {
    return sock_filter{code, jt, jf, k};
}

}  // namespace

std::vector<sock_filter> build_capture_filter(unsigned snaplen, unsigned dns_snaplen) {
    if (dns_snaplen == 0) return {stmt(BPF_RET | BPF_K, snaplen)};

    // Offsets are from the start of the Ethernet frame. Jump offsets (jt/jf) count instructions
    // to skip after the current one; the target of each is noted alongside.
    return {
        /*  0 */ stmt(BPF_LD | BPF_H | BPF_ABS, 12),                  // EtherType
        /*  1 */ jump(BPF_JMP | BPF_JEQ | BPF_K, 0x0800, 1, 0),       // IPv4 -> 3, else -> 2
        /*  2 */ jump(BPF_JMP | BPF_JEQ | BPF_K, 0x86DD, 8, 14),      // IPv6 -> 11, else -> 17
        // IPv4
        /*  3 */ stmt(BPF_LD | BPF_B | BPF_ABS, 23),                  // protocol
        /*  4 */ jump(BPF_JMP | BPF_JEQ | BPF_K, 17, 0, 12),          // UDP -> 5, else -> 17
        /*  5 */ stmt(BPF_LD | BPF_H | BPF_ABS, 20),                  // flags + fragment offset
        /*  6 */ jump(BPF_JMP | BPF_JSET | BPF_K, 0x1FFF, 10, 0),     // later fragment -> 17
        /*  7 */ stmt(BPF_LDX | BPF_B | BPF_MSH, 14),                 // X = IPv4 header length
        /*  8 */ stmt(BPF_LD | BPF_H | BPF_IND, 14),                  // UDP source port
        /*  9 */ jump(BPF_JMP | BPF_JEQ | BPF_K, 53, 6, 0),           // DNS -> 16, else -> 10
        /* 10 */ jump(BPF_JMP | BPF_JEQ | BPF_K, 5353, 5, 6),         // mDNS -> 16, else -> 17
        // IPv6
        /* 11 */ stmt(BPF_LD | BPF_B | BPF_ABS, 20),                  // next header
        /* 12 */ jump(BPF_JMP | BPF_JEQ | BPF_K, 17, 0, 4),           // UDP -> 13, else -> 17
        /* 13 */ stmt(BPF_LD | BPF_H | BPF_ABS, 54),                  // UDP source port
        /* 14 */ jump(BPF_JMP | BPF_JEQ | BPF_K, 53, 1, 0),           // DNS -> 16, else -> 15
        /* 15 */ jump(BPF_JMP | BPF_JEQ | BPF_K, 5353, 0, 1),         // mDNS -> 16, else -> 17
        /* 16 */ stmt(BPF_RET | BPF_K, dns_snaplen),
        /* 17 */ stmt(BPF_RET | BPF_K, snaplen),
    };
}

}  // namespace netpulse
