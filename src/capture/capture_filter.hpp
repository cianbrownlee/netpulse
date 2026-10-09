#pragma once

#include <cstdint>
#include <vector>

namespace netpulse {

// One classic-BPF instruction, laid out exactly like Linux's sock_filter and libpcap/Npcap's
// bpf_insn, so a program can be handed to either kernel as is.
struct BpfInstruction {
    std::uint16_t code;
    std::uint8_t jt;  // instructions to skip if a jump's condition holds
    std::uint8_t jf;  // ...and if it doesn't
    std::uint32_t k;
};

// The opcodes NetPulse's filter uses. Classic BPF's encoding is a fixed ABI shared by every
// kernel that runs it; these are spelled out here (rather than taken from <linux/filter.h> or
// <pcap/bpf.h>) so the filter builds, and is tested, the same on every platform.
namespace bpf {
inline constexpr std::uint16_t kLd = 0x00, kLdx = 0x01, kJmp = 0x05, kRet = 0x06;  // classes
inline constexpr std::uint16_t kHalf = 0x08, kByte = 0x10;                       // load sizes
inline constexpr std::uint16_t kAbs = 0x20, kInd = 0x40, kMsh = 0xA0;            // addressing
inline constexpr std::uint16_t kJeq = 0x10, kJset = 0x40;                        // jump tests
inline constexpr std::uint16_t kConst = 0x00;                                    // operand: k
}  // namespace bpf

// The classic-BPF program NetPulse installs on its capture handle. The kernel (Linux) or the
// Npcap driver (Windows) runs it for every packet and keeps as many bytes as it returns,
// *before* copying anything to NetPulse.
//
//   dns_snaplen == 0:  "return snaplen" for every packet (headers only).
//   dns_snaplen  > 0:  return dns_snaplen for DNS and mDNS responses (UDP from port 53 or 5353,
//                      untagged IPv4 without fragmentation, or IPv6 with UDP directly after the
//                      fixed header), and snaplen for everything else. That lets --dns-names read
//                      DNS answers without keeping any other payload.
//
// One caveat of the longer program: classic BPF ends a filter that reads past the end of a
// packet by returning 0, which drops the packet. With dns_snaplen set, runt IPv4/IPv6 frames too
// short to hold the fields it checks are therefore dropped rather than counted as malformed.
std::vector<BpfInstruction> build_capture_filter(unsigned snaplen, unsigned dns_snaplen);

}  // namespace netpulse
