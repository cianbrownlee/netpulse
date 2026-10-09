#pragma once

#include <cstdint>
#include <span>
#include <stdexcept>
#include <vector>

#include "capture/capture_filter.hpp"

namespace netpulse::test {

// Runs a classic BPF program over a packet the way the kernel does, for the instructions
// NetPulse's capture filter uses, and returns how many bytes the kernel would keep. As in the
// kernel, a load past the end of the packet ends the program with 0 (the packet is dropped).
// Used by the filter's unit tests and by the fuzz target that checks it against the parser.
inline std::uint32_t run_bpf(const std::vector<BpfInstruction>& program, std::span<const std::uint8_t> packet) {
    using namespace bpf;
    std::uint32_t a = 0;
    std::uint32_t x = 0;
    auto load = [&](std::size_t offset, std::size_t size, std::uint32_t& out) {
        if (offset + size > packet.size()) return false;
        out = 0;
        for (std::size_t i = 0; i < size; ++i) out = (out << 8) | packet[offset + i];
        return true;
    };
    for (std::size_t pc = 0; pc < program.size(); ++pc) {
        const BpfInstruction& in = program[pc];
        switch (in.code) {
            case kLd | kHalf | kAbs:
                if (!load(in.k, 2, a)) return 0;
                break;
            case kLd | kByte | kAbs:
                if (!load(in.k, 1, a)) return 0;
                break;
            case kLd | kHalf | kInd:
                if (!load(x + in.k, 2, a)) return 0;
                break;
            case kLdx | kByte | kMsh: {
                std::uint32_t byte = 0;
                if (!load(in.k, 1, byte)) return 0;
                x = 4 * (byte & 0x0F);
                break;
            }
            case kJmp | kJeq | kConst:
                pc += (a == in.k) ? in.jt : in.jf;
                break;
            case kJmp | kJset | kConst:
                pc += (a & in.k) ? in.jt : in.jf;
                break;
            case kRet | kConst:
                return in.k;
            default:
                throw std::logic_error("instruction the test interpreter doesn't know");
        }
    }
    throw std::logic_error("program fell off the end without returning");
}

}  // namespace netpulse::test
