#pragma once

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <span>

namespace netpulse {

// Most bytes of a frame NetPulse keeps. The parser needs at most 138 (Ethernet 14 + VLAN 4 +
// IPv4 up to 60 + TCP up to 60), and capture uses a 192-byte snaplen; anything past this is
// payload, which NetPulse never reads.
inline constexpr std::size_t kMaxCapturedBytes = 256;

// One frame handed from the capture thread to the aggregator thread.
//
// The bytes are a copy. libpcap owns the buffer it passes to its callback and reuses it as soon
// as the callback returns, so a view into it cannot safely cross a thread boundary.
//
// The copy lives inline in a fixed-size array rather than a heap-allocated vector: together with
// the queue's preallocated ring of these, the capture -> aggregator hot path does no heap
// allocation at all. (This was 1.08 allocations per packet before; see docs/benchmarks.md.)
struct CapturedPacket {
    std::array<std::uint8_t, kMaxCapturedBytes> bytes;  // only [0, length) is meaningful
    std::uint16_t length = 0;
    std::uint32_t wire_length = 0;  // full size on the wire; can exceed length
    std::chrono::steady_clock::time_point timestamp{};

    std::span<const std::uint8_t> data() const { return {bytes.data(), length}; }
};

}  // namespace netpulse
