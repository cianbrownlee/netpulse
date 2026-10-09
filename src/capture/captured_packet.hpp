#pragma once

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>

namespace netpulse {

// Most bytes of a frame NetPulse keeps. Normally capture keeps 192 bytes per packet, which
// covers IPv4's deepest header stack (138 bytes) and IPv6 with typical extension-header chains.
// With --dns-names, DNS responses are kept up to 512 bytes so their answers can be read.
inline constexpr std::size_t kMaxCapturedBytes = 512;

// One frame handed from the capture thread to the aggregator thread.
//
// The bytes are a copy. libpcap owns the buffer it passes to its callback and reuses it as soon
// as the callback returns, so a view into it cannot safely cross a thread boundary.
//
// The copy lives inline in a fixed-size array rather than a heap-allocated vector: together with
// the queue's preallocated ring of these, the capture -> aggregator hot path does no heap
// allocation at all (see docs/benchmarks.md). Copying one only moves the bytes actually in use,
// so a 60-byte packet costs the same whatever the array's capacity.
struct CapturedPacket {
    std::array<std::uint8_t, kMaxCapturedBytes> bytes;  // only [0, length) is meaningful
    std::uint16_t length = 0;
    std::uint32_t wire_length = 0;  // full size on the wire; can exceed length
    std::chrono::steady_clock::time_point timestamp{};

    CapturedPacket() = default;
    CapturedPacket(const CapturedPacket& other) { copy_from(other); }
    CapturedPacket& operator=(const CapturedPacket& other) {
        if (this != &other) copy_from(other);
        return *this;
    }
    // (No separate move operations: there is nothing to steal, so a move is this same copy.)

    std::span<const std::uint8_t> data() const { return {bytes.data(), length}; }

private:
    void copy_from(const CapturedPacket& other) {
        length = other.length;
        wire_length = other.wire_length;
        timestamp = other.timestamp;
        std::memcpy(bytes.data(), other.bytes.data(), length);
    }
};

}  // namespace netpulse
