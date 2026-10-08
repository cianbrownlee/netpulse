#pragma once

#include <chrono>
#include <cstdint>
#include <vector>

namespace netpulse {

// One frame handed from the capture thread to the aggregator thread.
//
// The bytes are a copy. libpcap owns the buffer it passes to its callback and reuses it as
// soon as the callback returns, so a view into it cannot safely cross a thread boundary.
// The copy is kept cheap by capturing headers only (see CaptureConfig::snaplen): typically
// well under 100 bytes per packet, regardless of how large the packet itself was. Avoiding the
// per-packet heap allocation (a reused buffer pool) is the planned Stage 6 optimization.
struct CapturedPacket {
    std::vector<std::uint8_t> data;  // Ethernet frame onward, truncated to snaplen
    std::uint32_t wire_length = 0;   // full size on the wire; can exceed data.size()
    std::chrono::steady_clock::time_point timestamp{};
};

}  // namespace netpulse
