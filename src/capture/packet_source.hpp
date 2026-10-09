#pragma once

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <optional>
#include <string>
#include <vector>

#include "capture/captured_packet.hpp"
#include "util/bounded_queue.hpp"
#include "util/local_networks.hpp"

namespace netpulse {

struct CaptureCounters {
    std::uint64_t captured = 0;         // packets delivered to us
    std::uint64_t kernel_drops = 0;     // lost before we saw them (e.g. kernel buffer overflow)
    std::uint64_t interface_drops = 0;  // dropped by the interface/driver
};

// Where packets come from. libpcap (live or from a file) in the app; an in-memory generator in
// the benchmark. Also the seam a native Windows (Npcap) port would plug into.
class PacketSource {
public:
    virtual ~PacketSource() = default;

    // Produces packets into `queue` on the calling thread until stop(), end of input, or error.
    virtual void run(BoundedQueue<CapturedPacket>& queue) = 0;
    virtual void stop() = 0;  // safe from any thread

    virtual CaptureCounters counters() const = 0;
    virtual std::optional<std::string> error() const = 0;  // why run() ended, if an error
    virtual bool is_offline() const = 0;  // replaying recorded traffic rather than live
    virtual bool is_demo() const { return false; }  // simulated traffic (--demo)
    virtual const std::string& description() const = 0;
    // The networks the source is attached to (a live interface's subnets), if it knows them.
    virtual LocalNetworks local_networks() const { return {}; }
};

// Turns raw captured bytes into queue entries, handing them over in batches.
//
// Live sources drop (and the queue counts) when the queue is full: blocking would only push
// the loss into the kernel's buffer, where it's harder to see. Recorded sources wait instead,
// since there's no buffer to overflow and no reason to lose anything.
//
// Sources call flush() whenever they're about to go idle (libpcap capture: after each
// pcap_dispatch, i.e. each block of packets the kernel hands over), so batching adds no
// latency beyond what the kernel's own buffering already has.
class PacketBatcher {
public:
    enum class Overflow { Drop, Wait };
    static constexpr std::size_t kDefaultBatchSize = 256;

    PacketBatcher(BoundedQueue<CapturedPacket>& queue, Overflow overflow,
                  std::size_t batch_size = kDefaultBatchSize)
        : queue_(queue), overflow_(overflow), batch_size_(std::max<std::size_t>(batch_size, 1)) {
        batch_.reserve(batch_size_);
    }

    // Copies the bytes (at most kMaxCapturedBytes: headers, never payload). The caller's buffer
    // may be reused as soon as this returns.
    void add(const std::uint8_t* bytes, std::size_t length, std::uint32_t wire_length,
             std::chrono::steady_clock::time_point timestamp) {
        CapturedPacket& packet = batch_.emplace_back();
        packet.length = static_cast<std::uint16_t>(std::min(length, kMaxCapturedBytes));
        std::memcpy(packet.bytes.data(), bytes, packet.length);
        packet.wire_length = wire_length;
        packet.timestamp = timestamp;
        if (batch_.size() >= batch_size_) flush();
    }

    void flush() {
        if (batch_.empty()) return;
        if (overflow_ == Overflow::Wait) {
            queue_.push_batch(batch_);
        } else {
            queue_.try_push_batch(batch_);  // a full queue counts the drops itself
        }
    }

private:
    BoundedQueue<CapturedPacket>& queue_;
    Overflow overflow_;
    std::size_t batch_size_;
    std::vector<CapturedPacket> batch_;  // capacity reserved once and reused
};

}  // namespace netpulse
