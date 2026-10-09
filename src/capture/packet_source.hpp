#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>

#include "capture/captured_packet.hpp"
#include "util/bounded_queue.hpp"

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
    virtual const std::string& description() const = 0;
};

// Turns raw captured bytes into queue entries.
//
// Live sources drop (and the queue counts) when the queue is full: blocking would only push
// the loss into the kernel's buffer, where it's harder to see. Recorded sources wait instead,
// since there's no buffer to overflow and no reason to lose anything.
class PacketBatcher {
public:
    enum class Overflow { Drop, Wait };

    PacketBatcher(BoundedQueue<CapturedPacket>& queue, Overflow overflow)
        : queue_(queue), overflow_(overflow) {}

    // Copies the bytes: the caller's buffer may be reused as soon as this returns.
    void add(const std::uint8_t* bytes, std::size_t length, std::uint32_t wire_length,
             std::chrono::steady_clock::time_point timestamp) {
        CapturedPacket packet;
        packet.data.assign(bytes, bytes + length);
        packet.wire_length = wire_length;
        packet.timestamp = timestamp;
        if (overflow_ == Overflow::Wait) {
            queue_.push(std::move(packet));
        } else {
            queue_.try_push(std::move(packet));  // a full queue counts the drop itself
        }
    }

    void flush() {}

private:
    BoundedQueue<CapturedPacket>& queue_;
    Overflow overflow_;
};

}  // namespace netpulse
