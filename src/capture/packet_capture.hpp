#pragma once

#include <atomic>
#include <chrono>
#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

#include "capture/captured_packet.hpp"
#include "util/bounded_queue.hpp"

struct pcap;
struct pcap_pkthdr;

namespace netpulse {

struct CaptureConfig {
    std::string interface;  // live capture from this interface...
    std::string pcap_file;  // ...or, if set, replay this file (development and testing)

    // Bytes captured per packet. Large enough for the deepest header stack NetPulse parses
    // (Ethernet 14 + VLAN 4 + IPv4 up to 60 + TCP up to 60 = 138), small enough that packet
    // *contents* are never captured. The kernel enforces this, so "only reads headers" is a
    // property of the capture itself, not just a promise about the parser.
    int snaplen = 192;
    int kernel_buffer_bytes = 16 * 1024 * 1024;
    // How long libpcap may hold packets before handing over a batch. Batching is far cheaper
    // than waking up per packet, and 100 ms is invisible on a 250 ms dashboard refresh.
    int read_timeout_ms = 100;
};

// Thrown when capture cannot start. The message is written for the person running the tool:
// what went wrong and what to do about it, not a raw errno string.
class CaptureError : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

struct CaptureCounters {
    std::uint64_t captured = 0;         // packets delivered to our callback
    std::uint64_t kernel_drops = 0;     // pcap_stats ps_drop: kernel buffer overflowed
    std::uint64_t interface_drops = 0;  // pcap_stats ps_ifdrop: dropped by the interface/driver
};

class PacketCapture {
public:
    static std::unique_ptr<PacketCapture> open(const CaptureConfig& config);

    ~PacketCapture();
    PacketCapture(const PacketCapture&) = delete;
    PacketCapture& operator=(const PacketCapture&) = delete;

    // Captures on the calling thread until stop(), end of file, or an error. Live packets go
    // through try_push (drop and count if the queue is full); file packets through push
    // (wait for space), since replay has no kernel buffer that could overflow.
    void run(BoundedQueue<CapturedPacket>& queue);

    // Safe to call from any thread. Wakes run() even if it is blocked waiting for packets.
    void stop();

    CaptureCounters counters() const;
    std::optional<std::string> error() const;  // why run() ended, if it was an error
    bool is_offline() const { return offline_; }
    const std::string& description() const { return description_; }

    static std::vector<std::string> list_interfaces();
    // First interface that is up, not loopback, and has an IPv4 address.
    static std::optional<std::string> default_interface();

private:
    PacketCapture(pcap* handle, bool offline, std::string description);
    static void on_packet(unsigned char* user, const pcap_pkthdr* header,
                          const unsigned char* bytes);
    void refresh_kernel_stats();

    pcap* handle_;
    bool offline_;
    std::string description_;
    BoundedQueue<CapturedPacket>* queue_ = nullptr;

    // Replay keeps the file's own timing: each packet is stamped at run start plus its offset
    // from the file's first packet, so rates and the sparkline show the recorded traffic's
    // real shape rather than how fast the file happened to be read.
    std::chrono::steady_clock::time_point replay_origin_{};
    std::optional<std::int64_t> first_file_timestamp_us_;
    std::atomic<bool> stop_requested_{false};

    std::atomic<std::uint64_t> captured_{0};
    std::atomic<std::uint64_t> kernel_drops_{0};
    std::atomic<std::uint64_t> interface_drops_{0};

    mutable std::mutex error_mutex_;
    std::optional<std::string> error_;
};

}  // namespace netpulse
