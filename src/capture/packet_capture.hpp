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
#include "capture/packet_source.hpp"
#include "util/bounded_queue.hpp"

struct pcap;
struct pcap_pkthdr;

namespace netpulse {

struct CaptureConfig {
    std::string interface;  // live capture from this interface...
    std::string pcap_file;  // ...or, if set, replay this file (development and testing)

    // Bytes captured per packet. Large enough for the deepest header stack NetPulse parses
    // (Ethernet 14 + VLAN 4 + IPv4 up to 60 + TCP up to 60 = 138), small enough that packet
    // *contents* are not captured. For live capture a kernel socket filter enforces this (see
    // truncate_in_kernel), so "only reads headers" holds for what reaches this process at all,
    // not just for what the parser looks at.
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

// libpcap capture: live from an interface, or replayed from a .pcap file.
// (kernel_drops / interface_drops come from pcap_stats ps_drop / ps_ifdrop.)
class PacketCapture : public PacketSource {
public:
    static std::unique_ptr<PacketCapture> open(const CaptureConfig& config);

    ~PacketCapture() override;
    PacketCapture(const PacketCapture&) = delete;
    PacketCapture& operator=(const PacketCapture&) = delete;

    // Captures on the calling thread until stop(), end of file, or an error. Live packets are
    // dropped (and counted) if the queue is full; file packets wait for space, since replay
    // has no kernel buffer that could overflow.
    void run(BoundedQueue<CapturedPacket>& queue) override;

    // Safe to call from any thread. Wakes run() even if it is blocked waiting for packets.
    void stop() override;

    CaptureCounters counters() const override;
    std::optional<std::string> error() const override;
    bool is_offline() const override { return offline_; }
    const std::string& description() const override { return description_; }

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
    std::optional<PacketBatcher> batcher_;  // set for the duration of run()

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
