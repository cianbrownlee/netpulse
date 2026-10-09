#pragma once

#include <atomic>
#include <chrono>
#include <cstddef>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <thread>

#include "aggregate/aggregator.hpp"
#include "aggregate/snapshot.hpp"
#include "aggregate/status_tracker.hpp"
#include "capture/packet_capture.hpp"
#include "resolve/resolver.hpp"
#include "util/bounded_queue.hpp"

namespace netpulse {

// The three-stage pipeline:
//
//   capture thread --(bounded queue)--> aggregator thread --(snapshot)--> UI thread
//
// Capture only copies header bytes and enqueues, so it gets back to libpcap quickly; parsing
// and bookkeeping happen on the aggregator thread; the UI reads immutable snapshots and can
// never slow either of them down.
//
// Snapshot hand-off is a shared_ptr swap under a mutex held for a pointer copy, not for the
// copy of the data: the aggregator builds a complete new Snapshot off to the side, then
// publishes it; readers keep whatever version they grabbed for as long as they need it.
class Pipeline {
public:
    struct Config {
        CaptureConfig capture;
        bool resolve_names = true;
        std::size_t queue_capacity = 4096;
        // Most packets the aggregator takes from the queue per lock (1 = one at a time).
        std::size_t batch_size = PacketBatcher::kDefaultBatchSize;
        std::chrono::milliseconds publish_interval{250};
        Aggregator::Config aggregator;
    };

    // Opens the capture source immediately, so permission and interface problems surface as
    // a CaptureError before any thread starts or the screen is taken over.
    explicit Pipeline(Config config);
    // Uses `source` instead of opening config.capture (the benchmark feeds synthetic packets).
    Pipeline(Config config, std::unique_ptr<PacketSource> source);
    ~Pipeline();

    Pipeline(const Pipeline&) = delete;
    Pipeline& operator=(const Pipeline&) = delete;

    void start();
    void stop();  // idempotent; joins both threads

    std::shared_ptr<const Snapshot> latest() const;

    // True once capture has ended (end of file, stop(), or error) and every queued packet has
    // been aggregated into a final snapshot.
    bool finished() const { return finished_.load(); }
    std::optional<std::string> error() const { return capture_->error(); }
    bool is_offline() const { return capture_->is_offline(); }
    const std::string& source() const { return capture_->description(); }

private:
    void capture_loop();
    void aggregate_loop();
    Clock::time_point traffic_time() const;
    void publish(Clock::time_point now, Clock::duration uptime);
    void categorize(Snapshot& snapshot);

    struct NameLookup {
        NameState state = NameState::Unknown;
        std::string name;
    };
    NameLookup lookup_name(std::uint32_t ip);

    Config config_;
    std::unique_ptr<PacketSource> capture_;
    BoundedQueue<CapturedPacket> queue_;
    Aggregator aggregator_;  // touched only by the aggregator thread
    StatusTracker status_;   // likewise
    std::unique_ptr<Resolver> resolver_;
    Clock::time_point started_at_{};
    Clock::time_point latest_packet_time_{};  // aggregator thread only

    mutable std::mutex snapshot_mutex_;
    std::shared_ptr<const Snapshot> latest_;

    std::thread capture_thread_;
    std::thread aggregate_thread_;
    std::atomic<bool> finished_{false};
    bool started_ = false;
};

}  // namespace netpulse
