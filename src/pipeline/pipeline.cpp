#include "pipeline/pipeline.hpp"

#include <algorithm>
#include <span>
#include <utility>

#include "parse/packet_parser.hpp"

namespace netpulse {

Pipeline::Pipeline(Config config)
    : config_(std::move(config)),
      capture_(PacketCapture::open(config_.capture)),
      queue_(config_.queue_capacity),
      aggregator_(config_.aggregator),
      latest_(std::make_shared<Snapshot>()) {
    if (config_.resolve_names) resolver_ = std::make_unique<Resolver>();
}

Pipeline::~Pipeline() { stop(); }

void Pipeline::start() {
    if (started_) return;
    started_ = true;
    started_at_ = Clock::now();
    aggregate_thread_ = std::thread(&Pipeline::aggregate_loop, this);
    capture_thread_ = std::thread(&Pipeline::capture_loop, this);
}

void Pipeline::stop() {
    capture_->stop();
    queue_.close();
    if (capture_thread_.joinable()) capture_thread_.join();
    if (aggregate_thread_.joinable()) aggregate_thread_.join();
}

std::shared_ptr<const Snapshot> Pipeline::latest() const {
    std::lock_guard lock(snapshot_mutex_);
    return latest_;
}

void Pipeline::capture_loop() {
    capture_->run(queue_);
    // Whatever ended the run (EOF, stop, error), closing the queue lets the aggregator finish
    // what is already queued and then exit.
    queue_.close();
}

Clock::time_point Pipeline::traffic_time() const {
    // Live: the wall clock. Replay: the file's own clock (the newest packet seen so far), so
    // rates, history and idle-flow expiry follow the recorded traffic, not the read speed.
    if (!capture_->is_offline()) return Clock::now();
    return std::max(started_at_, latest_packet_time_);
}

void Pipeline::aggregate_loop() {
    auto next_publish = Clock::now() + config_.publish_interval;
    while (true) {
        // A short wait keeps snapshots flowing on a quiet network: the loop wakes at least
        // every 50 ms to check whether a publish is due even if no packets arrive.
        auto packet = queue_.pop_for(std::chrono::milliseconds(50));
        if (packet) {
            const PacketInfo info = parse_packet(std::span<const std::uint8_t>(packet->data));
            aggregator_.ingest(info, packet->wire_length, packet->timestamp);
            latest_packet_time_ = std::max(latest_packet_time_, packet->timestamp);
        } else if (queue_.drained()) {
            break;
        }

        const auto wall = Clock::now();
        if (wall >= next_publish) {
            const auto now = traffic_time();
            publish(now, now - started_at_);
            next_publish = wall + config_.publish_interval;
        }
    }

    const auto end = traffic_time();
    // A replayed file ends partway through a second; step past it so that last second counts
    // as complete in the final rates and history.
    const auto window_end = capture_->is_offline() ? end + std::chrono::seconds(1) : end;
    publish(window_end, end - started_at_);
    finished_.store(true);
}

std::string Pipeline::name_for(std::uint32_t ip) {
    if (!resolver_) return {};
    auto result = resolver_->lookup(ip);
    return result.status == Resolver::Status::Resolved ? std::move(result.name) : std::string{};
}

void Pipeline::publish(Clock::time_point now, Clock::duration uptime) {
    auto snapshot = std::make_shared<Snapshot>(aggregator_.build_snapshot(now));
    snapshot->uptime = uptime;

    const CaptureCounters counters = capture_->counters();
    snapshot->health.captured = counters.captured;
    snapshot->health.kernel_drops = counters.kernel_drops;
    snapshot->health.interface_drops = counters.interface_drops;
    snapshot->health.queue_drops = queue_.dropped();

    // Only addresses that are actually on screen get looked up, which keeps DNS traffic
    // (and the resolver's queue) proportional to what the user can see.
    for (auto& host : snapshot->top_hosts) host.name = name_for(host.ip);
    for (auto& flow : snapshot->top_flows) {
        flow.name_a = name_for(flow.key.ip_a);
        flow.name_b = name_for(flow.key.ip_b);
    }

    std::lock_guard lock(snapshot_mutex_);
    latest_ = std::move(snapshot);
}

}  // namespace netpulse
