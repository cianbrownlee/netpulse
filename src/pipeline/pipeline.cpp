#include "pipeline/pipeline.hpp"

#include <algorithm>
#include <array>
#include <span>
#include <utility>

#include "aggregate/classifier.hpp"
#include "parse/packet_parser.hpp"
#include "util/format.hpp"
#include "util/net.hpp"

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
    // Live: publish every interval of wall-clock time. Replay: every interval of the *file's*
    // time, so smoothed rates and status checks see the recording as it happened rather than
    // as one instant, and replaying the same file always produces the same results.
    const bool offline = capture_->is_offline();
    auto next_publish = offline ? Clock::time_point{} : Clock::now() + config_.publish_interval;

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

        const auto clock = offline ? traffic_time() : Clock::now();
        if (clock >= next_publish) {
            const auto now = traffic_time();
            publish(now, now - started_at_);
            next_publish = clock + config_.publish_interval;
        }
    }

    const auto end = traffic_time();
    // A replayed file ends partway through a second; step past it so that last second counts
    // as complete in the final rates and history.
    const auto window_end = capture_->is_offline() ? end + std::chrono::seconds(1) : end;
    publish(window_end, end - started_at_);
    finished_.store(true);
}

void Pipeline::publish(Clock::time_point now, Clock::duration uptime) {
    auto snapshot = std::make_shared<Snapshot>(aggregator_.build_snapshot(now));
    snapshot->uptime = uptime;

    const CaptureCounters counters = capture_->counters();
    snapshot->health.captured = counters.captured;
    snapshot->health.kernel_drops = counters.kernel_drops;
    snapshot->health.interface_drops = counters.interface_drops;
    snapshot->health.queue_drops = queue_.dropped();

    // Names for the rows on screen and the rows the status checks look at. (Classification below
    // also asks for the remote end of every active flow; the resolver's cache keeps that to one
    // lookup per address per session.)
    for (auto* hosts : {&snapshot->top_hosts, &snapshot->rate_leaders}) {
        for (auto& host : *hosts) {
            auto [state, name] = lookup_name(host.ip);
            host.name_state = state;
            host.name = std::move(name);
        }
    }
    auto name_flow = [&](FlowRow& flow) {
        auto a = lookup_name(flow.key.ip_a);
        auto b = lookup_name(flow.key.ip_b);
        flow.name_state_a = a.state;
        flow.name_a = std::move(a.name);
        flow.name_state_b = b.state;
        flow.name_b = std::move(b.name);
        const bool remote_is_a = !orient(flow.key).client_is_a;
        const FlowFacts facts =
            flow_facts(flow.key, flow.stats, remote_is_a ? flow.name_a : flow.name_b);
        const Classification c = classify(facts);
        flow.category = c.category;
        flow.method = c.method;
        flow.reason = explain(facts, c);
    };
    for (auto& flow : snapshot->top_flows) name_flow(flow);
    if (snapshot->busiest_flow) name_flow(*snapshot->busiest_flow);

    categorize(*snapshot);
    snapshot->status = status_.update(*snapshot);

    std::lock_guard lock(snapshot_mutex_);
    latest_ = std::move(snapshot);
}

Pipeline::NameLookup Pipeline::lookup_name(std::uint32_t ip) {
    if (!resolver_) return {};
    auto result = resolver_->lookup(ip);
    switch (result.status) {
        case Resolver::Status::Resolved: return {NameState::Named, std::move(result.name)};
        case Resolver::Status::NoName: return {NameState::NoName, {}};
        case Resolver::Status::Pending: break;
    }
    return {};
}

void Pipeline::categorize(Snapshot& s) {
    struct Tally {
        std::uint64_t bytes = 0;
        std::size_t flows = 0;
        std::uint64_t known_bytes = 0;
        std::uint64_t shape_bytes = 0;
        std::uint64_t biggest_bytes = 0;
        FlowKey biggest_key;
        FlowFacts biggest_facts;
        Classification biggest_class;
    };
    std::array<Tally, 6> tally{};

    // Every active conversation, not just the ones on screen, so the breakdown covers all of
    // the traffic. The reason text is only built for the biggest flow in each category.
    for (const auto& [key, stats] : aggregator_.flows()) {
        FlowFacts facts = flow_facts(key, stats, lookup_name(orient(key).server_ip).name);
        const Classification c = classify(facts);
        Tally& t = tally[static_cast<std::size_t>(c.category)];
        t.bytes += stats.bytes;
        t.flows += 1;
        if (c.method == ClassMethod::KnownService) t.known_bytes += stats.bytes;
        if (c.method == ClassMethod::FlowShape) t.shape_bytes += stats.bytes;
        if (stats.bytes >= t.biggest_bytes) {
            t.biggest_bytes = stats.bytes;
            t.biggest_key = key;
            t.biggest_facts = std::move(facts);
            t.biggest_class = c;
        }
    }

    s.background_bytes = tally[static_cast<std::size_t>(Category::Background)].bytes;
    for (const Category category : kShownCategories) {
        const Tally& t = tally[static_cast<std::size_t>(category)];
        if (t.flows == 0) continue;

        CategoryRow row;
        row.category = category;
        row.bytes = t.bytes;
        row.flows = t.flows;
        if (t.known_bytes > 0 || t.shape_bytes > 0) {
            row.main_method = t.known_bytes >= t.shape_bytes ? ClassMethod::KnownService
                                                              : ClassMethod::FlowShape;
        }

        const FlowEnds ends = orient(t.biggest_key);
        const std::string server = t.biggest_facts.remote_name.empty()
                                       ? ipv4_to_string(ends.server_ip)
                                       : t.biggest_facts.remote_name;
        row.explanation = format_count(t.flows) + (t.flows == 1 ? " active conversation, " : " active conversations, ") +
                          format_bytes(static_cast<double>(t.bytes)) + " in total.";
        if (t.known_bytes > 0 && t.shape_bytes > 0) {
            const double known = static_cast<double>(t.known_bytes) / static_cast<double>(t.bytes);
            row.explanation += " " + format_percent(known) +
                               " of these bytes matched known services; the rest were labeled "
                               "by pattern.";
        }
        row.explanation += " Biggest: " + ipv4_to_string(ends.client_ip) + " with " + server +
                           " (port " + std::to_string(ends.server_port) + "). " +
                           explain(t.biggest_facts, t.biggest_class);
        s.categories.push_back(std::move(row));
    }
    std::sort(s.categories.begin(), s.categories.end(),
              [](const CategoryRow& a, const CategoryRow& b) { return a.bytes > b.bytes; });
}

}  // namespace netpulse
