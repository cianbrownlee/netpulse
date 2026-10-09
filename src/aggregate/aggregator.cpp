#include "aggregate/aggregator.hpp"

#include <algorithm>
#include <cmath>
#include <tuple>
#include <utility>

#include "util/net.hpp"

namespace netpulse {

namespace {

// Top-n entries of a map under `better`, without sorting the whole map: partial_sort over a
// vector of pointers.
template <typename Map, typename Better>
std::vector<const typename Map::value_type*> top_entries(const Map& map, std::size_t n,
                                                         Better better) {
    std::vector<const typename Map::value_type*> entries;
    entries.reserve(map.size());
    for (const auto& entry : map) entries.push_back(&entry);
    n = std::min(n, entries.size());
    std::partial_sort(entries.begin(), entries.begin() + static_cast<std::ptrdiff_t>(n),
                      entries.end(), better);
    entries.resize(n);
    return entries;
}

bool key_less(const FlowKey& x, const FlowKey& y) {
    return std::tie(x.ip_a, x.port_a, x.ip_b, x.port_b, x.protocol) <
           std::tie(y.ip_a, y.port_a, y.ip_b, y.port_b, y.protocol);
}

}  // namespace

Aggregator::Aggregator() : Aggregator(Config{}) {}

Aggregator::Aggregator(Config config)
    : config_(config), throughput_(config.window_seconds) {}

TrafficCounter& Aggregator::counter_for(PacketKind kind) {
    switch (kind) {
        case PacketKind::Tcp: return tcp_;
        case PacketKind::Udp: return udp_;
        case PacketKind::OtherIp: return other_ip_;
        case PacketKind::NonIp: return non_ip_;
        case PacketKind::Malformed: break;
    }
    return malformed_;
}

void Aggregator::credit_host(const IpAddress& ip, std::uint32_t bytes, Clock::time_point t) {
    auto [it, inserted] = hosts_.try_emplace(ip);
    HostStats& h = it->second;
    if (inserted) h.first_seen = t;
    h.packets += 1;
    h.bytes += bytes;
    h.last_seen = t;
}

void Aggregator::ingest(const PacketInfo& info, std::uint32_t wire_length, Clock::time_point t) {
    if (!rates_started_) {
        rates_started_ = true;
        last_tick_ = t;
    }

    total_.packets += 1;
    total_.bytes += wire_length;
    TrafficCounter& kind_counter = counter_for(info.kind);
    kind_counter.packets += 1;
    kind_counter.bytes += wire_length;
    throughput_.add(t, wire_length);

    if (!info.is_ip()) return;
    TrafficCounter& version_counter = info.ip_version == 6 ? ipv6_ : ipv4_;
    version_counter.packets += 1;
    version_counter.bytes += wire_length;

    // A host's total is everything it sent plus everything it received.
    credit_host(info.src_ip, wire_length, t);
    if (info.dst_ip != info.src_ip) credit_host(info.dst_ip, wire_length, t);

    const auto [key, a_to_b] = make_flow_key(info);
    auto [it, inserted] = flows_.try_emplace(key);
    FlowStats& f = it->second;
    if (inserted) f.first_seen = t;
    f.packets += 1;
    f.bytes += wire_length;
    (a_to_b ? f.bytes_a_to_b : f.bytes_b_to_a) += wire_length;
    f.last_seen = std::max(f.last_seen, t);

    // `>` rather than `!=`: a slightly late packet from an earlier second must not count that
    // second twice.
    const std::int64_t second = second_index(t);
    if (second > f.last_active_second) {
        ++f.active_seconds;
        f.last_active_second = second;
    }
}

void Aggregator::expire_idle_flows(Clock::time_point now) {
    std::erase_if(flows_, [&](const auto& entry) {
        return now - entry.second.last_seen > config_.flow_idle_timeout;
    });
    last_expiry_ = now;
}

void Aggregator::update_rates(Clock::time_point now) {
    if (!rates_started_) return;
    const double dt = std::chrono::duration<double>(now - last_tick_).count();
    if (dt <= 0) return;

    // Exponentially weighted moving average that is correct for uneven tick spacing:
    // the weight of the newest interval depends on how long that interval was.
    const double tau = std::chrono::duration<double>(config_.rate_time_constant).count();
    const double alpha = 1.0 - std::exp(-dt / tau);
    auto step = [&](double& rate, std::uint64_t& bytes_at_last_tick, std::uint64_t bytes) {
        const double instant = static_cast<double>(bytes - bytes_at_last_tick) / dt;
        rate += alpha * (instant - rate);
        bytes_at_last_tick = bytes;
    };

    step(total_current_bps_, total_bytes_at_last_tick_, total_.bytes);
    for (auto& [ip, h] : hosts_) step(h.current_bps, h.bytes_at_last_tick, h.bytes);
    for (auto& [key, f] : flows_) step(f.current_bps, f.bytes_at_last_tick, f.bytes);
    last_tick_ = now;
}

HostRow Aggregator::host_row(const IpAddress& ip, const HostStats& h, Clock::time_point now) const {
    HostRow row;
    row.ip = ip;
    row.is_local = config_.local_networks.is_local(ip);
    row.packets = h.packets;
    row.bytes = h.bytes;
    row.current_bps = h.current_bps;
    row.seen_for = now - h.first_seen;
    // At least one second, so a host seen a moment ago doesn't get an absurd average.
    const double seconds = std::max(1.0, std::chrono::duration<double>(row.seen_for).count());
    row.average_bps = static_cast<double>(h.bytes) / seconds;
    return row;
}

FlowRow Aggregator::flow_row(const FlowKey& key, const FlowStats& stats) const {
    FlowRow row;
    row.key = key;
    row.stats = stats;
    row.local_a = config_.local_networks.is_local(key.ip_a);
    row.local_b = config_.local_networks.is_local(key.ip_b);
    return row;
}

Snapshot Aggregator::build_snapshot(Clock::time_point now) {
    // Expiry walks every flow, so at most once a second rather than on every snapshot.
    if (now - last_expiry_ >= std::chrono::seconds(1)) expire_idle_flows(now);
    throughput_.advance_to(now);
    update_rates(now);

    Snapshot s;
    s.total = total_;
    s.tcp = tcp_;
    s.udp = udp_;
    s.other_ip = other_ip_;
    s.non_ip = non_ip_;
    s.ipv4 = ipv4_;
    s.ipv6 = ipv6_;
    s.malformed = malformed_;
    s.bytes_per_second = throughput_.bytes_per_second();
    s.packets_per_second = throughput_.packets_per_second();
    s.current_bps = total_current_bps_;
    s.byte_history = throughput_.byte_history();
    s.active_flows = flows_.size();
    s.known_hosts = hosts_.size();

    for (const auto* e : top_entries(hosts_, config_.top_n, [](auto* a, auto* b) {
             return a->second.bytes != b->second.bytes ? a->second.bytes > b->second.bytes
                                                       : a->first < b->first;  // stable ties
         })) {
        s.top_hosts.push_back(host_row(e->first, e->second, now));
    }
    for (const auto* e : top_entries(hosts_, config_.rate_leaders, [](auto* a, auto* b) {
             return a->second.current_bps != b->second.current_bps
                        ? a->second.current_bps > b->second.current_bps
                        : a->first < b->first;
         })) {
        s.rate_leaders.push_back(host_row(e->first, e->second, now));
    }

    for (const auto* e : top_entries(flows_, config_.top_n, [](auto* a, auto* b) {
             return a->second.bytes != b->second.bytes ? a->second.bytes > b->second.bytes
                                                       : key_less(a->first, b->first);
         })) {
        s.top_flows.push_back(flow_row(e->first, e->second));
    }
    for (const auto* e : top_entries(flows_, 1, [](auto* a, auto* b) {
             return a->second.current_bps != b->second.current_bps
                        ? a->second.current_bps > b->second.current_bps
                        : key_less(a->first, b->first);
         })) {
        s.busiest_flow = flow_row(e->first, e->second);
    }
    s.local_networks = config_.local_networks.to_string();
    return s;
}

}  // namespace netpulse
