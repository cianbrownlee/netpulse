#include "aggregate/aggregator.hpp"

#include <algorithm>
#include <tuple>
#include <utility>

#include "util/net.hpp"

namespace netpulse {

Aggregator::Aggregator() : Aggregator(Config{}) {}

Aggregator::Aggregator(Config config)
    : config_(config), throughput_(config.window_seconds) {}

TrafficCounter& Aggregator::counter_for(PacketKind kind) {
    switch (kind) {
        case PacketKind::Tcp: return tcp_;
        case PacketKind::Udp: return udp_;
        case PacketKind::OtherIpv4: return other_ipv4_;
        case PacketKind::NonIpv4: return non_ipv4_;
        case PacketKind::Malformed: break;
    }
    return malformed_;
}

void Aggregator::credit_host(std::uint32_t ip, std::uint32_t bytes, Clock::time_point t) {
    auto [it, inserted] = hosts_.try_emplace(ip);
    HostStats& h = it->second;
    if (inserted) h.first_seen = t;
    h.packets += 1;
    h.bytes += bytes;
    h.last_seen = t;
}

void Aggregator::ingest(const PacketInfo& info, std::uint32_t wire_length, Clock::time_point t) {
    total_.packets += 1;
    total_.bytes += wire_length;
    TrafficCounter& kind_counter = counter_for(info.kind);
    kind_counter.packets += 1;
    kind_counter.bytes += wire_length;
    throughput_.add(t, wire_length);

    if (!info.is_ipv4()) return;

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
    f.last_seen = t;
}

void Aggregator::expire_idle_flows(Clock::time_point now) {
    std::erase_if(flows_, [&](const auto& entry) {
        return now - entry.second.last_seen > config_.flow_idle_timeout;
    });
    last_expiry_ = now;
}

Snapshot Aggregator::build_snapshot(Clock::time_point now) {
    // Expiry walks every flow, so at most once a second rather than on every snapshot.
    if (now - last_expiry_ >= std::chrono::seconds(1)) expire_idle_flows(now);
    throughput_.advance_to(now);

    Snapshot s;
    s.total = total_;
    s.tcp = tcp_;
    s.udp = udp_;
    s.other_ipv4 = other_ipv4_;
    s.non_ipv4 = non_ipv4_;
    s.malformed = malformed_;
    s.bytes_per_second = throughput_.bytes_per_second();
    s.packets_per_second = throughput_.packets_per_second();
    s.byte_history = throughput_.byte_history();
    s.active_flows = flows_.size();
    s.known_hosts = hosts_.size();

    // Top-N by bytes without sorting the whole map: partial_sort over a vector of pointers.
    {
        std::vector<const std::pair<const std::uint32_t, HostStats>*> hosts;
        hosts.reserve(hosts_.size());
        for (const auto& entry : hosts_) hosts.push_back(&entry);
        const auto n = std::min(config_.top_n, hosts.size());
        std::partial_sort(hosts.begin(), hosts.begin() + static_cast<std::ptrdiff_t>(n),
                          hosts.end(), [](auto* a, auto* b) {
                              return a->second.bytes != b->second.bytes
                                         ? a->second.bytes > b->second.bytes
                                         : a->first < b->first;  // stable order for ties
                          });
        for (std::size_t i = 0; i < n; ++i) {
            HostRow row;
            row.ip = hosts[i]->first;
            row.is_local = is_local_ipv4(row.ip);
            row.packets = hosts[i]->second.packets;
            row.bytes = hosts[i]->second.bytes;
            s.top_hosts.push_back(std::move(row));
        }
    }
    {
        std::vector<const std::pair<const FlowKey, FlowStats>*> flows;
        flows.reserve(flows_.size());
        for (const auto& entry : flows_) flows.push_back(&entry);
        const auto n = std::min(config_.top_n, flows.size());
        std::partial_sort(flows.begin(), flows.begin() + static_cast<std::ptrdiff_t>(n),
                          flows.end(), [](auto* a, auto* b) {
                              if (a->second.bytes != b->second.bytes) {
                                  return a->second.bytes > b->second.bytes;
                              }
                              const FlowKey& x = a->first;
                              const FlowKey& y = b->first;
                              return std::tie(x.ip_a, x.port_a, x.ip_b, x.port_b, x.protocol) <
                                     std::tie(y.ip_a, y.port_a, y.ip_b, y.port_b, y.protocol);
                          });
        for (std::size_t i = 0; i < n; ++i) {
            FlowRow row;
            row.key = flows[i]->first;
            row.stats = flows[i]->second;
            s.top_flows.push_back(std::move(row));
        }
    }
    return s;
}

}  // namespace netpulse
