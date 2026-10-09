#include "ui/dashboard_model.hpp"

namespace netpulse {

const std::vector<ProtocolRowSpec>& protocol_rows() {
    static const std::vector<ProtocolRowSpec> rows = {
        {"proto:tcp", "TCP", &Snapshot::tcp, {"tcp", "packet"}},
        {"proto:udp", "UDP", &Snapshot::udp, {"udp", "packet"}},
        {"proto:other-ipv4", "Other IPv4", &Snapshot::other_ipv4, {"other-ipv4", "icmp"}},
        {"proto:non-ipv4", "Non-IPv4", &Snapshot::non_ipv4, {"non-ipv4"}},
        {"proto:malformed", "Malformed", &Snapshot::malformed, {"malformed", "header"}},
    };
    return rows;
}

std::string host_row_id(std::uint32_t ip) { return "host:" + std::to_string(ip); }

std::string flow_row_id(const FlowKey& k) {
    return "flow:" + std::to_string(k.protocol) + ":" + std::to_string(k.ip_a) + ":" +
           std::to_string(k.port_a) + "-" + std::to_string(k.ip_b) + ":" + std::to_string(k.port_b);
}

const char* protocol_term(std::uint8_t ip_protocol) {
    switch (ip_protocol) {
        case 1: return "icmp";
        case 6: return "tcp";
        case 17: return "udp";
        default: return "protocol";
    }
}

std::vector<std::string> host_terms(const HostRow& host) {
    // A shown name came from reverse DNS, so DNS is one of the things worth explaining.
    if (host.name.empty()) return {"ip-address", "local-address"};
    return {"ip-address", "dns", "local-address"};
}

std::vector<std::string> flow_terms(const FlowRow& flow) {
    const char* protocol = protocol_term(flow.key.protocol);
    const bool has_ports = flow.key.protocol == 6 || flow.key.protocol == 17;
    if (has_ports) return {"flow", protocol, "port"};
    return {"flow", protocol};
}

std::vector<FocusRow> dashboard_focus_rows(const Snapshot& s) {
    std::vector<FocusRow> rows;
    rows.push_back({kThroughputRowId, {"throughput", "packet"}});
    for (const auto& p : protocol_rows()) rows.push_back({p.id, p.terms});
    for (const auto& h : s.top_hosts) rows.push_back({host_row_id(h.ip), host_terms(h)});
    for (const auto& f : s.top_flows) rows.push_back({flow_row_id(f.key), flow_terms(f)});
    rows.push_back({kHealthRowId, {"dropped-packet"}});
    return rows;
}

}  // namespace netpulse
