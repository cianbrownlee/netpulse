#include "ui/dashboard_model.hpp"

#include <string_view>

#include "ui/glossary.hpp"
#include "ui/labels.hpp"

namespace netpulse {

namespace {

constexpr std::string_view kWhyStatus = "why:status";
constexpr std::string_view kWhyCategoryPrefix = "why:category:";
constexpr std::string_view kWhyFlowPrefix = "why:flow:";

const char* method_term(ClassMethod m) {
    switch (m) {
        case ClassMethod::KnownService: return "known-domain-match";
        case ClassMethod::FlowShape: return "flow-shape-heuristic";
        case ClassMethod::None: break;
    }
    return nullptr;
}

}  // namespace

const std::vector<ProtocolRowSpec>& protocol_rows() {
    static const std::vector<ProtocolRowSpec> rows = {
        {"proto:tcp", "TCP", &Snapshot::tcp, {"tcp", "packet"}},
        {"proto:udp", "UDP", &Snapshot::udp, {"udp", "packet"}},
        {"proto:other-ip", "Other IP", &Snapshot::other_ip, {"other-ip", "icmp"}},
        {"proto:non-ip", "Non-IP", &Snapshot::non_ip, {"non-ip"}},
        {"proto:malformed", "Malformed", &Snapshot::malformed, {"malformed", "header"}},
    };
    return rows;
}

const std::vector<ProtocolRowSpec>& ip_version_rows() {
    static const std::vector<ProtocolRowSpec> rows = {
        {"ipver:4", "IPv4", &Snapshot::ipv4, {"ipv4", "ip-address"}},
        {"ipver:6", "IPv6", &Snapshot::ipv6, {"ipv6", "ip-address"}},
    };
    return rows;
}

std::string host_row_id(const IpAddress& ip) { return "host:" + ip.to_string(); }

std::string flow_row_id(const FlowKey& k) {
    return "flow:" + std::to_string(k.protocol) + ":" + k.ip_a.to_string() + "/" +
           std::to_string(k.port_a) + "-" + k.ip_b.to_string() + "/" + std::to_string(k.port_b);
}

std::string category_row_id(Category category) {
    return std::string("category:") + category_key(category);
}

const char* protocol_term(std::uint8_t ip_protocol) {
    switch (ip_protocol) {
        case 1:
        case 58: return "icmp";  // ICMP and ICMPv6 share an explanation
        case 6: return "tcp";
        case 17: return "udp";
        default: return "protocol";
    }
}

std::vector<std::string> host_terms(const HostRow& host) {
    // A shown name came from reverse DNS, so DNS is one of the things worth explaining.
    if (host.name.empty()) return {"ip-address", "throughput", "local-address"};
    return {"ip-address", "dns", "throughput", "local-address"};
}

std::vector<std::string> flow_terms(const FlowRow& flow) {
    const char* protocol = protocol_term(flow.key.protocol);
    std::string why = std::string(kWhyFlowPrefix) + flow_row_id(flow.key);
    if (has_ports(flow.key)) return {"flow", protocol, "port", std::move(why)};
    return {"flow", protocol, std::move(why)};
}

std::vector<std::string> category_terms(const CategoryRow& row) {
    std::string why = std::string(kWhyCategoryPrefix) + category_key(row.category);
    if (const char* method = method_term(row.main_method)) return {std::move(why), method};
    return {std::move(why)};
}

std::vector<FocusRow> dashboard_focus_rows(const Snapshot& s) {
    std::vector<FocusRow> rows;
    rows.push_back({kStatusRowId, {std::string(kWhyStatus)}});
    rows.push_back({kThroughputRowId, {"throughput", "packet"}});
    for (const auto& c : s.categories) rows.push_back({category_row_id(c.category), category_terms(c)});
    for (const auto& p : protocol_rows()) rows.push_back({p.id, p.terms});
    for (const auto& v : ip_version_rows()) rows.push_back({v.id, v.terms});
    for (const auto& h : s.top_hosts) rows.push_back({host_row_id(h.ip), host_terms(h)});
    for (const auto& f : s.top_flows) rows.push_back({flow_row_id(f.key), flow_terms(f)});
    rows.push_back({kHealthRowId, {"dropped-packet"}});
    return rows;
}

std::optional<LearnContent> learn_content(const std::string& term, const Snapshot& s) {
    const std::string_view t = term;

    if (t == kWhyStatus) {
        return LearnContent{s.status.heads_up() ? "Why this heads-up" : "Why \"everything looks normal\"",
                            s.status.explanation};
    }
    if (t.starts_with(kWhyCategoryPrefix)) {
        const auto key = t.substr(kWhyCategoryPrefix.size());
        for (const auto& c : s.categories) {
            if (key == category_key(c.category)) {
                return LearnContent{std::string("Why: ") + category_label(c.category), c.explanation};
            }
        }
        return std::nullopt;
    }
    if (t.starts_with(kWhyFlowPrefix)) {
        const auto id = t.substr(kWhyFlowPrefix.size());
        for (const auto& f : s.top_flows) {
            if (id == flow_row_id(f.key)) {
                return LearnContent{std::string("Why: ") + category_label(f.category), f.reason};
            }
        }
        return std::nullopt;
    }

    if (const GlossaryEntry* entry = find_glossary_entry(t)) {
        return LearnContent{std::string(entry->title), std::string(entry->text)};
    }
    return std::nullopt;
}

}  // namespace netpulse
