#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "aggregate/snapshot.hpp"
#include "ui/focus_model.hpp"

namespace netpulse {

// What is selectable on the dashboard, which terms each row explains, and what the Learn panel
// says about each. Kept apart from the FTXUI rendering so the focus order and explanation
// coverage are unit-testable.
//
// The dashboard draws its sections in exactly this order: status, throughput, categories,
// protocol breakdown, IP versions, top talkers, top flows, capture health. dashboard_focus_rows() must list
// rows in the same order.

inline constexpr const char* kStatusRowId = "status";
inline constexpr const char* kThroughputRowId = "throughput";
inline constexpr const char* kHealthRowId = "health";

struct ProtocolRowSpec {
    const char* id;
    const char* label;
    TrafficCounter Snapshot::*counter;
    std::vector<std::string> terms;
};

// TCP, UDP, Other IP, Non-IP, Malformed.
const std::vector<ProtocolRowSpec>& protocol_rows();
// IPv4, IPv6: the same traffic split by IP version, shown under the protocol breakdown.
const std::vector<ProtocolRowSpec>& ip_version_rows();

std::string host_row_id(const IpAddress& ip);
std::string flow_row_id(const FlowKey& key);
std::string category_row_id(Category category);

// Glossary key for an IP protocol number: "tcp", "udp", "icmp", or the generic "protocol".
const char* protocol_term(std::uint8_t ip_protocol);

std::vector<std::string> host_terms(const HostRow& host);
std::vector<std::string> flow_terms(const FlowRow& flow);
std::vector<std::string> category_terms(const CategoryRow& row);

std::vector<FocusRow> dashboard_focus_rows(const Snapshot& snapshot);

// What the Learn panel shows for a focused term. Most terms are fixed glossary entries; terms
// starting with "why:" are explanations of this moment's judgments (the status line, a
// category, one flow's classification), built from the snapshot.
struct LearnContent {
    std::string title;
    std::string text;
};
std::optional<LearnContent> learn_content(const std::string& term, const Snapshot& snapshot);

}  // namespace netpulse
