#pragma once

#include <cstdint>
#include <span>
#include <string>
#include <vector>

#include "aggregate/snapshot.hpp"
#include "ui/focus_model.hpp"

namespace netpulse {

// What is selectable on the dashboard, and which glossary terms each row explains. Kept apart
// from the FTXUI rendering so the focus order and glossary coverage are unit-testable.
//
// The dashboard draws its sections in exactly this order: throughput, protocol breakdown, top
// talkers, top flows, capture health. dashboard_focus_rows() must list rows in the same order.

inline constexpr const char* kThroughputRowId = "throughput";
inline constexpr const char* kHealthRowId = "health";

struct ProtocolRowSpec {
    const char* id;
    const char* label;
    TrafficCounter Snapshot::*counter;
    std::vector<std::string> terms;
};

// TCP, UDP, Other IPv4, Non-IPv4, Malformed.
const std::vector<ProtocolRowSpec>& protocol_rows();

std::string host_row_id(std::uint32_t ip);
std::string flow_row_id(const FlowKey& key);

// Glossary key for an IP protocol number: "tcp", "udp", "icmp", or the generic "protocol".
const char* protocol_term(std::uint8_t ip_protocol);

std::vector<std::string> host_terms(const HostRow& host);
std::vector<std::string> flow_terms(const FlowRow& flow);

std::vector<FocusRow> dashboard_focus_rows(const Snapshot& snapshot);

}  // namespace netpulse
