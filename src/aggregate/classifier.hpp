#pragma once

#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

#include "aggregate/category.hpp"
#include "aggregate/flow.hpp"

namespace netpulse {

// Which end of a conversation is "yours" (the client / local device) and which is the remote
// service. One private address and one public address settle it; otherwise the end with the
// lower port is taken as the server, since services listen on well-known low ports and
// clients use high ephemeral ones.
struct FlowEnds {
    bool client_is_a = true;
    IpAddress client_ip;
    IpAddress server_ip;
    std::uint16_t server_port = 0;
};
FlowEnds orient(const FlowKey& key);

// Everything the classifier looks at for one conversation. Headers and timing only.
struct FlowFacts {
    std::uint8_t protocol = 0;
    std::uint16_t server_port = 0;
    std::uint64_t bytes = 0;
    std::uint64_t packets = 0;
    std::uint64_t bytes_to_client = 0;    // downloaded, from the local device's point of view
    std::uint64_t bytes_from_client = 0;  // uploaded
    double seconds = 0;                   // lifetime so far
    double duty_cycle = 0;                // share of lifetime seconds that carried traffic
    std::string remote_name;              // reverse-DNS name of the server end, if known
};
FlowFacts flow_facts(const FlowKey& key, const FlowStats& stats, std::string remote_name);

struct KnownService {
    std::string_view domain;  // matched as the name itself or any subdomain of it
    Category category;
};

// The built-in list. Deliberately short and incomplete: a known-service match only happens
// when an address's reverse-DNS name is on it, and many services' addresses have no such name.
std::optional<KnownService> match_known_service(std::string_view hostname);

struct Classification {
    Category category = Category::Other;
    ClassMethod method = ClassMethod::None;
};

// Layer 1: housekeeping ports and protocols go to Background. Layer 2: a known-service name
// match. Layer 3: the shape of the flow (see classifier.cpp for the exact rules and why).
Classification classify(const FlowFacts& facts);

// Plain-language reason for a classification, with the numbers that drove it. Built only
// when something is going to show it.
std::string explain(const FlowFacts& facts, const Classification& c);

}  // namespace netpulse
