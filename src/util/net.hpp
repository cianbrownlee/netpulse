#pragma once

#include <cstdint>
#include <string>

namespace netpulse {

// IPv4 addresses are carried in host byte order throughout NetPulse.
std::string ipv4_to_string(std::uint32_t ip);

// Addresses that belong to "your" side of the network rather than the internet: private,
// loopback, link-local and carrier-grade-NAT ranges, plus multicast and broadcast.
bool is_local_ipv4(std::uint32_t ip);

// "TCP", "UDP", "ICMP", or "IP proto 47" for anything without a friendly name.
std::string ip_protocol_name(std::uint8_t protocol);

}  // namespace netpulse
