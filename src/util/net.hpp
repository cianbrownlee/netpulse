#pragma once

#include <cstdint>
#include <string>

namespace netpulse {

// IPv4 addresses are carried in host byte order throughout NetPulse.
std::string ipv4_to_string(std::uint32_t ip);

// Private, loopback, link-local and carrier-grade-NAT ranges: addresses that belong to
// "your" side of the network rather than the internet.
bool is_local_ipv4(std::uint32_t ip);

// "TCP", "UDP", "ICMP", or "IP proto 47" for anything without a friendly name.
std::string ip_protocol_name(std::uint8_t protocol);

}  // namespace netpulse
