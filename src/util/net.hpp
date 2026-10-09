#pragma once

#include <cstdint>
#include <string>

#include "util/ip_address.hpp"

namespace netpulse {

// Addresses a single device on your side of the network can have, judged from the address
// alone. IPv4: private (RFC 1918), loopback, link-local, carrier-grade NAT. IPv6: unique local
// (fc00::/7), link-local (fe80::/10), loopback (::1).
//
// Note that IPv6 home networks usually give devices *global* addresses (no NAT), which this
// can't recognize as local; see LocalNetworks for the interface-aware version.
bool is_private(const IpAddress& ip);

// Group and placeholder addresses: multicast, broadcast and unspecified ones, and IPv4's "this
// network" block. They stay on the local network but never name a single device.
bool is_group_or_unspecified(const IpAddress& ip);

// Addresses that belong to "your" side of the network rather than the internet, judged from the
// address alone: is_private or is_group_or_unspecified.
bool is_local(const IpAddress& ip);

// "TCP", "UDP", "ICMP", "ICMPv6", ..., or "IP proto 47" for anything without a friendly name.
std::string ip_protocol_name(std::uint8_t protocol);

}  // namespace netpulse
