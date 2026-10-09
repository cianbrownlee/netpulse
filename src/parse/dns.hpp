#pragma once

#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <vector>

#include "util/ip_address.hpp"

namespace netpulse {

// One name and the addresses a DNS (or mDNS) response says it has.
struct DnsNameAnswer {
    std::string name;  // lowercase, without a trailing dot
    std::vector<IpAddress> addresses;
};

// Reads the A and AAAA answers out of a DNS response (a UDP payload from port 53 or 5353).
//
// Each address is paired with the name that was *asked* for (the question), not the record's
// own name: a lookup of www.youtube.com usually answers through a CNAME chain ending at
// something like youtube-ui.l.google.com, and the question is the name that means something to a
// person (and to the classifier's known-services list). mDNS responses usually carry no
// question; then the record's own name is used (e.g. living-room-tv.local).
//
// Hostile input is expected: every read is bounds-checked, compression pointers may only point
// backwards (which rules out loops), and names with non-printable characters are rejected, since
// they'd otherwise end up on the user's terminal. A response cut short by capture yields
// whatever complete answers came before the cut.
std::vector<DnsNameAnswer> parse_dns_response(std::span<const std::uint8_t> payload);

}  // namespace netpulse
