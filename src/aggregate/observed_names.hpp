#pragma once

#include <cstddef>
#include <deque>
#include <string>
#include <unordered_map>

#include "parse/dns.hpp"
#include "util/ip_address.hpp"

namespace netpulse {

// Names learned from DNS and mDNS answers seen on the wire (--dns-names): "142.250.72.14 is
// www.youtube.com, because a device here just looked that up and got this answer".
//
// Usually far more useful than reverse DNS, which for most CDN addresses returns nothing or a
// generic name. Bounded: past `capacity` addresses, the oldest learned name is forgotten.
class ObservedNames {
public:
    explicit ObservedNames(std::size_t capacity = 4096) : capacity_(capacity) {}

    void record(const DnsNameAnswer& answer);
    const std::string* find(const IpAddress& ip) const;
    std::size_t size() const { return names_.size(); }

private:
    std::size_t capacity_;
    std::unordered_map<IpAddress, std::string> names_;
    std::deque<IpAddress> order_;  // first-learned first, for eviction
};

}  // namespace netpulse
