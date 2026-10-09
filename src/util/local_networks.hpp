#pragma once

#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "util/ip_address.hpp"

namespace netpulse {

// A network such as 192.168.1.0/24 or 2001:db8:1::/64.
struct IpPrefix {
    IpAddress network;
    int bits = 0;  // prefix length within the address's own family (at most 32 for IPv4)

    bool contains(const IpAddress& ip) const {
        return ip.is_v4() == network.is_v4() && ip.in_prefix(network, bits);
    }
    std::string to_string() const { return network.to_string() + "/" + std::to_string(bits); }

    // "192.168.1.0/24", "2001:db8::/32" (host bits are cleared, so "192.168.1.14/24" works too);
    // a bare address is a single-host prefix.
    static std::optional<IpPrefix> parse(std::string_view text);

    // From an interface address and its netmask, the way operating systems report them.
    // nullopt if the families differ or the mask isn't a contiguous run of ones.
    static std::optional<IpPrefix> from_netmask(const IpAddress& address, const IpAddress& netmask);
};

// The networks NetPulse is capturing on, used to tell "your devices" from the rest of the
// internet.
//
// Address ranges alone can't do that for IPv6: home networks usually give every device a
// globally routable address, with no NAT in between, so 2601:... can be "this laptop" just as
// 192.168.1.14 is. These come from the capture interface's own addresses (and --local).
class LocalNetworks {
public:
    void add(const IpPrefix& prefix);

    bool contains(const IpAddress& ip) const;

    // On your side of the network: a private/local range (see is_local in net.hpp), or inside
    // one of these networks.
    bool is_local(const IpAddress& ip) const;

    // Could be a single device on your side: is_local, minus group and placeholder addresses
    // (multicast, broadcast, unspecified), which never name one device.
    bool is_device(const IpAddress& ip) const;

    const std::vector<IpPrefix>& prefixes() const { return prefixes_; }
    bool empty() const { return prefixes_.empty(); }
    std::string to_string() const;  // "192.168.1.0/24, 2001:db8:1::/64"

private:
    std::vector<IpPrefix> prefixes_;
};

// For callers with no interface information (unit tests, plain helpers).
const LocalNetworks& no_local_networks();

}  // namespace netpulse
