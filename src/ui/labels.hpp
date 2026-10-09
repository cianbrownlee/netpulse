#pragma once

#include <string>

#include "aggregate/snapshot.hpp"
#include "util/net.hpp"

namespace netpulse {

// "router.lan (192.168.1.1)" when a name is known, otherwise just the address. The real
// address always stays visible next to the friendly name.
inline std::string host_label(const IpAddress& ip, const std::string& name) {
    return name.empty() ? ip.to_string() : name + " (" + ip.to_string() + ")";
}

// "192.168.1.14:51000", or "[2001:db8::1]:443": IPv6 addresses contain colons themselves, so
// they're bracketed when a port follows (RFC 3986).
inline std::string address_with_port(const IpAddress& ip, std::uint16_t port) {
    const std::string address = ip.to_string();
    return (ip.is_v4() ? address : "[" + address + "]") + ":" + std::to_string(port);
}

// Whether the conversation has ports worth showing: TCP or UDP, and not a flow of later IP
// fragments, which carry no transport header (port 0 is never a real TCP/UDP port).
inline bool has_ports(const FlowKey& k) {
    return (k.protocol == 6 || k.protocol == 17) && (k.port_a != 0 || k.port_b != 0);
}

// "192.168.1.14:51000  ⇄  93.184.216.34:443". The local device is shown first, since
// "my laptop talking to that server" is the natural way to read a conversation. Ports are
// omitted for protocols that have none (ICMP, fragments).
inline std::string conversation_label(const FlowRow& f, const char* arrow) {
    const bool show_ports = has_ports(f.key);
    auto endpoint = [&](const IpAddress& ip, const std::string& name, std::uint16_t port) {
        const std::string address = show_ports ? address_with_port(ip, port) : ip.to_string();
        return name.empty() ? address : name + " (" + address + ")";
    };
    std::string a = endpoint(f.key.ip_a, f.name_a, f.key.port_a);
    std::string b = endpoint(f.key.ip_b, f.name_b, f.key.port_b);
    if (f.local_b && !f.local_a) std::swap(a, b);
    return a + arrow + b;
}

}  // namespace netpulse
