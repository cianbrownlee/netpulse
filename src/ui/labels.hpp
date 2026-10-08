#pragma once

#include <string>

#include "aggregate/snapshot.hpp"
#include "util/net.hpp"

namespace netpulse {

// "router.lan (192.168.1.1)" when a name is known, otherwise just the address. The real
// address always stays visible next to the friendly name.
inline std::string host_label(std::uint32_t ip, const std::string& name) {
    return name.empty() ? ipv4_to_string(ip) : name + " (" + ipv4_to_string(ip) + ")";
}

// "192.168.1.14:51000  ⇄  93.184.216.34:443". The local device is shown first, since
// "my laptop talking to that server" is the natural way to read a conversation. Ports are
// omitted for protocols that have none (ICMP, fragments).
inline std::string conversation_label(const FlowRow& f, const char* arrow) {
    const bool has_ports = f.key.protocol == 6 || f.key.protocol == 17;
    auto endpoint = [&](std::uint32_t ip, const std::string& name, std::uint16_t port) {
        std::string s = host_label(ip, name);
        if (has_ports) s += ":" + std::to_string(port);
        return s;
    };
    std::string a = endpoint(f.key.ip_a, f.name_a, f.key.port_a);
    std::string b = endpoint(f.key.ip_b, f.name_b, f.key.port_b);
    if (is_local_ipv4(f.key.ip_b) && !is_local_ipv4(f.key.ip_a)) std::swap(a, b);
    return a + arrow + b;
}

}  // namespace netpulse
