#pragma once

#include <algorithm>
#include <string>
#include <string_view>

#include "aggregate/snapshot.hpp"
#include "util/net.hpp"

namespace netpulse {

// Terminal columns taken by UTF-8 text, assuming one column per character (true for everything
// the dashboard draws: ASCII, box drawing, arrows, block elements).
inline std::size_t display_width(std::string_view s) {
    return static_cast<std::size_t>(
        std::count_if(s.begin(), s.end(), [](char c) { return (static_cast<unsigned char>(c) & 0xC0) != 0x80; }));
}

// `s` cut down to at most `width` columns by dropping characters from the front, with "…"
// marking the cut: the end of a hostname ("…oca.nflxvideo.net") says more about it than the
// start, and the port stays visible at the end of "name:port". For ASCII input only (addresses,
// and names, which are made printable ASCII before display).
inline std::string elide_front(const std::string& s, std::size_t width) {
    if (s.size() <= width) return s;
    if (width == 0) return {};
    return "…" + s.substr(s.size() - (width - 1));
}

// "router.lan (192.168.1.1)" when a name is known, otherwise just the address. The real
// address always stays visible next to the friendly name.
inline std::string host_label(const IpAddress& ip, const std::string& name) {
    return name.empty() ? ip.to_string() : name + " (" + ip.to_string() + ")";
}

// For a narrow column: the name alone if there is one, shortened from the front to `width`.
// (A list switches every row to this form at once, so rows don't mix styles.)
inline std::string compact_host_label(const IpAddress& ip, const std::string& name, std::size_t width) {
    return elide_front(name.empty() ? ip.to_string() : name, width);
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

// Whether endpoint B goes first: the local device is shown first, since "my laptop talking to
// that server" is the natural way to read a conversation, unless the reader picked a device
// (`first`), which then leads every line about it.
inline bool b_first(const FlowRow& f, const IpAddress* first) {
    if (first && (f.key.ip_a == *first || f.key.ip_b == *first)) {
        return f.key.ip_b == *first && f.key.ip_a != *first;
    }
    return f.local_b && !f.local_a;
}

// "192.168.1.14:51000  ⇄  93.184.216.34:443", with names where known:
// "laptop.lan (192.168.1.14:51000)". Ports are omitted for protocols that have none (ICMP,
// fragments).
inline std::string conversation_label(const FlowRow& f, std::string_view arrow,
                                      const IpAddress* first = nullptr) {
    const bool show_ports = has_ports(f.key);
    auto endpoint = [&](const IpAddress& ip, const std::string& name, std::uint16_t port) {
        const std::string address = show_ports ? address_with_port(ip, port) : ip.to_string();
        return name.empty() ? address : name + " (" + address + ")";
    };
    std::string a = endpoint(f.key.ip_a, f.name_a, f.key.port_a);
    std::string b = endpoint(f.key.ip_b, f.name_b, f.key.port_b);
    if (b_first(f, first)) std::swap(a, b);
    return a + std::string(arrow) + b;
}

// For a narrow column, in at most `width` columns: named ends drop their address
// ("phone.local:61930  ⇄  zoomsea42mmr.sea.zoom.us:8801"), and if that's still too long, each
// end is shortened from the front, the longer one first.
inline std::string compact_conversation_label(const FlowRow& f, std::string_view arrow, std::size_t width,
                                              const IpAddress* first = nullptr) {
    const bool show_ports = has_ports(f.key);
    auto endpoint = [&](const IpAddress& ip, const std::string& name, std::uint16_t port) {
        if (name.empty()) return show_ports ? address_with_port(ip, port) : ip.to_string();
        return show_ports ? name + ":" + std::to_string(port) : name;
    };
    std::string a = endpoint(f.key.ip_a, f.name_a, f.key.port_a);
    std::string b = endpoint(f.key.ip_b, f.name_b, f.key.port_b);
    if (b_first(f, first)) std::swap(a, b);

    const std::size_t arrow_width = display_width(arrow);
    const std::size_t room = width > arrow_width ? width - arrow_width : 0;
    if (a.size() + b.size() > room) {
        // Equal halves, except that a short end gives its spare room to the other.
        const std::size_t half = room / 2;
        const std::size_t a_room = std::min(a.size(), std::max(half, room - std::min(b.size(), room)));
        a = elide_front(a, a_room);
        b = elide_front(b, room - a_room);
    }
    return a + std::string(arrow) + b;
}

}  // namespace netpulse
