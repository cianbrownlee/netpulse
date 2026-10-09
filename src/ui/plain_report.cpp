#include "ui/plain_report.hpp"

#include <chrono>
#include <cstdio>

#include "ui/labels.hpp"
#include "util/format.hpp"
#include "util/net.hpp"

namespace netpulse {

namespace {

std::string protocol_line(const char* label, const TrafficCounter& c, const TrafficCounter& total) {
    const double share =
        total.bytes == 0 ? 0.0 : static_cast<double>(c.bytes) / static_cast<double>(total.bytes);
    char buf[128];
    std::snprintf(buf, sizeof buf, "  %-11s %12s pkts  %10s  %5s of bytes\n", label,
                  format_count(c.packets).c_str(), format_bytes(static_cast<double>(c.bytes)).c_str(),
                  format_percent(share).c_str());
    return buf;
}

}  // namespace

void print_report(std::ostream& out, const Snapshot& s, const std::string& source) {
    const auto uptime = std::chrono::duration_cast<std::chrono::seconds>(s.uptime);
    out << "== NetPulse · " << source << " · running " << format_duration(uptime) << " ==\n";
    out << (s.status.heads_up() ? "[!] " : "[ok] ") << s.status.headline << "\n";
    out << "Throughput: " << format_rate(s.bytes_per_second) << " · "
        << format_count(static_cast<std::uint64_t>(s.packets_per_second)) << " packets/s\n";
    out << "Total: " << format_count(s.total.packets) << " packets, "
        << format_bytes(static_cast<double>(s.total.bytes)) << "\n";

    out << "Traffic by category (active conversations):\n";
    std::uint64_t shown_bytes = 0;
    for (const auto& c : s.categories) shown_bytes += c.bytes;
    for (const auto& c : s.categories) {
        const double share =
            shown_bytes == 0 ? 0.0 : static_cast<double>(c.bytes) / static_cast<double>(shown_bytes);
        char buf[160];
        std::snprintf(buf, sizeof buf, "  %-18s %-23s %5s  %10s\n", category_label(c.category),
                      method_tag(c.main_method), format_percent(share).c_str(),
                      format_bytes(static_cast<double>(c.bytes)).c_str());
        out << buf;
    }
    if (s.background_bytes > 0) {
        out << "  (not counted: " << format_bytes(static_cast<double>(s.background_bytes))
            << " of background traffic)\n";
    }

    out << "Protocols:\n";
    out << protocol_line("TCP", s.tcp, s.total);
    out << protocol_line("UDP", s.udp, s.total);
    out << protocol_line("Other IP", s.other_ip, s.total);
    out << protocol_line("Non-IP", s.non_ip, s.total);
    out << protocol_line("Malformed", s.malformed, s.total);
    out << "IP versions:\n";
    out << protocol_line("IPv4", s.ipv4, s.total);
    out << protocol_line("IPv6", s.ipv6, s.total);

    out << "Top talkers (sent + received):\n";
    for (const auto& h : s.top_hosts) {
        char buf[256];
        std::snprintf(buf, sizeof buf, "  %-48s %10s  %s\n", host_label(h.ip, h.name).c_str(),
                      format_bytes(static_cast<double>(h.bytes)).c_str(),
                      h.is_local ? "local" : "internet");
        out << buf;
    }

    out << "Top flows:\n";
    for (const auto& f : s.top_flows) {
        char buf[320];
        std::snprintf(buf, sizeof buf, "  %-6s %-10s %s  %s  (%s pkts)\n",
                      ip_protocol_name(f.key.protocol).c_str(), category_short_label(f.category),
                      conversation_label(f, " <-> ").c_str(),
                      format_bytes(static_cast<double>(f.stats.bytes)).c_str(),
                      format_count(f.stats.packets).c_str());
        out << buf;
    }

    out << "Missed " << format_percent(s.health.missed_fraction(), 2) << " of packets ("
        << s.health.queue_drops << " queue, " << s.health.kernel_drops << " kernel) · "
        << s.active_flows << " active flows\n";

    out << "summary: packets=" << s.total.packets << " bytes=" << s.total.bytes
        << " tcp=" << s.tcp.packets << " udp=" << s.udp.packets
        << " other_ip=" << s.other_ip.packets << " non_ip=" << s.non_ip.packets
        << " malformed=" << s.malformed.packets << " ipv6=" << s.ipv6.packets
        << " flows=" << s.active_flows << " hosts=" << s.known_hosts
        << " missed=" << s.health.missed() << "\n";

    // Conversations per category, every category always listed, in a fixed order.
    out << "categories:";
    for (const Category c : kShownCategories) {
        std::size_t flows = 0;
        for (const auto& row : s.categories) {
            if (row.category == c) flows = row.flows;
        }
        out << ' ' << category_key(c) << '=' << flows;
    }
    out << "\nstatus: " << status_key(s.status.kind) << "\n";
    out.flush();
}

}  // namespace netpulse
