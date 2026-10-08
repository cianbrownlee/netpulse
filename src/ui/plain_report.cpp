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
    out << "Throughput: " << format_rate(s.bytes_per_second) << " · "
        << format_count(static_cast<std::uint64_t>(s.packets_per_second)) << " packets/s\n";
    out << "Total: " << format_count(s.total.packets) << " packets, "
        << format_bytes(static_cast<double>(s.total.bytes)) << "\n";

    out << "Protocols:\n";
    out << protocol_line("TCP", s.tcp, s.total);
    out << protocol_line("UDP", s.udp, s.total);
    out << protocol_line("Other IPv4", s.other_ipv4, s.total);
    out << protocol_line("Non-IPv4", s.non_ipv4, s.total);
    out << protocol_line("Malformed", s.malformed, s.total);

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
        std::snprintf(buf, sizeof buf, "  %-5s %s  %s  (%s pkts)\n",
                      ip_protocol_name(f.key.protocol).c_str(),
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
        << " other_ipv4=" << s.other_ipv4.packets << " non_ipv4=" << s.non_ipv4.packets
        << " malformed=" << s.malformed.packets << " flows=" << s.active_flows
        << " hosts=" << s.known_hosts << " missed=" << s.health.missed() << "\n";
    out.flush();
}

}  // namespace netpulse
