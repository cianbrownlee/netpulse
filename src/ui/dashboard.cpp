#include "ui/dashboard.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <string>
#include <thread>

#include <ftxui/component/component.hpp>
#include <ftxui/component/screen_interactive.hpp>
#include <ftxui/dom/elements.hpp>

#include "pipeline/pipeline.hpp"
#include "ui/labels.hpp"
#include "util/format.hpp"
#include "util/net.hpp"

namespace netpulse {

namespace {

using namespace ftxui;

constexpr auto kRefreshInterval = std::chrono::milliseconds(250);

double share_of(std::uint64_t part, std::uint64_t whole) {
    return whole == 0 ? 0.0 : static_cast<double>(part) / static_cast<double>(whole);
}

std::string sparkline(const std::vector<std::uint64_t>& values) {
    static constexpr const char* kBars[] = {" ", "▁", "▂", "▃", "▄", "▅", "▆", "▇", "█"};
    const std::uint64_t peak = values.empty() ? 0 : *std::max_element(values.begin(), values.end());
    std::string out;
    for (const std::uint64_t v : values) {
        // Any non-zero second gets at least the lowest bar, so light traffic is still visible.
        std::size_t level = 0;
        if (v > 0 && peak > 0) level = 1 + static_cast<std::size_t>(v * 7 / peak);
        out += kBars[std::min<std::size_t>(level, 8)];
    }
    return out;
}

Element cell(const std::string& s, int width) { return text(s) | size(WIDTH, EQUAL, width); }

Element right_cell(const std::string& s, int width) {
    return hbox({filler(), text(s)}) | size(WIDTH, EQUAL, width);
}

Element header(const Snapshot& s, const Pipeline& p) {
    std::string mode = "live";
    if (p.is_offline()) mode = p.finished() ? "replay finished" : "replaying file";
    const auto uptime = std::chrono::duration_cast<std::chrono::seconds>(s.uptime);
    return hbox({
        text(" NetPulse ") | bold | inverted,
        text("  " + p.source() + " · " + mode),
        filler(),
        text("running " + format_duration(uptime) + "   "),
        text("q to quit ") | dim,
    });
}

Element throughput(const Snapshot& s) {
    return hbox({
        text(" Throughput  "),
        text(format_rate(s.bytes_per_second)) | bold,
        text("  " + format_count(static_cast<std::uint64_t>(s.packets_per_second)) + " packets/s   "),
        text(sparkline(s.byte_history)) | color(Color::Cyan),
        text("  last 60s") | dim,
    });
}

Element protocol_row(const std::string& label, const TrafficCounter& c, const TrafficCounter& total,
                     Color bar_color) {
    const double share = share_of(c.bytes, total.bytes);
    return hbox({
        cell(" " + label, 13),
        right_cell(format_percent(share), 6),
        text("  "),
        gauge(static_cast<float>(share)) | color(bar_color) | size(WIDTH, EQUAL, 30),
        text("  "),
        right_cell(format_bytes(static_cast<double>(c.bytes)), 10),
        right_cell(format_count(c.packets) + " pkts", 18),
    });
}

Element protocols(const Snapshot& s) {
    return window(text(" Protocols (share of bytes) "),
                  vbox({
                      protocol_row("TCP", s.tcp, s.total, Color::Green),
                      protocol_row("UDP", s.udp, s.total, Color::Blue),
                      protocol_row("Other IPv4", s.other_ipv4, s.total, Color::Yellow),
                      protocol_row("Non-IPv4", s.non_ipv4, s.total, Color::Magenta),
                      protocol_row("Malformed", s.malformed, s.total, Color::Red),
                  }));
}

Element top_talkers(const Snapshot& s) {
    Elements rows;
    rows.push_back(hbox({cell(" Device / address", 50), right_cell("Bytes", 10),
                         right_cell("Of all traffic", 16), text("   Where")}) | dim);
    for (const auto& h : s.top_hosts) {
        rows.push_back(hbox({
            cell(" " + host_label(h.ip, h.name), 50),
            right_cell(format_bytes(static_cast<double>(h.bytes)), 10),
            right_cell(format_percent(share_of(h.bytes, s.total.bytes)), 16),
            text(h.is_local ? "   local" : "   internet"),
        }));
    }
    if (s.top_hosts.empty()) {
        rows.push_back(text(" waiting for traffic...") | dim);
    } else {
        rows.push_back(text(" Each conversation counts toward both of its ends, so these can add "
                            "up to more than 100%.") | dim);
    }
    return window(text(" Top talkers (bytes sent + received) "), vbox(std::move(rows)));
}

Element top_flows(const Snapshot& s) {
    Elements rows;
    rows.push_back(hbox({cell(" Proto", 7), cell("Conversation", 70), right_cell("Bytes", 10),
                         right_cell("Packets", 12)}) | dim);
    for (const auto& f : s.top_flows) {
        rows.push_back(hbox({
            cell(" " + ip_protocol_name(f.key.protocol), 7),
            cell(conversation_label(f, "  ⇄  "), 70),
            right_cell(format_bytes(static_cast<double>(f.stats.bytes)), 10),
            right_cell(format_count(f.stats.packets), 12),
        }));
    }
    if (s.top_flows.empty()) rows.push_back(text(" waiting for traffic...") | dim);
    return window(text(" Top flows (conversations) "), vbox(std::move(rows)));
}

Element footer(const Snapshot& s) {
    const double missed = s.health.missed_fraction();
    return hbox({
        text(" Missed " + format_percent(missed, 2) + " of packets") |
            color(missed > 0.01 ? Color(Color::Yellow) : Color(Color::Default)),
        text(" (" + format_count(s.health.queue_drops) + " in NetPulse's queue, " +
             format_count(s.health.kernel_drops) + " in the kernel)") | dim,
        filler(),
        text(format_count(s.active_flows) + " active flows · " + format_count(s.known_hosts) +
             " addresses seen "),
    });
}

}  // namespace

void run_dashboard(Pipeline& pipeline) {
    auto screen = ScreenInteractive::Fullscreen();

    auto renderer = Renderer([&] {
        const auto snapshot = pipeline.latest();
        const Snapshot& s = *snapshot;
        return vbox({
            header(s, pipeline),
            separator(),
            throughput(s),
            protocols(s),
            top_talkers(s),
            top_flows(s),
            filler(),
            separator(),
            footer(s),
        });
    });

    auto app = CatchEvent(renderer, [&](const Event& event) {
        if (event == Event::Character('q') || event == Event::Escape) {
            screen.Exit();
            return true;
        }
        return false;
    });

    // FTXUI redraws on events, so a ticker thread posts one per refresh interval. It also
    // closes the dashboard if capture dies, so a failure is reported instead of the screen
    // silently freezing on its last numbers.
    std::atomic<bool> running{true};
    std::thread ticker([&] {
        while (running.load()) {
            std::this_thread::sleep_for(kRefreshInterval);
            screen.PostEvent(Event::Custom);
            if (pipeline.error()) {
                screen.Post(screen.ExitLoopClosure());
                return;
            }
        }
    });

    screen.Loop(app);
    running.store(false);
    ticker.join();
}

}  // namespace netpulse
