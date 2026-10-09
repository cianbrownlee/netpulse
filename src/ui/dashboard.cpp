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
#include "ui/dashboard_model.hpp"
#include "ui/focus_model.hpp"
#include "ui/labels.hpp"
#include "util/format.hpp"
#include "util/net.hpp"

namespace netpulse {

namespace {

using namespace ftxui;

constexpr auto kRefreshInterval = std::chrono::milliseconds(250);
constexpr int kLearnTextLines = 4;

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

// Every selectable row gets a two-column gutter for the ▸ cursor. The focused row is also
// marked with `focus`, which makes the surrounding yframe scroll to keep it visible.
Element selectable(Element row, bool focused) {
    // xflex: the row still spans the full width, so fillers inside it keep working.
    if (!focused) return hbox({text("  "), std::move(row) | xflex});
    return hbox({text("▸ ") | color(Color::Cyan) | bold, std::move(row) | bold | xflex}) | focus;
}

Element header(const Snapshot& s, const Pipeline& p) {
    std::string mode = "live";
    if (p.is_offline()) mode = p.finished() ? "replay finished" : "replaying file";
    if (s.dns_names) mode += " · DNS names on";
    const auto uptime = std::chrono::duration_cast<std::chrono::seconds>(s.uptime);
    return hbox({
        text(" NetPulse ") | bold | inverted,
        text("  " + p.source() + " · " + mode),
        filler(),
        text("running " + format_duration(uptime) + "   "),
        text("↑↓ pick a row · ←→ more terms · q quit ") | dim,
    });
}

// The status sentence: green when nothing stands out, amber for a heads-up. Never red: a tool
// that can't see packet contents has no business making threat judgments.
Element status_row(const Snapshot& s, const FocusModel& model) {
    const Color dot = s.status.heads_up() ? Color::Yellow : Color::Green;
    return selectable(hbox({text("● ") | color(dot), text(s.status.headline) | bold}),
                      model.is_focused(kStatusRowId));
}

Element categories(const Snapshot& s, const FocusModel& model) {
    std::uint64_t shown_bytes = 0;
    for (const auto& c : s.categories) shown_bytes += c.bytes;

    Elements rows;
    for (const auto& c : s.categories) {
        const double share = share_of(c.bytes, shown_bytes);
        rows.push_back(selectable(hbox({
                                      cell(category_label(c.category), 19),
                                      cell(method_tag(c.main_method), 25) | dim,
                                      right_cell(format_percent(share), 5),
                                      text("  "),
                                      gauge(static_cast<float>(share)) | color(Color::Cyan) |
                                          size(WIDTH, EQUAL, 20),
                                      right_cell(format_bytes(static_cast<double>(c.bytes)), 10),
                                      right_cell(format_count(c.flows) +
                                                     (c.flows == 1 ? " conversation" : " conversations"),
                                                 19),
                                  }),
                                  model.is_focused(category_row_id(c.category))));
    }
    if (s.categories.empty()) rows.push_back(text("  waiting for traffic...") | dim);
    if (s.background_bytes > 0) {
        rows.push_back(text("  Not counted: " + format_bytes(static_cast<double>(s.background_bytes)) +
                            " of background traffic (DNS, time sync, device discovery, ping).") |
                       dim);
    }
    return window(text(" Traffic by category (active conversations; a best guess, see tags) "),
                  vbox(std::move(rows)));
}

Element throughput_row(const Snapshot& s, const FocusModel& model) {
    return selectable(hbox({
                          text("Throughput  "),
                          text(format_rate(s.bytes_per_second)) | bold,
                          text("  " + format_count(static_cast<std::uint64_t>(s.packets_per_second)) +
                               " packets/s   "),
                          text(sparkline(s.byte_history)) | color(Color::Cyan),
                          text("  last 60s") | dim,
                      }),
                      model.is_focused(kThroughputRowId));
}

Element protocols(const Snapshot& s, const FocusModel& model) {
    static const Color kBarColors[] = {Color::Green, Color::Blue, Color::Yellow, Color::Magenta,
                                       Color::Red};
    Elements rows;
    auto add_row = [&](const ProtocolRowSpec& p, Color bar) {
        const TrafficCounter& c = s.*(p.counter);
        const double share = share_of(c.bytes, s.total.bytes);
        rows.push_back(selectable(hbox({
                                      cell(p.label, 12),
                                      right_cell(format_percent(share), 5),
                                      text("  "),
                                      gauge(static_cast<float>(share)) | color(bar) |
                                          size(WIDTH, EQUAL, 30),
                                      text("  "),
                                      right_cell(format_bytes(static_cast<double>(c.bytes)), 10),
                                      right_cell(format_count(c.packets) + " packets", 20),
                                  }),
                                  model.is_focused(p.id)));
    };
    std::size_t i = 0;
    for (const auto& p : protocol_rows()) add_row(p, kBarColors[i++ % 5]);
    rows.push_back(text("  The same traffic by IP version:") | dim);
    for (const auto& v : ip_version_rows()) add_row(v, Color::Cyan);
    return window(text(" Protocols (share of bytes) "), vbox(std::move(rows)));
}

Element top_talkers(const Snapshot& s, const FocusModel& model) {
    Elements rows;
    // The address column stretches: IPv6 addresses (with a name) can be long.
    rows.push_back(hbox({text("  "), text("Device / address") | flex, right_cell("Now", 11),
                         right_cell("Bytes", 10), right_cell("Of all traffic", 16),
                         cell("   Where", 12)}) | dim);
    for (const auto& h : s.top_hosts) {
        rows.push_back(selectable(hbox({
                                      text(host_label(h.ip, h.name)) | flex,
                                      right_cell(format_rate(h.current_bps), 11),
                                      right_cell(format_bytes(static_cast<double>(h.bytes)), 10),
                                      right_cell(format_percent(share_of(h.bytes, s.total.bytes)), 16),
                                      cell(h.is_local ? "   local" : "   internet", 12),
                                  }),
                                  model.is_focused(host_row_id(h.ip))));
    }
    if (s.top_hosts.empty()) {
        rows.push_back(text("  waiting for traffic...") | dim);
    } else {
        rows.push_back(text("  Each conversation counts toward both of its ends, so these can add "
                            "up to more than 100%.") | dim);
    }
    return window(text(" Top talkers (bytes sent + received) "), vbox(std::move(rows)));
}

Element top_flows(const Snapshot& s, const FocusModel& model) {
    Elements rows;
    // The conversation column stretches: an IPv6 conversation can be 70+ characters.
    rows.push_back(hbox({text("  "), cell("Proto", 7), text("Conversation") | flex,
                         cell(" Kind", 11), right_cell("Bytes", 10), right_cell("Packets", 10)}) |
                   dim);
    for (const auto& f : s.top_flows) {
        rows.push_back(selectable(hbox({
                                      cell(ip_protocol_name(f.key.protocol), 7),
                                      text(conversation_label(f, "  ⇄  ")) | flex,
                                      cell(" " + std::string(category_short_label(f.category)), 11),
                                      right_cell(format_bytes(static_cast<double>(f.stats.bytes)), 10),
                                      right_cell(format_count(f.stats.packets), 10),
                                  }),
                                  model.is_focused(flow_row_id(f.key))));
    }
    if (s.top_flows.empty()) rows.push_back(text("  waiting for traffic...") | dim);
    return window(text(" Top flows (conversations) "), vbox(std::move(rows)));
}

// The persistent explanation for whatever is focused. There is no mode to enter or leave:
// moving the cursor is all it takes.
Element learn_panel(const FocusModel& model, const Snapshot& s) {
    const std::string* term = model.focused_term();
    const auto content = term ? learn_content(*term, s) : std::nullopt;
    if (!content) {
        return window(text(" Learn "),
                      text(" Move the cursor with ↑↓ to see what anything on screen means.") | dim |
                          size(HEIGHT, EQUAL, kLearnTextLines));
    }

    std::string title = " Learn: " + content->title + " ";
    const std::size_t term_count = model.focused_row()->terms.size();
    if (term_count > 1) {
        title += "· " + std::to_string(model.term_index() + 1) + " of " +
                 std::to_string(term_count) + ", ←→ for more ";
    }
    return window(text(title) | bold,
                  hbox({text(" "), paragraph(content->text) | flex, text(" ")}) |
                      size(HEIGHT, EQUAL, kLearnTextLines));
}

Element footer(const Snapshot& s, const FocusModel& model) {
    const double missed = s.health.missed_fraction();
    return selectable(
        hbox({
            text("Missed " + format_percent(missed, 2) + " of packets") |
                color(missed > 0.01 ? Color(Color::Yellow) : Color(Color::Default)),
            text(" (" + format_count(s.health.queue_drops) + " queue, " +
                 format_count(s.health.kernel_drops) + " kernel)") | dim,
            filler(),
            text(format_count(s.active_flows) + " active flows · " + format_count(s.known_hosts) +
                 " addresses seen "),
        }),
        model.is_focused(kHealthRowId));
}

// Terminals disagree on Home/End: xterm-style sends ESC[H / ESC[F, while tmux, screen and the
// Linux console send ESC[1~ / ESC[4~. FTXUI only knows the first form.
bool is_home(const Event& e) {
    return e == Event::Home || e == Event::Special("\x1B[1~") || e == Event::Special("\x1B[7~");
}
bool is_end(const Event& e) {
    return e == Event::End || e == Event::Special("\x1B[4~") || e == Event::Special("\x1B[8~");
}

}  // namespace

void run_dashboard(Pipeline& pipeline) {
    auto screen = ScreenInteractive::Fullscreen();
    FocusModel model;  // touched only on the UI thread (render and event handling)

    auto renderer = Renderer([&] {
        const auto snapshot = pipeline.latest();
        const Snapshot& s = *snapshot;
        model.update(dashboard_focus_rows(s));
        return vbox({
            header(s, pipeline),
            separator(),
            vbox({
                status_row(s, model),
                throughput_row(s, model),
                categories(s, model),
                protocols(s, model),
                top_talkers(s, model),
                top_flows(s, model),
            }) | yframe | flex,
            learn_panel(model, s),
            footer(s, model),
        });
    });

    auto app = CatchEvent(renderer, [&](Event event) {  // by value: FTXUI's mouse() is non-const
        if (event == Event::Character('q') || event == Event::Escape) {
            screen.Exit();
            return true;
        }
        if (event == Event::ArrowUp || event == Event::Character('k')) model.move_row(-1);
        else if (event == Event::ArrowDown || event == Event::Character('j')) model.move_row(1);
        else if (event == Event::ArrowLeft || event == Event::Character('h')) model.move_term(-1);
        else if (event == Event::ArrowRight || event == Event::Character('l')) model.move_term(1);
        else if (event == Event::PageUp) model.move_row(-10);
        else if (event == Event::PageDown) model.move_row(10);
        else if (is_home(event) || event == Event::Character('g')) model.move_row(-1'000'000);
        else if (is_end(event) || event == Event::Character('G')) model.move_row(1'000'000);
        else if (event.is_mouse() && event.mouse().button == Mouse::WheelUp) model.move_row(-1);
        else if (event.is_mouse() && event.mouse().button == Mouse::WheelDown) model.move_row(1);
        else return false;
        return true;
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
