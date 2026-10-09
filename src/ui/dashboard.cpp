#include "ui/dashboard.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <optional>
#include <string>
#include <thread>

#include <ftxui/component/component.hpp>
#include <ftxui/component/screen_interactive.hpp>
#include <ftxui/dom/elements.hpp>
#include <ftxui/screen/terminal.hpp>

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
// A selectable row inside a window: two border columns plus the two-column cursor gutter.
constexpr int kRowChrome = 4;
constexpr const char* kArrow = "  ⇄  ";

// What the person looking at the dashboard has chosen, as opposed to what the traffic is.
struct View {
    int width = 120;                    // terminal columns
    std::optional<IpAddress> device;    // a top talker picked with Enter: list its conversations
    bool paused = false;
    bool help = false;
};

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

std::size_t columns(int width) { return static_cast<std::size_t>(std::max(width, 1)); }

// A dim side note under a section, wrapped (with its indent) on narrow terminals.
Element note(const std::string& s) { return hbox({text("  "), paragraph(s) | xflex}) | dim; }

// Every selectable row gets a two-column gutter for the ▸ cursor. The focused row is also
// marked with `focus`, which makes the surrounding yframe scroll to keep it visible.
Element selectable(Element row, bool focused) {
    // xflex: the row still spans the full width, so fillers inside it keep working.
    if (!focused) return hbox({text("  "), std::move(row) | xflex});
    return hbox({text("▸ ") | color(Color::Cyan) | bold, std::move(row) | bold | xflex}) | focus;
}

// The key that does something useful right where the cursor is, so it never has to be
// remembered from the help screen.
std::string context_hint(const Snapshot& s, const FocusModel& model, const View& view) {
    if (view.paused) return "space: resume";
    if (view.device) return "Esc: all conversations";
    if (const FocusRow* row = model.focused_row(); row && host_for_row(s, row->id)) {
        return "Enter: its conversations";
    }
    return "↑↓ move · ←→ more terms";
}

Element header(const Snapshot& s, const Pipeline& p, const FocusModel& model, const View& view) {
    std::string mode = "live";
    if (p.is_offline()) mode = p.finished() ? "replay finished" : "replaying file";
    if (p.is_demo()) mode = "simulated traffic";
    std::string source = "  " + p.source() + " · " + mode + (s.dns_names ? " · DNS names on" : "");
    std::string running =
        "running " + format_duration(std::chrono::duration_cast<std::chrono::seconds>(s.uptime)) + "   ";
    const std::string context = context_hint(s, model, view);
    std::string hint = context + " · ? help · q quit ";
    const std::string paused = view.paused ? " PAUSED " : "";

    // Narrow terminal: drop the least useful pieces first. A hint about the row under the
    // cursor outlasts the generic one, and both outlast the source's full name.
    auto total = [&] {
        return 10 + display_width(paused) + display_width(source) + display_width(running) +
               display_width(hint);
    };
    const auto width = columns(view.width);
    if (total() > width) running.clear();
    if (total() > width && context.starts_with("↑↓")) hint = "? help · q quit ";
    if (total() > width) source = "  " + p.source() + " · " + mode;
    if (total() > width) {
        const std::size_t used = total() - display_width(source);
        source = used + 2 < width ? "  " + elide_front(p.source(), width - used - 2) : "";
    }
    if (total() > width) hint = "? help ";

    return hbox({
        text(" NetPulse ") | bold | inverted,
        view.paused ? text(paused) | bold | inverted | color(Color::Yellow) : text(""),
        text(source),
        filler(),
        text(running),
        text(hint) | dim,
    });
}

// The status sentence: green when nothing stands out, amber for a heads-up. Never red: a tool
// that can't see packet contents has no business making threat judgments.
Element status_row(const Snapshot& s, const FocusModel& model) {
    const Color dot = s.status.heads_up() ? Color::Yellow : Color::Green;
    return selectable(hbox({text("● ") | color(dot), paragraph(s.status.headline) | bold | xflex}),
                      model.is_focused(kStatusRowId));
}

std::string short_method_tag(ClassMethod m) {
    switch (m) {
        case ClassMethod::KnownService: return "[known]";
        case ClassMethod::FlowShape: return "[pattern]";
        case ClassMethod::None: break;
    }
    return "";
}

Element categories(const Snapshot& s, const FocusModel& model, const View& view) {
    std::uint64_t shown_bytes = 0;
    for (const auto& c : s.categories) shown_bytes += c.bytes;

    // Columns: label 19, method tag, share 5, gap 2, gauge, bytes 10, conversations.
    const int inner = view.width - kRowChrome;
    const bool wide = inner >= 100;
    const int flows_width = wide ? 19 : 9;
    int tag_width = 25;
    if (inner < 19 + tag_width + 5 + 2 + 6 + 10 + flows_width) tag_width = 11;
    const int gauge_width = std::clamp(inner - (19 + tag_width + 5 + 2 + 10 + flows_width), 6, 30);

    Elements rows;
    for (const auto& c : s.categories) {
        const double share = share_of(c.bytes, shown_bytes);
        const std::string tag = tag_width == 25 ? method_tag(c.main_method) : short_method_tag(c.main_method);
        const std::string flows =
            wide ? format_count(c.flows) + (c.flows == 1 ? " conversation" : " conversations")
                 : format_count(c.flows) + (c.flows == 1 ? " flow" : " flows");
        rows.push_back(selectable(hbox({
                                      cell(category_label(c.category), 19),
                                      cell(tag, tag_width) | dim,
                                      right_cell(format_percent(share), 5),
                                      text("  "),
                                      gauge(static_cast<float>(share)) | color(Color::Cyan) |
                                          size(WIDTH, EQUAL, gauge_width),
                                      right_cell(format_bytes(static_cast<double>(c.bytes)), 10),
                                      right_cell(flows, flows_width),
                                  }),
                                  model.is_focused(category_row_id(c.category))));
    }
    if (s.categories.empty()) rows.push_back(text("  waiting for traffic...") | dim);
    if (s.background_bytes > 0) {
        rows.push_back(note("Not counted: " + format_bytes(static_cast<double>(s.background_bytes)) +
                            " of background traffic (DNS, time sync, device discovery, ping)."));
    }
    return window(text(" Traffic by category (active conversations; a best guess, see tags) "),
                  vbox(std::move(rows)));
}

Element throughput_row(const Snapshot& s, const FocusModel& model, const View& view) {
    const std::string rate = format_rate(s.bytes_per_second);
    const std::string packets =
        "  " + format_count(static_cast<std::uint64_t>(s.packets_per_second)) + " packets/s   ";
    // As many seconds of history as fit, newest last.
    const int fixed = 2 + 12 + static_cast<int>(display_width(rate) + display_width(packets)) + 11;
    const auto seconds = static_cast<std::size_t>(std::clamp(view.width - fixed, 10, 60));
    const auto& history = s.byte_history;
    const std::vector<std::uint64_t> recent(
        history.end() - static_cast<std::ptrdiff_t>(std::min(seconds, history.size())), history.end());
    return selectable(hbox({
                          text("Throughput  "),
                          text(rate) | bold,
                          text(packets),
                          text(sparkline(recent)) | color(Color::Cyan),
                          text("  last " + std::to_string(recent.size()) + "s") | dim,
                      }),
                      model.is_focused(kThroughputRowId));
}

Element protocols(const Snapshot& s, const FocusModel& model, const View& view) {
    static const Color kBarColors[] = {Color::Green, Color::Blue, Color::Yellow, Color::Magenta,
                                       Color::Red};
    const int gauge_width = std::clamp(view.width - kRowChrome - (12 + 5 + 2 + 2 + 10 + 20), 8, 30);
    Elements rows;
    auto add_row = [&](const ProtocolRowSpec& p, Color bar) {
        const TrafficCounter& c = s.*(p.counter);
        const double share = share_of(c.bytes, s.total.bytes);
        rows.push_back(selectable(hbox({
                                      cell(p.label, 12),
                                      right_cell(format_percent(share), 5),
                                      text("  "),
                                      gauge(static_cast<float>(share)) | color(bar) |
                                          size(WIDTH, EQUAL, gauge_width),
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

Element top_talkers(const Snapshot& s, const FocusModel& model, const View& view) {
    const bool wide = view.width - kRowChrome >= 100;
    const int share_width = wide ? 16 : 7;
    // The address column takes whatever the fixed columns leave.
    const int name_width = view.width - kRowChrome - (11 + 10 + share_width + 12);

    // If any row's name and address don't fit together, every row goes compact, so the list
    // doesn't mix styles.
    const bool compact = std::any_of(s.top_hosts.begin(), s.top_hosts.end(), [&](const HostRow& h) {
        return display_width(host_label(h.ip, h.name)) > columns(name_width);
    });

    Elements rows;
    rows.push_back(hbox({text("  "), text("Device / address") | flex, right_cell("Now", 11),
                         right_cell("Bytes", 10), right_cell(wide ? "Of all traffic" : "Share", share_width),
                         cell("   Where", 12)}) | dim);
    for (const auto& h : s.top_hosts) {
        const std::string name =
            compact ? compact_host_label(h.ip, h.name, columns(name_width)) : host_label(h.ip, h.name);
        Element label = text(name) | flex;
        if (view.device == h.ip) label = label | color(Color::Cyan);  // the picked device
        rows.push_back(selectable(hbox({
                                      label,
                                      right_cell(format_rate(h.current_bps), 11),
                                      right_cell(format_bytes(static_cast<double>(h.bytes)), 10),
                                      right_cell(format_percent(share_of(h.bytes, s.total.bytes)),
                                                 share_width),
                                      cell(h.is_local ? "   local" : "   internet", 12),
                                  }),
                                  model.is_focused(host_row_id(h.ip))));
    }
    if (s.top_hosts.empty()) {
        rows.push_back(text("  waiting for traffic...") | dim);
    } else {
        rows.push_back(note("Each conversation counts toward both of its ends, so these can add up to "
                            "more than 100%."));
    }
    return window(text(" Top talkers (bytes sent + received) "), vbox(std::move(rows)));
}

Element top_flows(const Snapshot& s, const FocusModel& model, const View& view) {
    const int conversation_width = view.width - kRowChrome - (7 + 11 + 10 + 10) - 1;

    std::string title = " Top flows (conversations) ";
    const HostRow* device = view.device ? find_top_host(s, *view.device) : nullptr;
    if (view.device) {
        const std::string who = device ? host_label(device->ip, device->name) : view.device->to_string();
        title = " Conversations of " + elide_front(who, columns(view.width - 40)) + " · Esc for all ";
    }

    const std::vector<FlowRow>& flows = shown_flows(s, view.device);
    const IpAddress* first = view.device ? &*view.device : nullptr;  // the picked device leads
    const bool compact = std::any_of(flows.begin(), flows.end(), [&](const FlowRow& f) {
        return display_width(conversation_label(f, kArrow)) > columns(conversation_width);
    });

    Elements rows;
    rows.push_back(hbox({text("  "), cell("Proto", 7), text("Conversation") | flex,
                         cell(" Kind", 11), right_cell("Bytes", 10), right_cell("Packets", 10),
                         text(" ")}) |
                   dim);
    for (const auto& f : flows) {
        const std::string label = compact
                                      ? compact_conversation_label(f, kArrow, columns(conversation_width), first)
                                      : conversation_label(f, kArrow, first);
        rows.push_back(selectable(hbox({
                                      cell(ip_protocol_name(f.key.protocol), 7),
                                      text(label) | flex,
                                      cell(" " + std::string(category_short_label(f.category)), 11),
                                      right_cell(format_bytes(static_cast<double>(f.stats.bytes)), 10),
                                      right_cell(format_count(f.stats.packets), 10),
                                      text(" "),
                                  }),
                                  model.is_focused(flow_row_id(f.key))));
    }
    if (view.device && !device) {
        rows.push_back(note(view.device->to_string() +
                            " is no longer among the top talkers. Press Esc to see all conversations."));
    } else if (flows.empty()) {
        rows.push_back(text("  waiting for traffic...") | dim);
    }
    return window(text(title) | (view.device ? bold : nothing), vbox(std::move(rows)));
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

Element footer(const Snapshot& s, const FocusModel& model, const View& view) {
    const double missed = s.health.missed_fraction();
    const bool wide = view.width >= 100;
    const std::string counts =
        wide ? format_count(s.active_flows) + " active flows · " + format_count(s.known_hosts) + " addresses seen "
             : format_count(s.active_flows) + " flows · " + format_count(s.known_hosts) + " addresses ";
    return selectable(
        hbox({
            text("Missed " + format_percent(missed, 2) + " of packets") |
                color(missed > 0.01 ? Color(Color::Yellow) : Color(Color::Default)),
            wide ? text(" (" + format_count(s.health.queue_drops) + " queue, " +
                        format_count(s.health.kernel_drops) + " kernel)") | dim
                 : text(""),
            filler(),
            text(counts),
        }),
        model.is_focused(kHealthRowId));
}

Element help_overlay() {
    auto key = [](const std::string& keys, const std::string& what) {
        return hbox({text("  "), text(keys) | bold | size(WIDTH, EQUAL, 16), paragraph(what) | xflex});
    };
    return window(text(" Help ") | bold,
                  vbox({
                      key("↑ ↓   j k", "move between rows (the mouse wheel works too)"),
                      key("← →   h l", "step through the terms on a row"),
                      key("PgUp PgDn", "move 10 rows"),
                      key("Home End  g G", "first or last row"),
                      key("Enter", "on a top talker: list only its conversations"),
                      key("Esc", "back to all conversations; closes this help"),
                      key("Space", "pause the display (capture keeps running)"),
                      key("?", "show or hide this help"),
                      key("q", "quit"),
                      separator(),
                      hbox({text("  "),
                            paragraph("Everything on screen can explain itself: put the cursor on a row and "
                                      "read the Learn panel at the bottom. When its title says \"1 of 3\", "
                                      "← and → show the rest.") |
                                xflex,
                            text("  ")}),
                  })) |
           size(WIDTH, LESS_THAN, 76) | clear_under | center;
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
    // Touched only on the UI thread (render and event handling).
    FocusModel model;
    View view;
    std::shared_ptr<const Snapshot> shown;  // what's on screen; held still while paused

    auto renderer = Renderer([&] {
        if (!view.paused || !shown) shown = pipeline.latest();
        const Snapshot& s = *shown;
        view.width = Terminal::Size().dimx;
        model.update(dashboard_focus_rows(s, view.device));
        Element main = vbox({
            header(s, pipeline, model, view),
            separator(),
            vbox({
                status_row(s, model),
                throughput_row(s, model, view),
                categories(s, model, view),
                protocols(s, model, view),
                top_talkers(s, model, view),
                top_flows(s, model, view),
            }) | yframe | flex,
            learn_panel(model, s),
            footer(s, model, view),
        });
        if (!view.help) return main;
        return dbox({std::move(main), help_overlay()});
    });

    auto app = CatchEvent(renderer, [&](Event event) {  // by value: FTXUI's mouse() is non-const
        if (event == Event::Character('q')) {
            screen.Exit();
            return true;
        }
        if (event == Event::Character('?')) {
            view.help = !view.help;
            return true;
        }
        if (event == Event::Escape) {
            // Back out one level at a time: help, then the per-device view, then quit.
            if (view.help) view.help = false;
            else if (view.device) view.device.reset();
            else screen.Exit();
            return true;
        }
        if (view.help) {
            if (event == Event::Return) view.help = false;
            return !event.is_mouse();  // the help screen swallows keys; Custom (refresh) passes
        }
        if (event == Event::Character(' ')) {
            view.paused = !view.paused;
            return true;
        }
        if (event == Event::Return) {
            if (const FocusRow* row = model.focused_row(); row && shown) {
                if (const HostRow* host = host_for_row(*shown, row->id)) {
                    // Enter on the device already shown goes back to everything.
                    if (view.device == host->ip) view.device.reset();
                    else view.device = host->ip;
                }
            }
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
