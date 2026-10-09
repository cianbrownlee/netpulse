#include "aggregate/classifier.hpp"

#include <algorithm>
#include <array>
#include <cctype>

#include "util/format.hpp"
#include "util/net.hpp"

namespace netpulse {

// ---------------------------------------------------------------------------------------------
// Labels
// ---------------------------------------------------------------------------------------------

const char* category_label(Category c) {
    switch (c) {
        case Category::Streaming: return "Streaming / video";
        case Category::Browsing: return "Web browsing";
        case Category::CallsGaming: return "Calls / gaming";
        case Category::FileTransfer: return "File transfer";
        case Category::Other: return "Other";
        case Category::Background: return "Background";
    }
    return "?";
}

const char* category_short_label(Category c) {
    switch (c) {
        case Category::Streaming: return "Streaming";
        case Category::Browsing: return "Browsing";
        case Category::CallsGaming: return "Call/game";
        case Category::FileTransfer: return "Transfer";
        case Category::Other: return "Other";
        case Category::Background: return "Background";
    }
    return "?";
}

const char* category_key(Category c) {
    switch (c) {
        case Category::Streaming: return "streaming";
        case Category::Browsing: return "browsing";
        case Category::CallsGaming: return "calls-gaming";
        case Category::FileTransfer: return "file-transfer";
        case Category::Other: return "other";
        case Category::Background: return "background";
    }
    return "?";
}

const char* method_tag(ClassMethod m) {
    switch (m) {
        case ClassMethod::KnownService: return "[known-domain match]";
        case ClassMethod::FlowShape: return "[flow-shape heuristic]";
        case ClassMethod::None: return "";
    }
    return "";
}

// ---------------------------------------------------------------------------------------------
// Facts
// ---------------------------------------------------------------------------------------------

FlowEnds orient(const FlowKey& k) {
    const bool a_private = is_private(k.ip_a);
    const bool b_private = is_private(k.ip_b);
    FlowEnds e;
    if (a_private != b_private) {
        e.client_is_a = a_private;
    } else {
        e.client_is_a = k.port_a >= k.port_b;  // the server listens on the lower port
    }
    e.client_ip = e.client_is_a ? k.ip_a : k.ip_b;
    e.server_ip = e.client_is_a ? k.ip_b : k.ip_a;
    e.server_port = e.client_is_a ? k.port_b : k.port_a;
    return e;
}

FlowFacts flow_facts(const FlowKey& key, const FlowStats& stats, std::string remote_name) {
    const FlowEnds ends = orient(key);
    FlowFacts f;
    f.protocol = key.protocol;
    f.server_port = ends.server_port;
    f.bytes = stats.bytes;
    f.packets = stats.packets;
    f.bytes_to_client = ends.client_is_a ? stats.bytes_b_to_a : stats.bytes_a_to_b;
    f.bytes_from_client = ends.client_is_a ? stats.bytes_a_to_b : stats.bytes_b_to_a;
    f.seconds = stats.duration().count();
    f.duty_cycle = stats.duty_cycle();
    f.remote_name = std::move(remote_name);
    return f;
}

// ---------------------------------------------------------------------------------------------
// Known services
// ---------------------------------------------------------------------------------------------

namespace {

constexpr std::array kKnownServices = {
    KnownService{"netflix.com", Category::Streaming},
    KnownService{"nflxvideo.net", Category::Streaming},
    KnownService{"youtube.com", Category::Streaming},
    KnownService{"googlevideo.com", Category::Streaming},
    KnownService{"ytimg.com", Category::Streaming},
    KnownService{"twitch.tv", Category::Streaming},
    KnownService{"ttvnw.net", Category::Streaming},
    KnownService{"hulu.com", Category::Streaming},
    KnownService{"disneyplus.com", Category::Streaming},
    KnownService{"bamgrid.com", Category::Streaming},
    KnownService{"spotify.com", Category::Streaming},  // audio shares the streaming bucket
    KnownService{"scdn.co", Category::Streaming},
    KnownService{"zoom.us", Category::CallsGaming},
    KnownService{"discord.com", Category::CallsGaming},
    KnownService{"discord.gg", Category::CallsGaming},
    KnownService{"discordapp.com", Category::CallsGaming},
    KnownService{"steampowered.com", Category::CallsGaming},
    KnownService{"xboxlive.com", Category::CallsGaming},
    KnownService{"playstation.net", Category::CallsGaming},
    // Steam's content servers deliver game downloads and updates: bulk transfers, not play.
    KnownService{"steamcontent.com", Category::FileTransfer},
    // Much of this is background API and sync traffic rather than literal browsing.
    KnownService{"googleapis.com", Category::Browsing},
    KnownService{"gstatic.com", Category::Browsing},
};

bool is_background_port(std::uint16_t port) {
    switch (port) {
        case 53:    // DNS
        case 67:    // DHCP
        case 68:    // DHCP
        case 123:   // NTP
        case 137:   // NetBIOS name service
        case 138:   // NetBIOS datagrams
        case 853:   // DNS over TLS
        case 1900:  // SSDP (device discovery)
        case 5353:  // mDNS
        case 5355:  // LLMNR
            return true;
        default:
            return false;
    }
}

const char* background_name(const FlowFacts& f) {
    if (f.protocol == 1) return "ICMP";
    if (f.protocol == 2) return "IGMP";
    switch (f.server_port) {
        case 53: return "DNS lookups";
        case 853: return "DNS over TLS";
        case 67:
        case 68: return "DHCP address assignment";
        case 123: return "time synchronization (NTP)";
        case 137:
        case 138: return "NetBIOS name service";
        case 1900: return "SSDP device discovery";
        case 5353: return "mDNS device discovery";
        case 5355: return "LLMNR name lookups";
        default: return "housekeeping traffic";
    }
}

// Thresholds for the flow-shape rules. Starting points, meant to be tuned against real traffic.
constexpr double kMostlyOneWay = 0.85;        // one direction carries at least this share
constexpr double kBothWaysMinShare = 0.15;    // each direction carries at least this share
constexpr double kContinuousDuty = 0.85;      // traffic in at least this share of seconds
constexpr double kCallMinSeconds = 5;
constexpr double kCallSteadyDuty = 0.8;
constexpr double kCallMaxAvgPacket = 1200;    // bytes; bulk transfers fill ~1500-byte packets
constexpr std::uint64_t kTransferMinBytes = 5'000'000;
constexpr double kTransferMinSeconds = 3;
constexpr double kStreamingMinSeconds = 10;
constexpr std::uint64_t kStreamingMinBytes = 1'000'000;
constexpr std::uint64_t kBrowsingMaxBytes = 2'000'000;

double share(std::uint64_t part, std::uint64_t whole) {
    return whole == 0 ? 0.0 : static_cast<double>(part) / static_cast<double>(whole);
}

// TCP 80/443, plus UDP 443: QUIC (HTTP/3), which is how YouTube and many big sites now deliver
// most of their traffic.
bool is_web(const FlowFacts& f) {
    if (f.protocol == 6) return f.server_port == 443 || f.server_port == 80;
    if (f.protocol == 17) return f.server_port == 443;
    return false;
}

bool is_tcp_or_udp(const FlowFacts& f) { return f.protocol == 6 || f.protocol == 17; }

std::string port_label(const FlowFacts& f) {
    std::string s = "port " + std::to_string(f.server_port);
    if (f.protocol == 17 && f.server_port == 443) s += " (QUIC)";
    return s;
}

std::string duration_label(double seconds) {
    return format_duration(std::chrono::seconds(static_cast<long long>(seconds)));
}

}  // namespace

std::optional<KnownService> match_known_service(std::string_view hostname) {
    std::string host(hostname);
    std::transform(host.begin(), host.end(), host.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    if (!host.empty() && host.back() == '.') host.pop_back();  // fully-qualified form

    for (const auto& service : kKnownServices) {
        const std::string_view d = service.domain;
        if (host == d) return service;
        // Subdomains only: "notnetflix.com" must not match "netflix.com".
        if (host.size() > d.size() && host.ends_with(d) && host[host.size() - d.size() - 1] == '.') {
            return service;
        }
    }
    return std::nullopt;
}

// ---------------------------------------------------------------------------------------------
// Rules
// ---------------------------------------------------------------------------------------------

Classification classify(const FlowFacts& f) {
    if (!is_tcp_or_udp(f)) {
        // ICMP and IGMP are housekeeping. Anything else (GRE, ESP: VPN tunnels) can carry real
        // traffic NetPulse can't see into, so it's Other rather than hidden as background.
        if (f.protocol == 1 || f.protocol == 2) return {Category::Background, ClassMethod::None};
        return {Category::Other, ClassMethod::None};
    }
    if (is_background_port(f.server_port)) return {Category::Background, ClassMethod::None};

    if (!f.remote_name.empty()) {
        if (const auto service = match_known_service(f.remote_name)) {
            return {service->category, ClassMethod::KnownService};
        }
    }

    const double down = share(f.bytes_to_client, f.bytes);
    const double up = share(f.bytes_from_client, f.bytes);
    const double avg_packet = f.packets == 0 ? 0.0 : static_cast<double>(f.bytes) / f.packets;

    // Calls and games: a steady stream of modest UDP packets in both directions. Port 443 is
    // excluded because UDP there is QUIC, i.e. web traffic.
    if (f.protocol == 17 && !is_web(f) && f.seconds >= kCallMinSeconds &&
        f.duty_cycle >= kCallSteadyDuty && std::min(down, up) >= kBothWaysMinShare &&
        avg_packet <= kCallMaxAvgPacket) {
        return {Category::CallsGaming, ClassMethod::FlowShape};
    }

    // Bulk transfer: large, continuous, essentially one-way. Checked before streaming because
    // a download is the flat-out, never-pausing case.
    if (f.bytes >= kTransferMinBytes && f.seconds >= kTransferMinSeconds &&
        f.duty_cycle >= kContinuousDuty && std::max(down, up) >= kMostlyOneWay) {
        return {Category::FileTransfer, ClassMethod::FlowShape};
    }

    // Streaming: a long-lived, download-dominated web connection. Video and music players fetch
    // a few seconds ahead and then pause, so (once past the initial buffering burst, which can
    // look like a download) the flow arrives in on/off bursts rather than continuously.
    if (is_web(f) && f.seconds >= kStreamingMinSeconds && f.bytes >= kStreamingMinBytes &&
        down >= kMostlyOneWay) {
        return {Category::Streaming, ClassMethod::FlowShape};
    }

    // Browsing: small exchanges on web ports (page loads, images, API calls, keep-alives).
    if (is_web(f) && f.bytes < kBrowsingMaxBytes) {
        return {Category::Browsing, ClassMethod::FlowShape};
    }

    return {Category::Other, ClassMethod::None};
}

std::string explain(const FlowFacts& f, const Classification& c) {
    if (c.category == Category::Background) {
        return std::string("Network housekeeping (") + background_name(f) +
               "). It's real traffic, but a negligible share, so it's left out of the category "
               "breakdown.";
    }
    if (c.method == ClassMethod::KnownService) {
        const auto service = match_known_service(f.remote_name);
        return "Matched a known service: the address's name, " + f.remote_name + ", belongs to " +
               std::string(service ? service->domain : f.remote_name) +
               ", which NetPulse's built-in list files under " + category_label(c.category) + ".";
    }

    const std::string prefix = "Labeled by pattern, not certainty: ";
    const auto bytes = format_bytes(static_cast<double>(f.bytes));
    switch (c.category) {
        case Category::Streaming:
            return prefix + "one long-lived connection (" + duration_label(f.seconds) + ") on " +
                   port_label(f) + ", almost all of it downloading (" +
                   format_bytes(static_cast<double>(f.bytes_to_client)) +
                   "). Long, download-heavy web connections are usually video or music, which "
                   "players fetch a few seconds ahead at a time.";
        case Category::FileTransfer:
            return prefix + "a large (" + bytes + "), continuous transfer running almost entirely " +
                   (f.bytes_to_client >= f.bytes_from_client ? "toward this device"
                                                             : "away from this device") +
                   ", which is the usual shape of a download or upload.";
        case Category::CallsGaming: {
            const auto avg = f.packets == 0 ? 0 : f.bytes / f.packets;
            return prefix + "a steady two-way stream of small UDP packets (about " +
                   std::to_string(avg) + " bytes each) for " + duration_label(f.seconds) +
                   ". Calls and online games send small updates continuously in both directions.";
        }
        case Category::Browsing:
            return prefix + "a small exchange (" + bytes + ") on a web " + port_label(f) +
                   ", the usual shape of loading pages, images or app data.";
        case Category::Other:
        case Category::Background:
            break;
    }
    return "Didn't match a known service or a typical traffic pattern (" +
           ip_protocol_name(f.protocol) + (is_tcp_or_udp(f) ? " " + port_label(f) : std::string()) +
           ", " + bytes + " over " + duration_label(f.seconds) +
           "), so it's shown as Other rather than guessed.";
}

}  // namespace netpulse
