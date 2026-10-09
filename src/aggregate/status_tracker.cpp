#include "aggregate/status_tracker.hpp"

#include <cmath>
#include <string>
#include <utility>

#include "aggregate/classifier.hpp"
#include "util/format.hpp"
#include "util/net.hpp"

namespace netpulse {

namespace {

constexpr const char* kNormalExplanation =
    "None of NetPulse's \"worth noticing\" checks is true right now: no device is far above its "
    "usual rate, no newly appeared device is taking most of the traffic, no address without a "
    "name is taking most of it, and capture is keeping up. These are a few simple, specific "
    "checks, not a security scan.";

std::string device_label(const HostRow& h) {
    return h.name.empty() ? h.ip.to_string() : h.name + " (" + h.ip.to_string() + ")";
}

std::string seconds_label(Clock::duration d) {
    return format_duration(std::chrono::duration_cast<std::chrono::seconds>(d));
}

Status heads_up(StatusKind kind, std::string headline, std::string explanation) {
    Status s;
    s.kind = kind;
    s.headline = std::move(headline);
    s.explanation = std::move(explanation);
    return s;
}

}  // namespace

StatusTracker::StatusTracker(StatusThresholds thresholds, LocalNetworks local)
    : t_(thresholds), local_(std::move(local)) {
    shown_.explanation = kNormalExplanation;
}

Status StatusTracker::update(const Snapshot& s) {
    Status candidate = evaluate(s);

    if (candidate.heads_up()) {
        shown_ = std::move(candidate);
        last_true_ = s.uptime;
    } else if (shown_.heads_up() && s.uptime - last_true_ < t_.hold) {
        // Keep the message up a little longer; see StatusThresholds::hold.
    } else {
        shown_ = std::move(candidate);
    }
    return shown_;
}

Status StatusTracker::evaluate(const Snapshot& s) {
    // Health is checked unconditionally so its sliding window keeps sampling every update.
    auto health = check_capture_health(s);
    if (health) return *health;
    if (auto st = check_device_above_usual(s)) return *st;
    if (auto st = check_new_device(s)) return *st;
    if (auto st = check_unnamed_destination(s)) return *st;

    Status normal;
    normal.explanation = kNormalExplanation;
    return normal;
}

std::optional<Status> StatusTracker::check_capture_health(const Snapshot& s) {
    const CaptureHealth& h = s.health;
    health_.push_back({s.uptime, h.captured + h.kernel_drops, h.missed(), h.queue_drops,
                       h.kernel_drops});
    // Keep exactly one sample at or before the start of the window as the baseline.
    while (health_.size() > 2 && s.uptime - health_[1].at >= t_.drop_window) health_.pop_front();

    const HealthSample& from = health_.front();
    const HealthSample& to = health_.back();
    const std::uint64_t seen = to.seen - from.seen;
    if (seen < t_.drop_min_packets) return std::nullopt;
    const double fraction =
        static_cast<double>(to.missed - from.missed) / static_cast<double>(seen);
    if (fraction <= t_.drop_fraction) return std::nullopt;

    return heads_up(
        StatusKind::ToolFallingBehind, "Note — this tool is having trouble keeping up with traffic right now.",
        "NetPulse missed " + format_percent(fraction, 1) + " of packets over the last few seconds (" +
            format_count(to.queue_drops - from.queue_drops) + " in its own queue, " +
            format_count(to.kernel_drops - from.kernel_drops) +
            " in the kernel's capture buffer), so the numbers on screen are running a little "
            "behind reality. This is about the tool, not your network.");
}

std::optional<Status> StatusTracker::check_device_above_usual(const Snapshot& s) const {
    if (s.uptime < t_.warm_up) return std::nullopt;
    for (const HostRow& h : s.rate_leaders) {
        if (!local_.is_device(h.ip)) continue;  // "devices" are on your side of the network
        if (h.seen_for < t_.warm_up) continue;
        if (h.current_bps < t_.min_rate_bps) continue;
        if (h.current_bps < t_.above_usual_factor * h.average_bps) continue;

        const double factor = h.average_bps > 0 ? h.current_bps / h.average_bps : 0.0;
        return heads_up(
            StatusKind::DeviceAboveUsual,
            "Heads up — " + device_label(h) + " is using a lot more data than usual.",
            device_label(h) + " is moving " + format_rate(h.current_bps) + " right now, about " +
                std::to_string(static_cast<int>(std::lround(factor))) + "x its average of " +
                format_rate(h.average_bps) + " since NetPulse first saw it " + seconds_label(h.seen_for) +
                " ago. That's a comparison with its own history, nothing more: it often just "
                "means a download, an update or a video started.");
    }
    return std::nullopt;
}

std::optional<Status> StatusTracker::check_new_device(const Snapshot& s) const {
    if (s.current_bps < t_.min_rate_bps) return std::nullopt;
    for (const HostRow& h : s.rate_leaders) {
        if (!local_.is_device(h.ip)) continue;
        if (h.seen_for > t_.new_device_window) continue;
        // Only devices that arrived after the warm-up: at the start of a session everything is
        // "new" to NetPulse, which says nothing about the network.
        if (s.uptime - h.seen_for < t_.warm_up) continue;
        const double share = h.current_bps / s.current_bps;
        if (share <= t_.new_device_share) continue;

        return heads_up(
            StatusKind::NewDeviceHeavy,
            "Heads up — a new device (" + device_label(h) + ") just started using a lot of data.",
            device_label(h) + " first showed up " + seconds_label(h.seen_for) + " ago and is already " +
                format_percent(share) + " of all traffic (" + format_rate(h.current_bps) +
                "). Often that's just a phone, console or laptop that joined the network and "
                "started syncing or updating.");
    }
    return std::nullopt;
}

std::optional<Status> StatusTracker::check_unnamed_destination(const Snapshot& s) const {
    if (!s.busiest_flow || s.current_bps < t_.min_rate_bps) return std::nullopt;
    const FlowRow& f = *s.busiest_flow;
    const FlowEnds ends = orient(f.key, local_);
    const bool remote_is_a = !ends.client_is_a;
    const NameState remote_state = remote_is_a ? f.name_state_a : f.name_state_b;

    // Only a finished lookup that found nothing counts; "still looking it up" is not "no name".
    if (remote_state != NameState::NoName) return std::nullopt;
    if (local_.is_local(ends.server_ip)) return std::nullopt;  // unnamed LAN devices are normal
    if (f.stats.duration() < t_.unnamed_min_duration) return std::nullopt;
    const double share = f.stats.current_bps / s.current_bps;
    if (share <= t_.unnamed_share) return std::nullopt;

    return heads_up(
        StatusKind::UnnamedDestination,
        "Worth noticing — most of your traffic right now is going to an address without a known name.",
        format_percent(share) + " of traffic right now (" + format_rate(f.stats.current_bps) +
            ") is one conversation with " + ends.server_ip.to_string() +
            ", and a reverse-DNS lookup found no name for that address. Plenty of legitimate "
            "services (many content delivery networks, for example) don't publish names, so "
            "this is worth a look, not a warning.");
}

}  // namespace netpulse
