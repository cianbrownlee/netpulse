#pragma once

#include <string>

namespace netpulse {

// The one-line summary at the top of the dashboard.
//
// A deliberately small set of specific, literal "worth noticing" checks, not threat detection.
// Wording always reads as "worth noticing", never as "you are being attacked", and there is no
// red state: a tool that can't see packet contents has no business making threat judgments.
enum class StatusKind {
    Normal,
    ToolFallingBehind,   // NetPulse itself is missing packets
    DeviceAboveUsual,    // a device is far above its own average
    NewDeviceHeavy,      // a device that just appeared is taking a big share
    UnnamedDestination,  // most traffic is going to an address with no reverse-DNS name
};

// Stable identifier for scripts and tests ("normal", "device-above-usual", ...).
inline const char* status_key(StatusKind kind) {
    switch (kind) {
        case StatusKind::Normal: return "normal";
        case StatusKind::ToolFallingBehind: return "tool-falling-behind";
        case StatusKind::DeviceAboveUsual: return "device-above-usual";
        case StatusKind::NewDeviceHeavy: return "new-device-heavy";
        case StatusKind::UnnamedDestination: return "unnamed-destination";
    }
    return "?";
}

struct Status {
    StatusKind kind = StatusKind::Normal;
    std::string headline = "Everything looks normal";
    std::string explanation;  // why, with the actual numbers; shown in the Learn panel

    bool heads_up() const { return kind != StatusKind::Normal; }
};

}  // namespace netpulse
