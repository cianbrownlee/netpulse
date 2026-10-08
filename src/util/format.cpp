#include "util/format.hpp"

#include <array>
#include <cstdio>

namespace netpulse {

std::string format_bytes(double bytes) {
    static constexpr std::array<const char*, 5> kUnits = {"B", "kB", "MB", "GB", "TB"};
    std::size_t unit = 0;
    while (bytes >= 1000.0 && unit + 1 < kUnits.size()) {
        bytes /= 1000.0;
        ++unit;
    }
    char buf[32];
    if (unit == 0) {
        std::snprintf(buf, sizeof buf, "%.0f %s", bytes, kUnits[unit]);
    } else {
        // Three significant digits reads cleanly at every magnitude: 1.23, 12.3, 123.
        std::snprintf(buf, sizeof buf, bytes < 100.0 ? "%.1f %s" : "%.0f %s", bytes, kUnits[unit]);
    }
    return buf;
}

std::string format_rate(double bytes_per_second) { return format_bytes(bytes_per_second) + "/s"; }

std::string format_count(std::uint64_t n) {
    std::string digits = std::to_string(n);
    std::string out;
    out.reserve(digits.size() + digits.size() / 3);
    const std::size_t lead = digits.size() % 3;
    for (std::size_t i = 0; i < digits.size(); ++i) {
        if (i != 0 && i >= lead && (i - lead) % 3 == 0) out += ',';
        out += digits[i];
    }
    return out;
}

std::string format_duration(std::chrono::seconds d) {
    const auto total = d.count() < 0 ? 0 : d.count();
    char buf[32];
    if (total < 60) {
        std::snprintf(buf, sizeof buf, "%lld s", static_cast<long long>(total));
    } else if (total < 3600) {
        std::snprintf(buf, sizeof buf, "%lld min", static_cast<long long>(total / 60));
    } else {
        std::snprintf(buf, sizeof buf, "%lld h %02lld min", static_cast<long long>(total / 3600),
                      static_cast<long long>((total % 3600) / 60));
    }
    return buf;
}

std::string format_percent(double fraction, int decimals) {
    char buf[32];
    std::snprintf(buf, sizeof buf, "%.*f%%", decimals, fraction * 100.0);
    return buf;
}

}  // namespace netpulse
