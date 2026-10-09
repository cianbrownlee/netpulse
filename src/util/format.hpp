#pragma once

#include <chrono>
#include <cstdint>
#include <string>

namespace netpulse {

// Human-scale numbers for the UI. Decimal (SI) units, so "MB/s" means 10^6 bytes per second,
// matching how network speeds are usually quoted.
std::string format_bytes(double bytes);              // "812 B", "12.4 MB"
std::string format_rate(double bytes_per_second);    // "12.4 MB/s"
std::string format_count(std::uint64_t n);           // "1,234,567"
std::string format_duration(std::chrono::seconds d); // "45 s", "14 min", "2 h 05 min"
std::string format_percent(double fraction, int decimals = 0);  // 0.0123 -> "1%" / "1.23%"

// Replaces control and non-ASCII bytes with '?'. For text that came from the network (names
// from DNS) before it reaches the terminal: an escape sequence hidden in a hostname would
// otherwise be interpreted by the user's terminal.
std::string printable(std::string text);

}  // namespace netpulse
