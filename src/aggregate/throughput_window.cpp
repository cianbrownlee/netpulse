#include "aggregate/throughput_window.hpp"

#include <algorithm>

namespace netpulse {

ThroughputWindow::ThroughputWindow(std::size_t window_seconds)
    : window_seconds_(std::max<std::size_t>(window_seconds, 1)), ring_(window_seconds_ + 1) {}

std::int64_t ThroughputWindow::second_of(Clock::time_point t) const {
    return std::chrono::duration_cast<std::chrono::seconds>(t - origin_).count();
}

void ThroughputWindow::advance_to(Clock::time_point now) {
    if (!started_) {
        started_ = true;
        origin_ = now;
        current_second_ = 0;
        return;
    }
    const std::int64_t target = second_of(now);
    if (target <= current_second_) return;

    // Clear every bucket we step into; after a long idle gap that is the whole ring.
    const auto ring_size = static_cast<std::int64_t>(ring_.size());
    const std::int64_t steps = std::min(target - current_second_, ring_size);
    for (std::int64_t s = target - steps + 1; s <= target; ++s) {
        ring_[static_cast<std::size_t>(s % ring_size)] = Bucket{};
    }
    current_second_ = target;
}

void ThroughputWindow::add(Clock::time_point t, std::uint64_t bytes) {
    advance_to(t);
    const std::int64_t s = second_of(t);
    // Packets can arrive slightly out of order (stamped on the capture thread, counted later).
    // Credit them to their own second if it is still inside the window; otherwise drop them
    // from the rate (they are still counted in the cumulative totals elsewhere).
    if (s < 0 || current_second_ - s >= static_cast<std::int64_t>(ring_.size())) return;
    auto& bucket = ring_[static_cast<std::size_t>(s % static_cast<std::int64_t>(ring_.size()))];
    bucket.bytes += bytes;
    bucket.packets += 1;
}

const ThroughputWindow::Bucket* ThroughputWindow::bucket_for(std::int64_t second) const {
    if (!started_ || second < 0 || second >= current_second_) return nullptr;  // not complete
    if (current_second_ - second > static_cast<std::int64_t>(window_seconds_)) return nullptr;
    return &ring_[static_cast<std::size_t>(second % static_cast<std::int64_t>(ring_.size()))];
}

double ThroughputWindow::bytes_per_second() const {
    const Bucket* b = bucket_for(current_second_ - 1);
    return b ? static_cast<double>(b->bytes) : 0.0;
}

double ThroughputWindow::packets_per_second() const {
    const Bucket* b = bucket_for(current_second_ - 1);
    return b ? static_cast<double>(b->packets) : 0.0;
}

std::vector<std::uint64_t> ThroughputWindow::byte_history() const {
    std::vector<std::uint64_t> history;
    history.reserve(window_seconds_);
    const auto window = static_cast<std::int64_t>(window_seconds_);
    for (std::int64_t s = current_second_ - window; s < current_second_; ++s) {
        const Bucket* b = bucket_for(s);
        history.push_back(b ? b->bytes : 0);
    }
    return history;
}

}  // namespace netpulse
