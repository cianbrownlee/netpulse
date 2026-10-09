#pragma once

#include <algorithm>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <mutex>
#include <optional>
#include <utility>
#include <vector>

namespace netpulse {

// Fixed-capacity, thread-safe FIFO between two pipeline stages.
//
// The producer picks its overflow policy per call:
//   try_push() never blocks and counts a drop when full. Live capture uses this: stalling the
//              capture thread would just move the loss into the kernel buffer, where it is
//              harder to see. Dropped-and-counted beats blocked-and-silent.
//   push()     waits for space. Offline file replay uses this: there is no kernel buffer to
//              overflow, so there is no reason to lose anything.
//
// Bounded on purpose: an unbounded queue under sustained overload only postpones an
// out-of-memory crash instead of preventing it.
//
// Storage is a ring of slots allocated once, up front, so pushing and popping never touch the
// heap. T must be default-constructible and move-assignable.
template <typename T>
class BoundedQueue {
public:
    explicit BoundedQueue(std::size_t capacity) : slots_(std::max<std::size_t>(capacity, 1)) {}

    BoundedQueue(const BoundedQueue&) = delete;
    BoundedQueue& operator=(const BoundedQueue&) = delete;

    // Returns false if the item was not queued: full (counted as a drop) or closed (not counted).
    bool try_push(T item) {
        {
            std::lock_guard lock(mutex_);
            if (closed_) return false;
            if (count_ == slots_.size()) {
                ++dropped_;
                return false;
            }
            put(std::move(item));
        }
        not_empty_.notify_one();
        return true;
    }

    // Blocks while full. Returns false only if the queue was closed.
    bool push(T item) {
        {
            std::unique_lock lock(mutex_);
            not_full_.wait(lock, [&] { return closed_ || count_ < slots_.size(); });
            if (closed_) return false;
            put(std::move(item));
        }
        not_empty_.notify_one();
        return true;
    }

    // Batch versions of the above: one lock and one wake-up for a whole batch instead of one
    // per item. Under load that's the difference between threads waking each other hundreds
    // of thousands of times a second and a few thousand. `items` is left empty either way.

    // Queues as many as fit; the rest are dropped and counted. Returns how many were queued.
    std::size_t try_push_batch(std::vector<T>& items) {
        std::size_t queued = 0;
        {
            std::lock_guard lock(mutex_);
            if (!closed_) {
                queued = std::min(items.size(), slots_.size() - count_);
                for (std::size_t i = 0; i < queued; ++i) put(std::move(items[i]));
                dropped_ += items.size() - queued;
            }
        }
        items.clear();
        if (queued > 0) not_empty_.notify_one();
        return queued;
    }

    // Queues everything, waiting for space as needed. Returns false if the queue was closed
    // before all of it fit.
    bool push_batch(std::vector<T>& items) {
        std::size_t next = 0;
        while (next < items.size()) {
            {
                std::unique_lock lock(mutex_);
                not_full_.wait(lock, [&] { return closed_ || count_ < slots_.size(); });
                if (closed_) break;
                const std::size_t n = std::min(items.size() - next, slots_.size() - count_);
                for (std::size_t i = 0; i < n; ++i) put(std::move(items[next + i]));
                next += n;
            }
            not_empty_.notify_one();
        }
        const bool all = next == items.size();
        items.clear();
        return all;
    }

    // Waits up to `timeout` for at least one item, then takes up to `max` of them into `out`
    // (replacing its contents). Returns how many were taken; 0 means timeout, or closed and
    // drained.
    template <typename Rep, typename Period>
    std::size_t pop_batch(std::vector<T>& out, std::size_t max,
                          std::chrono::duration<Rep, Period> timeout) {
        out.clear();
        {
            std::unique_lock lock(mutex_);
            not_empty_.wait_for(lock, timeout, [&] { return closed_ || count_ > 0; });
            const std::size_t n = std::min(max, count_);
            for (std::size_t i = 0; i < n; ++i) {
                out.push_back(std::move(slots_[head_]));
                head_ = (head_ + 1) % slots_.size();
            }
            count_ -= n;
        }
        if (!out.empty()) not_full_.notify_all();
        return out.size();
    }

    // Waits up to `timeout` for an item. Returns nullopt on timeout, or when the queue is
    // closed and fully drained (check drained() to tell the two apart).
    template <typename Rep, typename Period>
    std::optional<T> pop_for(std::chrono::duration<Rep, Period> timeout) {
        std::optional<T> item;
        {
            std::unique_lock lock(mutex_);
            not_empty_.wait_for(lock, timeout, [&] { return closed_ || count_ > 0; });
            if (count_ == 0) return std::nullopt;
            item.emplace(std::move(slots_[head_]));
            head_ = (head_ + 1) % slots_.size();
            --count_;
        }
        not_full_.notify_one();
        return item;
    }

    // Rejects further pushes and wakes every waiter. Items already queued can still be popped.
    void close() {
        {
            std::lock_guard lock(mutex_);
            closed_ = true;
        }
        not_empty_.notify_all();
        not_full_.notify_all();
    }

    bool closed() const {
        std::lock_guard lock(mutex_);
        return closed_;
    }

    bool drained() const {
        std::lock_guard lock(mutex_);
        return closed_ && count_ == 0;
    }

    std::size_t size() const {
        std::lock_guard lock(mutex_);
        return count_;
    }

    std::uint64_t dropped() const {
        std::lock_guard lock(mutex_);
        return dropped_;
    }

    std::size_t capacity() const { return slots_.size(); }

private:
    // Caller holds mutex_ and has checked there is room.
    void put(T&& item) {
        slots_[(head_ + count_) % slots_.size()] = std::move(item);
        ++count_;
    }

    mutable std::mutex mutex_;
    std::condition_variable not_empty_;
    std::condition_variable not_full_;
    std::vector<T> slots_;
    std::size_t head_ = 0;   // oldest item
    std::size_t count_ = 0;  // items currently queued
    std::uint64_t dropped_ = 0;
    bool closed_ = false;
};

}  // namespace netpulse
