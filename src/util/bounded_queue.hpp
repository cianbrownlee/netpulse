#pragma once

#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <mutex>
#include <optional>
#include <utility>

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
template <typename T>
class BoundedQueue {
public:
    explicit BoundedQueue(std::size_t capacity) : capacity_(capacity) {}

    BoundedQueue(const BoundedQueue&) = delete;
    BoundedQueue& operator=(const BoundedQueue&) = delete;

    // Returns false if the item was not queued: full (counted as a drop) or closed (not counted).
    bool try_push(T item) {
        {
            std::lock_guard lock(mutex_);
            if (closed_) return false;
            if (items_.size() >= capacity_) {
                ++dropped_;
                return false;
            }
            items_.push_back(std::move(item));
        }
        not_empty_.notify_one();
        return true;
    }

    // Blocks while full. Returns false only if the queue was closed.
    bool push(T item) {
        {
            std::unique_lock lock(mutex_);
            not_full_.wait(lock, [&] { return closed_ || items_.size() < capacity_; });
            if (closed_) return false;
            items_.push_back(std::move(item));
        }
        not_empty_.notify_one();
        return true;
    }

    // Waits up to `timeout` for an item. Returns nullopt on timeout, or when the queue is
    // closed and fully drained (check drained() to tell the two apart).
    template <typename Rep, typename Period>
    std::optional<T> pop_for(std::chrono::duration<Rep, Period> timeout) {
        std::optional<T> item;
        {
            std::unique_lock lock(mutex_);
            not_empty_.wait_for(lock, timeout, [&] { return closed_ || !items_.empty(); });
            if (items_.empty()) return std::nullopt;
            item.emplace(std::move(items_.front()));
            items_.pop_front();
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
        return closed_ && items_.empty();
    }

    std::size_t size() const {
        std::lock_guard lock(mutex_);
        return items_.size();
    }

    std::uint64_t dropped() const {
        std::lock_guard lock(mutex_);
        return dropped_;
    }

    std::size_t capacity() const { return capacity_; }

private:
    const std::size_t capacity_;
    mutable std::mutex mutex_;
    std::condition_variable not_empty_;
    std::condition_variable not_full_;
    std::deque<T> items_;
    std::uint64_t dropped_ = 0;
    bool closed_ = false;
};

}  // namespace netpulse
