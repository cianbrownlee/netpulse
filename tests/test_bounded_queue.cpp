#include <atomic>
#include <catch2/catch_test_macros.hpp>
#include <chrono>
#include <thread>
#include <vector>

#include "util/bounded_queue.hpp"

using netpulse::BoundedQueue;
using namespace std::chrono_literals;

TEST_CASE("try_push drops and counts once the queue is full", "[queue]") {
    BoundedQueue<int> q(3);
    CHECK(q.try_push(1));
    CHECK(q.try_push(2));
    CHECK(q.try_push(3));
    CHECK_FALSE(q.try_push(4));
    CHECK_FALSE(q.try_push(5));
    CHECK(q.dropped() == 2);
    CHECK(q.size() == 3);
}

TEST_CASE("items come out in FIFO order", "[queue]") {
    BoundedQueue<int> q(8);
    for (int i = 0; i < 5; ++i) q.try_push(i);
    for (int i = 0; i < 5; ++i) CHECK(q.pop_for(0ms) == i);
    CHECK_FALSE(q.pop_for(0ms).has_value());
}

TEST_CASE("pop_for times out on an empty queue", "[queue]") {
    BoundedQueue<int> q(1);
    const auto start = std::chrono::steady_clock::now();
    CHECK_FALSE(q.pop_for(30ms).has_value());
    CHECK(std::chrono::steady_clock::now() - start >= 25ms);
    CHECK_FALSE(q.drained());  // timed out, not closed
}

TEST_CASE("close rejects new items but lets queued ones drain", "[queue]") {
    BoundedQueue<int> q(4);
    q.try_push(1);
    q.try_push(2);
    q.close();

    CHECK_FALSE(q.try_push(3));
    CHECK_FALSE(q.push(4));
    CHECK(q.dropped() == 0);  // rejection after close is shutdown, not overload

    CHECK_FALSE(q.drained());
    CHECK(q.pop_for(0ms) == 1);
    CHECK(q.pop_for(0ms) == 2);
    CHECK_FALSE(q.pop_for(10ms).has_value());
    CHECK(q.drained());
}

TEST_CASE("blocking push waits for space instead of dropping", "[queue]") {
    BoundedQueue<int> q(1);
    q.push(1);

    std::atomic<bool> pushed{false};
    std::thread producer([&] {
        q.push(2);
        pushed = true;
    });

    std::this_thread::sleep_for(50ms);
    CHECK_FALSE(pushed.load());  // still waiting: the queue is full
    CHECK(q.pop_for(0ms) == 1);
    producer.join();
    CHECK(pushed.load());
    CHECK(q.pop_for(0ms) == 2);
    CHECK(q.dropped() == 0);
}

TEST_CASE("close wakes threads blocked in push and pop", "[queue]") {
    BoundedQueue<int> full(1);
    full.push(0);
    BoundedQueue<int> empty(1);

    bool push_result = true;
    std::optional<int> pop_result = 99;
    std::thread blocked_push([&] { push_result = full.push(1); });
    std::thread blocked_pop([&] { pop_result = empty.pop_for(10s); });

    std::this_thread::sleep_for(50ms);
    const auto start = std::chrono::steady_clock::now();
    full.close();
    empty.close();
    blocked_push.join();
    blocked_pop.join();

    CHECK(std::chrono::steady_clock::now() - start < 1s);
    CHECK_FALSE(push_result);
    CHECK_FALSE(pop_result.has_value());
}

TEST_CASE("many producers and consumers: every item delivered exactly once", "[queue][threads]") {
    constexpr int kProducers = 4;
    constexpr int kConsumers = 3;
    constexpr int kPerProducer = 20000;

    BoundedQueue<int> q(64);  // small, so producers and consumers contend constantly
    std::vector<std::atomic<int>> seen(kProducers * kPerProducer);
    std::atomic<long long> sum{0};

    std::vector<std::thread> consumers;
    for (int c = 0; c < kConsumers; ++c) {
        consumers.emplace_back([&] {
            while (true) {
                auto item = q.pop_for(10ms);
                if (!item) {
                    if (q.drained()) return;
                    continue;
                }
                seen[static_cast<std::size_t>(*item)].fetch_add(1);
                sum += *item;
            }
        });
    }

    std::vector<std::thread> producers;
    for (int p = 0; p < kProducers; ++p) {
        producers.emplace_back([&, p] {
            for (int i = 0; i < kPerProducer; ++i) q.push(p * kPerProducer + i);
        });
    }
    for (auto& t : producers) t.join();
    q.close();
    for (auto& t : consumers) t.join();

    const long long n = kProducers * kPerProducer;
    CHECK(sum.load() == n * (n - 1) / 2);
    bool all_once = true;
    for (const auto& s : seen) all_once = all_once && s.load() == 1;
    CHECK(all_once);
    CHECK(q.dropped() == 0);
}
