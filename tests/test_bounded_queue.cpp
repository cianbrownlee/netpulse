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

TEST_CASE("order survives wrapping around the ring many times", "[queue]") {
    BoundedQueue<int> q(3);
    int next_in = 0;
    int next_out = 0;
    for (int round = 0; round < 100; ++round) {
        // Uneven fills and drains so head and tail cross the end of the ring at every offset.
        for (int i = 0; i < 1 + round % 3 && q.size() < q.capacity(); ++i) {
            REQUIRE(q.try_push(next_in++));
        }
        for (int i = 0; i < 1 + round % 2; ++i) {
            if (auto item = q.pop_for(0ms)) REQUIRE(*item == next_out++);
        }
    }
    while (auto item = q.pop_for(0ms)) CHECK(*item == next_out++);
    CHECK(next_out == next_in);
    CHECK(q.dropped() == 0);
}

TEST_CASE("try_push_batch queues what fits and counts the rest as drops", "[queue][batch]") {
    BoundedQueue<int> q(5);
    q.try_push(0);
    std::vector<int> batch = {1, 2, 3, 4, 5, 6};
    CHECK(q.try_push_batch(batch) == 4);
    CHECK(batch.empty());
    CHECK(q.dropped() == 2);

    std::vector<int> out;
    CHECK(q.pop_batch(out, 100, 0ms) == 5);
    CHECK(out == std::vector<int>{0, 1, 2, 3, 4});
}

TEST_CASE("pop_batch takes at most max items, oldest first", "[queue][batch]") {
    BoundedQueue<int> q(10);
    std::vector<int> batch = {1, 2, 3, 4, 5, 6, 7};
    q.try_push_batch(batch);
    std::vector<int> out = {99};  // replaced, not appended to
    CHECK(q.pop_batch(out, 3, 0ms) == 3);
    CHECK(out == std::vector<int>{1, 2, 3});
    CHECK(q.pop_batch(out, 10, 0ms) == 4);
    CHECK(out == std::vector<int>{4, 5, 6, 7});
    CHECK(q.pop_batch(out, 10, 10ms) == 0);
    CHECK(out.empty());
}

TEST_CASE("push_batch waits for room rather than dropping", "[queue][batch]") {
    BoundedQueue<int> q(4);
    std::vector<int> batch(10);
    for (int i = 0; i < 10; ++i) batch[static_cast<std::size_t>(i)] = i;

    std::atomic<bool> done{false};
    std::thread producer([&] {
        CHECK(q.push_batch(batch));
        done = true;
    });

    std::vector<int> received;
    std::vector<int> out;
    while (received.size() < 10) {
        if (q.pop_batch(out, 3, 100ms) > 0) received.insert(received.end(), out.begin(), out.end());
    }
    producer.join();
    CHECK(done.load());
    CHECK(received == std::vector<int>{0, 1, 2, 3, 4, 5, 6, 7, 8, 9});
    CHECK(q.dropped() == 0);
}

TEST_CASE("close wakes a producer blocked in push_batch", "[queue][batch]") {
    BoundedQueue<int> q(2);
    std::vector<int> batch = {1, 2, 3, 4, 5};
    bool result = true;
    std::thread producer([&] { result = q.push_batch(batch); });
    std::this_thread::sleep_for(50ms);
    q.close();
    producer.join();
    CHECK_FALSE(result);
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

TEST_CASE("batched producers and consumers: every item delivered exactly once",
          "[queue][batch][threads]") {
    constexpr int kProducers = 4;
    constexpr int kConsumers = 2;
    constexpr int kPerProducer = 50000;

    BoundedQueue<int> q(100);  // smaller than a batch, so batches have to be split
    std::vector<std::atomic<int>> seen(kProducers * kPerProducer);

    std::vector<std::thread> consumers;
    for (int c = 0; c < kConsumers; ++c) {
        consumers.emplace_back([&] {
            std::vector<int> out;
            while (true) {
                if (q.pop_batch(out, 64, 10ms) == 0) {
                    if (q.drained()) return;
                    continue;
                }
                for (int item : out) seen[static_cast<std::size_t>(item)].fetch_add(1);
            }
        });
    }
    std::vector<std::thread> producers;
    for (int p = 0; p < kProducers; ++p) {
        producers.emplace_back([&, p] {
            std::vector<int> batch;
            for (int i = 0; i < kPerProducer; ++i) {
                batch.push_back(p * kPerProducer + i);
                if (batch.size() == 256) q.push_batch(batch);
            }
            q.push_batch(batch);
        });
    }
    for (auto& t : producers) t.join();
    q.close();
    for (auto& t : consumers) t.join();

    bool all_once = true;
    for (const auto& s : seen) all_once = all_once && s.load() == 1;
    CHECK(all_once);
    CHECK(q.dropped() == 0);
}
