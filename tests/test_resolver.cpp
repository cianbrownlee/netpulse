#include <atomic>
#include <catch2/catch_test_macros.hpp>
#include <chrono>
#include <memory>
#include <thread>

#include "resolve/resolver.hpp"

using netpulse::Resolver;
using namespace std::chrono_literals;

namespace {

// Polls until the address leaves Pending or the deadline passes.
Resolver::Result wait_for_answer(Resolver& r, std::uint32_t ip, std::chrono::milliseconds limit) {
    const auto deadline = std::chrono::steady_clock::now() + limit;
    auto result = r.lookup(ip);
    while (result.status == Resolver::Status::Pending &&
           std::chrono::steady_clock::now() < deadline) {
        std::this_thread::sleep_for(5ms);
        result = r.lookup(ip);
    }
    return result;
}

}  // namespace

TEST_CASE("first lookup is pending, then the answer is cached", "[resolve]") {
    Resolver r([](std::uint32_t ip) -> std::optional<std::string> {
        return ip == 0x0A000001 ? std::optional<std::string>("router.lan") : std::nullopt;
    });

    CHECK(r.lookup(0x0A000001).status == Resolver::Status::Pending);
    const auto named = wait_for_answer(r, 0x0A000001, 2s);
    CHECK(named.status == Resolver::Status::Resolved);
    CHECK(named.name == "router.lan");

    const auto unnamed = wait_for_answer(r, 0x0A000002, 2s);
    CHECK(unnamed.status == Resolver::Status::NoName);
    CHECK(unnamed.name.empty());
}

TEST_CASE("each address is looked up only once", "[resolve]") {
    auto calls = std::make_shared<std::atomic<int>>(0);
    Resolver r([calls](std::uint32_t) -> std::optional<std::string> {
        ++*calls;
        return "host";
    });
    for (int i = 0; i < 50; ++i) r.lookup(42);
    wait_for_answer(r, 42, 2s);
    for (int i = 0; i < 50; ++i) r.lookup(42);
    CHECK(calls->load() == 1);
}

TEST_CASE("a slow DNS server never blocks the caller", "[resolve]") {
    Resolver r([](std::uint32_t) -> std::optional<std::string> {
        std::this_thread::sleep_for(500ms);
        return "slow.example";
    });

    const auto start = std::chrono::steady_clock::now();
    for (std::uint32_t ip = 1; ip <= 20; ++ip) {
        CHECK(r.lookup(ip).status == Resolver::Status::Pending);
    }
    CHECK(std::chrono::steady_clock::now() - start < 100ms);
}

TEST_CASE("destroying the resolver does not wait for in-flight lookups", "[resolve]") {
    auto r = std::make_unique<Resolver>([](std::uint32_t) -> std::optional<std::string> {
        std::this_thread::sleep_for(1500ms);
        return "very.slow.example";
    });
    r->lookup(1);
    r->lookup(2);
    std::this_thread::sleep_for(50ms);  // let the workers pick them up and block

    const auto start = std::chrono::steady_clock::now();
    r.reset();
    CHECK(std::chrono::steady_clock::now() - start < 300ms);
}
