#include <atomic>
#include <catch2/catch_test_macros.hpp>
#include <chrono>
#include <memory>
#include <thread>

#include "resolve/resolver.hpp"

using netpulse::IpAddress;
using netpulse::Resolver;
using namespace std::chrono_literals;

namespace {

// Polls until the address leaves Pending or the deadline passes.
Resolver::Result wait_for_answer(Resolver& r, const IpAddress& ip, std::chrono::milliseconds limit) {
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
    const auto router = IpAddress::v4(10, 0, 0, 1);
    Resolver r([router](const IpAddress& ip) -> std::optional<std::string> {
        return ip == router ? std::optional<std::string>("router.lan") : std::nullopt;
    });

    CHECK(r.lookup(router).status == Resolver::Status::Pending);
    const auto named = wait_for_answer(r, router, 2s);
    CHECK(named.status == Resolver::Status::Resolved);
    CHECK(named.name == "router.lan");

    const auto unnamed = wait_for_answer(r, IpAddress::v4(10, 0, 0, 2), 2s);
    CHECK(unnamed.status == Resolver::Status::NoName);
    CHECK(unnamed.name.empty());
}

TEST_CASE("each address is looked up only once", "[resolve]") {
    auto calls = std::make_shared<std::atomic<int>>(0);
    Resolver r([calls](const IpAddress&) -> std::optional<std::string> {
        ++*calls;
        return "host";
    });
    const auto addr = IpAddress::v4(42);
    for (int i = 0; i < 50; ++i) r.lookup(addr);
    wait_for_answer(r, addr, 2s);
    for (int i = 0; i < 50; ++i) r.lookup(addr);
    CHECK(calls->load() == 1);
}

TEST_CASE("a slow DNS server never blocks the caller", "[resolve]") {
    Resolver r([](const IpAddress&) -> std::optional<std::string> {
        std::this_thread::sleep_for(500ms);
        return "slow.example";
    });

    const auto start = std::chrono::steady_clock::now();
    for (std::uint32_t ip = 1; ip <= 20; ++ip) {
        CHECK(r.lookup(IpAddress::v4(ip)).status == Resolver::Status::Pending);
    }
    CHECK(std::chrono::steady_clock::now() - start < 100ms);
}

TEST_CASE("destroying the resolver does not wait for in-flight lookups", "[resolve]") {
    auto r = std::make_unique<Resolver>([](const IpAddress&) -> std::optional<std::string> {
        std::this_thread::sleep_for(1500ms);
        return "very.slow.example";
    });
    r->lookup(IpAddress::v4(1));
    r->lookup(IpAddress::v4(2));
    std::this_thread::sleep_for(50ms);  // let the workers pick them up and block

    const auto start = std::chrono::steady_clock::now();
    r.reset();
    CHECK(std::chrono::steady_clock::now() - start < 300ms);
}
