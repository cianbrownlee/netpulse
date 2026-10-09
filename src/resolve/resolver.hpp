#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <thread>
#include <vector>

#include "util/ip_address.hpp"

namespace netpulse {

// Blocking reverse-DNS lookup (getnameinfo with NI_NAMEREQD). Returns nullopt if the address
// has no name. Can take seconds when a DNS server is slow or unreachable, which is exactly why
// it only ever runs on Resolver's worker threads.
std::optional<std::string> reverse_dns_lookup(const IpAddress& ip);

// Asynchronous hostname resolution with a session-long cache.
//
// lookup() never blocks on DNS: the first time it sees an address it queues it for a worker
// thread and reports Pending, and later calls return the cached answer. A slow or hanging DNS
// server therefore delays a *name* appearing, never the statistics pipeline.
//
// getnameinfo() has no per-call timeout, so a stuck lookup cannot be cancelled. Instead it is
// isolated: workers share their state through a shared_ptr and are detached on shutdown, so
// destroying the Resolver (and quitting the app) never waits for DNS either.
class Resolver {
public:
    using LookupFn = std::function<std::optional<std::string>(const IpAddress& ip)>;

    enum class Status { Pending, Resolved, NoName };

    struct Result {
        Status status = Status::Pending;
        std::string name;  // set when Resolved
    };

    struct Config {
        std::size_t workers = 2;
        std::size_t queue_capacity = 256;
    };

    explicit Resolver(LookupFn lookup = reverse_dns_lookup);
    Resolver(LookupFn lookup, Config config);
    ~Resolver();

    Resolver(const Resolver&) = delete;
    Resolver& operator=(const Resolver&) = delete;

    // Non-blocking. Schedules resolution the first time an address is seen.
    Result lookup(const IpAddress& ip);

private:
    struct State;
    static void worker_loop(std::shared_ptr<State> state);

    std::shared_ptr<State> state_;
    std::vector<std::thread> workers_;
};

}  // namespace netpulse
