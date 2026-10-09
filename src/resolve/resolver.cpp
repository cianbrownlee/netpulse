#include "resolve/resolver.hpp"

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pthread.h>
#include <sys/socket.h>

#include <chrono>
#include <cstring>
#include <mutex>
#include <unordered_map>
#include <utility>

#include "util/bounded_queue.hpp"

namespace netpulse {

std::optional<std::string> reverse_dns_lookup(const IpAddress& ip) {
    char host[NI_MAXHOST];
    int rc = 0;
    if (ip.is_v4()) {
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(ip.v4_value());
        rc = getnameinfo(reinterpret_cast<const sockaddr*>(&addr), sizeof addr, host, sizeof host,
                         nullptr, 0, NI_NAMEREQD);
    } else {
        sockaddr_in6 addr{};
        addr.sin6_family = AF_INET6;
        std::memcpy(addr.sin6_addr.s6_addr, ip.bytes().data(), 16);
        rc = getnameinfo(reinterpret_cast<const sockaddr*>(&addr), sizeof addr, host, sizeof host,
                         nullptr, 0, NI_NAMEREQD);
    }
    if (rc != 0) return std::nullopt;
    return std::string(host);
}

struct Resolver::State {
    State(LookupFn fn, std::size_t capacity) : lookup(std::move(fn)), pending(capacity) {}

    LookupFn lookup;
    BoundedQueue<IpAddress> pending;
    std::mutex mutex;
    std::unordered_map<IpAddress, Result> cache;
};

Resolver::Resolver(LookupFn lookup) : Resolver(std::move(lookup), Config{}) {}

Resolver::Resolver(LookupFn lookup, Config config)
    : state_(std::make_shared<State>(std::move(lookup), config.queue_capacity)) {
    for (std::size_t i = 0; i < config.workers; ++i) {
        workers_.emplace_back(worker_loop, state_);
    }
}

Resolver::~Resolver() {
    state_->pending.close();
    // Detach rather than join: a worker may be blocked inside getnameinfo() for seconds.
    // It holds its own shared_ptr to State, so it can finish safely after we are gone.
    for (auto& worker : workers_) worker.detach();
}

Resolver::Result Resolver::lookup(const IpAddress& ip) {
    {
        std::lock_guard lock(state_->mutex);
        auto [it, inserted] = state_->cache.try_emplace(ip);
        if (!inserted) return it->second;
    }
    // First sighting: hand it to a worker. If the queue is full, forget the entry so a later
    // lookup() retries instead of the address being stuck at Pending forever.
    if (!state_->pending.try_push(ip)) {
        std::lock_guard lock(state_->mutex);
        state_->cache.erase(ip);
    }
    return Result{};
}

void Resolver::worker_loop(std::shared_ptr<State> state) {
    pthread_setname_np(pthread_self(), "np-resolve");
    // Once closed, abandon whatever is still queued: nobody is left to read the answers.
    while (!state->pending.closed()) {
        auto ip = state->pending.pop_for(std::chrono::milliseconds(200));
        if (!ip) continue;
        std::optional<std::string> name = state->lookup(*ip);
        std::lock_guard lock(state->mutex);
        Result& entry = state->cache[*ip];
        if (name) {
            entry.status = Status::Resolved;
            entry.name = std::move(*name);
        } else {
            entry.status = Status::NoName;
        }
    }
}

}  // namespace netpulse
