// netpulse_bench: pushes synthetic packets through NetPulse's real pipeline (queue, parser,
// aggregator, snapshots, classifier, status checks) as fast as it will go, and reports
// throughput, CPU, context switches and heap allocations per packet.
//
// There's no libpcap, kernel or capture permission in the loop, so this isolates NetPulse's own
// per-packet cost and is repeatable enough to compare one change against the next. Behavior
// under real load (including the kernel's side) is measured by tools/bench_live.sh.
//
// Usage: netpulse_bench [--packets N] [--flows N] [--overload]
//   default        producer waits for queue space: measures maximum sustainable throughput
//   --overload     producer never waits, as live capture doesn't: measures drop behavior when
//                  packets arrive faster than they can be processed

#include <sys/resource.h>

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <new>
#include <random>
#include <string>
#include <thread>
#include <vector>

#include "capture/packet_source.hpp"
#include "pipeline/pipeline.hpp"
#include "util/format.hpp"

// Count every heap allocation in the process (all threads), to report allocations per packet.
namespace {
std::atomic<std::uint64_t> g_allocations{0};
}

// These replace the global allocator as a pair (malloc/free underneath), which GCC's
// mismatched-new-delete check can't see through once they're inlined.
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmismatched-new-delete"
void* operator new(std::size_t size) {
    g_allocations.fetch_add(1, std::memory_order_relaxed);
    if (void* p = std::malloc(size == 0 ? 1 : size)) return p;
    throw std::bad_alloc();
}
void operator delete(void* p) noexcept { std::free(p); }
void operator delete(void* p, std::size_t) noexcept { std::free(p); }
#pragma GCC diagnostic pop

namespace {

using namespace netpulse;
using Clock = std::chrono::steady_clock;

struct Frame {
    std::vector<std::uint8_t> headers;  // what a 192-byte-snaplen capture would hold
    std::uint32_t wire_length = 0;
};

void put16(std::vector<std::uint8_t>& out, std::uint16_t v) {
    out.push_back(static_cast<std::uint8_t>(v >> 8));
    out.push_back(static_cast<std::uint8_t>(v));
}

void put32(std::vector<std::uint8_t>& out, std::uint32_t v) {
    put16(out, static_cast<std::uint16_t>(v >> 16));
    put16(out, static_cast<std::uint16_t>(v));
}

Frame make_frame(std::uint32_t src, std::uint16_t sport, std::uint32_t dst, std::uint16_t dport,
                 bool tcp, std::uint32_t payload) {
    Frame f;
    auto& b = f.headers;
    b = {0x02, 0, 0, 0, 0, 2, 0x02, 0, 0, 0, 0, 1};  // MACs
    put16(b, 0x0800);
    const std::uint32_t l4 = tcp ? 20 : 8;
    b.push_back(0x45);
    b.push_back(0);
    put16(b, static_cast<std::uint16_t>(20 + l4 + payload));
    put32(b, 0x12344000);  // id, DF
    b.push_back(64);
    b.push_back(tcp ? 6 : 17);
    put16(b, 0);
    put32(b, src);
    put32(b, dst);
    put16(b, sport);
    put16(b, dport);
    if (tcp) {
        put32(b, 1000);
        put32(b, 2000);
        b.push_back(0x50);
        b.push_back(0x10);  // ACK
        put16(b, 65535);
        put32(b, 0);
    } else {
        put16(b, static_cast<std::uint16_t>(8 + payload));
        put16(b, 0);
    }
    f.wire_length = static_cast<std::uint32_t>(b.size()) + payload;
    return f;
}

// A mix of web, DNS, call-like and SSH conversations between local devices and public servers.
std::vector<Frame> make_frames(std::size_t flows, std::size_t count) {
    std::mt19937 rng(42);
    struct Flow {
        std::uint32_t client, server;
        std::uint16_t cport, sport;
        bool tcp;
    };
    std::vector<Flow> table;
    for (std::size_t i = 0; i < flows; ++i) {
        Flow fl;
        fl.client = (192u << 24) | (168u << 16) | (1u << 8) | static_cast<std::uint32_t>(2 + i % 240);
        fl.server = (static_cast<std::uint32_t>(1 + rng() % 200) << 24) | (rng() & 0xFFFFFF);
        fl.cport = static_cast<std::uint16_t>(40000 + i % 20000);
        const unsigned kind = rng() % 10;
        fl.tcp = kind < 7;
        fl.sport = kind < 6 ? 443 : kind < 7 ? 22 : kind < 8 ? 53 : kind < 9 ? 3478 : 443;
        table.push_back(fl);
    }
    std::vector<Frame> frames;
    frames.reserve(count);
    for (std::size_t i = 0; i < count; ++i) {
        const Flow& fl = table[rng() % table.size()];
        const bool download = rng() % 3 != 0;
        const std::uint32_t payload = fl.tcp ? (download ? 1448 : 0) : 160 + rng() % 1000;
        frames.push_back(download ? make_frame(fl.server, fl.sport, fl.client, fl.cport, fl.tcp, payload)
                                  : make_frame(fl.client, fl.cport, fl.server, fl.sport, fl.tcp, payload));
    }
    return frames;
}

class SyntheticSource final : public PacketSource {
public:
    // rate: packets offered per second (0 = as fast as possible). Any rate implies overload
    // semantics: the producer never waits, as live capture doesn't.
    SyntheticSource(std::vector<Frame> frames, std::uint64_t packets, bool overload, double rate,
                    std::size_t batch_size)
        : frames_(std::move(frames)), packets_(packets), overload_(overload || rate > 0),
          rate_(rate), batch_size_(batch_size) {}

    void run(BoundedQueue<CapturedPacket>& queue) override {
        PacketBatcher batcher(queue,
                              overload_ ? PacketBatcher::Overflow::Drop : PacketBatcher::Overflow::Wait,
                              batch_size_);
        const auto start = Clock::now();
        for (std::uint64_t i = 0; i < packets_; ++i) {
            if ((i & 4095) == 0) {
                if (stop_.load(std::memory_order_relaxed)) break;
                produced_.store(i, std::memory_order_relaxed);
                if (rate_ > 0) {  // pace in chunks of 4096 packets
                    batcher.flush();
                    std::this_thread::sleep_until(
                        start + std::chrono::duration_cast<Clock::duration>(
                                    std::chrono::duration<double>(static_cast<double>(i) / rate_)));
                }
            }
            const Frame& f = frames_[i % frames_.size()];
            batcher.add(f.headers.data(), f.headers.size(), f.wire_length, Clock::now());
        }
        batcher.flush();
        produced_.store(packets_, std::memory_order_relaxed);
    }

    void stop() override { stop_.store(true); }
    CaptureCounters counters() const override {
        CaptureCounters c;
        c.captured = produced_.load(std::memory_order_relaxed);
        return c;
    }
    std::optional<std::string> error() const override { return std::nullopt; }
    bool is_offline() const override { return !overload_; }
    const std::string& description() const override { return description_; }

private:
    std::vector<Frame> frames_;
    std::uint64_t packets_;
    bool overload_;
    double rate_;
    std::size_t batch_size_;
    std::atomic<bool> stop_{false};
    std::atomic<std::uint64_t> produced_{0};
    std::string description_ = "synthetic";
};

double seconds(const timeval& tv) { return static_cast<double>(tv.tv_sec) + tv.tv_usec / 1e6; }

}  // namespace

int main(int argc, char** argv) {
    std::uint64_t packets = 10'000'000;
    std::size_t flows = 2000;
    bool overload = false;
    double rate = 0;
    std::size_t batch = PacketBatcher::kDefaultBatchSize;
    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];
        if (arg == "--packets" && i + 1 < argc) packets = std::strtoull(argv[++i], nullptr, 10);
        else if (arg == "--flows" && i + 1 < argc) flows = std::strtoull(argv[++i], nullptr, 10);
        else if (arg == "--rate" && i + 1 < argc) rate = std::strtod(argv[++i], nullptr);
        else if (arg == "--batch" && i + 1 < argc) batch = std::strtoull(argv[++i], nullptr, 10);
        else if (arg == "--overload") overload = true;
        else {
            std::fprintf(stderr,
                         "usage: netpulse_bench [--packets N] [--flows N] [--overload] "
                         "[--rate PACKETS_PER_SEC] [--batch N]\n");
            return 2;
        }
    }

    Pipeline::Config config;
    config.resolve_names = false;
    config.batch_size = batch;
    Pipeline pipeline(config, std::make_unique<SyntheticSource>(make_frames(flows, 65536), packets,
                                                                overload, rate, batch));

    rusage before{};
    getrusage(RUSAGE_SELF, &before);
    const std::uint64_t allocs_before = g_allocations.load();
    const auto start = Clock::now();

    pipeline.start();
    while (!pipeline.finished()) std::this_thread::sleep_for(std::chrono::milliseconds(5));

    const double wall = std::chrono::duration<double>(Clock::now() - start).count();
    const std::uint64_t allocs = g_allocations.load() - allocs_before;
    rusage after{};
    getrusage(RUSAGE_SELF, &after);
    pipeline.stop();

    const auto snapshot = pipeline.latest();
    const std::uint64_t processed = snapshot->total.packets;
    const std::uint64_t dropped = snapshot->health.queue_drops;
    const double cpu = seconds(after.ru_utime) - seconds(before.ru_utime) +
                       seconds(after.ru_stime) - seconds(before.ru_stime);
    const double sys = seconds(after.ru_stime) - seconds(before.ru_stime);
    const long switches = (after.ru_nvcsw - before.ru_nvcsw) + (after.ru_nivcsw - before.ru_nivcsw);
    const double per_packet = static_cast<double>(packets);

    std::string mode = overload ? "overload" : "throughput";
    if (rate > 0) mode = "fixed rate " + format_count(static_cast<std::uint64_t>(rate)) + " packets/s offered";
    std::printf("mode:              %s, %s packets, %zu flows, batch %zu\n", mode.c_str(),
                format_count(packets).c_str(), flows, batch);
    std::printf("time:              %.2f s  ->  %.2f M packets/s processed (%.0f ns/packet)\n", wall,
                processed / wall / 1e6, wall * 1e9 / per_packet);
    // What the producer actually managed. With --rate this can fall short of the target when the
    // producer side itself is the bottleneck, and drop rates are only comparable at equal offers.
    std::printf("offered:           %.2f M packets/s\n", per_packet / wall / 1e6);
    std::printf("cpu:               %.2f s (%.2f s system)  ->  %.2f cores busy, %.0f ns CPU/packet\n",
                cpu, sys, cpu / wall, cpu * 1e9 / per_packet);
    std::printf("context switches:  %s  (%.1f per 1,000 packets)\n", format_count(switches).c_str(),
                switches * 1000.0 / per_packet);
    std::printf("heap allocations:  %s  (%.3f per packet)\n", format_count(allocs).c_str(),
                allocs / per_packet);
    std::printf("dropped:           %s  (%.2f%%)\n", format_count(dropped).c_str(),
                dropped * 100.0 / per_packet);
    std::printf("check:             processed + dropped = %s of %s\n",
                format_count(processed + dropped).c_str(), format_count(packets).c_str());
    return processed + dropped == packets ? 0 : 1;
}
