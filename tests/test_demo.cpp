#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>
#include <chrono>
#include <memory>
#include <thread>

#include "demo/demo_source.hpp"
#include "pipeline/pipeline.hpp"

using namespace netpulse;
using Catch::Matchers::ContainsSubstring;

namespace {

// Runs the demo through the real pipeline, as fast as possible, for `seconds` of simulated
// time. Like a replay, it runs on its own clock, so the result is the same every time.
std::shared_ptr<const Snapshot> run_demo(int seconds) {
    Pipeline::Config config;
    config.resolve_names = false;
    config.dns_names = true;
    DemoSource::Options options;
    options.realtime = false;
    options.duration = std::chrono::seconds(seconds);
    Pipeline pipeline(config, std::make_unique<DemoSource>(options));
    pipeline.start();
    while (!pipeline.finished()) std::this_thread::sleep_for(std::chrono::milliseconds(5));
    pipeline.stop();
    return pipeline.latest();
}

const CategoryRow* find(const Snapshot& s, Category c) {
    for (const auto& row : s.categories) {
        if (row.category == c) return &row;
    }
    return nullptr;
}

const HostRow* find_host(const Snapshot& s, const IpAddress& ip) {
    for (const auto& h : s.top_hosts) {
        if (h.ip == ip) return &h;
    }
    return nullptr;
}

}  // namespace

TEST_CASE("demo: every generated frame parses, and every category it scripts shows up", "[demo]") {
    const auto s = run_demo(DemoSource::kDownloadStart + 20);

    CHECK(s->total.packets > 100'000);
    CHECK(s->malformed.packets == 0);
    CHECK(s->health.missed() == 0);
    CHECK(s->ipv6.bytes > 0);
    CHECK(s->non_ip.packets > 0);  // ARP

    // DNS answers name the video, call and download servers, so those are known-service
    // matches; browsing and the unnamed game server are labeled by pattern.
    struct Expected {
        Category category;
        ClassMethod method;
    };
    for (const Expected e : {Expected{Category::Streaming, ClassMethod::KnownService},
                             Expected{Category::FileTransfer, ClassMethod::KnownService},
                             Expected{Category::CallsGaming, ClassMethod::KnownService},
                             Expected{Category::Browsing, ClassMethod::FlowShape}}) {
        INFO(category_label(e.category));
        const CategoryRow* row = find(*s, e.category);
        REQUIRE(row != nullptr);
        CHECK(row->main_method == e.method);
    }
    CHECK(find(*s, Category::Other) != nullptr);  // the SSH session
    CHECK(s->background_bytes > 0);

    // Devices are named by their own mDNS announcements.
    const HostRow* laptop = find_host(*s, IpAddress::v4(192, 168, 1, 20));
    REQUIRE(laptop != nullptr);
    CHECK(laptop->name == "family-laptop.local");
    CHECK(laptop->name_source == NameSource::ObservedDns);
    CHECK(laptop->is_local);
}

TEST_CASE("demo: the gaming PC's download is the scripted status-line event", "[demo]") {
    SECTION("before it starts, nothing stands out") {
        const auto s = run_demo(DemoSource::kDownloadStart - 1);
        CHECK(s->status.kind == StatusKind::Normal);
    }
    SECTION("once it's running, the status line points at the gaming PC") {
        const auto s = run_demo(DemoSource::kDownloadStart + 15);
        CHECK(s->status.kind == StatusKind::DeviceAboveUsual);
        CHECK_THAT(s->status.headline, ContainsSubstring("gaming-pc.local"));
    }
}
