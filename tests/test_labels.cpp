#include <catch2/catch_test_macros.hpp>
#include <string>

#include "frame_builder.hpp"
#include "ui/labels.hpp"

using namespace netpulse;
using netpulse::test::ip;
using netpulse::test::ip6;

namespace {

constexpr const char* kArrow = "  ⇄  ";  // 5 columns, 7 bytes

FlowRow named_flow() {
    FlowRow f;
    f.key.ip_a = ip(192, 168, 1, 40);
    f.key.port_a = 56334;
    f.key.ip_b = ip(203, 0, 113, 80);
    f.key.port_b = 443;
    f.key.protocol = 6;
    f.local_a = true;
    f.name_a = "gaming-pc.local";
    f.name_b = "cache3-sea1.steamcontent.com";
    return f;
}

}  // namespace

TEST_CASE("display width counts characters, not bytes", "[labels]") {
    CHECK(display_width("abc") == 3);
    CHECK(display_width(kArrow) == 5);
    CHECK(display_width("…net") == 4);
}

TEST_CASE("elide_front keeps the end of a name, where the domain is", "[labels]") {
    CHECK(elide_front("short", 10) == "short");
    CHECK(elide_front("ipv6-c012-sea001.1.oca.nflxvideo.net", 14) == "…nflxvideo.net");
    CHECK(display_width(elide_front("ipv6-c012-sea001.1.oca.nflxvideo.net", 14)) == 14);
    CHECK(elide_front("anything", 0).empty());
}

TEST_CASE("compact host labels: the name alone, then the name's end", "[labels]") {
    const IpAddress a = ip(203, 0, 113, 80);
    CHECK(host_label(a, "github.com") == "github.com (203.0.113.80)");
    CHECK(compact_host_label(a, "github.com", 20) == "github.com");
    CHECK(compact_host_label(a, "cache3-sea1.steamcontent.com", 17) == "…steamcontent.com");
    CHECK(compact_host_label(a, "", 8) == "….113.80");
    CHECK(compact_host_label(ip6("2001:db8:1::50"), "", 40) == "2001:db8:1::50");
}

TEST_CASE("conversation labels: local device first, or the device the reader picked", "[labels]") {
    FlowRow f = named_flow();
    CHECK(conversation_label(f, kArrow) ==
          "gaming-pc.local (192.168.1.40:56334)  ⇄  cache3-sea1.steamcontent.com (203.0.113.80:443)");

    // Stored the other way round, the local device still leads.
    std::swap(f.key.ip_a, f.key.ip_b);
    std::swap(f.key.port_a, f.key.port_b);
    std::swap(f.name_a, f.name_b);
    std::swap(f.local_a, f.local_b);
    CHECK(conversation_label(f, kArrow).starts_with("gaming-pc.local"));

    // Picking the server (Enter on it in the top talkers) puts it first instead.
    const IpAddress server = ip(203, 0, 113, 80);
    CHECK(conversation_label(f, kArrow, &server).starts_with("cache3-sea1"));
}

TEST_CASE("compact conversation labels fit their column without losing ports", "[labels]") {
    const FlowRow f = named_flow();

    // Named ends drop their addresses but keep their ports.
    CHECK(compact_conversation_label(f, kArrow, 60) ==
          "gaming-pc.local:56334  ⇄  cache3-sea1.steamcontent.com:443");

    // Still too long: both ends shortened from the front, within the width exactly.
    const std::string tight = compact_conversation_label(f, kArrow, 40);
    CHECK(display_width(tight) == 40);
    CHECK(tight.ends_with("content.com:443"));
    CHECK(tight.find("…") != std::string::npos);

    // A short end lends its spare room to the long one.
    FlowRow g = named_flow();
    g.name_a.clear();
    g.key.ip_a = ip(10, 0, 0, 1);
    g.key.port_a = 5;
    const std::string lent = compact_conversation_label(g, kArrow, 40);
    CHECK(lent.starts_with("10.0.0.1:5  ⇄  "));
    CHECK(display_width(lent) == 40);
}
