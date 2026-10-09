#include <catch2/catch_test_macros.hpp>
#include <string>

#include "aggregate/classifier.hpp"
#include "frame_builder.hpp"

using namespace netpulse;
using netpulse::test::ip;

namespace {

// A flow from the local device's point of view.
FlowFacts facts(std::uint8_t protocol, std::uint16_t port, double seconds, std::uint64_t down,
                std::uint64_t up, double duty, std::uint64_t packets = 0) {
    FlowFacts f;
    f.protocol = protocol;
    f.server_port = port;
    f.seconds = seconds;
    f.bytes_to_client = down;
    f.bytes_from_client = up;
    f.bytes = down + up;
    f.duty_cycle = duty;
    f.packets = packets ? packets : (f.bytes / 1400 + 1);
    return f;
}

constexpr std::uint8_t kTcp = 6;
constexpr std::uint8_t kUdp = 17;
constexpr std::uint64_t MB = 1'000'000;

Category category_of(const FlowFacts& f) { return classify(f).category; }

}  // namespace

TEST_CASE("orient: the private end is the client", "[classifier]") {
    FlowKey k;
    k.ip_a = ip(93, 184, 216, 34);  // canonical order puts the public address first here
    k.port_a = 443;
    k.ip_b = ip(192, 168, 1, 14);
    k.port_b = 51000;
    k.protocol = kTcp;
    const FlowEnds e = orient(k);
    CHECK_FALSE(e.client_is_a);
    CHECK(e.client_ip == ip(192, 168, 1, 14));
    CHECK(e.server_ip == ip(93, 184, 216, 34));
    CHECK(e.server_port == 443);
}

TEST_CASE("orient: between two private or two public ends, the lower port is the server",
          "[classifier]") {
    FlowKey k;
    k.ip_a = ip(192, 168, 1, 1);  // the router's DNS
    k.port_a = 53;
    k.ip_b = ip(192, 168, 1, 14);
    k.port_b = 50000;
    k.protocol = kUdp;
    CHECK(orient(k).server_ip == ip(192, 168, 1, 1));
    CHECK(orient(k).server_port == 53);
}

TEST_CASE("flow_facts maps directions onto download and upload", "[classifier]") {
    FlowKey k;
    k.ip_a = ip(93, 184, 216, 34);
    k.port_a = 443;
    k.ip_b = ip(192, 168, 1, 14);
    k.port_b = 51000;
    k.protocol = kTcp;
    FlowStats s;
    s.bytes_a_to_b = 9000;  // server -> laptop
    s.bytes_b_to_a = 1000;
    s.bytes = 10000;
    const FlowFacts f = flow_facts(k, s, "example.net");
    CHECK(f.bytes_to_client == 9000);
    CHECK(f.bytes_from_client == 1000);
    CHECK(f.server_port == 443);
    CHECK(f.remote_name == "example.net");
}

TEST_CASE("known services match whole domains and their subdomains only", "[classifier]") {
    CHECK(match_known_service("netflix.com")->category == Category::Streaming);
    CHECK(match_known_service("ipv4-c001-sea001-ix.1.oca.nflxvideo.net")->category ==
          Category::Streaming);
    CHECK(match_known_service("RR3---SN-AB5L6NZR.GOOGLEVIDEO.COM.")->category ==
          Category::Streaming);  // case and trailing dot
    CHECK(match_known_service("cache1.steamcontent.com")->category == Category::FileTransfer);
    CHECK(match_known_service("zoom.us")->category == Category::CallsGaming);

    CHECK_FALSE(match_known_service("notnetflix.com"));            // not a subdomain
    CHECK_FALSE(match_known_service("netflix.com.attacker.example"));
    CHECK_FALSE(match_known_service(""));
}

TEST_CASE("a known-service name beats the flow-shape guess", "[classifier]") {
    FlowFacts f = facts(kTcp, 443, 2, 50'000, 5'000, 1.0);  // looks like browsing by shape
    f.remote_name = "ipv4-c001.oca.nflxvideo.net";
    const auto c = classify(f);
    CHECK(c.category == Category::Streaming);
    CHECK(c.method == ClassMethod::KnownService);
    CHECK(explain(f, c).find("nflxvideo.net") != std::string::npos);
}

TEST_CASE("housekeeping is background; unknown IP protocols are not hidden", "[classifier]") {
    CHECK(category_of(facts(kUdp, 53, 1, 200, 60, 1.0)) == Category::Background);
    CHECK(category_of(facts(kUdp, 123, 1, 90, 90, 1.0)) == Category::Background);
    CHECK(category_of(facts(kUdp, 1900, 1, 0, 800, 1.0)) == Category::Background);
    CHECK(category_of(facts(1, 0, 3, 300, 300, 1.0)) == Category::Background);  // ICMP

    // GRE / ESP carry VPN tunnels: real traffic NetPulse can't see into.
    CHECK(category_of(facts(47, 0, 60, 40 * MB, 2 * MB, 1.0)) == Category::Other);

    // Background wins even over a name match: a DNS server's name says nothing about usage.
    FlowFacts dns = facts(kUdp, 53, 1, 200, 60, 1.0);
    dns.remote_name = "dns.google.youtube.com";
    CHECK(category_of(dns) == Category::Background);
}

TEST_CASE("streaming: long-lived, download-heavy, bursty web connection", "[classifier]") {
    const auto tcp = facts(kTcp, 443, 180, 60 * MB, 1 * MB, 0.35);
    CHECK(classify(tcp).category == Category::Streaming);
    CHECK(classify(tcp).method == ClassMethod::FlowShape);

    // YouTube in Chrome is mostly QUIC: UDP on port 443.
    const auto quic = facts(kUdp, 443, 180, 60 * MB, 1 * MB, 0.35, 45'000);
    CHECK(classify(quic).category == Category::Streaming);
    CHECK(explain(quic, classify(quic)).find("QUIC") != std::string::npos);

    // Not long enough yet to call it streaming.
    CHECK(category_of(facts(kTcp, 443, 6, 3 * MB, 100'000, 0.6)) != Category::Streaming);
}

TEST_CASE("file transfer: large, continuous and one-way, either direction", "[classifier]") {
    CHECK(category_of(facts(kTcp, 443, 30, 300 * MB, 2 * MB, 1.0)) == Category::FileTransfer);
    CHECK(category_of(facts(kTcp, 22, 40, 1 * MB, 120 * MB, 0.95)) == Category::FileTransfer);

    // The same volume arriving in on/off bursts on a web port reads as streaming instead.
    CHECK(category_of(facts(kTcp, 443, 300, 300 * MB, 2 * MB, 0.4)) == Category::Streaming);
}

TEST_CASE("calls and games: steady, two-way, small UDP packets", "[classifier]") {
    // 60 s of ~200-byte packets both ways, every second.
    CHECK(category_of(facts(kUdp, 3478, 60, 1'200'000, 1'100'000, 1.0, 11'500)) ==
          Category::CallsGaming);

    // One-way UDP isn't a conversation.
    CHECK(category_of(facts(kUdp, 3478, 60, 2'300'000, 10'000, 1.0, 11'500)) !=
          Category::CallsGaming);
    // Large packets look like bulk data, not call/game updates.
    CHECK(category_of(facts(kUdp, 3478, 60, 1'200'000, 1'100'000, 1.0, 1'550)) !=
          Category::CallsGaming);
    // Port 443 UDP is QUIC web traffic, never a call.
    CHECK(category_of(facts(kUdp, 443, 60, 1'200'000, 1'100'000, 1.0, 11'500)) !=
          Category::CallsGaming);
}

TEST_CASE("browsing: small exchanges on web ports", "[classifier]") {
    CHECK(category_of(facts(kTcp, 443, 2, 80'000, 6'000, 1.0)) == Category::Browsing);
    CHECK(category_of(facts(kTcp, 80, 1, 15'000, 1'000, 1.0)) == Category::Browsing);
    // A long-lived but tiny keep-alive is still web traffic.
    CHECK(category_of(facts(kTcp, 443, 600, 30'000, 20'000, 0.05)) == Category::Browsing);
}

TEST_CASE("anything else is Other, shown honestly rather than force-fit", "[classifier]") {
    const auto ssh = facts(kTcp, 22, 120, 2 * MB, 1 * MB, 0.3);
    const auto c = classify(ssh);
    CHECK(c.category == Category::Other);
    CHECK(c.method == ClassMethod::None);
    CHECK(explain(ssh, c).find("rather than guessed") != std::string::npos);
}

TEST_CASE("every explanation names the evidence", "[classifier]") {
    const auto dns = facts(kUdp, 53, 1, 200, 60, 1.0);
    CHECK(explain(dns, classify(dns)).find("DNS") != std::string::npos);

    const auto stream = facts(kTcp, 443, 180, 60 * MB, 1 * MB, 0.35);
    const auto reason = explain(stream, classify(stream));
    CHECK(reason.find("pattern, not certainty") != std::string::npos);
    CHECK(reason.find("port 443") != std::string::npos);
    CHECK(reason.find("3 min") != std::string::npos);
}
