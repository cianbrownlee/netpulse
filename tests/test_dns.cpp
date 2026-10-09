#include <catch2/catch_test_macros.hpp>
#include <random>

#include "frame_builder.hpp"
#include "parse/dns.hpp"

using namespace netpulse;
using namespace netpulse::test;

namespace {

std::vector<DnsNameAnswer> parse(const Bytes& message) {
    return parse_dns_response(std::span<const std::uint8_t>(message));
}

constexpr std::uint16_t kQuestionOffset = 12;  // where the first question's name starts
constexpr std::uint16_t kTypeA = 1;
constexpr std::uint16_t kTypeCname = 5;
constexpr std::uint16_t kTypeAaaa = 28;

}  // namespace

TEST_CASE("an A answer names the address with the question that was asked", "[dns]") {
    DnsMessage m;
    m.question(DnsMessage::name("www.Example.COM"))
        .answer(DnsMessage::pointer(kQuestionOffset), kTypeA, DnsMessage::a(ip(93, 184, 216, 34)));
    const auto answers = parse(m.bytes);
    REQUIRE(answers.size() == 1);
    CHECK(answers[0].name == "www.example.com");  // lowercased
    REQUIRE(answers[0].addresses.size() == 1);
    CHECK(answers[0].addresses[0] == ip(93, 184, 216, 34));
}

TEST_CASE("a CNAME chain still pairs the final addresses with the question", "[dns]") {
    // www.youtube.com -> CNAME youtube-ui.l.google.com -> two A records.
    DnsMessage m;
    m.question(DnsMessage::name("www.youtube.com"));
    const auto cname_target = DnsMessage::name("youtube-ui.l.google.com");
    const auto target_offset = static_cast<std::uint16_t>(m.bytes.size() + 2 + 10);
    m.answer(DnsMessage::pointer(kQuestionOffset), kTypeCname, cname_target)
        .answer(DnsMessage::pointer(target_offset), kTypeA, DnsMessage::a(ip(142, 250, 72, 14)))
        .answer(DnsMessage::pointer(target_offset), kTypeA, DnsMessage::a(ip(142, 250, 72, 46)));

    const auto answers = parse(m.bytes);
    REQUIRE(answers.size() == 1);
    CHECK(answers[0].name == "www.youtube.com");
    CHECK(answers[0].addresses == std::vector<IpAddress>{ip(142, 250, 72, 14), ip(142, 250, 72, 46)});
}

TEST_CASE("AAAA answers give IPv6 addresses", "[dns][ipv6]") {
    DnsMessage m;
    m.question(DnsMessage::name("example.com"), kTypeAaaa)
        .answer(DnsMessage::pointer(kQuestionOffset), kTypeAaaa,
                DnsMessage::aaaa(ip6("2606:2800:220:1:248:1893:25c8:1946")));
    const auto answers = parse(m.bytes);
    REQUIRE(answers.size() == 1);
    CHECK(answers[0].addresses[0] == ip6("2606:2800:220:1:248:1893:25c8:1946"));
}

TEST_CASE("mDNS answers without a question use the record's own name", "[dns]") {
    DnsMessage m(0x8400);  // response, authoritative
    m.answer(DnsMessage::name("Living-Room-TV.local"), kTypeA, DnsMessage::a(ip(192, 168, 1, 31)),
             0x8001);  // class IN with mDNS's cache-flush bit
    const auto answers = parse(m.bytes);
    REQUIRE(answers.size() == 1);
    CHECK(answers[0].name == "living-room-tv.local");
    CHECK(answers[0].addresses[0] == ip(192, 168, 1, 31));
}

TEST_CASE("queries and error responses teach nothing", "[dns]") {
    DnsMessage query(0x0100);  // QR = 0
    query.question(DnsMessage::name("example.com"))
        .answer(DnsMessage::pointer(kQuestionOffset), kTypeA, DnsMessage::a(ip(1, 2, 3, 4)));
    CHECK(parse(query.bytes).empty());

    DnsMessage nxdomain(0x8183);  // response, RCODE 3
    nxdomain.question(DnsMessage::name("nope.example.com"));
    CHECK(parse(nxdomain.bytes).empty());
}

TEST_CASE("a response cut short keeps the answers that fit", "[dns][malformed]") {
    DnsMessage m;
    m.question(DnsMessage::name("example.com"))
        .answer(DnsMessage::pointer(kQuestionOffset), kTypeA, DnsMessage::a(ip(1, 1, 1, 1)))
        .answer(DnsMessage::pointer(kQuestionOffset), kTypeA, DnsMessage::a(ip(2, 2, 2, 2)));
    const std::size_t one_answer = m.bytes.size() - 16;  // each pointer-owned A answer is 16 bytes

    for (std::size_t len = 0; len <= m.bytes.size(); ++len) {
        INFO("prefix length " << len);
        const Bytes prefix(m.bytes.begin(), m.bytes.begin() + static_cast<std::ptrdiff_t>(len));
        const auto answers = parse(prefix);
        const std::size_t expected = len < one_answer ? 0 : len < m.bytes.size() ? 1 : 2;
        CHECK((answers.empty() ? 0 : answers[0].addresses.size()) == expected);
    }
}

TEST_CASE("hostile names are rejected", "[dns][malformed]") {
    SECTION("a pointer to itself (a loop)") {
        DnsMessage m;
        m.question(DnsMessage::pointer(kQuestionOffset));
        CHECK(parse(m.bytes).empty());
    }
    SECTION("a backward pointer into the same name (a loop through the labels)") {
        // "a", then a pointer back to that "a": earlier than the pointer, but it leads straight
        // back to it. Rejected by the pointer rule, without relying on the name-length cap.
        DnsMessage m;
        m.question(Bytes{1, 'a', 0xC0, kQuestionOffset})
            .answer(DnsMessage::pointer(kQuestionOffset), kTypeA, DnsMessage::a(ip(1, 2, 3, 4)));
        CHECK(parse(m.bytes).empty());
    }
    SECTION("a forward pointer") {
        DnsMessage m;
        m.question(DnsMessage::pointer(200));
        CHECK(parse(m.bytes).empty());
    }
    SECTION("a two-pointer cycle") {
        // Question name is a pointer to the answer's owner, which points back at the question.
        DnsMessage m;
        m.question(DnsMessage::pointer(18))  // offset of the answer below
            .answer(DnsMessage::pointer(kQuestionOffset), kTypeA, DnsMessage::a(ip(1, 2, 3, 4)));
        CHECK(parse(m.bytes).empty());
    }
    SECTION("a terminal escape sequence hidden in a name") {
        DnsMessage m;
        m.question(DnsMessage::name("evil\x1b[2Jcom"))
            .answer(DnsMessage::pointer(kQuestionOffset), kTypeA, DnsMessage::a(ip(6, 6, 6, 6)));
        CHECK(parse(m.bytes).empty());
    }
    SECTION("a label longer than the message") {
        DnsMessage m;
        Bytes bad = {50, 'a', 'b', 0};
        m.question(bad);
        CHECK(parse(m.bytes).empty());
    }
    SECTION("an over-long name") {
        std::string long_name;
        for (int i = 0; i < 6; ++i) long_name += std::string(50, 'a') + ".";
        long_name += "com";  // 6 x 51 + 3 = 309 characters
        DnsMessage m;
        m.question(DnsMessage::name(long_name))
            .answer(DnsMessage::pointer(kQuestionOffset), kTypeA, DnsMessage::a(ip(1, 2, 3, 4)));
        CHECK(parse(m.bytes).empty());
    }
    SECTION("obsolete label types") {
        DnsMessage m;
        m.question(Bytes{0x41, 'x', 0});
        CHECK(parse(m.bytes).empty());
    }
}

TEST_CASE("random garbage never crashes the DNS parser", "[dns][malformed]") {
    std::mt19937 rng(777);
    std::uniform_int_distribution<int> len_dist(0, 300);
    std::uniform_int_distribution<int> byte_dist(0, 255);
    for (int i = 0; i < 20000; ++i) {
        Bytes msg(static_cast<std::size_t>(len_dist(rng)));
        for (auto& b : msg) b = static_cast<std::uint8_t>(byte_dist(rng));
        if (msg.size() >= 12) {
            msg[2] = 0x81;  // a response, so parsing goes deep
            msg[3] = 0x80;
            msg[4] = 0;
            msg[5] = static_cast<std::uint8_t>(i % 3);
            msg[6] = 0;
            msg[7] = static_cast<std::uint8_t>(i % 7);
        }
        // Also plant compression pointers in some of them.
        if (msg.size() > 20 && i % 2 == 0) {
            msg[12] = 0xC0;
            msg[13] = static_cast<std::uint8_t>(byte_dist(rng));
        }
        (void)parse(msg);
    }
    SUCCEED();
}
