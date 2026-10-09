#include <catch2/catch_test_macros.hpp>
#include <set>
#include <string>

#include "frame_builder.hpp"
#include "ui/dashboard_model.hpp"
#include "ui/glossary.hpp"

using namespace netpulse;
using netpulse::test::ip;

namespace {

FlowRow flow(std::uint8_t protocol, std::uint16_t port_a, std::uint16_t port_b, Category category) {
    FlowRow f;
    f.key.ip_a = ip(10, 0, 0, 1);
    f.key.ip_b = ip(93, 184, 216, 34);
    f.key.port_a = port_a;
    f.key.port_b = port_b;
    f.key.protocol = protocol;
    f.category = category;
    f.reason = "because of reasons, at some length";
    return f;
}

CategoryRow category(Category c, ClassMethod method) {
    CategoryRow row;
    row.category = c;
    row.main_method = method;
    row.bytes = 1000;
    row.flows = 1;
    row.explanation = "1 active conversation, 1.0 kB in total.";
    return row;
}

// A snapshot exercising every kind of row the dashboard can show.
Snapshot representative_snapshot() {
    Snapshot s;
    HostRow named;
    named.ip = ip(1, 1, 1, 1);
    named.name = "one.one.one.one";
    HostRow unnamed;
    unnamed.ip = ip(192, 168, 1, 14);
    unnamed.is_local = true;
    s.top_hosts = {named, unnamed};
    s.top_flows = {flow(6, 51000, 443, Category::Streaming), flow(17, 50000, 53, Category::Background),
                   flow(1, 0, 0, Category::Background), flow(47, 0, 0, Category::Other)};
    s.categories = {category(Category::Streaming, ClassMethod::FlowShape),
                    category(Category::Browsing, ClassMethod::KnownService),
                    category(Category::Other, ClassMethod::None)};
    s.status.explanation = "Nothing stands out right now.";
    return s;
}

}  // namespace

TEST_CASE("every term the dashboard can focus has something to say", "[dashboard][glossary]") {
    // A missing entry would show an empty Learn panel; catch it here instead.
    const Snapshot s = representative_snapshot();
    for (const auto& row : dashboard_focus_rows(s)) {
        REQUIRE_FALSE(row.terms.empty());
        for (const auto& term : row.terms) {
            INFO("row " << row.id << ", term " << term);
            const auto content = learn_content(term, s);
            REQUIRE(content.has_value());
            CHECK_FALSE(content->title.empty());
            CHECK_FALSE(content->text.empty());
        }
    }
}

TEST_CASE("glossary entries are unique and complete", "[glossary]") {
    std::set<std::string_view> keys;
    for (const auto& entry : glossary()) {
        INFO("key " << entry.key);
        CHECK(keys.insert(entry.key).second);
        CHECK_FALSE(entry.title.empty());
        CHECK(entry.text.size() > 40);
    }
    CHECK(find_glossary_entry("no-such-term") == nullptr);
    CHECK_FALSE(learn_content("no-such-term", Snapshot{}).has_value());
}

TEST_CASE("focus rows follow the on-screen section order with unique ids", "[dashboard]") {
    const Snapshot s = representative_snapshot();
    const auto rows = dashboard_focus_rows(s);
    REQUIRE(rows.size() == 2 + s.categories.size() + protocol_rows().size() + s.top_hosts.size() +
                               s.top_flows.size() + 1);
    CHECK(rows[0].id == kStatusRowId);
    CHECK(rows[1].id == kThroughputRowId);
    CHECK(rows[2].id == category_row_id(Category::Streaming));
    CHECK(rows[2 + s.categories.size()].id == protocol_rows().front().id);
    CHECK(rows[2 + s.categories.size() + protocol_rows().size()].id ==
          host_row_id(s.top_hosts.front().ip));
    CHECK(rows.back().id == kHealthRowId);

    std::set<std::string> ids;
    for (const auto& r : rows) CHECK(ids.insert(r.id).second);
}

TEST_CASE("row terms match what the row actually shows", "[dashboard]") {
    const Snapshot s = representative_snapshot();
    CHECK(host_terms(s.top_hosts[0]) ==
          std::vector<std::string>{"ip-address", "dns", "throughput", "local-address"});
    CHECK(host_terms(s.top_hosts[1]) ==
          std::vector<std::string>{"ip-address", "throughput", "local-address"});

    const std::string why0 = "why:flow:" + flow_row_id(s.top_flows[0].key);
    CHECK(flow_terms(s.top_flows[0]) == std::vector<std::string>{"flow", "tcp", "port", why0});
    CHECK(flow_terms(s.top_flows[2]).at(1) == "icmp");      // no ports
    CHECK(flow_terms(s.top_flows[3]).at(1) == "protocol");  // GRE etc.
    CHECK(flow_terms(s.top_flows[3]).size() == 3);

    // Categories explain themselves first, then how they were decided (if anything decided).
    CHECK(category_terms(s.categories[0]) ==
          std::vector<std::string>{"why:category:streaming", "flow-shape-heuristic"});
    CHECK(category_terms(s.categories[1]).at(1) == "known-domain-match");
    CHECK(category_terms(s.categories[2]).size() == 1);
}

TEST_CASE("'why' terms explain this moment's judgments from the snapshot", "[dashboard]") {
    Snapshot s = representative_snapshot();

    auto status = learn_content("why:status", s);
    REQUIRE(status);
    CHECK(status->text == "Nothing stands out right now.");
    s.status.kind = StatusKind::DeviceAboveUsual;
    CHECK(learn_content("why:status", s)->title == "Why this heads-up");

    auto cat = learn_content("why:category:streaming", s);
    REQUIRE(cat);
    CHECK(cat->title == "Why: Streaming / video");

    auto fl = learn_content("why:flow:" + flow_row_id(s.top_flows[0].key), s);
    REQUIRE(fl);
    CHECK(fl->text == s.top_flows[0].reason);

    // A row that has since disappeared has nothing to explain.
    CHECK_FALSE(learn_content("why:category:file-transfer", s).has_value());
}
