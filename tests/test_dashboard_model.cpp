#include <catch2/catch_test_macros.hpp>
#include <set>
#include <string>

#include "frame_builder.hpp"
#include "ui/dashboard_model.hpp"
#include "ui/glossary.hpp"

using namespace netpulse;
using netpulse::test::ip;

namespace {

FlowRow flow(std::uint8_t protocol, std::uint16_t port_a, std::uint16_t port_b) {
    FlowRow f;
    f.key.ip_a = ip(10, 0, 0, 1);
    f.key.ip_b = ip(93, 184, 216, 34);
    f.key.port_a = port_a;
    f.key.port_b = port_b;
    f.key.protocol = protocol;
    return f;
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
    s.top_flows = {flow(6, 51000, 443), flow(17, 50000, 53), flow(1, 0, 0), flow(47, 0, 0)};
    return s;
}

}  // namespace

TEST_CASE("every term the dashboard can focus has a glossary entry", "[dashboard][glossary]") {
    // A missing entry would show an empty Learn panel; catch it here instead.
    for (const auto& row : dashboard_focus_rows(representative_snapshot())) {
        REQUIRE_FALSE(row.terms.empty());
        for (const auto& term : row.terms) {
            INFO("row " << row.id << ", term " << term);
            CHECK(find_glossary_entry(term) != nullptr);
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
}

TEST_CASE("focus rows follow the on-screen section order with unique ids", "[dashboard]") {
    const Snapshot s = representative_snapshot();
    const auto rows = dashboard_focus_rows(s);
    REQUIRE(rows.size() == 1 + protocol_rows().size() + s.top_hosts.size() + s.top_flows.size() + 1);
    CHECK(rows.front().id == kThroughputRowId);
    CHECK(rows[1].id == protocol_rows().front().id);
    CHECK(rows[1 + protocol_rows().size()].id == host_row_id(s.top_hosts.front().ip));
    CHECK(rows.back().id == kHealthRowId);

    std::set<std::string> ids;
    for (const auto& r : rows) CHECK(ids.insert(r.id).second);
}

TEST_CASE("row terms match what the row actually shows", "[dashboard]") {
    const Snapshot s = representative_snapshot();
    CHECK(host_terms(s.top_hosts[0]) == std::vector<std::string>{"ip-address", "dns", "local-address"});
    CHECK(host_terms(s.top_hosts[1]) == std::vector<std::string>{"ip-address", "local-address"});

    CHECK(flow_terms(s.top_flows[0]) == std::vector<std::string>{"flow", "tcp", "port"});
    CHECK(flow_terms(s.top_flows[1]) == std::vector<std::string>{"flow", "udp", "port"});
    CHECK(flow_terms(s.top_flows[2]) == std::vector<std::string>{"flow", "icmp"});      // no ports
    CHECK(flow_terms(s.top_flows[3]) == std::vector<std::string>{"flow", "protocol"});  // GRE etc.
}
