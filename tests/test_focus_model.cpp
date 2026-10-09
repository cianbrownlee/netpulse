#include <catch2/catch_test_macros.hpp>

#include "ui/focus_model.hpp"

using netpulse::FocusModel;
using netpulse::FocusRow;

namespace {

std::vector<FocusRow> rows(std::initializer_list<const char*> ids) {
    std::vector<FocusRow> out;
    for (const char* id : ids) out.push_back({id, {std::string(id) + "-term"}});
    return out;
}

std::string focused(const FocusModel& m) { return m.focused_row() ? m.focused_row()->id : "<none>"; }

}  // namespace

TEST_CASE("an empty model has nothing focused and ignores movement", "[focus]") {
    FocusModel m;
    CHECK(m.empty());
    CHECK(m.focused_row() == nullptr);
    CHECK(m.focused_term() == nullptr);
    m.move_row(1);
    m.move_term(1);
    CHECK(m.focused_row() == nullptr);
}

TEST_CASE("focus starts on the first row and stops at both ends", "[focus]") {
    FocusModel m;
    m.update(rows({"a", "b", "c"}));
    CHECK(focused(m) == "a");
    m.move_row(-1);
    CHECK(focused(m) == "a");
    m.move_row(1);
    CHECK(focused(m) == "b");
    m.move_row(10);
    CHECK(focused(m) == "c");
    CHECK(m.is_focused("c"));
    CHECK_FALSE(m.is_focused("b"));
}

TEST_CASE("focus follows the same item when live rows re-sort", "[focus]") {
    // e.g. top talkers: the device under the cursor moves from 2nd place to 4th.
    FocusModel m;
    m.update(rows({"host:1", "host:2", "host:3", "host:4"}));
    m.move_row(1);
    REQUIRE(focused(m) == "host:2");

    m.update(rows({"host:1", "host:3", "host:4", "host:2"}));
    CHECK(focused(m) == "host:2");
    CHECK(*m.focused_term() == "host:2-term");
}

TEST_CASE("if the focused item disappears, focus stays at the same position", "[focus]") {
    FocusModel m;
    m.update(rows({"a", "b", "c", "d"}));
    m.move_row(1);  // b
    m.update(rows({"a", "c", "d"}));
    CHECK(focused(m) == "c");  // whatever now sits where b was

    m.move_row(1);  // d, the last row
    m.update(rows({"a", "c"}));
    CHECK(focused(m) == "c");  // clamped to the new last row
}

TEST_CASE("focus survives a refresh with no rows at all", "[focus]") {
    FocusModel m;
    m.update(rows({"a", "b"}));
    m.move_row(1);
    m.update({});
    CHECK(m.focused_row() == nullptr);
    m.update(rows({"x", "a", "b"}));
    CHECK(focused(m) == "b");
}

TEST_CASE("left and right move between the terms on a row", "[focus]") {
    FocusModel m;
    m.update({{"flow", {"flow", "tcp", "port"}}, {"icmp-flow", {"flow", "icmp"}}, {"one", {"x"}}});
    CHECK(*m.focused_term() == "flow");
    m.move_term(1);
    m.move_term(1);
    CHECK(*m.focused_term() == "port");
    m.move_term(5);
    CHECK(*m.focused_term() == "port");  // stops at the last term
    CHECK(m.term_index() == 2);

    m.move_term(-1);
    m.move_term(-1);
    m.move_term(-1);
    CHECK(*m.focused_term() == "flow");  // stops at the first term
}

TEST_CASE("moving to another row starts on that row's main term", "[focus]") {
    FocusModel m;
    m.update({{"throughput", {"throughput", "packet"}}, {"proto:tcp", {"tcp", "packet"}}});
    m.move_term(1);
    REQUIRE(*m.focused_term() == "packet");
    m.move_row(1);
    CHECK(*m.focused_term() == "tcp");

    // Bumping into the end of the list is not a move, so the term stays put.
    m.move_term(1);
    m.move_row(1);
    CHECK(*m.focused_term() == "packet");
}

TEST_CASE("a refresh keeps the term position on the same row", "[focus]") {
    FocusModel m;
    m.update({{"f1", {"flow", "tcp", "port"}}});
    m.move_term(2);
    m.update({{"new", {"flow"}}, {"f1", {"flow", "tcp", "port"}}});
    CHECK(*m.focused_term() == "port");
}
