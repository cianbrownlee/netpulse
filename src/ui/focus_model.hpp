#pragma once

#include <cstddef>
#include <string>
#include <vector>

namespace netpulse {

// One selectable row on the dashboard. `id` identifies *what* the row shows (a host, a flow, a
// protocol), not where it currently sits, so focus can follow it when live rows re-sort.
// `terms` are glossary keys for the technical terms on the row, in left-to-right order.
struct FocusRow {
    std::string id;
    std::vector<std::string> terms;
};

// Keyboard focus over a list of rows that is rebuilt on every refresh.
//
// The rows under the cursor change constantly: top talkers re-rank, flows appear and expire.
// Index-based focus would make the cursor silently jump to a different device whenever the
// ranking shifts, and the explanation panel would change under the reader. Instead the model
// remembers the focused row's id and finds it again after each update; only if that row has
// disappeared does it fall back to the same position, clamped to the new list.
//
// Pure logic with no UI dependency, so it is unit-tested directly.
class FocusModel {
public:
    void update(std::vector<FocusRow> rows);

    void move_row(int delta);   // up/down; stops at the ends
    void move_term(int delta);  // left/right within the focused row; stops at the ends

    bool empty() const { return rows_.empty(); }
    const FocusRow* focused_row() const;
    const std::string* focused_term() const;  // nullptr if nothing is focusable
    std::size_t term_index() const { return term_; }
    bool is_focused(const std::string& row_id) const;

private:
    void clamp_term();

    std::vector<FocusRow> rows_;
    std::size_t index_ = 0;
    std::size_t term_ = 0;
    std::string focused_id_;  // survives updates, including ones where the list is empty
};

}  // namespace netpulse
