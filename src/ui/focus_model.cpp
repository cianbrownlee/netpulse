#include "ui/focus_model.hpp"

#include <algorithm>
#include <utility>

namespace netpulse {

void FocusModel::update(std::vector<FocusRow> rows) {
    rows_ = std::move(rows);
    if (rows_.empty()) return;  // keep focused_id_: the row may come back next refresh

    const auto it = std::find_if(rows_.begin(), rows_.end(),
                                 [&](const FocusRow& r) { return r.id == focused_id_; });
    if (!focused_id_.empty() && it != rows_.end()) {
        index_ = static_cast<std::size_t>(it - rows_.begin());
    } else {
        index_ = std::min(index_, rows_.size() - 1);
    }
    focused_id_ = rows_[index_].id;
    clamp_term();
}

void FocusModel::move_row(int delta) {
    if (rows_.empty()) return;
    const auto last = static_cast<long long>(rows_.size()) - 1;
    const auto next = std::clamp(static_cast<long long>(index_) + delta, 0LL, last);
    if (static_cast<std::size_t>(next) == index_) return;
    index_ = static_cast<std::size_t>(next);
    focused_id_ = rows_[index_].id;
    // A new row always starts on its main term: pressing down onto the TCP row should explain
    // TCP, whatever term was being read on the row above.
    term_ = 0;
}

void FocusModel::move_term(int delta) {
    const FocusRow* row = focused_row();
    if (!row || row->terms.empty()) return;
    const auto last = static_cast<long long>(row->terms.size()) - 1;
    term_ = static_cast<std::size_t>(std::clamp(static_cast<long long>(term_) + delta, 0LL, last));
}

void FocusModel::clamp_term() {
    const FocusRow* row = focused_row();
    if (!row || row->terms.empty()) {
        term_ = 0;
        return;
    }
    term_ = std::min(term_, row->terms.size() - 1);
}

const FocusRow* FocusModel::focused_row() const {
    return rows_.empty() ? nullptr : &rows_[index_];
}

const std::string* FocusModel::focused_term() const {
    const FocusRow* row = focused_row();
    if (!row || row->terms.empty()) return nullptr;
    return &row->terms[term_];
}

bool FocusModel::is_focused(const std::string& row_id) const {
    return !rows_.empty() && rows_[index_].id == row_id;
}

}  // namespace netpulse
