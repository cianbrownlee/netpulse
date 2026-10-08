#pragma once

#include <ostream>
#include <string>

#include "aggregate/snapshot.hpp"

namespace netpulse {

// Multi-line text summary of a snapshot, for --plain mode, piped output, and the end-of-run
// report. The final "summary:" line is stable key=value text meant for scripts and tests.
void print_report(std::ostream& out, const Snapshot& snapshot, const std::string& source);

}  // namespace netpulse
