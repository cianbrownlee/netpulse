#pragma once

namespace netpulse {

class Pipeline;

// Full-screen live dashboard (FTXUI). Redraws from the pipeline's latest snapshot every
// 250 ms until the user quits (q / Esc / Ctrl-C) or capture fails. A replayed file stays on
// screen after it finishes so the final numbers can be read.
void run_dashboard(Pipeline& pipeline);

}  // namespace netpulse
