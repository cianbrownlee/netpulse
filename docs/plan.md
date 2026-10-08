# NetPulse: staged development plan

The milestones from the original design doc (kept as private notes, not in this repo), reorganized into
checkpointed stages sized for part-time work (~10-15 hrs/week, ~8-9 weeks total). Each stage
ends with something runnable and a check-in before moving on.

## Progress

| Stage | Status |
|---|---|
| 0. Environment & scaffolding | **Done, live capture verified.** Remaining: capture real fixtures, push to GitHub so CI runs |
| 1. Header parsing | **Done.** 15 parser test cases incl. truncation, malformed headers, random garbage |
| 2. Concurrency core | **Done, verified on live traffic**, except the load test under `iperf3` |
| 3. Async hostname resolution | **Done, verified live** (real reverse-DNS names appear) |
| 4. Core dashboard | **Thin slice done** (render-only). Selection-model spike and layout polish remain |
| 5. Teaching layer | Not started |
| 6. Benchmarking & least privilege | `setcap` flow + actionable permission error done; benchmarking not started |
| 7. Docs, CI, polish | CI workflow written (3 jobs); README is a working draft |

## Corrections folded in before building

1. **No zero-copy across the queue.** libpcap reuses its callback buffer, so a view can't cross
   the thread boundary. The copy is kept small instead (192-byte snaplen: headers only), and the
   real Stage 6 optimization is a reused buffer pool. Design doc 3.1 and 5 updated.
2. **Section order** in the design doc fixed (3.6 / 3.7 now follow 3.5).
3. *(Found while building)* **`getnameinfo()` has no timeout**, so the doc's "500 ms timeout"
   wasn't implementable. Replaced by isolation: lookups only on worker threads, detached at
   shutdown. Design doc 3.6 updated.
4. *(Found while building)* **`setcap` doesn't work on `/mnt/c`** (no xattrs on DrvFs), so the build
   directory must live on the Linux filesystem. Design doc Section 10 updated.

## Stages

### Stage 0: Environment & scaffolding
- WSL2 Ubuntu with `build-essential cmake libpcap-dev`; repo layout per design doc 4.1
- CMake build, `.clang-format`, MIT license, CI from day one
- Minimal capture loop, sample `.pcap` fixtures
- **Checkpoint:** live capture counts real traffic; CI green; fixtures captured.

### Stage 1: Header parsing (pure, unit-tested)
- Ethernet (+802.1Q) → IPv4 → TCP/UDP as pure functions over `std::span`
- Catch2: known-good frames, every truncated prefix, inconsistent headers, random garbage
- **Checkpoint:** tests green; parser output matches `tshark` on real fixtures.

### Stage 2: Concurrency core (no UI)
- Capture thread → bounded queue (drop-and-count) → aggregator thread → snapshot
- Totals, per-protocol counters, canonical bidirectional flows, top talkers, sliding-window
  throughput, idle-flow expiry
- `--plain` stdout reports
- **Checkpoint:** sane numbers under `iperf3` load, no hangs, drop counter behaves under overload.

### Stage 3: Async hostname resolution
- Worker threads + session cache; non-blocking lookups; only on-screen addresses resolved
- **Checkpoint:** a slow/blackholed DNS server never stalls the pipeline.

### Stage 4: Core dashboard (FTXUI)
- *Pulled forward as a thin slice:* header, throughput + sparkline, protocol gauges, top talkers,
  top flows, capture-health footer. Render-only.
- Remaining: a throwaway spike proving the selectable-focus model from design doc 3.3 works in
  FTXUI (highest-risk item in the project), then layout polish toward the 3.3 mock.
- **Checkpoint:** live dashboard on real traffic; focus-model spike works.

### Stage 5: Teaching layer
- **5a, logic first:** classifier (3.4) and status sentence (3.5) as pure, unit-tested functions.
  Needs per-host recent throughput vs. rolling average, and "new device" tracking.
- **5b, UI:** focus cursor, persistent "Learn:" panel, glossary, known-domains table,
  classifier-tag explanations.
- **Checkpoint:** 5a tests green; dashboard matches the 3.3 mock end to end.

### Stage 6: Benchmarking & least privilege
- `iperf3` / `tcpreplay` load; packets/s and CPU; one documented before/after optimization
  (buffer pool, and/or batched queue pops)
- **Checkpoint:** before/after numbers recorded; runs without `sudo`.

### Stage 7: Docs, CI, polish
- Full README (architecture diagram, benchmark results, classifier accuracy caveats)
- Fresh-clone test following only the README
- **Checkpoint:** demo-ready.

## Why this order
- UI late and split from logic, so the least predictable risk (FTXUI interactivity) never
  tangles with the parts that are easy to get right in isolation.
- Fixtures and CI first: cheap, and every later stage leans on them.
- Each checkpoint is also a scope checkpoint: if a stage runs long, trim scope there rather than
  letting the slip compound.
