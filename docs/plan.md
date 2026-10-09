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
| 4. Core dashboard | **Done.** Focus model (follows items across re-sorts, unit-tested), Learn panel, scrolling, keyboard + mouse wheel; verified by driving it with real keystrokes |
| 5. Teaching layer | **Done, pending live check.** Classifier and status line (pure, unit-tested), category section, per-device "now" rates, and "why" explanations for every judgment. Verified end to end on a 70 s replay with one of each traffic pattern; still needs a look on real traffic and threshold tuning |
| 6. Benchmarking & least privilege | **Done.** Three measured changes: no per-packet allocation, batched hand-off, kernel-side truncation. Live TCP capture 47% → 5% of a core; the capture no longer slows the traffic it measures. See [benchmarks.md](benchmarks.md) |
| 7. Docs, CI, polish | **Mostly done.** Fresh-clone test passes (0 warnings, all tests). Remaining: confirm CI green on GitHub; tune thresholds on real traffic |
| Phase 2: DNS names | **Done, verified live.** Opt-in `--dns-names`: a BPF filter keeps 512 bytes of DNS/mDNS responses only; a hardened DNS parser (loop-proof compression pointers, no control characters) names addresses from the answers devices receive. Verified on the replay fixture (video and call become known-service matches) and live on WSL's `eth0` (a real DNS answer named the HTTPS server it pointed to; the interface's subnets were picked up as local). TLS SNI deliberately deferred (see below) |
| Phase 2: demo and usability | **Done.** `--demo` runs a simulated household through the real pipeline (no permissions needed; tested end to end), recorded as the README's animated `docs/demo.svg`. Dashboard: Enter drills into a device's conversations, Space pauses, `?` lists keys, a context hint shows the useful key for the current row, and the layout adapts down to 80 columns |
| Phase 2: native Windows | **Done, live capture verified.** Npcap capture, MSVC build (no warnings at /W4), the same code above the capture layer. Adapters by their Windows names ("Wi-Fi"), the default skips virtual adapters (WSL, Hyper-V, VirtualBox) and unconnected ones; the kernel filter is installed in the Npcap driver, and measured to truncate there. All tests pass on Windows (the benchmark and fuzz drivers are Linux-only); CI builds and tests it. The interactive dashboard on Windows Terminal still needs a look |
| Phase 2: fuzzing | **Done.** libFuzzer, 2 minutes per target locally: 9.3 M frames, 17 M DNS messages, 128 M filter comparisons, no failures. Three targets with checked properties (packet parser + aggregator, DNS-answer parser, and the kernel filter differentially against the parser), run as tests everywhere and as libFuzzer in CI. Found that the DNS parser's loop protection rested on the name-length cap, not on its pointer rule as documented; fixed |
| Phase 2: IPv6 | **Done.** IPv6 with extension-header chains and fragments, IPv4/IPv6 split in the protocol view, IPv6-aware labels, resolver and classifier; fuzzed under ASan. "Local" now means the capture interface's own subnets too (IPv6 home devices have public addresses), plus `--local` for replays. Still unverified on a real IPv6 network: WSL2's NAT mode has no IPv6 connectivity |

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
5. *(Stage 5)* **Streaming vs. file transfer was backwards.** The original rule called steady flows
   streaming and bursty ones file transfers; adaptive video actually arrives in on/off bursts while
   downloads run flat out. The classifier uses duty cycle accordingly.
6. *(Stage 5)* **QUIC.** Much streaming is UDP on port 443, which TCP-only rules would miss; UDP 443
   is treated as web traffic.
7. *(Stage 5)* **`steamcontent.com`** serves game downloads, so it maps to File transfer, not
   Calls/Gaming.
8. *(Stage 5)* **Status guard rails** the original spec didn't have: a 60 s warm-up (otherwise every
   device is "new" at startup), a minimum traffic level (3x of almost nothing is noise), a 10 s hold
   (no flicker), and the tool-health check moved to first priority (when NetPulse is dropping
   packets, its other numbers are less trustworthy).
9. *(Stage 6)* **libpcap's snaplen doesn't truncate in the kernel** on Linux's memory-mapped path: the
   kernel copied whole packets into the capture ring and libpcap trimmed them afterwards. That made
   the "payloads are never captured" claim false and cost 46% of a core on TCP bulk. Fixed with a
   one-instruction kernel socket filter; see benchmarks.md, step 4.
10. *(Fuzzing)* **"Backward-only" compression pointers don't prevent loops** in DNS names: a pointer
    can jump back to labels that lead forward to the same pointer. Names like that were only ever
    rejected by the 253-character cap. Now each jump must land before everything already read for
    the name, which bounds the jumps by the message length.

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

## Deliberately deferred

- **TLS SNI (server name from the TLS handshake).** Would name HTTPS connections even when DNS
  answers aren't seen (DNS over HTTPS, cached lookups). Not done yet because doing it properly
  is a multi-week feature: modern Chrome sends ~1.8 kB ClientHellos (post-quantum key shares)
  split across two TCP segments, with extension order randomized, so finding the name needs
  reassembly of each connection's first flight; QUIC carries its ClientHello encrypted with
  per-connection keys; and Encrypted Client Hello hides the name entirely on a growing share of
  sites. It would also widen the opt-in payload exception beyond DNS.
- **Security-grade anomaly detection.** The status line is deliberately a few literal checks; real
  detection (scans, statistical baselines, false-positive tuning) is a different, harder problem.
