# Benchmarks

How fast NetPulse's capture pipeline is, what limited it, and what changed. Measured, not
asserted: every number below comes from a command in this repo, and each optimization was
measured on its own against the same harness.

**Machine:** AMD Ryzen 9 9955HX (16 cores / 32 threads), Ubuntu 24.04 under WSL2, GCC 13.3,
`RelWithDebInfo` build.

## TL;DR

| | Baseline | A: no per-packet allocation | **B: + batched hand-off** |
|---|---|---|---|
| Max throughput | 2.73 M packets/s | 4.55 M | **8.33 M (3.0×)** |
| CPU per packet | 505 ns | 401 ns | **167 ns (−67%)** |
| Heap allocations per packet | 1.08 | 0 | 0 |
| Context switches per 1,000 packets | 22 | 3 | 3.5 |
| Dropped at 3 M packets/s offered | 8.7% | 0.14% | 0.06% |

(Medians of 3 runs, synthetic benchmark; details below.)

## What was slow

The first live measurement (`tools/bench_live.sh`, iperf3 over loopback) showed NetPulse using
**47% of a core to capture ~73k packets/s of TCP**, about 6 µs per packet, when parsing and counting
a packet should take well under 1 µs. A per-thread breakdown during that run:

| Thread | User CPU | System CPU | Voluntary context switches |
|---|---|---|---|
| capture | 0.47 s | **3.50 s** | **148,780** |
| aggregator | 0.50 s | 0.83 s | 141,647 |

The time was going to the kernel, not to NetPulse's own logic: the two threads were waking each
other up roughly 12,000 times a second each, taking the queue's lock once per packet, and every
packet also cost a heap allocation (a `std::vector` for its bytes, plus the `std::deque`'s nodes),
allocated on the capture thread and freed on the aggregator thread.

## The changes

**A. No heap allocation on the hot path.** A queued packet became a fixed-size value (a 256-byte
inline array; capture is headers-only with a 192-byte snaplen, and the parser never needs more
than 138 bytes) instead of a heap-allocated vector, and the queue became a ring of slots allocated
once at startup instead of a `std::deque`. Allocations per packet: 1.08 → 0.

**B. Batched hand-off.** The capture side gathers packets into batches of up to 256 and queues a
whole batch under one lock; the aggregator takes up to 256 per lock. One lock acquisition and
one wake-up now cover hundreds of packets instead of one. Batches are flushed every time libpcap
hands back a block, so this adds no latency beyond the kernel's own buffering. The batch size is a
setting, and `--batch 1` reproduces step A exactly, which is how A and B were measured separately.

What did *not* change: the queue is still a plain mutex + condition-variable bounded queue. A
lock-free queue would be the next step if a measurement ever pointed at the lock itself; with
batching, it's taken a few thousand times a second.

## Synthetic benchmark: the pipeline itself

`netpulse_bench` pushes synthetic packets (2,000 conversations mixing HTTPS, SSH, DNS and
call-like UDP) through the real pipeline (queue, parser, aggregator, snapshots, classifier,
status checks) with no libpcap or kernel in the loop, so it measures NetPulse's own cost and
needs no capture permission.

```bash
~/netpulse-build/netpulse_bench                     # max throughput: the producer waits for room
~/netpulse-build/netpulse_bench --rate 3000000      # fixed offered rate; the producer never waits,
                                                    # as live capture doesn't, so overload shows as drops
~/netpulse-build/netpulse_bench --batch 1           # step A behavior (no batching)
```

The baseline was measured by building this same harness against commit `591ce97` (the code before
both changes, with a two-line shim so the newer harness compiles; the shim configures batching,
which that code doesn't have).

### Maximum throughput (10 M packets; three runs each)

| Run | Baseline | A | B |
|---|---|---|---|
| 1 | 2.81 M/s, 496 ns CPU | 4.67 M/s, 388 ns | 8.36 M/s, 166 ns |
| 2 | 2.70 M/s, 514 ns | 4.50 M/s, 405 ns | 8.33 M/s, 167 ns |
| 3 | 2.73 M/s, 505 ns | 4.55 M/s, 401 ns | 8.19 M/s, 169 ns |

### Fixed offered rate (12 M packets; the producer never waits)

Drop rates are only comparable at equal offered load, so the *achieved* offered rate is reported
too. The baseline's producer couldn't reach more than ~3.2 M packets/s at all: it was slowed by the
same per-packet allocation.

| Offered (target) | Baseline: offered → dropped | A | B |
|---|---|---|---|
| 2 M/s | 2.00 → 0.05% | 2.00 → 0.07% | 2.00 → 0.01% |
| 3 M/s | 2.96 → **8.72%** | 3.00 → 0.14% | 3.00 → **0.06%** |
| 4 M/s | 3.23 → 13.0% | 3.99 → 1.22% | 4.00 → 0.39% |
| 6 M/s | 2.99 → 7.59% | 5.02 → 29.5% | 5.98 → **0.94%** |

Small drop rates below capacity (e.g. 0.39% at 4 M/s for B) come from the harness pacing in
bursts of 4,096 packets into a 4,096-slot queue, which is not unlike real traffic bursts.

All runs account for every packet (`processed + dropped = sent`), and every mode also runs clean
under ThreadSanitizer.

## Live capture: loopback with iperf3

```bash
tools/bench_live.sh ~/netpulse-build/netpulse 10
```

iperf3 generates traffic over the loopback interface while NetPulse captures it. This includes
everything the synthetic benchmark leaves out: libpcap, the kernel's capture ring, and the real
arrival pattern.

| Test (10 s) | Version | Packets/s seen | Missed | NetPulse CPU |
|---|---|---|---|---|
| TCP bulk (18.9 Gbit/s) | baseline | ~73k | 0.12% (kernel) | 47% of a core |
| UDP flood, 64-byte packets | baseline | ~400k | 0 | 19% of a core |
| TCP bulk | after | *pending* | | |
| UDP flood | after | *pending* | | |

Note what loopback TCP looks like to a capture: the kernel hands over ~64 kB offloaded segments
rather than 1,500-byte packets, so ~19 Gbit/s is only ~73k "packets" per second. The UDP flood
(limited by iperf3 itself at ~400k packets/s here) is the packet-rate stress test.
