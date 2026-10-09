# NetPulse

A live network traffic analyzer for Linux, written in C++20. It captures packet **headers**
(never contents) with libpcap, parses Ethernet → IPv4 or IPv6 → TCP/UDP, and shows
throughput, protocol mix, top talkers and conversations in a terminal dashboard that explains
itself: put the cursor on any number, label or judgment and the Learn panel says what it means
and why NetPulse thinks so.

![NetPulse running its built-in demo: a household's traffic by category, protocol, device and conversation; the status line flags a big download, and the view drills into that device's conversations](docs/demo.svg)

Try it without capture permissions or interesting traffic of your own: `netpulse --demo` runs a
simulated household (the recording above) through the real pipeline.

> **Status:** working and tested (capture, IPv4/IPv6 parsing, aggregation, naming, the
> classifier and status line, the dashboard, benchmarks). Not yet tried on a wide range of
> real networks; the classifier's thresholds are starting points. See [`docs/plan.md`](docs/plan.md)
> for the plan and progress.

## Architecture

```
 ┌────────────────┐  bounded queue   ┌─────────────────────┐  immutable snapshot  ┌────────────┐
 │ capture thread │ ───────────────▶ │  aggregator thread  │ ───────────────────▶ │ UI thread  │
 │ libpcap,       │  header bytes,   │ parse, flows, top   │  shared_ptr swap     │ FTXUI or   │
 │ headers only   │  drop + count    │ talkers, throughput │  every 250 ms        │ --plain    │
 └────────────────┘  when full       └─────────────────────┘                      └────────────┘
                                               │  on-screen addresses only
                                               ▼
                                       ┌────────────────┐
                                       │ resolver pool  │  reverse DNS off the hot path
                                       └────────────────┘
```

Decisions worth knowing about:

- **Capture never waits on processing.** A slow consumer can't push loss back into the kernel
  buffer where it's invisible. The queue between them is bounded, and when it's full the packet
  is dropped *and counted*. Both kinds of loss (NetPulse's queue, the kernel buffer) are shown on
  screen, never hidden.
- **Headers only, enforced in the kernel.** 192 bytes covers the deepest header stack NetPulse
  parses. A kernel socket filter truncates every packet to that length *before* the kernel
  copies it to NetPulse. libpcap's snaplen setting alone doesn't do this on Linux: it trims in
  user space after the kernel has already copied the whole packet, which was found by
  measurement (see [docs/benchmarks.md](docs/benchmarks.md)).
- **One opt-in exception: DNS answers.** With `--dns-names`, the filter keeps up to 512 bytes of
  DNS and mDNS *responses* (and nothing more of anything else), so NetPulse can read which names
  your devices looked up: "142.250.72.14 is www.youtube.com". That names addresses reverse DNS
  can't, and turns many pattern guesses into known-service matches. It's off by default because
  it means reading the contents of one kind of packet. Names from the network are treated as
  hostile input: compression pointers may only point backwards (no loops), and anything with
  control characters is rejected, so a DNS answer can't inject escape codes into your terminal.
- **Least privilege.** The binary gets `CAP_NET_RAW` + `CAP_NET_ADMIN` via `setcap` instead of
  running as root. Missing permission produces the exact command to fix it, not an errno string.
- **DNS can't stall anything.** Reverse lookups run on worker threads with a session cache;
  a hung DNS server delays a name appearing, never the statistics, and never blocks quitting.
- **Conversations, not packets.** Flow keys are canonical, so both directions of a conversation
  share one entry, with byte counts per direction.
- **No heap allocation and no per-packet locking on the hot path.** Packets are fixed-size values
  in a preallocated ring, handed between threads in batches: ~9.5 M packets/s through the full
  pipeline, 3.5× the first version. Live, capturing ~80 Gbit/s of loopback TCP costs 5% of one
  core, down from 47%, and NetPulse no longer slows down the traffic it measures (it used to cut
  it by ~79%). [docs/benchmarks.md](docs/benchmarks.md) tells how each of those was found.

## How NetPulse makes its judgments (and where they fall short)

NetPulse never reads packet contents, and most traffic is encrypted anyway, so anything it
says about *what* traffic is for is an inference. Every inference is labeled with how it was
made, and selecting it shows the evidence.

**Traffic categories** (streaming, browsing, calls/gaming, file transfer, other):

1. *Background* first: DNS, NTP, DHCP, device discovery and ICMP are real but negligible, and
   are left out of the breakdown.
2. *Known-domain match*: the remote address's name (its reverse-DNS name, or with
   `--dns-names` the name a device actually looked up) is checked against a short built-in
   list (e.g. `nflxvideo.net` → streaming). Reliable when it fires, but many services'
   addresses have no matching reverse-DNS name (CDNs especially), which is what `--dns-names`
   is for.
3. *Flow-shape heuristic*: duration, volume, direction, and **duty cycle** (the share of seconds
   that carried traffic). A file download runs flat out, close to 100%; video players fetch a few
   seconds ahead and pause, giving on/off bursts. UDP on port 443 is QUIC (how YouTube and many
   large sites deliver content) and is treated as web traffic. Calls and games are steady,
   two-way streams of small UDP packets.
4. Anything else is shown as *Other* rather than forced into a category.

**Status line**: a few specific "worth noticing" checks, never threat detection, so it can be
amber but never red. In priority order: NetPulse itself missing more than 1% of packets; a
device moving more than 3x its own average; a newly appeared device taking more than 30% of
traffic; most traffic going to an address with no reverse-DNS name. Each check has guard rails
(a warm-up period, minimum traffic levels, and a short hold so messages don't flicker), and all
thresholds are tunable constants. The unnamed-address check will fire on some perfectly normal
services, since many CDNs publish no reverse-DNS names; its explanation says so.

## Building (WSL2 / Ubuntu 24.04)

```bash
sudo apt update && sudo apt install -y build-essential cmake libpcap-dev
```

Build **out of tree on the Linux filesystem**, even if the repo is on the Windows side
(`/mnt/c/...`). `setcap` can't store capabilities on the Windows mount, and builds are much
faster under `~`:

```bash
cmake -S . -B ~/netpulse-build
cmake --build ~/netpulse-build -j
```

FTXUI and Catch2 are fetched automatically by CMake (pinned versions).

## Running

Grant capture capabilities once (repeat after every rebuild, since rebuilding replaces the binary):

```bash
sudo setcap cap_net_raw,cap_net_admin=eip ~/netpulse-build/netpulse
```

Then, without `sudo`:

```bash
~/netpulse-build/netpulse                 # dashboard on the default interface (q to quit)
~/netpulse-build/netpulse -i eth0 --plain # text report every second
~/netpulse-build/netpulse --list-interfaces
```

Replay a capture file instead of live traffic (no special permissions needed). Rates follow the
file's own timestamps:

```bash
~/netpulse-build/netpulse --read sample_pcaps/synthetic.pcap
```

Or watch the built-in demo, also without permissions:

```bash
~/netpulse-build/netpulse --demo
```

The demo is a scripted household (a TV streaming over IPv6, a laptop watching video and
browsing, a phone on a call, a gaming PC that starts a big download about 10 seconds in) made
of real Ethernet frames, which go through the same parser, aggregator and classifier as
captured ones. Every address in it is from the ranges reserved for documentation.

In the dashboard: **↑↓** move between rows and **←→** step through a row's terms, each
explained in the Learn panel; **Enter** on a top talker lists only its conversations (**Esc**
goes back); **Space** pauses the display; **?** lists every key; **q** quits.

Under WSL2, `eth0` is a virtual adapter behind NAT, so NetPulse sees the WSL VM's own traffic,
not every device on your home network. The packets are real; the vantage point is just narrower.

**What counts as "local".** Private IPv4 ranges (192.168.x.x and so on) are obviously yours, but
IPv6 home networks usually give every device a *public* address. So a live capture also treats
everything inside the capture interface's own subnets as local (`--list-interfaces` shows them),
and `--local PREFIX` adds more, which mostly matters for replays:

```bash
~/netpulse-build/netpulse --read capture.pcap --local 2001:db8:1::/64
```

## Testing

```bash
ctest --test-dir ~/netpulse-build --output-on-failure
```

- **Unit tests (Catch2):** header parsing for IPv4 and IPv6 (including every truncated prefix
  of a frame, inconsistent headers, hostile IPv6 extension-header chains, and 20,000
  random-garbage frames), the bounded queue (including multi-producer/multi-consumer
  exactly-once tests), flow keys, the throughput window, aggregation, the classifier and status
  checks, the dashboard's focus and explanation logic, the async resolver, and formatting.
- **End-to-end:** two captures are replayed through the real capture → queue → aggregator
  pipeline. `synthetic.pcap` checks parsing and counting; `traffic_mix.pcap` holds one
  conversation of each traffic pattern and checks that each lands in the right category and
  that the status line flags the big download at the end. Both are generated by
  [`tools/make_synthetic_pcap.py`](tools/make_synthetic_pcap.py), which builds frames
  independently of the C++ code. Replays run on the file's own clock, so results are the same
  on every machine. The demo runs through the same pipeline in a test too, which checks that
  it still tells the story it's meant to.
- **CI** (GitHub Actions) runs everything three ways: a `-Werror` release build,
  AddressSanitizer + UndefinedBehaviorSanitizer, and ThreadSanitizer.

To run a sanitizer build locally:

```bash
cmake -S . -B ~/netpulse-asan -DCMAKE_BUILD_TYPE=Debug -DNETPULSE_SANITIZER=address,undefined
cmake --build ~/netpulse-asan -j && ctest --test-dir ~/netpulse-asan --output-on-failure
```

ThreadSanitizer on Ubuntu 24.04 kernels needs `sudo sysctl vm.mmap_rnd_bits=28` first, or run
individual binaries under `setarch "$(uname -m)" -R`.

## Layout

```
src/capture/    libpcap wrapper (live + file replay)
src/demo/       simulated household traffic for --demo
src/parse/      Ethernet / IPv4 / IPv6 (with extension headers) / TCP / UDP parsing: pure functions
src/aggregate/  flows, hosts, throughput window, snapshots
src/resolve/    async reverse-DNS with cache
src/pipeline/   the threads and the hand-offs between them
src/ui/         FTXUI dashboard and plain-text report
src/util/       bounded queue, IPv4/IPv6 address type, formatting
tests/          Catch2 suite
tools/          fixture generator, live benchmark, demo recording (record_demo.sh draws
                docs/demo.svg from tmux captures with terminal_svg.py)
```

## License

MIT
