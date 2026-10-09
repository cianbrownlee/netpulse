# NetPulse

A live network traffic analyzer for Linux and Windows, written in C++20. It captures packet
**headers** (never contents) with libpcap or Npcap, parses Ethernet → IPv4 or IPv6 → TCP/UDP,
and shows
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
  parses. A classic-BPF filter truncates every packet to that length *before* it's copied to
  NetPulse: attached to the capture socket on Linux, installed in the Npcap driver on Windows.
  libpcap's snaplen setting alone doesn't do this on Linux: it trims in user space after the
  kernel has already copied the whole packet, which was found by measurement. On Windows,
  measured during a download, nothing but DNS answers arrives longer than 192 bytes (see
  [docs/benchmarks.md](docs/benchmarks.md)).
- **One opt-in exception: DNS answers.** With `--dns-names`, the filter keeps up to 512 bytes of
  DNS and mDNS *responses* (and nothing more of anything else), so NetPulse can read which names
  your devices looked up: "142.250.72.14 is www.youtube.com". That names addresses reverse DNS
  can't, and turns many pattern guesses into known-service matches. It's off by default because
  it means reading the contents of one kind of packet. Names from the network are treated as
  hostile input: each compression pointer must land before everything already read for that
  name, so pointers can't loop ("backwards" alone wasn't enough, which fuzzing showed), and
  anything with control characters is rejected, so a DNS answer can't inject escape codes into
  your terminal.
- **Least privilege.** On Linux the binary gets `CAP_NET_RAW` + `CAP_NET_ADMIN` via `setcap`
  instead of running as root; on Windows, Npcap's default install lets ordinary users capture.
  Missing permission produces the exact fix, not an errno string.
- **One codebase, two capture systems.** Everything above the capture layer (parsing,
  aggregation, the classifier, the dashboard) is the same on Linux and Windows. The platform
  differences are the capture filter's installation, adapter naming ("Wi-Fi" rather than
  `\Device\NPF_{…}`), and a few small system calls in one file.
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

## Building on Linux (WSL2 / Ubuntu 24.04)

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

## Building and running on Windows

Needs [Npcap](https://npcap.com) (installed with Wireshark, or on its own; the free edition is
fine), the [Npcap SDK](https://npcap.com/#download) unpacked anywhere, Visual Studio 2022 or
its Build Tools with the C++ workload, CMake and Git. In a PowerShell or Developer prompt:

```powershell
cmake -S . -B build -DNPCAP_SDK=C:/path/to/npcap-sdk
cmake --build build --config Release
build\Release\netpulse.exe --list-interfaces
build\Release\netpulse.exe                 # dashboard on the active adapter (q to quit)
build\Release\netpulse.exe -i Wi-Fi --dns-names
```

No administrator rights are needed unless Npcap was installed with "Restrict Npcap driver's
access to Administrators only". Interfaces go by their Windows names ("Wi-Fi", "Ethernet"), or
any unique part of the adapter's description. By default NetPulse picks the connected hardware
adapter, skipping virtual ones like WSL's and Hyper-V's. Unlike WSL, this sees the whole
machine's traffic: browsers, calls, games and downloads. Run it in Windows Terminal for the
dashboard's colors and box drawing.

The benchmark and the fuzzing harnesses are Linux-only for now.

## Running on Linux

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
not the rest of the machine's. The packets are real; the vantage point is just narrower. The
Windows build sees everything the machine sends and receives.

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
- **Fuzzing** ([`fuzz/`](fuzz/)): the code that reads untrusted bytes, checked against
  properties rather than just "doesn't crash". The packet parser and aggregator get arbitrary
  frames; the DNS-answer parser gets arbitrary messages and must only return terminal-safe
  names; and the kernel capture filter is checked *differentially* against the C++ parser,
  since they're two independent answers to "is this a DNS response?" and must agree on every
  frame. Each target runs as an ordinary test (seed frames plus random mutations), and with
  clang as a coverage-guided libFuzzer binary: `tools/fuzz.sh [seconds]`. Deliberately
  injected bugs (wrong ports, a dropped fragment check, a wrong header offset, a pointer loop,
  a control-character leak) are each caught.
- **CI** (GitHub Actions) runs everything three ways: a `-Werror` release build,
  AddressSanitizer + UndefinedBehaviorSanitizer, and ThreadSanitizer. A fourth job fuzzes each
  target for a minute with libFuzzer, and a fifth builds with MSVC on Windows (warnings as
  errors) and runs the tests there.

To run a sanitizer build locally:

```bash
cmake -S . -B ~/netpulse-asan -DCMAKE_BUILD_TYPE=Debug -DNETPULSE_SANITIZER=address,undefined
cmake --build ~/netpulse-asan -j && ctest --test-dir ~/netpulse-asan --output-on-failure
```

ThreadSanitizer on Ubuntu 24.04 kernels needs `sudo sysctl vm.mmap_rnd_bits=28` first, or run
individual binaries under `setarch "$(uname -m)" -R`.

## Layout

```
src/capture/    libpcap / Npcap capture (live + file replay), the kernel filter
src/demo/       simulated household traffic for --demo
src/parse/      Ethernet / IPv4 / IPv6 (with extension headers) / TCP / UDP parsing: pure functions
src/aggregate/  flows, hosts, throughput window, snapshots
src/resolve/    async reverse-DNS with cache
src/pipeline/   the threads and the hand-offs between them
src/ui/         FTXUI dashboard and plain-text report
src/util/       bounded queue, IPv4/IPv6 address type, formatting, platform calls
tests/          Catch2 suite
fuzz/           fuzz targets, the driver that runs them as tests, DNS seed corpus
tools/          fixture generator, live benchmark, demo recording (record_demo.sh draws
                docs/demo.svg from tmux captures with terminal_svg.py)
```

## License

MIT
