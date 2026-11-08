# NetPulse

A live network traffic analyzer for Linux and Windows, written in C++20. It captures packet headers (never contents) with libpcap or Npcap, parses Ethernet, IPv4 or IPv6, and TCP/UDP, and shows throughput, protocol mix, top talkers and conversations in a terminal dashboard. It is meant to teach as well as measure: put the cursor on any number, label or judgment and the Learn panel explains what it means and why NetPulse reached that conclusion.

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

Main design decisions (more in [docs/design.md](docs/design.md)):

- **Capture does not wait on processing.** The queue between the capture and aggregator threads is bounded. When it is full, the packet is dropped and counted, so a slow consumer can't push loss into the kernel buffer where nobody would see it. Both kinds of loss, NetPulse's queue and the kernel buffer, are shown on screen.
- **Headers only, enforced in the kernel.** 192 bytes covers the deepest header stack NetPulse parses. A classic-BPF filter truncates every packet to that length before it is copied to NetPulse. On Linux it is attached to the capture socket, and on Windows it is installed in the Npcap driver. On Linux, libpcap's snaplen setting trims in user space after the kernel has already copied the whole packet, which I found by measurement. On Windows, measured during a download, only DNS answers arrive longer than 192 bytes (see [docs/benchmarks.md](docs/benchmarks.md)).
- **DNS answers are the one opt-in exception.** With `--dns-names`, the filter keeps up to 512 bytes of DNS and mDNS responses (and nothing more of anything else), so NetPulse can read which names your devices looked up, for example "142.250.72.14 is www.youtube.com". That names addresses reverse DNS can't, and turns many pattern guesses into known-service matches. It is off by default because it means reading the contents of one kind of packet. Names from the network are treated as hostile input. Each compression pointer must land before everything already read for that name, so pointers can't loop (requiring "backwards" alone wasn't enough, which fuzzing showed), and names with control characters are rejected so a DNS answer can't inject escape codes into your terminal.
- **No heap allocation and no per-packet locking on the hot path.** Packets are fixed-size values in a preallocated ring, handed between threads in batches. The full pipeline handles about 9.5 M packets/s, 3.5x the first version. Capturing about 80 Gbit/s of loopback TCP live costs 5% of one core, down from 47%, and NetPulse no longer slows the traffic it measures (it used to cut it by about 79%). [docs/benchmarks.md](docs/benchmarks.md) shows how each of these was found.
- **Least privilege.** On Linux the binary gets `CAP_NET_RAW` and `CAP_NET_ADMIN` through `setcap` instead of running as root. On Windows, Npcap's default install lets ordinary users capture. If permission is missing, NetPulse prints the exact fix instead of an errno string.

## How NetPulse classifies traffic

NetPulse never reads packet contents, and most traffic is encrypted anyway, so anything it says about what traffic is for is an inference. Each inference is labeled with how it was made, and selecting it shows the evidence.

Traffic categories (streaming, browsing, calls/gaming, file transfer, other) are assigned in this order:

1. **Background.** DNS, NTP, DHCP, device discovery and ICMP are real but negligible, so they are left out of the breakdown.
2. **Known-domain match.** The remote address's name (its reverse-DNS name, or with `--dns-names` the name a device actually looked up) is checked against a short built-in list (for example `nflxvideo.net` is streaming). This is reliable when it matches, but many services' addresses have no matching reverse-DNS name (CDNs especially), which is what `--dns-names` is for.
3. **Flow shape.** Duration, volume, direction, and duty cycle (the share of seconds that carried traffic). A file download runs flat out, close to 100%. Video players fetch a few seconds ahead and pause, which gives on/off bursts. UDP on port 443 is QUIC (how YouTube and many large sites deliver content) and is treated as web traffic. Calls and games are steady, two-way streams of small UDP packets.
4. Anything else is shown as Other instead of being forced into a category.

The status line runs a few specific "worth noticing" checks. It is not threat detection, so it can be amber but never red. In priority order the checks are: NetPulse itself missing more than 1% of packets, a device moving more than 3x its own average, a newly appeared device taking more than 30% of traffic, and most traffic going to an address with no reverse-DNS name. Each check has guard rails (a warm-up period, minimum traffic levels, and a short hold so messages don't flicker), and all thresholds are tunable constants. The unnamed-address check will fire on some perfectly normal services, since many CDNs publish no reverse-DNS names, and its explanation says so.

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

- **Unit tests (Catch2)** cover header parsing for IPv4 and IPv6 (every truncated prefix of a frame, inconsistent headers, hostile IPv6 extension-header chains, and 20,000 random garbage frames), the bounded queue (including multi-producer, multi-consumer exactly-once tests), flow keys, the throughput window, aggregation, the classifier and status checks, the dashboard's focus and explanation logic, the async resolver, and formatting.
- **End-to-end tests** replay two captures through the real capture, queue and aggregator pipeline. `synthetic.pcap` checks parsing and counting. `traffic_mix.pcap` holds one conversation of each traffic pattern and checks that each lands in the right category and that the status line flags the big download at the end. Both are generated by [`tools/make_synthetic_pcap.py`](tools/make_synthetic_pcap.py), which builds frames independently of the C++ code. Replays run on the file's own clock, so results are the same on every machine. The demo also runs through the pipeline in a test, which checks that it still shows what it is meant to.
- **Fuzzing** ([`fuzz/`](fuzz/)) targets the code that reads untrusted bytes and checks properties instead of only "doesn't crash". The packet parser and aggregator get arbitrary frames. The DNS-answer parser gets arbitrary messages and must only return terminal-safe names. The kernel capture filter is checked against the C++ parser, since they are two independent answers to "is this a DNS response?" and must agree on every frame. Each target runs as an ordinary test (seed frames plus random mutations), and with clang as a coverage-guided libFuzzer binary: `tools/fuzz.sh [seconds]`. Bugs injected on purpose (wrong ports, a dropped fragment check, a wrong header offset, a pointer loop, a control-character leak) are each caught.
- **CI** (GitHub Actions) runs a `-Werror` release build, an AddressSanitizer + UndefinedBehaviorSanitizer build, and a ThreadSanitizer build. A fourth job fuzzes each target for a minute with libFuzzer, and a fifth builds with MSVC on Windows (warnings as errors) and runs the tests there.

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
