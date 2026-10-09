// Runs a fuzz target without libFuzzer, with any compiler: over seed inputs, then over random
// mutations of them. It isn't coverage-guided like libFuzzer, but it's deterministic and quick,
// so every fuzz target also runs as an ordinary test (under the sanitizers in CI) and replays any
// input libFuzzer saved.
//
// Usage: fuzz_<target> [--pcap FILE]... [--dns] [--mutations N] [--seed N] [FILE|DIR...]
//   FILE, DIR       inputs to run: files, or every file in a directory (a seed corpus, or a
//                   crash file libFuzzer saved)
//   --pcap FILE     seed with a capture file's frames (one per distinct packet shape)
//   --dns           seed with the DNS and mDNS messages in those frames instead (DNS target)
//   --mutations N   then run N randomly mutated copies of the seeds
//   --seed N        random seed for the mutations (default 1)
//
// If an input fails, it's written to fuzz-failure.bin before the process dies.

#include <fcntl.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <csignal>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <random>
#include <set>
#include <span>
#include <string>
#include <tuple>
#include <vector>

#include "parse/dns.hpp"
#include "parse/packet_parser.hpp"

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size);

namespace {

using Input = std::vector<std::uint8_t>;

const Input* g_current = nullptr;

// Saves the input being run when the target aborts or crashes. Only async-signal-safe calls.
void on_crash(int signal) {
    if (g_current) {
        const int fd = ::open("fuzz-failure.bin", O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (fd >= 0) {
            [[maybe_unused]] auto written = ::write(fd, g_current->data(), g_current->size());
            ::close(fd);
        }
        const char note[] = "fuzz: failing input written to fuzz-failure.bin\n";
        [[maybe_unused]] auto noted = ::write(STDERR_FILENO, note, sizeof note - 1);
    }
    std::signal(signal, SIG_DFL);
    std::raise(signal);
}

void run(const Input& input) {
    g_current = &input;
    LLVMFuzzerTestOneInput(input.data(), input.size());
    g_current = nullptr;
}

Input read_file(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        std::fprintf(stderr, "fuzz: can't read %s\n", path.c_str());
        std::exit(2);
    }
    return Input(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
}

// The frames of a classic pcap file (either byte order, micro- or nanosecond timestamps).
std::vector<Input> read_pcap(const std::string& path) {
    const Input file = read_file(path);
    std::vector<Input> frames;
    if (file.size() < 24) return frames;
    std::uint32_t magic = 0;
    std::memcpy(&magic, file.data(), 4);
    const bool swapped = magic == 0xd4c3b2a1 || magic == 0x4d3cb2a1;
    if (!swapped && magic != 0xa1b2c3d4 && magic != 0xa1b23c4d) {
        std::fprintf(stderr, "fuzz: %s is not a pcap file\n", path.c_str());
        std::exit(2);
    }
    auto u32 = [&](std::size_t at) {
        std::uint32_t v = 0;
        std::memcpy(&v, file.data() + at, 4);
        return swapped ? __builtin_bswap32(v) : v;
    };
    for (std::size_t at = 24; at + 16 <= file.size();) {
        const std::size_t length = u32(at + 8);
        if (at + 16 + length > file.size()) break;
        frames.emplace_back(file.begin() + static_cast<std::ptrdiff_t>(at + 16),
                            file.begin() + static_cast<std::ptrdiff_t>(at + 16 + length));
        at += 16 + length;
    }
    return frames;
}

// A few random edits, biased toward values that mean something in packet headers.
Input mutate(Input input, std::mt19937_64& rng) {
    static constexpr std::array<std::uint8_t, 10> kBytes = {0x00, 0x01, 0x05, 0x06, 0x11, 0x3A,
                                                            0x45, 0x60, 0x7F, 0xFF};
    static constexpr std::array<std::uint16_t, 10> kWords = {0, 8, 53, 5353, 0x0800, 0x86DD,
                                                             0x8100, 0xC00C, 0x1FFF, 0xFFFF};
    auto pick = [&](std::size_t n) { return static_cast<std::size_t>(rng() % n); };
    const std::size_t edits = 1 + pick(4);
    for (std::size_t e = 0; e < edits; ++e) {
        const std::size_t at = input.empty() ? 0 : pick(input.size());
        switch (pick(7)) {
            case 0:
                if (!input.empty()) input[at] ^= static_cast<std::uint8_t>(1u << pick(8));
                break;
            case 1:
                if (!input.empty()) input[at] = kBytes[pick(kBytes.size())];
                break;
            case 2:
                if (input.size() >= 2) {
                    const std::uint16_t w = kWords[pick(kWords.size())];
                    const std::size_t p = std::min(at, input.size() - 2);
                    input[p] = static_cast<std::uint8_t>(w >> 8);
                    input[p + 1] = static_cast<std::uint8_t>(w);
                }
                break;
            case 3:
                input.insert(input.begin() + static_cast<std::ptrdiff_t>(at), static_cast<std::uint8_t>(rng()));
                break;
            case 4:
                if (!input.empty()) {
                    const std::size_t n = 1 + pick(std::min<std::size_t>(16, input.size() - at));
                    input.erase(input.begin() + static_cast<std::ptrdiff_t>(at),
                                input.begin() + static_cast<std::ptrdiff_t>(at + n));
                }
                break;
            case 5:
                input.resize(at);  // truncate
                break;
            default:
                if (!input.empty() && input.size() < 4096) {  // duplicate a chunk
                    const std::size_t n = 1 + pick(std::min<std::size_t>(32, input.size() - at));
                    const Input chunk(input.begin() + static_cast<std::ptrdiff_t>(at),
                                      input.begin() + static_cast<std::ptrdiff_t>(at + n));
                    input.insert(input.begin() + static_cast<std::ptrdiff_t>(pick(input.size() + 1)),
                                 chunk.begin(), chunk.end());
                }
                break;
        }
    }
    return input;
}

}  // namespace

int main(int argc, char** argv) {
    std::signal(SIGABRT, on_crash);
    std::signal(SIGSEGV, on_crash);
    std::signal(SIGBUS, on_crash);
    std::signal(SIGFPE, on_crash);

    std::vector<std::string> pcaps;
    std::vector<std::string> files;
    bool dns_messages = false;
    unsigned long long mutations = 0;
    unsigned long long seed = 1;
    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];
        if (arg == "--pcap" && i + 1 < argc) pcaps.push_back(argv[++i]);
        else if (arg == "--dns") dns_messages = true;
        else if (arg == "--mutations" && i + 1 < argc) mutations = std::strtoull(argv[++i], nullptr, 10);
        else if (arg == "--seed" && i + 1 < argc) seed = std::strtoull(argv[++i], nullptr, 10);
        else if (!arg.empty() && arg[0] != '-') files.push_back(arg);
        else {
            std::fprintf(stderr, "usage: %s [--pcap FILE]... [--dns] [--mutations N] [--seed N] [FILE|DIR...]\n",
                         argv[0]);
            return 2;
        }
    }

    std::vector<Input> seeds = {Input{}, Input{0x00}};
    for (const auto& path : files) {
        if (std::filesystem::is_directory(path)) {
            for (const auto& entry : std::filesystem::directory_iterator(path)) {
                if (entry.is_regular_file()) seeds.push_back(read_file(entry.path().string()));
            }
        } else {
            seeds.push_back(read_file(path));
        }
    }
    // Frames: one seed per packet shape, so mutations start from rare shapes (an IPv6 DNS
    // answer) as often as from common ones (the thousandth segment of the same download).
    // DNS messages: every one, since a capture holds few.
    std::set<std::tuple<int, int, int, int, int, bool, bool>> shapes;
    for (const auto& path : pcaps) {
        for (Input& frame : read_pcap(path)) {
            const netpulse::PacketInfo info = netpulse::parse_packet(std::span<const std::uint8_t>(frame));
            const bool from_dns_port =
                info.kind == netpulse::PacketKind::Udp && (info.src_port == 53 || info.src_port == 5353);
            if (dns_messages) {
                if (from_dns_port) seeds.emplace_back(info.udp_payload.begin(), info.udp_payload.end());
                continue;
            }
            const bool has_answers = from_dns_port && !netpulse::parse_dns_response(info.udp_payload).empty();
            const int low_port = std::min(info.src_port, info.dst_port);
            const auto shape = std::make_tuple(static_cast<int>(info.kind), static_cast<int>(info.ethertype),
                                               static_cast<int>(info.ip_protocol), low_port,
                                               static_cast<int>(frame.size() / 128), info.src_port == low_port,
                                               has_answers);
            if (shapes.insert(shape).second) seeds.push_back(std::move(frame));
        }
    }

    for (const Input& input : seeds) run(input);
    std::mt19937_64 rng(seed);
    for (unsigned long long i = 0; i < mutations; ++i) run(mutate(seeds[rng() % seeds.size()], rng));
    std::printf("%zu seeds and %llu mutations: all passed\n", seeds.size(), mutations);
    return 0;
}
