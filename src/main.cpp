#include <unistd.h>

#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdlib>
#include <iostream>
#include <optional>
#include <string>
#include <thread>
#include <vector>

#include "capture/packet_capture.hpp"
#include "pipeline/pipeline.hpp"
#include "ui/dashboard.hpp"
#include "ui/plain_report.hpp"

namespace {

using namespace netpulse;

struct Options {
    std::string interface;
    std::string read_file;
    bool plain = false;
    bool resolve = true;
    bool dns_names = false;
    bool list_interfaces = false;
    std::vector<IpPrefix> local_networks;
    std::optional<int> duration_seconds;
};

void print_usage(std::ostream& out) {
    out << "Usage: netpulse [options]\n"
           "\n"
           "Live network traffic analyzer. Captures packet headers (never contents) and shows\n"
           "throughput, protocols, top talkers and flows.\n"
           "\n"
           "  -i, --interface NAME   capture live from NAME (default: first active non-loopback)\n"
           "  -r, --read FILE        replay a .pcap file instead of capturing live\n"
           "      --plain            print text reports instead of the dashboard\n"
           "                         (automatic when output is not a terminal)\n"
           "  -d, --duration SECS    stop after SECS seconds (live --plain mode)\n"
           "      --no-resolve       don't look up hostnames (no reverse-DNS queries)\n"
           "      --dns-names        also learn names from the DNS answers your devices receive\n"
           "                         (opt-in: reads the contents of DNS responses, and only those)\n"
           "      --local PREFIX     treat PREFIX (e.g. 2001:db8:1::/64) as your own network;\n"
           "                         repeatable. Live capture adds the interface's own subnets\n"
           "                         automatically, so this matters mostly for replays\n"
           "      --list-interfaces  list capture interfaces and their networks, then exit\n"
           "  -h, --help             show this help\n";
}

// Returns nullopt (after printing why) if the arguments are unusable.
std::optional<Options> parse_args(int argc, char** argv) {
    Options opts;
    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];
        auto value = [&]() -> std::optional<std::string> {
            if (i + 1 >= argc) {
                std::cerr << "netpulse: " << arg << " needs a value\n";
                return std::nullopt;
            }
            return std::string(argv[++i]);
        };

        if (arg == "-h" || arg == "--help") {
            print_usage(std::cout);
            std::exit(0);
        } else if (arg == "-i" || arg == "--interface") {
            auto v = value();
            if (!v) return std::nullopt;
            opts.interface = *v;
        } else if (arg == "-r" || arg == "--read") {
            auto v = value();
            if (!v) return std::nullopt;
            opts.read_file = *v;
        } else if (arg == "-d" || arg == "--duration") {
            auto v = value();
            if (!v) return std::nullopt;
            try {
                opts.duration_seconds = std::stoi(*v);
            } catch (const std::exception&) {
                std::cerr << "netpulse: --duration expects a number of seconds\n";
                return std::nullopt;
            }
        } else if (arg == "--plain") {
            opts.plain = true;
        } else if (arg == "--no-resolve") {
            opts.resolve = false;
        } else if (arg == "--dns-names") {
            opts.dns_names = true;
        } else if (arg == "--local") {
            auto v = value();
            if (!v) return std::nullopt;
            const auto prefix = IpPrefix::parse(*v);
            if (!prefix) {
                std::cerr << "netpulse: --local expects an address or prefix like 192.168.1.0/24 "
                             "or 2001:db8:1::/64, not '" << *v << "'\n";
                return std::nullopt;
            }
            opts.local_networks.push_back(*prefix);
        } else if (arg == "--list-interfaces") {
            opts.list_interfaces = true;
        } else {
            std::cerr << "netpulse: unknown option '" << arg << "'\n\n";
            print_usage(std::cerr);
            return std::nullopt;
        }
    }
    if (!opts.interface.empty() && !opts.read_file.empty()) {
        std::cerr << "netpulse: use either --interface or --read, not both\n";
        return std::nullopt;
    }
    return opts;
}

std::atomic<bool> g_interrupted{false};

void on_sigint(int) { g_interrupted.store(true); }

int run_plain(Pipeline& pipeline, const Options& opts) {
    std::signal(SIGINT, on_sigint);
    std::signal(SIGTERM, on_sigint);

    const auto started = std::chrono::steady_clock::now();
    auto next_report = started + std::chrono::seconds(1);

    while (!pipeline.finished() && !g_interrupted.load()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        const auto now = std::chrono::steady_clock::now();
        if (opts.duration_seconds && now - started >= std::chrono::seconds(*opts.duration_seconds)) {
            break;
        }
        // Live mode prints a rolling report each second; replay just prints the final one.
        if (!pipeline.is_offline() && now >= next_report) {
            print_report(std::cout, *pipeline.latest(), pipeline.source());
            std::cout << '\n';
            next_report = now + std::chrono::seconds(1);
        }
    }

    pipeline.stop();
    print_report(std::cout, *pipeline.latest(), pipeline.source());
    return 0;
}

}  // namespace

int main(int argc, char** argv) {
    const auto opts = parse_args(argc, argv);
    if (!opts) return 2;

    if (opts->list_interfaces) {
        for (const auto& i : PacketCapture::describe_interfaces()) {
            std::cout << i.name;
            if (!i.up) std::cout << " (down)";
            if (!i.networks.empty()) std::cout << "  " << i.networks.to_string();
            std::cout << '\n';
        }
        return 0;
    }

    Pipeline::Config config;
    config.capture.interface = opts->interface;
    config.capture.pcap_file = opts->read_file;
    config.resolve_names = opts->resolve;
    config.local_networks = opts->local_networks;
    config.dns_names = opts->dns_names;

    std::optional<Pipeline> pipeline;
    try {
        pipeline.emplace(config);
    } catch (const CaptureError& e) {
        std::cerr << "netpulse: " << e.what() << '\n';
        return 1;
    }

    pipeline->start();
    const bool plain = opts->plain || !isatty(STDOUT_FILENO);
    const int status = plain ? run_plain(*pipeline, *opts) : (run_dashboard(*pipeline), 0);
    pipeline->stop();

    if (const auto error = pipeline->error()) {
        std::cerr << "netpulse: " << *error << '\n';
        return 1;
    }
    return status;
}
