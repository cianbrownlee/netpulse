#include "capture/packet_capture.hpp"

#include <pcap/pcap.h>

#ifdef _WIN32
#include <winsock2.h>
#include <windows.h>
#include <iphlpapi.h>
#else
#include <linux/filter.h>
#endif

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <utility>

#include "capture/capture_filter.hpp"
#include "util/platform.hpp"
#include "util/sockets.hpp"

namespace netpulse {

namespace {

std::string join(const std::vector<std::string>& items) {
    std::string out;
    for (const auto& item : items) {
        if (!out.empty()) out += ", ";
        out += item;
    }
    return out.empty() ? "(none found)" : out;
}

std::string lowercase(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}

#ifdef _WIN32

// Npcap installs its DLLs in System32\Npcap, off the normal search path (unless installed in
// WinPcap-compatible mode), and NetPulse delay-loads them so that a missing Npcap is a clear
// message rather than a failure to start. This points the loader there, once, and checks.
void load_npcap() {
    static const bool loaded = [] {
        wchar_t system[MAX_PATH];
        const UINT length = GetSystemDirectoryW(system, MAX_PATH);
        if (length > 0 && length < MAX_PATH) SetDllDirectoryW((std::wstring(system) + L"\\Npcap").c_str());
        return LoadLibraryW(L"wpcap.dll") != nullptr;
    }();
    if (!loaded) {
        throw CaptureError(
            "Npcap isn't installed, and NetPulse needs it to capture on Windows. Install it from "
            "https://npcap.com (the free edition is fine), then run NetPulse again.\n"
            "To look around without capturing anything, try: netpulse --demo");
    }
}

// Windows' own names for adapters ("Wi-Fi", "Ethernet"), keyed by the adapter GUID that also
// appears in Npcap's device names (\Device\NPF_{GUID}).
std::vector<std::pair<std::string, std::string>> adapter_friendly_names() {
    std::vector<std::pair<std::string, std::string>> names;
    ULONG size = 16 * 1024;
    std::vector<unsigned char> buffer;
    ULONG result = ERROR_BUFFER_OVERFLOW;
    for (int attempt = 0; attempt < 3 && result == ERROR_BUFFER_OVERFLOW; ++attempt) {
        buffer.resize(size);
        result = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST |
                                                     GAA_FLAG_SKIP_DNS_SERVER,
                                      nullptr, reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.data()), &size);
    }
    if (result != NO_ERROR) return names;
    for (auto* a = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.data()); a; a = a->Next) {
        const int bytes = WideCharToMultiByte(CP_UTF8, 0, a->FriendlyName, -1, nullptr, 0, nullptr, nullptr);
        if (bytes <= 1) continue;
        std::string friendly(static_cast<std::size_t>(bytes - 1), '\0');
        WideCharToMultiByte(CP_UTF8, 0, a->FriendlyName, -1, friendly.data(), bytes, nullptr, nullptr);
        names.emplace_back(a->AdapterName, std::move(friendly));
    }
    return names;
}

#else

void load_npcap() {}

std::string own_binary_path() {
    std::error_code ec;
    const auto path = std::filesystem::read_symlink("/proc/self/exe", ec);
    return ec ? std::string("./netpulse") : path.string();
}

#endif

// NetPulse parses Ethernet frames. Pseudo-interfaces like "any" use a different link-layer
// header (Linux "cooked" capture), so refuse them up front with a clear reason rather than
// reporting every packet as malformed.
void require_ethernet(pcap_t* handle, const std::string& source) {
    const int link = pcap_datalink(handle);
    if (link == DLT_EN10MB) return;
    const char* name = pcap_datalink_val_to_name(link);
    pcap_close(handle);
    throw CaptureError("'" + source + "' uses link type " + (name ? name : std::to_string(link)) +
                       ", but NetPulse only understands Ethernet frames. Pick a real network "
                       "interface (see --list-interfaces), not a pseudo-device like 'any' or a "
                       "loopback adapter.");
}

// The kernel decides how much of each packet to keep by running a classic-BPF program and keeping
// as many bytes as it returns (see build_capture_filter). Installing it there, rather than relying
// on libpcap's snaplen, is what makes "headers only" hold for what reaches this process at all.
//
// Linux: libpcap's memory-mapped capture applies the snaplen in user space, after the kernel has
// copied each whole packet into the ring shared with this process (measured: wake-ups per packet
// scaled with packet size). So the program is attached to the socket directly.
//
// Windows: the Npcap driver runs the program installed with pcap_setfilter and copies only what
// it returns.
//
// Returns why it failed, or an empty string.
std::string truncate_in_kernel(pcap_t* handle, int snaplen, int dns_snaplen) {
    const std::vector<BpfInstruction> code =
        build_capture_filter(static_cast<unsigned>(snaplen), static_cast<unsigned>(dns_snaplen));
#ifdef _WIN32
    std::vector<bpf_insn> program_code;
    for (const BpfInstruction& in : code) program_code.push_back(bpf_insn{in.code, in.jt, in.jf, in.k});
    bpf_program program{};
    program.bf_len = static_cast<u_int>(program_code.size());
    program.bf_insns = program_code.data();
    return pcap_setfilter(handle, &program) == 0 ? std::string() : std::string(pcap_geterr(handle));
#else
    std::vector<sock_filter> program_code;
    for (const BpfInstruction& in : code) program_code.push_back(sock_filter{in.code, in.jt, in.jf, in.k});
    sock_fprog program{};
    program.len = static_cast<unsigned short>(program_code.size());
    program.filter = program_code.data();
    const int rc = setsockopt(pcap_fileno(handle), SOL_SOCKET, SO_ATTACH_FILTER, &program, sizeof program);
    return rc == 0 ? std::string() : std::string(std::strerror(errno));
#endif
}

[[noreturn]] void throw_activate_error(pcap_t* handle, int status, const std::string& iface) {
    const std::string detail = pcap_geterr(handle);
    pcap_close(handle);
    switch (status) {
        case PCAP_ERROR_PERM_DENIED:
#ifdef _WIN32
            throw CaptureError(
                "Missing capture permission on '" + iface + "'.\n\n"
                "Npcap is set to let only administrators capture. Run NetPulse from a terminal opened "
                "with \"Run as administrator\", or reinstall Npcap without \"Restrict Npcap driver's "
                "access to Administrators only\".");
#else
            throw CaptureError(
                "Missing capture permission on '" + iface + "'.\n\n"
                "NetPulse needs the CAP_NET_RAW and CAP_NET_ADMIN capabilities, not full root.\n"
                "Grant them to the binary once:\n\n"
                "    sudo setcap cap_net_raw,cap_net_admin=eip " + own_binary_path() + "\n\n"
                "then run it again without sudo. Rebuilding replaces the binary and clears the\n"
                "capabilities, so repeat this after each build.");
#endif
        case PCAP_ERROR_NO_SUCH_DEVICE:
            throw CaptureError("There is no network interface named '" + iface +
                               "'. Available: " + join(PacketCapture::list_interfaces()) + ".");
        case PCAP_ERROR_IFACE_NOT_UP:
            throw CaptureError("Interface '" + iface + "' is down. Bring it up or pick another "
                               "one (see --list-interfaces).");
        default:
            throw CaptureError("Could not start capture on '" + iface + "': " +
                               pcap_statustostr(status) + (detail.empty() ? "" : " (" + detail + ")"));
    }
}

std::optional<IpAddress> to_ip_address(const sockaddr* sa) {
    if (!sa) return std::nullopt;
    if (sa->sa_family == AF_INET) {
        const auto* in = reinterpret_cast<const sockaddr_in*>(sa);
        return IpAddress::v4(ntohl(in->sin_addr.s_addr));
    }
    if (sa->sa_family == AF_INET6) {
        const auto* in6 = reinterpret_cast<const sockaddr_in6*>(sa);
        IpAddress::Bytes bytes{};
        std::memcpy(bytes.data(), in6->sin6_addr.s6_addr, bytes.size());
        return IpAddress::v6(bytes);
    }
    return std::nullopt;
}

}  // namespace

std::unique_ptr<PacketCapture> PacketCapture::open(const CaptureConfig& config) {
    load_npcap();
    char errbuf[PCAP_ERRBUF_SIZE] = {};

    if (!config.pcap_file.empty()) {
        pcap_t* handle = pcap_open_offline(config.pcap_file.c_str(), errbuf);
        if (!handle) {
            throw CaptureError("Could not open capture file '" + config.pcap_file + "': " + errbuf);
        }
        require_ethernet(handle, config.pcap_file);
        const std::string name = std::filesystem::path(config.pcap_file).filename().string();
        return std::unique_ptr<PacketCapture>(new PacketCapture(handle, true, name));
    }

    // Without capture permission, libpcap fails on the permission check before it ever looks
    // up the interface, so a typo would be misreported as "missing permission". Listing
    // interfaces needs no privileges, so resolve the name first.
    std::optional<InterfaceInfo> iface;
    if (config.interface.empty()) {
        const auto found = default_interface();
        if (!found) {
            throw CaptureError("No active network interface with an IPv4 address was found. "
                               "Name one with --interface (see --list-interfaces).");
        }
        iface = find_interface(*found);
    } else {
        iface = find_interface(config.interface);
        if (!iface) {
            throw CaptureError("There is no network interface named '" + config.interface +
                               "'. Available: " + join(list_interfaces()) + ".");
        }
    }
    if (!iface) throw CaptureError("Could not find the default network interface again.");

    pcap_t* handle = pcap_create(iface->name.c_str(), errbuf);
    if (!handle) throw CaptureError("Could not open interface '" + iface->label + "': " + errbuf);

    // libpcap also trims to its snaplen in user space, so it gets the larger of the two; the
    // kernel filter (below) is what holds every non-DNS packet to `snaplen`.
    pcap_set_snaplen(handle, std::max(config.snaplen, config.dns_snaplen));
    // Not promiscuous: only traffic this machine sends or receives. Seeing other devices'
    // traffic is not needed for the MVP and is not something a tool should do by default.
    pcap_set_promisc(handle, 0);
    pcap_set_timeout(handle, config.read_timeout_ms);
    pcap_set_buffer_size(handle, config.kernel_buffer_bytes);

    // Positive return values are warnings (capture still works); negative ones are fatal.
    const int status = pcap_activate(handle);
    if (status < 0) throw_activate_error(handle, status, iface->label);

    require_ethernet(handle, iface->label);
    if (const std::string why = truncate_in_kernel(handle, config.snaplen, config.dns_snaplen); !why.empty()) {
        std::fprintf(stderr,
                     "netpulse: note: couldn't set kernel-side truncation (%s); full packets will "
                     "reach the capture buffer and be trimmed afterwards. Capture still works.\n",
                     why.c_str());
    }
    auto capture = std::unique_ptr<PacketCapture>(new PacketCapture(handle, false, iface->label));
    capture->local_networks_ = iface->networks;
    return capture;
}

PacketCapture::PacketCapture(pcap* handle, bool offline, std::string description)
    : handle_(handle), offline_(offline), description_(std::move(description)) {}

PacketCapture::~PacketCapture() { pcap_close(handle_); }

void PacketCapture::run(BoundedQueue<CapturedPacket>& queue) {
    batcher_.emplace(queue, offline_ ? PacketBatcher::Overflow::Wait : PacketBatcher::Overflow::Drop);
    replay_origin_ = std::chrono::steady_clock::now();
    auto next_stats = replay_origin_;

    while (!stop_requested_.load()) {
        const int n = pcap_dispatch(handle_, -1, &PacketCapture::on_packet,
                                    reinterpret_cast<unsigned char*>(this));
        if (n == PCAP_ERROR_BREAK) break;
        if (n == PCAP_ERROR) {
            // e.g. the interface went away mid-run. Record why, then end the run so the
            // pipeline can report it instead of silently freezing on stale numbers.
            std::lock_guard lock(error_mutex_);
            error_ = "Capture on '" + description_ + "' stopped: " + pcap_geterr(handle_);
            break;
        }
        batcher_->flush();
        if (offline_ && n == 0) break;  // end of file

        if (!offline_ && std::chrono::steady_clock::now() >= next_stats) {
            refresh_kernel_stats();
            next_stats = std::chrono::steady_clock::now() + std::chrono::milliseconds(250);
        }
    }
    batcher_->flush();
    batcher_.reset();
    if (!offline_) refresh_kernel_stats();
}

void PacketCapture::stop() {
    stop_requested_.store(true);
    pcap_breakloop(handle_);
}

void PacketCapture::on_packet(unsigned char* user, const pcap_pkthdr* header,
                              const unsigned char* bytes) {
    auto* self = reinterpret_cast<PacketCapture*>(user);

    std::chrono::steady_clock::time_point timestamp;
    if (self->offline_) {
        const std::int64_t ts_us =
            static_cast<std::int64_t>(header->ts.tv_sec) * 1'000'000 + header->ts.tv_usec;
        if (!self->first_file_timestamp_us_) self->first_file_timestamp_us_ = ts_us;
        timestamp = self->replay_origin_ +
                    std::chrono::microseconds(ts_us - *self->first_file_timestamp_us_);
    } else {
        timestamp = std::chrono::steady_clock::now();
    }
    self->captured_.fetch_add(1, std::memory_order_relaxed);
    // The batcher copies: libpcap reuses `bytes` as soon as this callback returns.
    self->batcher_->add(bytes, header->caplen, header->len, timestamp);
}

void PacketCapture::refresh_kernel_stats() {
    pcap_stat stats{};
    if (pcap_stats(handle_, &stats) != 0) return;
    kernel_drops_.store(stats.ps_drop, std::memory_order_relaxed);
    interface_drops_.store(stats.ps_ifdrop, std::memory_order_relaxed);
}

CaptureCounters PacketCapture::counters() const {
    CaptureCounters c;
    c.captured = captured_.load(std::memory_order_relaxed);
    c.kernel_drops = kernel_drops_.load(std::memory_order_relaxed);
    c.interface_drops = interface_drops_.load(std::memory_order_relaxed);
    return c;
}

std::optional<std::string> PacketCapture::error() const {
    std::lock_guard lock(error_mutex_);
    return error_;
}

std::vector<PacketCapture::InterfaceInfo> PacketCapture::describe_interfaces() {
    load_npcap();
    std::vector<InterfaceInfo> interfaces;
    pcap_if_t* devices = nullptr;
    char errbuf[PCAP_ERRBUF_SIZE] = {};
    if (pcap_findalldevs(&devices, errbuf) != 0) return interfaces;
#ifdef _WIN32
    const auto friendly = adapter_friendly_names();
#endif
    for (const pcap_if_t* d = devices; d; d = d->next) {
        InterfaceInfo info;
        info.name = d->name;
        info.label = d->name;
        if (d->description) info.description = d->description;
#ifdef _WIN32
        for (const auto& [guid, name] : friendly) {
            if (info.name.find(guid) != std::string::npos) info.label = name;
        }
#endif
        info.up = (d->flags & PCAP_IF_UP) != 0;
        info.loopback = (d->flags & PCAP_IF_LOOPBACK) != 0;
        info.disconnected =
            (d->flags & PCAP_IF_CONNECTION_STATUS) == PCAP_IF_CONNECTION_STATUS_DISCONNECTED;
        info.is_virtual = looks_virtual(info.label, info.description);
        for (const pcap_addr_t* a = d->addresses; a; a = a->next) {
            const auto address = to_ip_address(a->addr);
            const auto netmask = to_ip_address(a->netmask);
            if (!address || !netmask) continue;
            if (const auto prefix = IpPrefix::from_netmask(*address, *netmask)) {
                info.networks.add(*prefix);
            }
        }
        interfaces.push_back(std::move(info));
    }
    pcap_freealldevs(devices);
    return interfaces;
}

std::vector<std::string> PacketCapture::list_interfaces() {
    std::vector<std::string> labels;
    for (const auto& i : describe_interfaces()) labels.push_back(i.label);
    return labels;
}

// Adapters that belong to hypervisors, virtual machines and tunnels. They're often up with an
// address (WSL's and Hyper-V's on Windows, Docker's on Linux), but aren't where a person's
// traffic is, so they're never the default.
bool PacketCapture::looks_virtual(const std::string& label, const std::string& description) {
    const std::string text = lowercase(label + " " + description);
    for (const char* marker : {"virtual", "hyper-v", "vethernet", "vmware", "virtualbox", "wan miniport",
                               "docker", "veth", "virbr", "vboxnet", "loopback", "tap-windows", "wireguard",
                               "tailscale"}) {
        if (text.find(marker) != std::string::npos) return true;
    }
    return false;
}

std::optional<std::string> PacketCapture::default_interface() { return pick_default(describe_interfaces()); }

std::optional<PacketCapture::InterfaceInfo> PacketCapture::find_interface(const std::string& wanted) {
    return match_interface(describe_interfaces(), wanted);
}

std::optional<std::string> PacketCapture::pick_default(const std::vector<InterfaceInfo>& interfaces) {
    // The first eligible interface, preferring (in this order) one with a link and one that
    // isn't virtual, so a Windows laptop picks its Wi-Fi over WSL's virtual adapter.
    std::optional<std::string> chosen;
    int best = -1;
    for (const auto& i : interfaces) {
        if (!i.up || i.loopback) continue;
        // 169.254.x.x is what an adapter gives itself when no network answered (no DHCP lease):
        // it has an address, but isn't connected to anything.
        const bool has_ipv4 = std::any_of(
            i.networks.prefixes().begin(), i.networks.prefixes().end(), [](const IpPrefix& p) {
                return p.network.is_v4() && !p.network.in_prefix(IpAddress::v4(169, 254, 0, 0), 16);
            });
        if (!has_ipv4) continue;
        const int score = (i.disconnected ? 0 : 2) + (i.is_virtual ? 0 : 1);
        if (score > best) {
            best = score;
            chosen = i.name;
        }
    }
    return chosen;
}

std::optional<PacketCapture::InterfaceInfo> PacketCapture::match_interface(
    const std::vector<InterfaceInfo>& interfaces, const std::string& wanted) {
    for (const auto& i : interfaces) {
        if (i.name == wanted || i.label == wanted) return i;
    }
    const std::string needle = lowercase(wanted);
    std::vector<const InterfaceInfo*> matches;
    for (const auto& i : interfaces) {
        if (lowercase(i.label).find(needle) != std::string::npos ||
            lowercase(i.description).find(needle) != std::string::npos) {
            matches.push_back(&i);
        }
    }
    if (matches.size() == 1) return *matches.front();
    if (matches.size() > 1) {
        std::vector<std::string> labels;
        for (const auto* m : matches) labels.push_back(m->label);
        throw CaptureError("'" + wanted + "' matches several interfaces: " + join(labels) +
                           ". Use the full name (see --list-interfaces).");
    }
    return std::nullopt;
}

}  // namespace netpulse
