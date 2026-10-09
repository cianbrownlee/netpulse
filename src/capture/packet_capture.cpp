#include "capture/packet_capture.hpp"

#include <pcap/pcap.h>
#include <sys/socket.h>

#include <algorithm>
#include <chrono>
#include <filesystem>
#include <utility>

namespace netpulse {

namespace {

std::string own_binary_path() {
    std::error_code ec;
    const auto path = std::filesystem::read_symlink("/proc/self/exe", ec);
    return ec ? std::string("./netpulse") : path.string();
}

std::string join(const std::vector<std::string>& items) {
    std::string out;
    for (const auto& item : items) {
        if (!out.empty()) out += ", ";
        out += item;
    }
    return out.empty() ? "(none found)" : out;
}

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
                       "interface (see --list-interfaces), not a pseudo-device like 'any'.");
}

[[noreturn]] void throw_activate_error(pcap_t* handle, int status, const std::string& iface) {
    const std::string detail = pcap_geterr(handle);
    pcap_close(handle);
    switch (status) {
        case PCAP_ERROR_PERM_DENIED:
            throw CaptureError(
                "Missing capture permission on '" + iface + "'.\n\n"
                "NetPulse needs the CAP_NET_RAW and CAP_NET_ADMIN capabilities, not full root.\n"
                "Grant them to the binary once:\n\n"
                "    sudo setcap cap_net_raw,cap_net_admin=eip " + own_binary_path() + "\n\n"
                "then run it again without sudo. Rebuilding replaces the binary and clears the\n"
                "capabilities, so repeat this after each build.");
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

}  // namespace

std::unique_ptr<PacketCapture> PacketCapture::open(const CaptureConfig& config) {
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

    std::string iface = config.interface;
    if (iface.empty()) {
        const auto found = default_interface();
        if (!found) {
            throw CaptureError("No active network interface with an IPv4 address was found. "
                               "Name one with --interface (see --list-interfaces).");
        }
        iface = *found;
    }

    // Without capture permission, libpcap fails on the permission check before it ever looks
    // up the interface, so a typo would be misreported as "missing permission". Listing
    // interfaces needs no privileges, so check the name first.
    const auto interfaces = list_interfaces();
    if (!interfaces.empty() &&
        std::find(interfaces.begin(), interfaces.end(), iface) == interfaces.end()) {
        throw CaptureError("There is no network interface named '" + iface +
                           "'. Available: " + join(interfaces) + ".");
    }

    pcap_t* handle = pcap_create(iface.c_str(), errbuf);
    if (!handle) throw CaptureError("Could not open interface '" + iface + "': " + errbuf);

    pcap_set_snaplen(handle, config.snaplen);
    // Not promiscuous: only traffic this machine sends or receives. Seeing other devices'
    // traffic is not needed for the MVP and is not something a tool should do by default.
    pcap_set_promisc(handle, 0);
    pcap_set_timeout(handle, config.read_timeout_ms);
    pcap_set_buffer_size(handle, config.kernel_buffer_bytes);

    // Positive return values are warnings (capture still works); negative ones are fatal.
    const int status = pcap_activate(handle);
    if (status < 0) throw_activate_error(handle, status, iface);

    require_ethernet(handle, iface);
    return std::unique_ptr<PacketCapture>(new PacketCapture(handle, false, iface));
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
        const std::int64_t ts_us = std::int64_t{header->ts.tv_sec} * 1'000'000 + header->ts.tv_usec;
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

std::vector<std::string> PacketCapture::list_interfaces() {
    std::vector<std::string> names;
    pcap_if_t* devices = nullptr;
    char errbuf[PCAP_ERRBUF_SIZE] = {};
    if (pcap_findalldevs(&devices, errbuf) != 0) return names;
    for (const pcap_if_t* d = devices; d; d = d->next) names.emplace_back(d->name);
    pcap_freealldevs(devices);
    return names;
}

std::optional<std::string> PacketCapture::default_interface() {
    pcap_if_t* devices = nullptr;
    char errbuf[PCAP_ERRBUF_SIZE] = {};
    if (pcap_findalldevs(&devices, errbuf) != 0) return std::nullopt;

    std::optional<std::string> chosen;
    for (const pcap_if_t* d = devices; d && !chosen; d = d->next) {
        if ((d->flags & PCAP_IF_LOOPBACK) || !(d->flags & PCAP_IF_UP)) continue;
        for (const pcap_addr_t* a = d->addresses; a; a = a->next) {
            if (a->addr && a->addr->sa_family == AF_INET) {
                chosen = d->name;
                break;
            }
        }
    }
    pcap_freealldevs(devices);
    return chosen;
}

}  // namespace netpulse
