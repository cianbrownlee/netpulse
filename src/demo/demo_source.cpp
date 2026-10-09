#include "demo/demo_source.hpp"

#include <array>
#include <cmath>
#include <memory>
#include <random>
#include <span>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

#include "parse/packet_parser.hpp"

namespace netpulse {

namespace {

using SteadyClock = std::chrono::steady_clock;
using Rng = std::mt19937;

constexpr double kTick = 0.01;  // seconds of simulated time per generation step

// ---------------------------------------------------------------------------------------------
// Addresses: documentation ranges only (RFC 5737, RFC 3849)
// ---------------------------------------------------------------------------------------------

IpAddress v6(std::array<std::uint16_t, 8> groups) {
    IpAddress::Bytes bytes{};
    for (std::size_t i = 0; i < 8; ++i) {
        bytes[2 * i] = static_cast<std::uint8_t>(groups[i] >> 8);
        bytes[2 * i + 1] = static_cast<std::uint8_t>(groups[i]);
    }
    return IpAddress::v6(bytes);
}

const IpAddress kRouter = IpAddress::v4(192, 168, 1, 1);
const IpAddress kRouter6 = v6({0x2001, 0xdb8, 1, 0, 0, 0, 0, 1});
const IpAddress kLaptop = IpAddress::v4(192, 168, 1, 20);
const IpAddress kPhone = IpAddress::v4(192, 168, 1, 31);
const IpAddress kGamingPc = IpAddress::v4(192, 168, 1, 40);
const IpAddress kTv = IpAddress::v4(192, 168, 1, 50);
const IpAddress kTv6 = v6({0x2001, 0xdb8, 1, 0, 0, 0, 0, 0x50});

const IpAddress kVideoCdn6 = v6({0x2001, 0xdb8, 0xf00d, 0, 0, 0, 0, 0x10});
const IpAddress kVideoQuic = IpAddress::v4(203, 0, 113, 40);
const IpAddress kCallServer = IpAddress::v4(198, 51, 100, 20);
const IpAddress kGameDownloads = IpAddress::v4(203, 0, 113, 80);
const IpAddress kGameServer = IpAddress::v4(198, 51, 100, 77);  // no DNS name: shown as an address
const IpAddress kSshServer = IpAddress::v4(203, 0, 113, 250);
const IpAddress kTimeServer = IpAddress::v4(192, 0, 2, 123);

const IpAddress kMdnsGroup = IpAddress::v4(224, 0, 0, 251);
const IpAddress kSsdpGroup = IpAddress::v4(239, 255, 255, 250);
const IpAddress kBroadcast = IpAddress::v4(255, 255, 255, 255);

constexpr std::string_view kVideoCdnName = "ipv6-c012-sea001.1.oca.nflxvideo.net";
constexpr std::string_view kVideoQuicName = "rr2---sn-p5qlsnz6.googlevideo.com";
constexpr std::string_view kCallServerName = "zoomsea42mmr.sea.zoom.us";
constexpr std::string_view kGameDownloadsName = "cache3-sea1.steamcontent.com";
constexpr std::string_view kSshServerName = "build.example.net";
constexpr std::string_view kTimeServerName = "time.example.org";

struct Site {
    std::string_view name;
    IpAddress address;
};

const std::array kSites = {
    Site{"en.wikipedia.org", IpAddress::v4(203, 0, 113, 101)},
    Site{"github.com", IpAddress::v4(203, 0, 113, 102)},
    Site{"news.example.org", IpAddress::v4(203, 0, 113, 103)},
    Site{"shop.example.net", IpAddress::v4(203, 0, 113, 104)},
    Site{"weather.example.com", IpAddress::v4(203, 0, 113, 105)},
    Site{"fonts.gstatic.com", IpAddress::v4(203, 0, 113, 106)},
    Site{"recipes.example.com", IpAddress::v4(203, 0, 113, 107)},
    Site{"docs.example.org", IpAddress::v4(203, 0, 113, 108)},
};

struct Endpoint {
    IpAddress ip;
    std::uint16_t port = 0;
};

double uniform(Rng& rng, double lo, double hi) {
    return std::uniform_real_distribution<double>(lo, hi)(rng);
}

std::uint16_t ephemeral_port(Rng& rng) {
    return static_cast<std::uint16_t>(std::uniform_int_distribution<int>(49152, 65535)(rng));
}

// Whether a periodic event (every `period` seconds, first at `offset`) falls in [t, t + dt).
bool due(double t, double dt, double period, double offset) {
    const double k = std::ceil((t - offset) / period);
    return offset + k * period < t + dt;
}

// ---------------------------------------------------------------------------------------------
// Frames
// ---------------------------------------------------------------------------------------------

// Writes Ethernet frames into the batcher. Only headers are generated (what a 192-byte capture
// would hold); payload sizes go into the IP length fields and the wire length.
class Emitter {
public:
    Emitter(PacketBatcher& batcher, SteadyClock::time_point origin)
        : batcher_(batcher), origin_(origin) {}

    void at(double seconds) {
        now_ = origin_ + std::chrono::duration_cast<SteadyClock::duration>(
                             std::chrono::duration<double>(seconds));
    }

    void tcp(const Endpoint& src, const Endpoint& dst, std::uint32_t payload,
             std::uint8_t flags = tcp_flags::kAck) {
        begin(src.ip, dst.ip, kIpProtoTcp, kTcpMinHeaderLength + payload);
        put16(src.port);
        put16(dst.port);
        put32(0x1000);  // sequence
        put32(0x2000);  // acknowledgment
        put8(0x50);     // data offset: 5 words
        put8(flags);
        put16(0xFFFF);  // window
        put32(0);       // checksum, urgent pointer
        finish();
    }

    void udp(const Endpoint& src, const Endpoint& dst, std::uint32_t payload) {
        begin(src.ip, dst.ip, kIpProtoUdp, kUdpHeaderLength + payload);
        udp_header(src, dst, payload);
        finish();
    }

    // A UDP datagram whose payload is captured too: DNS and mDNS answers.
    void udp(const Endpoint& src, const Endpoint& dst, std::span<const std::uint8_t> payload) {
        const auto length = static_cast<std::uint32_t>(payload.size());
        begin(src.ip, dst.ip, kIpProtoUdp, kUdpHeaderLength + length);
        udp_header(src, dst, length);
        for (const std::uint8_t b : payload) put8(b);
        finish();
    }

    // Neighbor solicitation and the like: ICMPv6 type, then the rest as payload.
    void icmpv6(const IpAddress& src, const IpAddress& dst, std::uint8_t type, std::uint32_t length) {
        begin(src, dst, kIpProtoIcmpv6, length);
        put8(type);
        put8(0);
        put16(0);
        finish();
    }

    void arp(const IpAddress& sender, const IpAddress& target, bool reply) {
        mac(reply ? mac_of(target) : kBroadcastMac);
        mac(mac_of(sender));
        put16(kEtherTypeArp);
        put16(1);       // Ethernet
        put16(0x0800);  // IPv4
        put8(6);
        put8(4);
        put16(reply ? 2 : 1);
        mac(mac_of(sender));
        put32(sender.v4_value());
        mac(reply ? mac_of(target) : Mac{});
        put32(target.v4_value());
        wire_length_ = 60;
        finish();
    }

    std::uint64_t count() const { return count_; }

private:
    using Mac = std::array<std::uint8_t, 6>;
    static constexpr Mac kBroadcastMac = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

    static Mac mac_of(const IpAddress& ip) {
        // Locally administered, derived from the address: stable and obviously made up.
        return {0x02, 0x00, 0x5E, 0x00, ip.bytes()[14], ip.bytes()[15]};
    }

    void begin(const IpAddress& src, const IpAddress& dst, std::uint8_t protocol,
               std::uint32_t ip_payload) {
        mac(mac_of(dst));
        mac(mac_of(src));
        if (src.is_v4()) {
            put16(kEtherTypeIpv4);
            const std::uint32_t total = std::min<std::uint32_t>(20 + ip_payload, 0xFFFF);
            put8(0x45);
            put8(0);
            put16(static_cast<std::uint16_t>(total));
            put16(static_cast<std::uint16_t>(count_));  // identification
            put16(0x4000);                              // don't fragment
            put8(64);                                   // TTL
            put8(protocol);
            put16(0);  // checksum (nothing checks it)
            put32(src.v4_value());
            put32(dst.v4_value());
            wire_length_ = static_cast<std::uint32_t>(kEthernetHeaderLength) + total;
        } else {
            put16(kEtherTypeIpv6);
            put32(0x60000000);  // version 6, no traffic class or flow label
            put16(static_cast<std::uint16_t>(std::min<std::uint32_t>(ip_payload, 0xFFFF)));
            put8(protocol);
            put8(64);  // hop limit
            for (const std::uint8_t b : src.bytes()) put8(b);
            for (const std::uint8_t b : dst.bytes()) put8(b);
            wire_length_ = static_cast<std::uint32_t>(kEthernetHeaderLength + kIpv6HeaderLength) +
                           ip_payload;
        }
    }

    void udp_header(const Endpoint& src, const Endpoint& dst, std::uint32_t payload) {
        put16(src.port);
        put16(dst.port);
        put16(static_cast<std::uint16_t>(std::min<std::uint32_t>(kUdpHeaderLength + payload, 0xFFFF)));
        put16(0);  // checksum
    }

    void finish() {
        batcher_.add(frame_.data(), length_, std::max<std::uint32_t>(wire_length_, 60), now_);
        length_ = 0;
        ++count_;
    }

    void put8(std::uint8_t v) {
        if (length_ < frame_.size()) frame_[length_++] = v;
    }
    void put16(std::uint16_t v) {
        put8(static_cast<std::uint8_t>(v >> 8));
        put8(static_cast<std::uint8_t>(v));
    }
    void put32(std::uint32_t v) {
        put16(static_cast<std::uint16_t>(v >> 16));
        put16(static_cast<std::uint16_t>(v));
    }
    void mac(const Mac& m) {
        for (const std::uint8_t b : m) put8(b);
    }

    PacketBatcher& batcher_;
    SteadyClock::time_point origin_;
    SteadyClock::time_point now_{};
    std::array<std::uint8_t, kMaxCapturedBytes> frame_{};
    std::size_t length_ = 0;
    std::uint32_t wire_length_ = 0;
    std::uint64_t count_ = 0;
};

// DNS messages, as a resolver (or an mDNS responder) would send them.
class DnsMessage {
public:
    // A standard answer to "what is the address of `name`?" with one A or AAAA record.
    static std::vector<std::uint8_t> answer(std::uint16_t id, std::string_view name,
                                            const IpAddress& address) {
        DnsMessage m;
        m.u16(id);
        m.u16(0x8180);  // response, recursion desired and available, no error
        m.u16(1);       // one question
        m.u16(1);       // one answer
        m.u16(0);
        m.u16(0);
        m.name(name);
        m.u16(address.is_v4() ? 1 : 28);  // A or AAAA
        m.u16(1);                          // class IN
        m.u16(0xC00C);                     // the answer's name: a pointer to the question's
        m.u16(address.is_v4() ? 1 : 28);
        m.record(address, 1, 300);
        return std::move(m.out_);
    }

    // An mDNS announcement: a device telling the network its own name, unprompted.
    static std::vector<std::uint8_t> announcement(std::string_view name,
                                                  std::span<const IpAddress> addresses) {
        DnsMessage m;
        m.u16(0);
        m.u16(0x8400);  // response, authoritative
        m.u16(0);       // no questions
        m.u16(static_cast<std::uint16_t>(addresses.size()));
        m.u16(0);
        m.u16(0);
        for (std::size_t i = 0; i < addresses.size(); ++i) {
            if (i == 0) {
                m.name(name);
            } else {
                m.u16(0xC00C);  // same name again
            }
            m.u16(addresses[i].is_v4() ? 1 : 28);
            m.record(addresses[i], 0x8001, 120);  // class IN with the cache-flush bit
        }
        return std::move(m.out_);
    }

private:
    void u8(std::uint8_t v) { out_.push_back(v); }
    void u16(std::uint16_t v) {
        u8(static_cast<std::uint8_t>(v >> 8));
        u8(static_cast<std::uint8_t>(v));
    }
    void u32(std::uint32_t v) {
        u16(static_cast<std::uint16_t>(v >> 16));
        u16(static_cast<std::uint16_t>(v));
    }
    void name(std::string_view n) {
        while (!n.empty()) {
            const auto dot = n.find('.');
            const auto label = n.substr(0, dot);
            u8(static_cast<std::uint8_t>(label.size()));
            for (const char c : label) u8(static_cast<std::uint8_t>(c));
            n = dot == std::string_view::npos ? std::string_view{} : n.substr(dot + 1);
        }
        u8(0);
    }
    // Class, TTL and data, after the owner name and type.
    void record(const IpAddress& address, std::uint16_t klass, std::uint32_t ttl) {
        u16(klass);
        u32(ttl);
        if (address.is_v4()) {
            u16(4);
            u32(address.v4_value());
        } else {
            u16(16);
            for (const std::uint8_t b : address.bytes()) u8(b);
        }
    }

    std::vector<std::uint8_t> out_;
};

// ---------------------------------------------------------------------------------------------
// What the household does
// ---------------------------------------------------------------------------------------------

constexpr std::uint32_t kTcpSegment = 1448;  // a full Ethernet-sized TCP payload
constexpr std::uint32_t kQuicPacket = 1252;

// A device looks up `name` at the router and gets `address` back.
void dns_lookup(Emitter& em, Rng& rng, const IpAddress& device, std::string_view name,
                const IpAddress& address) {
    const Endpoint client{device, ephemeral_port(rng)};
    const Endpoint resolver{device.is_v4() ? kRouter : kRouter6, 53};
    const auto id = static_cast<std::uint16_t>(rng());
    em.udp(client, resolver, static_cast<std::uint32_t>(name.size() + 18));
    em.udp(resolver, client, DnsMessage::answer(id, name, address));
}

class Activity {
public:
    virtual ~Activity() = default;
    // Emits the packets for simulated time [t, t + dt).
    virtual void step(double t, double dt, Emitter& em, Rng& rng) = 0;
};

// One long-lived download: video (on/off bursts) or a bulk transfer (flat out), over TCP or
// QUIC. The DNS lookup happens just before it starts and again every few minutes.
class Download final : public Activity {
public:
    struct Shape {
        double start = 0;         // seconds
        double rate = 0;          // bytes per second while on
        double period = 0;        // 0: always on once started
        double on_seconds = 0;    // within each period
        bool quic = false;
    };

    Download(IpAddress device, IpAddress server, std::string_view server_name, Shape shape, Rng& rng)
        : client_{device, ephemeral_port(rng)},
          server_{server, 443},
          name_(server_name),
          shape_(shape) {}

    void step(double t, double dt, Emitter& em, Rng& rng) override {
        const bool new_cycle = shape_.period > 0 && due(t, dt, shape_.period, shape_.start);
        if ((!name_.empty() && due(t, dt, 240, shape_.start - 0.2)) ||
            (new_cycle && !looked_up_this_cycle(t))) {
            em.at(t);
            dns_lookup(em, rng, client_.ip, name_, server_.ip);
            last_lookup_ = t;
        }
        if (t < shape_.start) return;
        if (shape_.period > 0 && std::fmod(t - shape_.start, shape_.period) >= shape_.on_seconds) return;

        owed_ += shape_.rate * dt * uniform(rng, 0.85, 1.15);
        const std::uint32_t size = shape_.quic ? kQuicPacket : kTcpSegment;
        const auto packets = static_cast<std::uint32_t>(owed_ / size);
        owed_ -= static_cast<double>(packets) * size;
        for (std::uint32_t i = 0; i < packets; ++i) {
            em.at(t + dt * i / packets);
            if (shape_.quic) {
                em.udp(server_, client_, size);
                if (++sent_ % 10 == 0) em.udp(client_, server_, 40);  // QUIC acknowledgments
            } else {
                em.tcp(server_, client_, size);
                if (++sent_ % 2 == 0) em.tcp(client_, server_, 0);  // TCP acks every other segment
            }
        }
    }

private:
    bool looked_up_this_cycle(double t) const { return last_lookup_ >= 0 && t - last_lookup_ < 5; }

    Endpoint client_;
    Endpoint server_;
    std::string_view name_;
    Shape shape_;
    double owed_ = 0;
    double last_lookup_ = -1;
    std::uint64_t sent_ = 0;
};

// A steady two-way stream of small UDP packets: a video call, or a game's state updates.
class Realtime final : public Activity {
public:
    struct Shape {
        double start = 0;
        double packets_per_second = 0;  // each way
        std::uint32_t down_bytes = 0;
        std::uint32_t up_bytes = 0;
    };

    Realtime(IpAddress device, IpAddress server, std::uint16_t port, std::string_view server_name,
             Shape shape, Rng& rng)
        : client_{device, ephemeral_port(rng)}, server_{server, port}, name_(server_name), shape_(shape) {}

    void step(double t, double dt, Emitter& em, Rng& rng) override {
        if (!name_.empty() && due(t, dt, 240, shape_.start - 0.2)) {
            em.at(t);
            dns_lookup(em, rng, client_.ip, name_, server_.ip);
        }
        if (t < shape_.start) return;
        owed_ += shape_.packets_per_second * dt;
        const auto packets = static_cast<int>(owed_);
        owed_ -= packets;
        for (int i = 0; i < packets; ++i) {
            em.at(t + dt * i / packets);
            const double wobble = uniform(rng, 0.8, 1.2);
            em.udp(server_, client_, static_cast<std::uint32_t>(shape_.down_bytes * wobble));
            em.udp(client_, server_, static_cast<std::uint32_t>(shape_.up_bytes * wobble));
        }
    }

private:
    Endpoint client_;
    Endpoint server_;
    std::string_view name_;
    Shape shape_;
    double owed_ = 0;
};

// A terminal session: a few small packets each way whenever someone types.
class Ssh final : public Activity {
public:
    Ssh(IpAddress device, Rng& rng) : client_{device, ephemeral_port(rng)}, server_{kSshServer, 22} {}

    void step(double t, double dt, Emitter& em, Rng& rng) override {
        if (due(t, dt, 240, 0.5)) {
            em.at(t);
            dns_lookup(em, rng, client_.ip, kSshServerName, server_.ip);
        }
        if (t < 1 || uniform(rng, 0, 1) > 0.04) return;
        em.at(t);
        em.tcp(client_, server_, 36, tcp_flags::kAck | tcp_flags::kPsh);
        em.tcp(server_, client_, static_cast<std::uint32_t>(uniform(rng, 36, 400)),
               tcp_flags::kAck | tcp_flags::kPsh);
    }

private:
    Endpoint client_;
    Endpoint server_;
};

// Opening web pages: a DNS lookup, then a short connection that downloads a few hundred kB.
class Browsing final : public Activity {
public:
    Browsing(IpAddress device, double mean_gap, double max_bytes)
        : device_(device), mean_gap_(mean_gap), max_bytes_(max_bytes) {}

    void step(double t, double dt, Emitter& em, Rng& rng) override {
        if (next_ < 0) next_ = uniform(rng, 0.5, mean_gap_);
        if (t >= next_) {
            const Site& site = kSites[std::uniform_int_distribution<std::size_t>(0, kSites.size() - 1)(rng)];
            em.at(t);
            dns_lookup(em, rng, device_, site.name, site.address);
            Load load;
            load.client = {device_, ephemeral_port(rng)};
            load.server = {site.address, 443};
            load.remaining = uniform(rng, 0.1, 1.0) * max_bytes_;
            load.rate = load.remaining / uniform(rng, 0.5, 2.5);
            em.tcp(load.client, load.server, 0, tcp_flags::kSyn);
            em.tcp(load.server, load.client, 0, tcp_flags::kSyn | tcp_flags::kAck);
            em.tcp(load.client, load.server, 520, tcp_flags::kAck | tcp_flags::kPsh);  // the request
            loads_.push_back(load);
            next_ = t + std::exponential_distribution<double>(1.0 / mean_gap_)(rng) + 0.3;
        }

        for (Load& load : loads_) {
            const double bytes = std::min(load.remaining, load.rate * dt);
            load.remaining -= bytes;
            load.owed += bytes;
            const auto packets = static_cast<std::uint32_t>(load.owed / kTcpSegment);
            load.owed -= static_cast<double>(packets) * kTcpSegment;
            for (std::uint32_t i = 0; i < packets; ++i) {
                em.at(t + dt * i / packets);
                em.tcp(load.server, load.client, kTcpSegment);
                if (i % 2 == 1) em.tcp(load.client, load.server, 0);
            }
            if (load.remaining <= 0) {
                em.at(t);
                em.tcp(load.client, load.server, 0, tcp_flags::kFin | tcp_flags::kAck);
                em.tcp(load.server, load.client, 0, tcp_flags::kFin | tcp_flags::kAck);
            }
        }
        std::erase_if(loads_, [](const Load& l) { return l.remaining <= 0; });
    }

private:
    struct Load {
        Endpoint client;
        Endpoint server;
        double remaining = 0;
        double rate = 0;
        double owed = 0;
    };

    IpAddress device_;
    double mean_gap_;
    double max_bytes_;
    double next_ = -1;
    std::vector<Load> loads_;
};

// The network's housekeeping: devices announcing their names over mDNS, clock sync, address
// resolution, and a TV advertising itself for casting.
class Background final : public Activity {
public:
    void step(double t, double dt, Emitter& em, Rng& rng) override {
        em.at(t);
        struct Device {
            std::string_view name;
            std::vector<IpAddress> addresses;
            double offset;
        };
        static const std::array kDevices = {
            Device{"family-laptop.local", {kLaptop}, 1.0},
            Device{"phone.local", {kPhone}, 2.5},
            Device{"gaming-pc.local", {kGamingPc}, 4.0},
            Device{"living-room-tv.local", {kTv, kTv6}, 5.5},
        };
        for (const Device& d : kDevices) {
            const IpAddress& ip = d.addresses.front();
            if (due(t, dt, 60, d.offset)) {
                em.udp(Endpoint{ip, 5353}, Endpoint{kMdnsGroup, 5353},
                       DnsMessage::announcement(d.name, d.addresses));
            }
            if (due(t, dt, 64, d.offset + 10)) {
                const Endpoint client{ip, 123};
                const Endpoint server{kTimeServer, 123};
                if (due(t, dt, 1024, d.offset + 10)) dns_lookup(em, rng, ip, kTimeServerName, kTimeServer);
                em.udp(client, server, 48);
                em.udp(server, client, 48);
            }
            if (due(t, dt, 20, d.offset + 3)) {
                em.arp(kRouter, ip, false);
                em.arp(ip, kRouter, true);
            }
        }
        if (due(t, dt, 30, 8)) {
            em.udp(Endpoint{kTv, 1900}, Endpoint{kSsdpGroup, 1900}, 310);  // SSDP NOTIFY
        }
        if (due(t, dt, 25, 12)) {
            em.icmpv6(kTv6, kRouter6, 135, 32);  // neighbor solicitation
            em.icmpv6(kRouter6, kTv6, 136, 32);  // neighbor advertisement
        }
        if (due(t, dt, 120, 30)) {
            em.udp(Endpoint{IpAddress::v4(0, 0, 0, 0), 68}, Endpoint{kBroadcast, 67}, 300);  // DHCP
        }
    }
};

class Household {
public:
    explicit Household(std::uint32_t seed) : rng_(seed) {
        activities_.push_back(std::make_unique<Background>());
        // The TV streams a show over IPv6: ~13 Mbit/s on average, fetched 4 s out of every 12.
        activities_.push_back(std::make_unique<Download>(
            kTv6, kVideoCdn6, kVideoCdnName,
            Download::Shape{.start = 0.5, .rate = 5'000'000, .period = 12, .on_seconds = 4, .quic = false},
            rng_));
        // The laptop watches video over QUIC, in shorter bursts.
        activities_.push_back(std::make_unique<Download>(
            kLaptop, kVideoQuic, kVideoQuicName,
            Download::Shape{.start = 5, .rate = 2'000'000, .period = 10, .on_seconds = 4, .quic = true},
            rng_));
        // The phone joins a video call.
        activities_.push_back(std::make_unique<Realtime>(
            kPhone, kCallServer, std::uint16_t{8801}, kCallServerName,
            Realtime::Shape{.start = 20, .packets_per_second = 50, .down_bytes = 1000, .up_bytes = 800},
            rng_));
        // The gaming PC plays online...
        activities_.push_back(std::make_unique<Realtime>(
            kGamingPc, kGameServer, std::uint16_t{27015}, std::string_view{},
            Realtime::Shape{.start = 0.2, .packets_per_second = 30, .down_bytes = 140, .up_bytes = 110},
            rng_));
        // ...and then starts a big game download, flat out (the scripted status-line event).
        activities_.push_back(std::make_unique<Download>(
            kGamingPc, kGameDownloads, kGameDownloadsName,
            Download::Shape{.start = DemoSource::kDownloadStart,
                            .rate = 15'000'000,
                            .period = DemoSource::kDownloadPeriod,
                            .on_seconds = DemoSource::kDownloadLength,
                            .quic = false},
            rng_));
        activities_.push_back(std::make_unique<Ssh>(kLaptop, rng_));
        activities_.push_back(std::make_unique<Browsing>(kLaptop, 6.0, 600'000));
        activities_.push_back(std::make_unique<Browsing>(kPhone, 9.0, 300'000));
    }

    void step(double t, double dt, Emitter& em) {
        for (auto& activity : activities_) activity->step(t, dt, em, rng_);
    }

private:
    Rng rng_;
    std::vector<std::unique_ptr<Activity>> activities_;
};

}  // namespace

DemoSource::DemoSource(Options options) : options_(options) {}

void DemoSource::run(BoundedQueue<CapturedPacket>& queue) {
    // Recorded-traffic semantics: wait for queue space rather than drop, since nothing is lost
    // by waiting.
    PacketBatcher batcher(queue, PacketBatcher::Overflow::Wait);
    const auto origin = SteadyClock::now();
    Emitter emitter(batcher, origin);
    Household household(options_.seed);
    const double preroll = std::chrono::duration<double>(options_.preroll).count();

    for (std::uint64_t i = 0; !stop_.load(std::memory_order_relaxed); ++i) {
        const double t = static_cast<double>(i) * kTick;
        if (options_.duration && t >= std::chrono::duration<double>(*options_.duration).count()) break;
        household.step(t, kTick, emitter);
        produced_.store(emitter.count(), std::memory_order_relaxed);

        // After the pre-roll, simulated time keeps pace with the wall clock: packets stamped
        // origin + t are released at origin + (t - preroll).
        if (options_.realtime && t >= preroll) {
            batcher.flush();
            std::this_thread::sleep_until(
                origin + std::chrono::duration_cast<SteadyClock::duration>(
                             std::chrono::duration<double>(t + kTick - preroll)));
        }
    }
    batcher.flush();
}

CaptureCounters DemoSource::counters() const {
    CaptureCounters c;
    c.captured = produced_.load(std::memory_order_relaxed);
    return c;
}

LocalNetworks DemoSource::local_networks() const {
    LocalNetworks networks;
    networks.add(*IpPrefix::parse("192.168.1.0/24"));
    networks.add(*IpPrefix::parse("2001:db8:1::/64"));
    return networks;
}

}  // namespace netpulse
