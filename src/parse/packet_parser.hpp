#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>

namespace netpulse {

inline constexpr std::uint16_t kEtherTypeIpv4 = 0x0800;
inline constexpr std::uint16_t kEtherTypeArp = 0x0806;
inline constexpr std::uint16_t kEtherTypeVlan = 0x8100;
inline constexpr std::uint16_t kEtherTypeIpv6 = 0x86DD;

inline constexpr std::uint8_t kIpProtoIcmp = 1;
inline constexpr std::uint8_t kIpProtoTcp = 6;
inline constexpr std::uint8_t kIpProtoUdp = 17;

inline constexpr std::size_t kEthernetHeaderLength = 14;
inline constexpr std::size_t kVlanTagLength = 4;
inline constexpr std::size_t kIpv4MinHeaderLength = 20;
inline constexpr std::size_t kTcpMinHeaderLength = 20;
inline constexpr std::size_t kUdpHeaderLength = 8;

// Each parse_* function reads one header from the front of `bytes` and returns nullopt if the
// bytes are too short or the header is internally inconsistent. They never read past the end
// of the span, so truncated or hostile input is rejected rather than crashing.
//
// All multi-byte fields are converted from network byte order (big-endian) to host order.

struct EthernetHeader {
    std::uint16_t ethertype = 0;     // of the payload, after any 802.1Q VLAN tag
    std::size_t header_length = 0;   // 14, or 18 with one VLAN tag
};

struct Ipv4Header {
    std::size_t header_length = 0;   // IHL * 4: 20 to 60 bytes
    std::uint16_t total_length = 0;  // header + payload, as claimed by the packet
    std::uint8_t protocol = 0;
    std::uint32_t src = 0;
    std::uint32_t dst = 0;
    // Fragment offset != 0: this packet carries the middle or end of a datagram, so it has
    // no transport (TCP/UDP) header of its own.
    bool is_later_fragment = false;
};

struct TcpHeader {
    std::uint16_t src_port = 0;
    std::uint16_t dst_port = 0;
    std::size_t header_length = 0;   // data offset * 4: 20 to 60 bytes
    std::uint8_t flags = 0;          // CWR ECE URG ACK PSH RST SYN FIN
};

struct UdpHeader {
    std::uint16_t src_port = 0;
    std::uint16_t dst_port = 0;
    std::uint16_t length = 0;
};

namespace tcp_flags {
inline constexpr std::uint8_t kFin = 0x01;
inline constexpr std::uint8_t kSyn = 0x02;
inline constexpr std::uint8_t kRst = 0x04;
inline constexpr std::uint8_t kPsh = 0x08;
inline constexpr std::uint8_t kAck = 0x10;
}  // namespace tcp_flags

std::optional<EthernetHeader> parse_ethernet(std::span<const std::uint8_t> bytes);
std::optional<Ipv4Header> parse_ipv4(std::span<const std::uint8_t> bytes);
std::optional<TcpHeader> parse_tcp(std::span<const std::uint8_t> bytes);
std::optional<UdpHeader> parse_udp(std::span<const std::uint8_t> bytes);

enum class PacketKind : std::uint8_t {
    Tcp,
    Udp,
    OtherIpv4,  // ICMP, IGMP, ..., and later IP fragments (no transport header to read)
    NonIpv4,    // ARP, IPv6, ... (IPv6 is out of MVP scope)
    Malformed,  // truncated or inconsistent headers
};

const char* to_string(PacketKind kind);

// Everything the aggregator needs from one Ethernet frame. Headers only: NetPulse never reads
// packet payload (and captures with a small snaplen, so payload mostly never reaches it).
struct PacketInfo {
    PacketKind kind = PacketKind::Malformed;
    std::uint16_t ethertype = 0;
    std::uint8_t ip_protocol = 0;
    std::uint32_t src_ip = 0;
    std::uint32_t dst_ip = 0;
    std::uint16_t src_port = 0;
    std::uint16_t dst_port = 0;
    std::uint8_t tcp_flags = 0;

    bool is_ipv4() const {
        return kind == PacketKind::Tcp || kind == PacketKind::Udp || kind == PacketKind::OtherIpv4;
    }
};

// Ethernet -> IPv4 -> TCP/UDP, stopping at the first layer that is absent or malformed.
PacketInfo parse_packet(std::span<const std::uint8_t> frame);

}  // namespace netpulse
