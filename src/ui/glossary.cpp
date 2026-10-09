#include "ui/glossary.hpp"

#include <algorithm>
#include <array>

namespace netpulse {

namespace {

// Hardcoded on purpose (content, not configuration). The first twelve entries are the
// glossary as written in the design phase; the entries after them were added for terms the
// dashboard shows that the original list didn't cover.
constexpr std::array kGlossary = {
    GlossaryEntry{"packet", "Packet",
                  "A small chunk that any network communication gets broken into for "
                  "transmission. Loading one web page might involve hundreds of packets, sent and "
                  "reassembled automatically."},
    GlossaryEntry{"protocol", "Protocol",
                  "An agreed-upon set of rules for how two computers communicate. TCP and UDP are "
                  "both protocols; there are many others."},
    GlossaryEntry{"tcp", "TCP (Transmission Control Protocol)",
                  "A connection type that guarantees data arrives complete and in order, resending "
                  "anything lost along the way. Used for things like loading web pages or "
                  "transferring files. Trade-off: that reliability adds a small amount of overhead "
                  "compared to UDP."},
    GlossaryEntry{"udp", "UDP (User Datagram Protocol)",
                  "A faster, \"fire and forget\" connection type with no guarantee data arrives or "
                  "arrives in order. Used for things like video calls or games, where a dropped "
                  "chunk matters less than the delay of resending it."},
    GlossaryEntry{"port", "Port",
                  "A number identifying which specific service or program on a device a piece of "
                  "traffic is meant for. A device can have many connections open at once; the port "
                  "is how they're told apart."},
    GlossaryEntry{"ip-address", "IP address",
                  "The numeric address that identifies a device on a network — similar in spirit "
                  "to a street address. Every packet has a source and a destination IP address."},
    GlossaryEntry{"flow", "Flow / connection",
                  "All the traffic between one specific pair of devices (and ports) treated as a "
                  "single ongoing conversation, rather than looking at each packet alone."},
    GlossaryEntry{"throughput", "Throughput",
                  "How much data is moving per second, right now. Shown here in human-readable "
                  "form, like \"12.4 MB/s.\""},
    GlossaryEntry{"latency", "Latency",
                  "The delay between sending something and it arriving. Matters most for things "
                  "that feel \"live,\" like a video call or an online game."},
    GlossaryEntry{"dropped-packet", "Dropped packet",
                  "A packet that didn't make it through — due to network congestion, a device "
                  "falling behind, or (in this tool's case) the capture process itself not keeping "
                  "up. This tool reports its own dropped count honestly rather than hiding it."},
    GlossaryEntry{"dns", "DNS (Domain Name System)",
                  "The system that turns a human-readable name into the numeric IP address a "
                  "computer actually needs. This tool uses it in reverse — turning IPs back into "
                  "readable names where possible."},
    GlossaryEntry{"header", "Header",
                  "The \"label\" portion of a packet — source/destination, ports, protocol type — "
                  "as opposed to the actual content being sent. This tool only ever reads headers, "
                  "never content."},

    // Added during implementation for terms the dashboard shows.
    GlossaryEntry{"icmp", "ICMP (Internet Control Message Protocol)",
                  "A small helper protocol devices use to report problems and check on each other, "
                  "rather than to carry data. Its best-known use is \"ping\", which sends a request "
                  "and times how long the reply takes. IPv6 has its own version, ICMPv6, which it "
                  "also relies on to find routers and neighbors on the local network."},
    GlossaryEntry{"other-ip", "Other IP",
                  "Traffic that uses IP (version 4 or 6) but isn't TCP or UDP, such as ICMP "
                  "\"ping\" messages and the ICMPv6 messages IPv6 uses to find its neighbors. "
                  "Usually a tiny share. Pieces of a packet that was split up in transit (fragments) "
                  "also land here, because only the first piece says which protocol it belongs to."},
    GlossaryEntry{"non-ip", "Non-IP",
                  "Traffic that isn't IP at all. On a home network that's mostly ARP, the way IPv4 "
                  "devices find each other's hardware addresses on the local network. NetPulse "
                  "counts it but doesn't look inside it."},
    GlossaryEntry{"ipv4", "IPv4 (Internet Protocol version 4)",
                  "The original internet addressing system: 32-bit addresses written as four "
                  "numbers, like 192.168.1.14. There are only about 4 billion of them, which is why "
                  "a home network usually shares one public IPv4 address between all its devices."},
    GlossaryEntry{"ipv6", "IPv6 (Internet Protocol version 6)",
                  "The newer addressing system: 128-bit addresses written in hexadecimal groups, "
                  "like 2001:db8::1, enough for every device to have its own public address. Most "
                  "networks run both versions side by side; how much of your traffic uses each "
                  "depends on your internet provider and the services you use."},
    GlossaryEntry{"malformed", "Malformed packet",
                  "A packet whose headers were cut short or didn't add up, so it couldn't be read "
                  "safely. This tool counts it and moves on rather than guessing. A few are normal; "
                  "a steady stream can point to a faulty device or a capture problem."},
    GlossaryEntry{"local-address", "Local vs. internet address",
                  "Some IP address ranges (like 192.168.x.x and 10.x.x.x) are reserved for private "
                  "networks, such as the devices in your home. \"Local\" means the address is on "
                  "that private side, inside the network NetPulse is capturing on (with IPv6, home "
                  "devices usually get public addresses, so this is how they're recognized), or one "
                  "devices use to announce things to everyone nearby (multicast and broadcast). "
                  "\"Internet\" means an address out on the wider internet."},
    GlossaryEntry{"observed-dns", "Name from a DNS answer",
                  "This is the name a device on your network asked for when it looked this "
                  "address up (like www.youtube.com), read from the DNS answer as it went by. "
                  "That's usually more meaningful than a reverse lookup, which for big services "
                  "often returns nothing or a generic server name. Reading DNS answers is opt-in "
                  "(--dns-names), because it means reading the contents of one kind of packet: "
                  "the names your devices look up."},
    GlossaryEntry{"flow-shape-heuristic", "Flow-shape heuristic",
                  "A label based on the shape of a conversation: how long it lasts, how much data "
                  "moves and in which direction, and whether it flows continuously or in bursts. "
                  "Not on what's inside it, which is encrypted and never read. It's an educated "
                  "guess and can be wrong, which is why it's labeled as one."},
    GlossaryEntry{"known-domain-match", "Known-domain match",
                  "A label based on who the traffic is going to: the address's name (from a reverse "
                  "DNS lookup, or from a DNS answer a device received) matched NetPulse's short "
                  "built-in list of well-known services (like nflxvideo.net for streaming). More "
                  "reliable than a pattern guess, but the list is small and many services' "
                  "addresses have no such name."},
};

}  // namespace

std::span<const GlossaryEntry> glossary() { return kGlossary; }

const GlossaryEntry* find_glossary_entry(std::string_view key) {
    const auto it = std::find_if(kGlossary.begin(), kGlossary.end(),
                                 [&](const GlossaryEntry& e) { return e.key == key; });
    return it == kGlossary.end() ? nullptr : &*it;
}

}  // namespace netpulse
