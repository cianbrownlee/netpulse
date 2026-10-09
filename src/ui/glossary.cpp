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
                  "and times how long the reply takes."},
    GlossaryEntry{"other-ipv4", "Other IPv4",
                  "Traffic that uses IPv4 addressing but isn't TCP or UDP, such as ICMP \"ping\" "
                  "messages. Usually a tiny share. Pieces of a packet that was split up in transit "
                  "(fragments) also land here, because only the first piece says which protocol it "
                  "belongs to."},
    GlossaryEntry{"non-ipv4", "Non-IPv4",
                  "Traffic that isn't IPv4 at all. On a home network that's mostly ARP (how "
                  "devices find each other on the local network) and IPv6 (the newer version of IP "
                  "addressing). This tool counts it but doesn't look inside it yet."},
    GlossaryEntry{"malformed", "Malformed packet",
                  "A packet whose headers were cut short or didn't add up, so it couldn't be read "
                  "safely. This tool counts it and moves on rather than guessing. A few are normal; "
                  "a steady stream can point to a faulty device or a capture problem."},
    GlossaryEntry{"local-address", "Local vs. internet address",
                  "Some IP address ranges (like 192.168.x.x and 10.x.x.x) are reserved for private "
                  "networks, such as the devices in your home. \"Local\" means the address is on "
                  "that private side, or is one devices use to announce things to everyone nearby "
                  "(multicast and broadcast). \"Internet\" means a public address out on the wider "
                  "internet."},
    GlossaryEntry{"flow-shape-heuristic", "Flow-shape heuristic",
                  "A label based on the shape of a conversation: how long it lasts, how much data "
                  "moves and in which direction, and whether it flows continuously or in bursts. "
                  "Not on what's inside it, which is encrypted and never read. It's an educated "
                  "guess and can be wrong, which is why it's labeled as one."},
    GlossaryEntry{"known-domain-match", "Known-domain match",
                  "A label based on who the traffic is going to: the address's name, found through "
                  "a reverse DNS lookup, matched NetPulse's short built-in list of well-known "
                  "services (like nflxvideo.net for streaming). More reliable than a pattern "
                  "guess, but the list is small and many services' addresses have no such name."},
};

}  // namespace

std::span<const GlossaryEntry> glossary() { return kGlossary; }

const GlossaryEntry* find_glossary_entry(std::string_view key) {
    const auto it = std::find_if(kGlossary.begin(), kGlossary.end(),
                                 [&](const GlossaryEntry& e) { return e.key == key; });
    return it == kGlossary.end() ? nullptr : &*it;
}

}  // namespace netpulse
