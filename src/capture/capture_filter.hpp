#pragma once

#include <linux/filter.h>

#include <vector>

namespace netpulse {

// The classic-BPF program NetPulse attaches to its capture socket. The kernel runs it for every
// packet and keeps as many bytes as it returns, *before* copying anything to NetPulse.
//
//   dns_snaplen == 0:  "return snaplen" for every packet (headers only).
//   dns_snaplen  > 0:  return dns_snaplen for DNS and mDNS responses (UDP from port 53 or 5353,
//                      untagged IPv4 without fragmentation, or IPv6 with UDP directly after the
//                      fixed header), and snaplen for everything else. That lets --dns-names read
//                      DNS answers without keeping any other payload.
//
// One caveat of the longer program: classic BPF ends a filter that reads past the end of a
// packet by returning 0, which drops the packet. With dns_snaplen set, runt IPv4/IPv6 frames too
// short to hold the fields it checks are therefore dropped rather than counted as malformed.
std::vector<sock_filter> build_capture_filter(unsigned snaplen, unsigned dns_snaplen);

}  // namespace netpulse
