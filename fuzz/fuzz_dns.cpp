// Fuzz target: an arbitrary DNS message through the DNS-answer parser (--dns-names), which reads
// bytes anyone on the network can send.
//
// Beyond "no crash, no endless loop, no sanitizer report" (compression pointers are the classic
// trap), it checks that every name it returns is safe to put on a terminal: printable ASCII with
// no spaces, lowercase, and no longer than a DNS name can be.

#include <cstddef>
#include <cstdint>
#include <span>

#include "fuzz_check.hpp"
#include "parse/dns.hpp"

using namespace netpulse;

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    const auto answers = parse_dns_response(std::span<const std::uint8_t>(data, size));
    FUZZ_CHECK(answers.size() <= 64);
    for (const DnsNameAnswer& answer : answers) {
        FUZZ_CHECK(!answer.name.empty());
        FUZZ_CHECK(answer.name.size() <= 253);
        FUZZ_CHECK(!answer.addresses.empty());
        for (const char c : answer.name) {
            const auto u = static_cast<unsigned char>(c);
            FUZZ_CHECK(u > 0x20 && u < 0x7F);
            FUZZ_CHECK(!(c >= 'A' && c <= 'Z'));
        }
    }
    return 0;
}
