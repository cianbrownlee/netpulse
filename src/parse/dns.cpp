#include "parse/dns.hpp"

#include <algorithm>

namespace netpulse {

namespace {

constexpr std::size_t kHeaderLength = 12;
constexpr std::size_t kMaxNameLength = 253;   // presentation form, without the trailing dot
constexpr std::size_t kMaxQuestions = 4;      // real responses have exactly one
constexpr std::size_t kMaxAnswers = 64;
constexpr std::uint16_t kTypeA = 1;
constexpr std::uint16_t kTypeAaaa = 28;
constexpr std::uint16_t kClassIn = 1;

std::uint16_t read_be16(std::span<const std::uint8_t> b, std::size_t offset) {
    return static_cast<std::uint16_t>((b[offset] << 8) | b[offset + 1]);
}

// Reads a possibly compressed name starting at `offset`. On success, `after` is set to where the
// record continues in the original position (just past the first pointer, or past the final
// zero-length label if there was none).
std::optional<std::string> read_name(std::span<const std::uint8_t> msg, std::size_t offset,
                                     std::size_t& after) {
    std::string name;
    std::size_t pos = offset;
    bool jumped = false;
    while (true) {
        if (pos >= msg.size()) return std::nullopt;
        const std::uint8_t length = msg[pos];

        if ((length & 0xC0) == 0xC0) {  // compression pointer: 14-bit offset into the message
            if (pos + 1 >= msg.size()) return std::nullopt;
            const std::size_t target = (std::size_t{length & 0x3Fu} << 8) | msg[pos + 1];
            // Only backwards. Every jump then lands strictly earlier, so following pointers
            // must end: a loop would need some pointer to go forwards or to itself.
            if (target >= pos) return std::nullopt;
            if (!jumped) {
                after = pos + 2;
                jumped = true;
            }
            pos = target;
            continue;
        }
        if ((length & 0xC0) != 0) return std::nullopt;  // 0x40 / 0x80 label types: unsupported

        if (length == 0) {
            if (!jumped) after = pos + 1;
            return name;
        }
        if (pos + 1 + length > msg.size()) return std::nullopt;
        if (!name.empty()) name += '.';
        for (std::size_t i = 0; i < length; ++i) {
            const auto c = static_cast<unsigned char>(msg[pos + 1 + i]);
            if (c <= 0x20 || c >= 0x7F) return std::nullopt;  // control, space, non-ASCII
            name += static_cast<char>(c >= 'A' && c <= 'Z' ? c + ('a' - 'A') : c);
        }
        if (name.size() > kMaxNameLength) return std::nullopt;
        pos += 1 + length;
    }
}

}  // namespace

std::vector<DnsNameAnswer> parse_dns_response(std::span<const std::uint8_t> msg) {
    std::vector<DnsNameAnswer> result;
    if (msg.size() < kHeaderLength) return result;

    // id (2) | flags (2) | question count | answer count | authority count | additional count
    const std::uint16_t flags = read_be16(msg, 2);
    const bool is_response = (flags & 0x8000) != 0;
    const unsigned rcode = flags & 0x000Fu;
    if (!is_response || rcode != 0) return result;
    const std::size_t questions = read_be16(msg, 4);
    const std::size_t answers = read_be16(msg, 6);
    if (questions > kMaxQuestions) return result;

    std::size_t pos = kHeaderLength;
    std::optional<std::string> question;
    for (std::size_t i = 0; i < questions; ++i) {
        std::size_t after = 0;
        auto name = read_name(msg, pos, after);
        if (!name || after + 4 > msg.size()) return result;  // type (2) + class (2)
        if (!question) question = std::move(name);
        pos = after + 4;
    }

    auto add = [&](const std::string& name, const IpAddress& address) {
        if (name.empty()) return;
        auto it = std::find_if(result.begin(), result.end(),
                               [&](const DnsNameAnswer& a) { return a.name == name; });
        if (it == result.end()) {
            result.push_back({name, {}});
            it = result.end() - 1;
        }
        if (std::find(it->addresses.begin(), it->addresses.end(), address) == it->addresses.end()) {
            it->addresses.push_back(address);
        }
    };

    for (std::size_t i = 0; i < std::min(answers, kMaxAnswers); ++i) {
        std::size_t after = 0;
        const auto owner = read_name(msg, pos, after);
        // type (2) | class (2) | TTL (4) | data length (2) | data
        if (!owner || after + 10 > msg.size()) break;  // cut off: keep what we have
        const std::uint16_t type = read_be16(msg, after);
        const std::uint16_t klass = read_be16(msg, after + 2) & 0x7FFF;  // mDNS cache-flush bit
        const std::size_t data_length = read_be16(msg, after + 8);
        const std::size_t data = after + 10;
        if (data + data_length > msg.size()) break;

        if (klass == kClassIn && type == kTypeA && data_length == 4) {
            add(question.value_or(*owner),
                IpAddress::v4(msg[data], msg[data + 1], msg[data + 2], msg[data + 3]));
        } else if (klass == kClassIn && type == kTypeAaaa && data_length == 16) {
            IpAddress::Bytes bytes{};
            std::copy_n(msg.begin() + static_cast<std::ptrdiff_t>(data), 16, bytes.begin());
            add(question.value_or(*owner), IpAddress::v6(bytes));
        }
        pos = data + data_length;
    }
    return result;
}

}  // namespace netpulse
