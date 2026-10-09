#pragma once

#include <cstdint>

namespace netpulse {

// What a conversation is probably for. A heuristic, not ground truth: NetPulse never reads
// payload, so these come from names (reverse DNS) and from the shape of the traffic.
enum class Category : std::uint8_t {
    Streaming,
    Browsing,
    CallsGaming,
    FileTransfer,
    Other,       // didn't match anything: shown honestly rather than force-fit
    Background,  // DNS, NTP, discovery, ICMP...: real but negligible, left out of the breakdown
};

inline constexpr Category kShownCategories[] = {Category::Streaming, Category::Browsing,
                                                Category::CallsGaming, Category::FileTransfer,
                                                Category::Other};

// How a category was decided. Shown next to every category so the reader always knows how
// much to trust it.
enum class ClassMethod : std::uint8_t {
    KnownService,  // the remote address's name matched the built-in list of services
    FlowShape,     // duration, volume, direction and burstiness matched a typical pattern
    None,          // nothing matched (Other) or not applicable (Background)
};

const char* category_label(Category c);        // "Streaming / video"
const char* category_short_label(Category c);  // "Streaming"
const char* category_key(Category c);          // "streaming"
const char* method_tag(ClassMethod m);         // "[known-service match]"

}  // namespace netpulse
