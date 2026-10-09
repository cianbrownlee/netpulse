#pragma once

#include <span>
#include <string_view>

namespace netpulse {

// Plain-language explanations behind the dashboard's "Learn" panel. Every technical term the
// dashboard shows is selectable, and its entry here is what the reader sees.
struct GlossaryEntry {
    std::string_view key;    // stable id the dashboard refers to, e.g. "tcp"
    std::string_view title;  // e.g. "TCP (Transmission Control Protocol)"
    std::string_view text;
};

std::span<const GlossaryEntry> glossary();
const GlossaryEntry* find_glossary_entry(std::string_view key);

}  // namespace netpulse
