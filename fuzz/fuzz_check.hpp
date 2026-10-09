#pragma once

#include <cstdio>
#include <cstdlib>

// A property every input must satisfy. Failing aborts, which both libFuzzer and the standalone
// driver treat as a crash: libFuzzer saves the input, the driver prints which one it was.
#define FUZZ_CHECK(condition)                                                                   \
    do {                                                                                        \
        if (!(condition)) {                                                                     \
            std::fprintf(stderr, "FUZZ_CHECK failed: %s (%s:%d)\n", #condition, __FILE__, __LINE__); \
            std::abort();                                                                       \
        }                                                                                       \
    } while (0)
