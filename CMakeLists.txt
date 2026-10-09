cmake_minimum_required(VERSION 3.24)
project(netpulse VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE RelWithDebInfo CACHE STRING "Build type" FORCE)
endif()

option(NETPULSE_BUILD_TESTS "Build the Catch2 test suite" ON)
option(NETPULSE_WARNINGS_AS_ERRORS "Treat compiler warnings as errors" OFF)
set(NETPULSE_SANITIZER "" CACHE STRING "Sanitizers to enable, e.g. 'address,undefined' or 'thread'")

# ---------------------------------------------------------------------------
# Dependencies
# ---------------------------------------------------------------------------
include(FetchContent)
find_package(Threads REQUIRED)

find_path(PCAP_INCLUDE_DIR pcap.h REQUIRED)
find_library(PCAP_LIBRARY pcap REQUIRED)
add_library(pcap::pcap UNKNOWN IMPORTED)
set_target_properties(pcap::pcap PROPERTIES
  IMPORTED_LOCATION "${PCAP_LIBRARY}"
  INTERFACE_INCLUDE_DIRECTORIES "${PCAP_INCLUDE_DIR}")

FetchContent_Declare(ftxui
  GIT_REPOSITORY https://github.com/ArthurSonzogni/FTXUI.git
  GIT_TAG v5.0.0
  GIT_SHALLOW TRUE)
FetchContent_MakeAvailable(ftxui)

# ---------------------------------------------------------------------------
# Shared compile options for NetPulse's own targets (not third-party code)
# ---------------------------------------------------------------------------
add_library(netpulse_options INTERFACE)
target_compile_options(netpulse_options INTERFACE -Wall -Wextra -Wpedantic -Wshadow)
if(NETPULSE_WARNINGS_AS_ERRORS)
  target_compile_options(netpulse_options INTERFACE -Werror)
endif()
if(NETPULSE_SANITIZER)
  target_compile_options(netpulse_options INTERFACE
    -fsanitize=${NETPULSE_SANITIZER} -fno-omit-frame-pointer)
  target_link_options(netpulse_options INTERFACE -fsanitize=${NETPULSE_SANITIZER})
endif()

# ---------------------------------------------------------------------------
# Libraries
# ---------------------------------------------------------------------------

# Pure logic: parsing, aggregation, name resolution, helpers. No libpcap, no UI,
# so the whole thing is unit-testable without capture privileges.
add_library(netpulse_core STATIC
  src/parse/packet_parser.cpp
  src/parse/dns.cpp
  src/capture/capture_filter.cpp
  src/aggregate/throughput_window.cpp
  src/aggregate/aggregator.cpp
  src/aggregate/classifier.cpp
  src/aggregate/status_tracker.cpp
  src/aggregate/observed_names.cpp
  src/resolve/resolver.cpp
  src/util/format.cpp
  src/util/net.cpp
  src/util/ip_address.cpp
  src/util/local_networks.cpp)
target_include_directories(netpulse_core PUBLIC src)
target_link_libraries(netpulse_core PUBLIC Threads::Threads netpulse_options)

# libpcap capture plus the threaded pipeline that connects it to the core.
add_library(netpulse_capture STATIC
  src/capture/packet_capture.cpp
  src/pipeline/pipeline.cpp)
target_link_libraries(netpulse_capture PUBLIC netpulse_core pcap::pcap)

# UI logic with no FTXUI dependency (focus handling, glossary, what each row explains), so it
# is unit-testable alongside the core.
add_library(netpulse_view STATIC
  src/ui/focus_model.cpp
  src/ui/glossary.cpp
  src/ui/dashboard_model.cpp)
target_link_libraries(netpulse_view PUBLIC netpulse_core)

# Simulated household traffic for --demo.
add_library(netpulse_demo STATIC
  src/demo/demo_source.cpp)
target_link_libraries(netpulse_demo PUBLIC netpulse_core)

add_library(netpulse_ui STATIC
  src/ui/dashboard.cpp
  src/ui/plain_report.cpp)
target_link_libraries(netpulse_ui PUBLIC netpulse_capture netpulse_view
  ftxui::screen ftxui::dom ftxui::component)

add_executable(netpulse src/main.cpp)
target_link_libraries(netpulse PRIVATE netpulse_ui netpulse_demo)

# Synthetic-load benchmark of the pipeline itself (no capture privileges needed).
add_executable(netpulse_bench src/bench/bench_main.cpp)
target_link_libraries(netpulse_bench PRIVATE netpulse_capture)

# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------
if(NETPULSE_BUILD_TESTS)
  enable_testing()

  FetchContent_Declare(Catch2
    GIT_REPOSITORY https://github.com/catchorg/Catch2.git
    GIT_TAG v3.7.1
    GIT_SHALLOW TRUE)
  FetchContent_MakeAvailable(Catch2)
  list(APPEND CMAKE_MODULE_PATH ${catch2_SOURCE_DIR}/extras)
  include(Catch)

  add_executable(netpulse_tests
    tests/test_parse.cpp
    tests/test_bounded_queue.cpp
    tests/test_flow_key.cpp
    tests/test_throughput_window.cpp
    tests/test_aggregator.cpp
    tests/test_resolver.cpp
    tests/test_format.cpp
    tests/test_focus_model.cpp
    tests/test_dashboard_model.cpp
    tests/test_classifier.cpp
    tests/test_status_tracker.cpp
    tests/test_local_networks.cpp
    tests/test_dns.cpp
    tests/test_capture_filter.cpp
    tests/test_demo.cpp)
  target_link_libraries(netpulse_tests PRIVATE netpulse_view netpulse_capture netpulse_demo
    Catch2::Catch2WithMain)
  target_include_directories(netpulse_tests PRIVATE tests)
  # Discover test cases when ctest runs rather than as a post-build step, so building never
  # depends on being able to execute the binary (sanitizer runtimes, cross builds).
  catch_discover_tests(netpulse_tests DISCOVERY_MODE PRE_TEST)

  # End-to-end: replay the synthetic fixture through the real capture -> queue ->
  # aggregator pipeline and check the totals. Expected numbers come from
  # tools/make_synthetic_pcap.py, which builds the file independently of the C++ parser.
  add_test(NAME replay_synthetic_pcap
    COMMAND netpulse --read ${CMAKE_SOURCE_DIR}/sample_pcaps/synthetic.pcap --plain --no-resolve)
  set_tests_properties(replay_synthetic_pcap PROPERTIES
    PASS_REGULAR_EXPRESSION "summary: packets=72 bytes=44782 tcp=44 udp=19 other_ip=4 non_ip=2 malformed=3 ipv6=9 flows=10 hosts=13 missed=0")

  # The --demo flag end to end (the demo's content is checked in test_demo.cpp).
  add_test(NAME demo_plain
    COMMAND netpulse --demo --plain --duration 1)
  set_tests_properties(demo_plain PROPERTIES
    PASS_REGULAR_EXPRESSION "summary: packets=[1-9][0-9]* [^\n]* malformed=0 [^\n]*\ncategories: streaming=2 ")

  # End-to-end for the classifier and status line: one conversation of each traffic pattern,
  # ending in a large download that should read as "a lot more data than usual".
  add_test(NAME replay_traffic_mix_pcap
    COMMAND netpulse --read ${CMAKE_SOURCE_DIR}/sample_pcaps/traffic_mix.pcap --plain --no-resolve)
  set_tests_properties(replay_traffic_mix_pcap PROPERTIES
    PASS_REGULAR_EXPRESSION "categories: streaming=1 browsing=8 calls-gaming=1 file-transfer=1 other=1\nstatus: device-above-usual")

  # With --dns-names, the DNS answers in the same capture name the video and call servers, so
  # those two become known-service matches instead of pattern guesses.
  add_test(NAME replay_traffic_mix_dns_names
    COMMAND netpulse --read ${CMAKE_SOURCE_DIR}/sample_pcaps/traffic_mix.pcap --plain --no-resolve --dns-names)
  set_tests_properties(replay_traffic_mix_dns_names PROPERTIES
    PASS_REGULAR_EXPRESSION "Streaming / video +\\[known-domain match\\][^\n]*\n[^\n]*\n *Calls / gaming +\\[known-domain match\\]")
endif()
