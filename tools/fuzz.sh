#!/usr/bin/env bash
# Coverage-guided fuzzing with libFuzzer: builds the fuzz targets (fuzz/) with clang,
# AddressSanitizer and UndefinedBehaviorSanitizer, seeds them from the sample captures and
# fuzz/corpus, and runs each for SECONDS. Any crash, sanitizer report or failed check stops the
# script with the input saved under BUILD_DIR/crashes.
#
# Usage: tools/fuzz.sh [SECONDS] [BUILD_DIR]      (needs clang and its libFuzzer runtime)
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
SECONDS_EACH=${1:-60}
BUILD=${2:-$HOME/netpulse-fuzz}
TARGETS=(fuzz_packet fuzz_dns fuzz_capture_filter)

CC=clang CXX=clang++ cmake -S "$ROOT" -B "$BUILD" -DCMAKE_BUILD_TYPE=RelWithDebInfo \
    -DNETPULSE_FUZZ=ON -DNETPULSE_SANITIZER=address,undefined -DNETPULSE_BUILD_TESTS=OFF > /dev/null
cmake --build "$BUILD" --target "${TARGETS[@]}" -j"$(nproc)"

# Seeds: each distinct frame of the sample captures, and the DNS messages among them plus the
# hand-made ones in fuzz/corpus/dns. libFuzzer adds what it discovers to these directories.
mkdir -p "$BUILD/corpus/frames" "$BUILD/corpus/dns" "$BUILD/crashes"
cp "$ROOT"/fuzz/corpus/dns/* "$BUILD/corpus/dns/"
python3 - "$BUILD/corpus" "$ROOT"/sample_pcaps/*.pcap <<'PY'
import hashlib, os, struct, sys
out = sys.argv[1]
for path in sys.argv[2:]:
    data = open(path, "rb").read()
    endian = "<" if data[:4] in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1") else ">"
    pos = 24
    while pos + 16 <= len(data):
        length = struct.unpack(endian + "I", data[pos + 8:pos + 12])[0]
        frame = data[pos + 16:pos + 16 + length]
        pos += 16 + length
        digest = hashlib.sha1(frame).hexdigest()[:16]
        open(os.path.join(out, "frames", digest), "wb").write(frame)
        # UDP from port 53 or 5353 over untagged IPv4: the DNS message is the payload.
        if len(frame) > 42 and frame[12:14] == b"\x08\x00" and frame[23] == 17:
            udp = 14 + (frame[14] & 0x0F) * 4
            if struct.unpack("!H", frame[udp:udp + 2])[0] in (53, 5353):
                open(os.path.join(out, "dns", digest), "wb").write(frame[udp + 8:])
PY

export ASAN_OPTIONS=abort_on_error=1 UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1
for target in "${TARGETS[@]}"; do
    corpus=$BUILD/corpus/frames
    [ "$target" = fuzz_dns ] && corpus=$BUILD/corpus/dns
    echo "== $target: ${SECONDS_EACH}s"
    log=$BUILD/$target.log
    status=0
    "$BUILD/$target" "$corpus" -max_total_time="$SECONDS_EACH" -timeout=5 -max_len=1600 \
        -artifact_prefix="$BUILD/crashes/$target-" -print_final_stats=1 > "$log" 2>&1 || status=$?
    grep -E '^#[0-9]+ +DONE|^stat::(number_of_executed_units|peak_rss_mb)' "$log" || true
    if [ "$status" -ne 0 ]; then
        tail -40 "$log"
        echo "$target FAILED; the input is saved in $BUILD/crashes"
        exit 1
    fi
done
echo "all fuzz targets ran ${SECONDS_EACH}s each without a failure"
