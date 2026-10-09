#!/usr/bin/env bash
# Live capture benchmark on the loopback interface: iperf3 generates traffic inside this
# machine while NetPulse captures it, then reports what NetPulse saw, what it missed (and
# where), and how much CPU it used.
#
# Usage: tools/bench_live.sh <path-to-netpulse> [seconds-per-test]
# The binary needs capture capabilities (setcap; see README). Needs iperf3.
set -uo pipefail

BIN=${1:?usage: bench_live.sh <path-to-netpulse> [seconds]}
SECS=${2:-10}
PORT=5299
WORK=$(mktemp -d)
trap 'kill $SERVER 2>/dev/null; rm -rf "$WORK"' EXIT

iperf3 -s -p $PORT >/dev/null 2>&1 &
SERVER=$!
sleep 0.5

run() {  # name, iperf3 client args...
    local name=$1; shift
    # Run NetPulse in a subshell and print the subshell's children CPU times afterwards.
    ( "$BIN" -i lo --plain --no-resolve -d $((SECS + 2)) > "$WORK/np.txt" 2>&1; times > "$WORK/times.txt" ) &
    local np=$!
    sleep 1
    iperf3 -c 127.0.0.1 -p $PORT -t "$SECS" "$@" > "$WORK/iperf.txt" 2>&1
    wait $np

    local summary missed_line cpu
    summary=$(grep '^summary:' "$WORK/np.txt" | tail -1)
    missed_line=$(grep '^Missed' "$WORK/np.txt" | tail -1)
    # `times` second line: children user and system time, e.g. "0m1.234s 0m0.567s"
    cpu=$(sed -n 2p "$WORK/times.txt" | awk '{
        split($1, u, /[ms]/); split($2, s, /[ms]/);
        printf "%.2f", u[1] * 60 + u[2] + s[1] * 60 + s[2] }')
    local packets=${summary#*packets=}; packets=${packets%% *}
    local sender
    sender=$(grep -E 'sender' "$WORK/iperf.txt" | tail -1 | awk '{print $7, $8}')

    printf '%-22s iperf3 %-14s | NetPulse saw %10s pkts (%8.0f/s) | %s | CPU %5.2f s (%3.0f%% of one core)\n' \
        "$name" "$sender" "$packets" "$(echo "$packets / ($SECS + 2)" | bc -l)" \
        "${missed_line%% ·*}" "$cpu" "$(echo "$cpu / ($SECS + 2) * 100" | bc -l)"
}

run "TCP bulk"
run "UDP 64-byte flood" -u -b 0 -l 64
