#!/usr/bin/env bash
# Records docs/demo.svg: the --demo dashboard driven through a short tour of keystrokes,
# captured with tmux and drawn by terminal_svg.py. Needs tmux and python3.
#
# Usage: tools/record_demo.sh [path/to/netpulse] [out.svg]
# Set FRAMES_DIR to keep the individual captures there.
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
BIN=${1:-$HOME/netpulse-build/netpulse}
OUT=${2:-$HERE/../docs/demo.svg}
COLS=100
ROWS=50
SESSION=netpulse-record-$$
if [ -n "${FRAMES_DIR:-}" ]; then
    DIR=$FRAMES_DIR
    mkdir -p "$DIR"
    trap 'tmux kill-session -t "$SESSION" 2>/dev/null || true' EXIT
else
    DIR=$(mktemp -d)
    trap 'tmux kill-session -t "$SESSION" 2>/dev/null || true; rm -rf "$DIR"' EXIT
fi

screen() { tmux capture-pane -p -t "$SESSION"; }
keys() { for k in "$@"; do tmux send-keys -t "$SESSION" "$k"; sleep 0.15; done; }
frames=()
shot() {  # shot HOLD: capture the screen, shown for HOLD seconds in the recording
    sleep 0.4
    local file="$DIR/${#frames[@]}.ans"
    tmux capture-pane -p -e -t "$SESSION" > "$file"
    frames+=("$file:$1")
}
# Moves the cursor down until it's on a row that starts with $1 (a top talker's name).
find_row() {
    for _ in $(seq 60); do
        screen | grep -q "▸ $1" && return 0
        keys Down
    done
    echo "row '$1' not found" >&2
    return 1
}

tmux new-session -d -s "$SESSION" -x "$COLS" -y "$ROWS" "$BIN --demo"
sleep 1.5
shot 3                       # the opening view
keys Down Down; shot 3       # a category: the Learn panel explains the judgment...
keys Right; shot 3           # ...and how it was made
# Live updates while the demo heads toward its scripted event: the gaming PC's big download.
until screen | grep -q "Heads up"; do shot 1; done
keys g; shot 5               # the status line, and why it says so
find_row "gaming-pc.local"; keys Enter; shot 5   # that device's own conversations
keys '?'; shot 4             # the keys

python3 "$HERE/terminal_svg.py" "$OUT" "${frames[@]}" --title "netpulse --demo"
echo "wrote $OUT (${#frames[@]} frames)"
