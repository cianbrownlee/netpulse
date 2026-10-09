#!/usr/bin/env python3
"""Render terminal screen captures as an SVG image, still or animated.

Input frames are text with ANSI color codes, as `tmux capture-pane -p -e` produces. One frame
gives a still image; several give an animation that steps through them (docs/demo.svg is made
this way by tools/record_demo.sh). Each frame can be held for several time steps: FRAME:N.

Box-drawing and block characters are drawn as shapes rather than text, so borders, gauges and
sparklines line up exactly whatever monospace font the viewer has. Standard library only.

Usage: terminal_svg.py OUT.svg FRAME[:N] [FRAME[:N] ...] [--step SECONDS] [--title TEXT]
"""

import argparse
import html
import re

CELL_W = 8.4
CELL_H = 18.0
FONT_SIZE = 14
PAD = 16
TITLE_BAR = 30
RADIUS = 4.0  # rounded box corners

BACKGROUND = "#0d1117"
FOREGROUND = "#c9d1d9"
# ANSI colors 0-15, after GitHub's dark theme.
PALETTE = [
    "#484f58", "#ff7b72", "#3fb950", "#d29922", "#58a6ff", "#bc8cff", "#39c5cf", "#b1bac4",
    "#6e7681", "#ffa198", "#56d364", "#e3b341", "#79c0ff", "#d2a8ff", "#56d4dd", "#f0f6fc",
]

# Box drawing: which edges of the cell each character connects to (up, down, left, right),
# and whether its corner is rounded.
BOX = {
    "─": (0, 0, 1, 1, False), "│": (1, 1, 0, 0, False),
    "┌": (0, 1, 0, 1, False), "┐": (0, 1, 1, 0, False), "└": (1, 0, 0, 1, False), "┘": (1, 0, 1, 0, False),
    "╭": (0, 1, 0, 1, True), "╮": (0, 1, 1, 0, True), "╰": (1, 0, 0, 1, True), "╯": (1, 0, 1, 0, True),
    "├": (1, 1, 0, 1, False), "┤": (1, 1, 1, 0, False), "┬": (0, 1, 1, 1, False), "┴": (1, 0, 1, 1, False),
    "┼": (1, 1, 1, 1, False),
}
LOWER_BLOCKS = {c: (i + 1) / 8 for i, c in enumerate("▁▂▃▄▅▆▇█")}  # height from the bottom
LEFT_BLOCKS = {c: (8 - i) / 8 for i, c in enumerate("█▉▊▋▌▍▎▏")}  # width from the left

SGR = re.compile(r"\x1b\[([0-9;]*)m")
OTHER_ESCAPE = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")


class Style:
    __slots__ = ("fg", "bg", "bold", "dim", "inverse")

    def __init__(self):
        self.fg = None  # None: the default color
        self.bg = None
        self.bold = False
        self.dim = False
        self.inverse = False

    def copy(self):
        s = Style()
        s.fg, s.bg, s.bold, s.dim, s.inverse = self.fg, self.bg, self.bold, self.dim, self.inverse
        return s

    def colors(self):
        fg = self.fg or FOREGROUND
        bg = self.bg
        if self.inverse:
            fg, bg = (bg or BACKGROUND), fg
        return fg, bg

    def key(self):
        return (self.colors(), self.bold, self.dim)


def color_256(n):
    if n < 16:
        return PALETTE[n]
    if n < 232:
        n -= 16
        levels = [0, 95, 135, 175, 215, 255]
        return "#%02x%02x%02x" % (levels[n // 36], levels[(n // 6) % 6], levels[n % 6])
    v = 8 + (n - 232) * 10
    return "#%02x%02x%02x" % (v, v, v)


def apply_sgr(style, params):
    codes = [int(p) if p else 0 for p in params.split(";")] if params else [0]
    i = 0
    while i < len(codes):
        c = codes[i]
        if c == 0:
            style.__init__()
        elif c == 1:
            style.bold = True
        elif c == 2:
            style.dim = True
        elif c == 22:
            style.bold = style.dim = False
        elif c == 7:
            style.inverse = True
        elif c == 27:
            style.inverse = False
        elif 30 <= c <= 37:
            style.fg = PALETTE[c - 30]
        elif 90 <= c <= 97:
            style.fg = PALETTE[c - 90 + 8]
        elif c == 39:
            style.fg = None
        elif 40 <= c <= 47:
            style.bg = PALETTE[c - 40]
        elif 100 <= c <= 107:
            style.bg = PALETTE[c - 100 + 8]
        elif c == 49:
            style.bg = None
        elif c in (38, 48) and i + 1 < len(codes):
            target = "fg" if c == 38 else "bg"
            if codes[i + 1] == 5 and i + 2 < len(codes):
                setattr(style, target, color_256(codes[i + 2]))
                i += 2
            elif codes[i + 1] == 2 and i + 4 < len(codes):
                setattr(style, target, "#%02x%02x%02x" % tuple(codes[i + 2:i + 5]))
                i += 4
        i += 1


def parse_frame(text):
    """Returns rows of (character, Style) cells. Style carries across lines, as in a terminal."""
    rows = []
    style = Style()
    for line in text.split("\n"):
        cells = []
        pos = 0
        for m in SGR.finditer(line):
            for ch in OTHER_ESCAPE.sub("", line[pos:m.start()]):
                cells.append((ch, style.copy()))
            apply_sgr(style, m.group(1))
            pos = m.end()
        for ch in OTHER_ESCAPE.sub("", line[pos:]):
            cells.append((ch, style.copy()))
        rows.append(cells)
    while rows and not any(ch.strip() for ch, _ in rows[-1]):
        rows.pop()
    return rows


def fmt(v):
    return ("%.2f" % v).rstrip("0").rstrip(".")


def render_frame(rows, cols):
    out = []
    # Backgrounds, merged into runs.
    for r, cells in enumerate(rows):
        c = 0
        while c < len(cells):
            bg = cells[c][1].colors()[1]
            start = c
            while c < len(cells) and cells[c][1].colors()[1] == bg:
                c += 1
            if bg:
                out.append('<rect x="%s" y="%s" width="%s" height="%s" fill="%s"/>'
                           % (fmt(start * CELL_W), fmt(r * CELL_H), fmt((c - start) * CELL_W), fmt(CELL_H), bg))

    # Box drawing: straight segments merged across cells, per color; rounded corners as curves.
    lines = {}  # color -> list of path commands
    for r, cells in enumerate(rows):
        for c, (ch, st) in enumerate(cells):
            if ch not in BOX:
                continue
            up, down, left, right, rounded = BOX[ch]
            color = st.colors()[0]
            cmds = lines.setdefault(color, [])
            x0, y0 = c * CELL_W, r * CELL_H
            cx, cy = x0 + CELL_W / 2, y0 + CELL_H / 2
            if rounded:
                hx = x0 if left else x0 + CELL_W
                vy = y0 if up else y0 + CELL_H
                sx = cx - RADIUS if left else cx + RADIUS
                sy = cy - RADIUS if up else cy + RADIUS
                cmds.append("M%s %sH%sQ%s %s %s %sV%s" % (fmt(hx), fmt(cy), fmt(sx), fmt(cx), fmt(cy),
                                                          fmt(cx), fmt(sy), fmt(vy)))
                continue
            if left or right:
                cmds.append("M%s %sH%s" % (fmt(x0 if left else cx), fmt(cy), fmt(x0 + CELL_W if right else cx)))
            if up or down:
                cmds.append("M%s %sV%s" % (fmt(cx), fmt(y0 if up else cy), fmt(y0 + CELL_H if down else cy)))
    for color, cmds in lines.items():
        out.append('<path d="%s" stroke="%s" stroke-width="1.2" fill="none"/>' % ("".join(cmds), color))

    # Block elements (gauges, sparklines) as rectangles; runs of full blocks merged.
    for r, cells in enumerate(rows):
        c = 0
        while c < len(cells):
            ch, st = cells[c]
            fg = st.colors()[0]
            if ch == "█":
                start = c
                while c < len(cells) and cells[c][0] == "█" and cells[c][1].colors()[0] == fg:
                    c += 1
                out.append('<rect x="%s" y="%s" width="%s" height="%s" fill="%s"/>'
                           % (fmt(start * CELL_W), fmt(r * CELL_H), fmt((c - start) * CELL_W), fmt(CELL_H), fg))
                continue
            if ch in LOWER_BLOCKS:
                h = LOWER_BLOCKS[ch] * CELL_H
                out.append('<rect x="%s" y="%s" width="%s" height="%s" fill="%s"/>'
                           % (fmt(c * CELL_W + 0.5), fmt((r + 1) * CELL_H - h), fmt(CELL_W - 1), fmt(h), fg))
            elif ch in LEFT_BLOCKS:
                out.append('<rect x="%s" y="%s" width="%s" height="%s" fill="%s"/>'
                           % (fmt(c * CELL_W), fmt(r * CELL_H), fmt(LEFT_BLOCKS[ch] * CELL_W), fmt(CELL_H), fg))
            c += 1

    # Text, in runs of one style; shapes drawn above are left out.
    def is_text(ch):
        return ch not in BOX and ch not in LOWER_BLOCKS and ch not in LEFT_BLOCKS

    for r, cells in enumerate(rows):
        c = 0
        while c < len(cells):
            if not is_text(cells[c][0]) or cells[c][0] == " ":
                c += 1
                continue
            key = cells[c][1].key()
            start = c
            while c < len(cells) and is_text(cells[c][0]) and (cells[c][0] == " " or cells[c][1].key() == key):
                c += 1
            run = "".join(ch for ch, _ in cells[start:c]).rstrip()
            (fg, _), bold, dim = key
            attrs = ' fill="%s"' % fg
            if bold:
                attrs += ' font-weight="bold"'
            if dim:
                attrs += ' fill-opacity="0.55"'
            out.append('<text x="%s" y="%s" textLength="%s"%s>%s</text>'
                       % (fmt(start * CELL_W), fmt((r + 0.5) * CELL_H), fmt(len(run) * CELL_W), attrs,
                          html.escape(run, quote=False)))
    return "\n".join(out)


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("out")
    parser.add_argument("frames", nargs="+", help="capture file, optionally :N to hold it N steps")
    parser.add_argument("--step", type=float, default=1.0, help="seconds per time step")
    parser.add_argument("--title", default="netpulse")
    args = parser.parse_args()

    frames = []
    for spec in args.frames:
        path, _, hold = spec.rpartition(":") if re.search(r":\d+$", spec) else (spec, "", "1")
        with open(path, encoding="utf-8") as f:
            frames.append((parse_frame(f.read()), int(hold)))

    rows = max(len(r) for r, _ in frames)
    cols = max(max((len(cells) for cells in r), default=0) for r, _ in frames)
    width = cols * CELL_W + 2 * PAD
    height = rows * CELL_H + 2 * PAD + TITLE_BAR

    svg = ['<svg xmlns="http://www.w3.org/2000/svg" width="%s" height="%s" viewBox="0 0 %s %s">'
           % (fmt(width), fmt(height), fmt(width), fmt(height))]
    total = sum(h for _, h in frames)
    css = ["text{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,'Liberation Mono',monospace;"
           "font-size:%dpx;dominant-baseline:central;white-space:pre}" % FONT_SIZE]
    if len(frames) > 1:
        css.append(".f{opacity:0;animation:%ss steps(1,end) infinite}" % fmt(total * args.step))
        t = 0
        for i, (_, hold) in enumerate(frames):
            a, b = 100 * t / total, 100 * (t + hold) / total
            keys = ["0%{opacity:0}"] if a > 0 else []
            keys.append("%s%%{opacity:1}" % fmt(a))
            if b < 100:
                keys.append("%s%%{opacity:0}" % fmt(b))
            keys.append("100%%{opacity:%d}" % (1 if b >= 100 else 0))
            css.append("@keyframes k%d{%s}.k%d{animation-name:k%d}" % (i, "".join(keys), i, i))
            t += hold
    svg.append("<style>%s</style>" % "".join(css))
    svg.append('<rect width="100%%" height="100%%" rx="8" fill="%s"/>' % BACKGROUND)
    for i, color in enumerate(["#ff5f57", "#febc2e", "#28c840"]):
        svg.append('<circle cx="%s" cy="%s" r="6" fill="%s"/>' % (fmt(PAD + 6 + i * 20), fmt(TITLE_BAR / 2 + 4), color))
    svg.append('<text x="%s" y="%s" fill="#8b949e" text-anchor="middle" style="font-size:13px">%s</text>'
               % (fmt(width / 2), fmt(TITLE_BAR / 2 + 4), html.escape(args.title)))
    svg.append('<g transform="translate(%s %s)">' % (fmt(PAD), fmt(PAD + TITLE_BAR)))
    for i, (rows_, _) in enumerate(frames):
        cls = ' class="f k%d"' % i if len(frames) > 1 else ""
        svg.append("<g%s>%s</g>" % (cls, render_frame(rows_, cols)))
    svg.append("</g></svg>")

    with open(args.out, "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(svg) + "\n")


if __name__ == "__main__":
    main()
