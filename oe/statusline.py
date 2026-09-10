"""Three-line Claude Code status line: tokens, dollars, live context fill.

This runs on every keystroke, so the only work it is allowed to do is read
stdin, stat + read one small JSON snapshot, and print. It never parses a
transcript: the watcher does that and leaves the numbers the status line needs
in ``state_dir()/<session_id>.live.json``. When that snapshot is missing or
stale the stdin payload alone still yields a correct (if less detailed) line,
because Claude Code already puts the authoritative cost and context window in
it -- so a dead watcher degrades the display, never the accuracy of what is
shown.

Budget is 80 ms wall including interpreter start-up, which is why nothing here
imports ``pathlib``, ``re``, ``dataclasses`` or any sibling module: each costs
milliseconds at import time and buys nothing this file cannot do with
``os.path``. The state directory is resolved by mirroring ``paths.state_dir()``
(a constant beside the code, never under the shared reports root). The
budget is enforced twice: a ``perf_counter`` deadline checked before every
optional step, and a SIGALRM backstop that converts an overrun into the minimal
fallback line.

Exit status is always 0. A status line that fails must never look like a broken
session.
"""

from __future__ import annotations

import json
import os
import sys
import time

_T0 = time.perf_counter()

# --------------------------------------------------------------------------
# tunables
# --------------------------------------------------------------------------

BUDGET_S = 0.080            # hard wall clock budget for the whole process
SNAPSHOT_SOFT_DEADLINE = 0.045   # stop optional work after this much elapsed
MAX_SNAPSHOT_BYTES = 2_000_000   # refuse to parse a watcher file that grew wild
STALE_AFTER_S = 90.0        # beyond this the snapshot's own numbers are marked
# Mirrors paths.STATE_ROOT. State sits beside the code, NOT under the reports
# root, because the reports root is the directory the user shares -- and this
# directory holds the map that turns `session_07` back into a real session. The
# reports root is deliberately absent from this file: nothing here reads it.
# Derived: oe/statusline.py -> <install root>/state. The statusline runs on
# every render and must not import oe.paths (cost), so it recomputes the one
# path it needs from __file__ instead of hardcoding it.
DEFAULT_STATE_DIR = os.path.join(
    os.environ.get("OE_INSTALL_ROOT")
    or os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "state")

# Palette. Chosen for legibility on both dark and light terminals: every colour
# sits in the mid-luminance band so nothing disappears on a white background.
FG = (231, 237, 243)
MUTED = (128, 137, 148)
FAINT = (98, 106, 116)
TRACK = (70, 78, 88)
GOLD = (232, 182, 92)       # money
BLUE = (121, 192, 255)      # model
MAUVE = (198, 160, 246)     # effort / thinking
ORANGE = (247, 146, 86)     # fast mode
TEAL = (86, 196, 190)       # tools
GREEN = (63, 185, 80)
AMBER = (214, 160, 40)
RED = (248, 81, 73)

# Gradient stops for the context bar: green until it matters, amber through the
# middle, red as the window closes.
_GRADIENT = ((0.0, GREEN), (0.55, AMBER), (1.0, RED))

BLOCKS = " ▏▎▍▌▋▊▉█"  # 1/8 .. 8/8
FULL = "█"
EMPTY = "░"
CAP_L = "▏"
CAP_R = "▕"
DOT = " · "
TIMES = "×"

_PAYLOAD: dict = {}          # stashed for the emergency renderer
_ASCII = False               # set when the terminal encoding cannot do blocks

# Every non-ASCII glyph the renderer can emit, with a stand-in. Applied once to
# the finished string rather than at each call site, so a terminal stuck on
# latin-1 loses the typography and nothing else.
_ASCII_MAP = {ord(k): v for k, v in {
    "\u00b7": "-", "\u00d7": "x", "\u2588": "#", "\u2591": ".",
    "\u258f": "[", "\u2595": "]", "\u258e": "#", "\u258d": "#",
    "\u258c": "#", "\u258b": "#", "\u258a": "#", "\u2589": "#",
}.items()}


def asciify(text: str) -> str:
    """Downgrade the box-drawing typography for terminals that cannot show it."""
    return text.translate(_ASCII_MAP)


# --------------------------------------------------------------------------
# formatting primitives
# --------------------------------------------------------------------------


def humanize_tokens(value) -> str:
    """Token counts as humans read them: 12.4M, 984K, 1.24M, 940.

    Three significant figures at most, so the column never jitters in width by
    more than one character as the session grows.
    """
    try:
        n = float(value or 0)
    except (TypeError, ValueError):
        return "0"
    if n < 0:
        n = 0.0
    for limit, suffix, scale in ((1e12, "T", 1e12), (1e9, "B", 1e9),
                                 (1e6, "M", 1e6), (1e3, "K", 1e3)):
        if n >= limit:
            scaled = n / scale
            text = ("%.0f" % scaled if scaled >= 100
                    else "%.1f" % scaled if scaled >= 10
                    else "%.2f" % scaled)
            if "." in text:  # 1.00M is noise; 1.24M is information
                text = text.rstrip("0").rstrip(".")
            return text + suffix
    return "%d" % int(n)


def money(value, force_cents: bool = False) -> str:
    """USD at a precision that matches the magnitude.

    Sub-dollar amounts show three decimals because a status line is where a
    $0.004 call is still interesting; past $10 the third decimal is noise, and
    past $10k so is the second.
    """
    try:
        v = float(value or 0.0)
    except (TypeError, ValueError):
        return "$0.00"
    sign = "-" if v < 0 else ""
    v = abs(v)
    if force_cents:
        return "%s$%.2f" % (sign, v)
    if v < 10:
        return "%s$%.3f" % (sign, v)
    if v < 10000:
        return "%s$%s" % (sign, format(v, ",.2f"))
    return "%s$%s" % (sign, format(int(round(v)), ","))


def short_duration(seconds) -> str:
    """Compact relative time: 45s, 12m, 2h13m, 3d."""
    try:
        s = int(float(seconds))
    except (TypeError, ValueError):
        return ""
    if s < 0:
        s = 0
    if s < 60:
        return "%ds" % s
    if s < 3600:
        return "%dm" % (s // 60)
    if s < 86400:
        hours, rest = divmod(s, 3600)
        minutes = rest // 60
        return "%dh%02dm" % (hours, minutes) if minutes else "%dh" % hours
    return "%dd" % (s // 86400)


def _lerp_rgb(a, b, t: float):
    return (int(round(a[0] + (b[0] - a[0]) * t)),
            int(round(a[1] + (b[1] - a[1]) * t)),
            int(round(a[2] + (b[2] - a[2]) * t)))


def gradient_at(t: float):
    """Colour for position ``t`` (0..1) along the green->amber->red ramp."""
    if t <= 0:
        return _GRADIENT[0][1]
    if t >= 1:
        return _GRADIENT[-1][1]
    for i in range(len(_GRADIENT) - 1):
        lo_t, lo_c = _GRADIENT[i]
        hi_t, hi_c = _GRADIENT[i + 1]
        if lo_t <= t <= hi_t:
            span = hi_t - lo_t or 1.0
            return _lerp_rgb(lo_c, hi_c, (t - lo_t) / span)
    return _GRADIENT[-1][1]


# --------------------------------------------------------------------------
# colour
# --------------------------------------------------------------------------


def colour_mode() -> str:
    """'truecolor', '256' or 'off'.

    Deliberate subtlety: Claude Code always pipes the status line's stdout, so
    "not a tty" cannot mean "no colour" here or the bar would be plain in the
    only place it is ever seen. A non-tty stdout keeps colour ONLY when the
    stdin payload proves we were invoked as the status line (its renderer does
    interpret ANSI); anything else piping us gets plain text. NO_COLOR,
    TERM=dumb and OE_COLOR=never always win.
    """
    env = os.environ
    if env.get("OE_COLOR") == "always":
        return "truecolor" if env.get("COLORTERM") in ("truecolor", "24bit") else "256"
    if env.get("OE_COLOR") == "never":
        return "off"
    if env.get("NO_COLOR") is not None:
        return "off"
    term = env.get("TERM", "")
    if term in ("dumb", ""):
        return "off"
    is_tty = False
    try:
        is_tty = sys.stdout.isatty()
    except Exception:
        pass
    if not is_tty and env.get("CLICOLOR_FORCE") not in ("1", "true"):
        if _PAYLOAD.get("hook_event_name") != "Status" and "model" not in _PAYLOAD:
            return "off"
    if env.get("COLORTERM") in ("truecolor", "24bit"):
        return "truecolor"
    return "256" if "256" in term or "color" in term else "off"


def _rgb_to_256(rgb) -> int:
    r, g, b = rgb
    if abs(r - g) < 12 and abs(g - b) < 12:
        grey = int(round((r + g + b) / 3.0))
        return 231 + max(1, min(24, int(round(grey / 255.0 * 24))))
    return 16 + 36 * int(r / 256.0 * 6) + 6 * int(g / 256.0 * 6) + int(b / 256.0 * 6)


def make_painter(mode: str):
    """Return ``paint(text, rgb, bold)`` for the active colour mode."""
    if mode == "off":
        def paint(text: str, rgb=None, bold: bool = False) -> str:
            return text
        return paint
    if mode == "256":
        cache: dict = {}

        def paint(text: str, rgb=None, bold: bool = False) -> str:
            if rgb is None and not bold:
                return text
            key = (rgb, bold)
            prefix = cache.get(key)
            if prefix is None:
                parts = []
                if bold:
                    parts.append("1")
                if rgb is not None:
                    parts.append("38;5;%d" % _rgb_to_256(rgb))
                prefix = "\x1b[" + ";".join(parts) + "m"
                cache[key] = prefix
            return prefix + text + "\x1b[0m"
        return paint

    def paint(text: str, rgb=None, bold: bool = False) -> str:
        if rgb is None and not bold:
            return text
        head = "\x1b[1m" if bold else ""
        if rgb is None:
            return head + text + "\x1b[0m"
        return "%s\x1b[38;2;%d;%d;%dm%s\x1b[0m" % (head, rgb[0], rgb[1], rgb[2], text)
    return paint


class Line:
    """A row of (text, colour) cells that knows its printable width.

    Padding has to happen on the plain text, not the escaped string, which is
    the whole reason the segments are kept apart until render time.
    """

    __slots__ = ("segs", "width")

    def __init__(self) -> None:
        self.segs: list = []
        self.width = 0

    def add(self, text, rgb=None, bold: bool = False) -> "Line":
        if not text:
            return self
        text = str(text)
        self.segs.append((text, rgb, bold))
        self.width += len(text)
        return self

    def pad_to(self, column: int) -> "Line":
        if self.width < column:
            self.add(" " * (column - self.width))
        return self

    def clip(self, limit: int) -> "Line":
        """Hard-cut to a printable width.

        A status line that wraps costs the user a row of their terminal and
        looks broken, so this is a floor under every layout decision above it:
        even a pathological COLUMNS cannot produce an over-long row.
        """
        if limit <= 0 or self.width <= limit:
            return self
        kept: list = []
        room = limit - 1
        for text, rgb, bold in self.segs:
            if room <= 0:
                break
            if len(text) <= room:
                kept.append((text, rgb, bold))
                room -= len(text)
            else:
                kept.append((text[:room], rgb, bold))
                room = 0
        kept.append(("\u2026", FAINT, False))
        self.segs = kept
        self.width = limit - room
        return self

    def render(self, paint) -> str:
        return "".join(paint(t, c, b) for t, c, b in self.segs)


# --------------------------------------------------------------------------
# the context bar
# --------------------------------------------------------------------------


def context_bar(line: Line, fraction: float, width: int) -> None:
    """Append a gradient fill bar to ``line``.

    Each filled cell is coloured by its own position on the ramp, so the bar is
    a true gradient rather than one flat colour that flips at a threshold: you
    can see the red creeping in before you reach it.
    """
    try:
        frac = float(fraction)
    except (TypeError, ValueError):
        frac = 0.0
    frac = 0.0 if frac < 0 else 1.0 if frac > 1 else frac
    width = max(6, int(width))
    line.add(CAP_L, TRACK)
    exact = frac * width
    whole = int(exact)
    remainder = exact - whole
    denom = float(width - 1) or 1.0
    for i in range(whole):
        line.add(FULL, gradient_at(i / denom))
    if whole < width:
        if remainder > 0.05:
            eighth = max(1, min(8, int(remainder * 8)))
            line.add(BLOCKS[eighth], gradient_at(whole / denom))
            whole += 1
        if whole < width:
            line.add(EMPTY * (width - whole), TRACK)
    line.add(CAP_R, TRACK)


# --------------------------------------------------------------------------
# inputs
# --------------------------------------------------------------------------


def read_stdin_payload() -> dict:
    """The Status payload, or {} for anything unreadable.

    Skipped entirely when stdin is a terminal so that running this by hand does
    not hang waiting for input that will never come.
    """
    try:
        if sys.stdin is None or sys.stdin.isatty():
            return {}
        raw = sys.stdin.read()
    except Exception:
        return {}
    if not raw or not raw.strip():
        return {}
    try:
        obj = json.loads(raw)
    except Exception:
        return {}
    return obj if isinstance(obj, dict) else {}


def state_dir() -> str:
    """Mirror of ``paths.state_dir()`` without importing pathlib.

    One constant, because state no longer follows the reports root: it lives
    beside the code so that an archive of the reports tree cannot carry the map
    that de-pseudonymises it. That also makes this mirror cheaper -- it no
    longer opens config.json on the 80 ms path. OE_STATE_DIR overrides it, and
    is the same override paths.state_dir() honours.
    """
    return os.environ.get("OE_STATE_DIR") or DEFAULT_STATE_DIR


def read_snapshot(session_id: str) -> tuple:
    """(snapshot_dict, age_seconds) written by the watcher, or ({}, None).

    Cheap by construction: one stat, one read, one parse, all skipped when the
    budget is already spent or the file is implausibly large.
    """
    if not session_id:
        return {}, None
    if time.perf_counter() - _T0 > SNAPSHOT_SOFT_DEADLINE:
        return {}, None
    path = os.path.join(state_dir(), "%s.live.json" % session_id)
    try:
        info = os.stat(path)
    except Exception:
        return {}, None
    if info.st_size <= 0 or info.st_size > MAX_SNAPSHOT_BYTES:
        return {}, None
    age = max(0.0, time.time() - info.st_mtime)
    try:
        with open(path, "rb") as handle:
            snap = json.loads(handle.read().decode("utf-8", "replace"))
    except Exception:
        return {}, None
    if not isinstance(snap, dict):
        return {}, None
    # A stale file left by a previous session under a reused path would quietly
    # print someone else's numbers; refuse it.
    sid = snap.get("session_id") or (snap.get("session") or {}).get("session_id")
    if sid and session_id and sid != session_id:
        return {}, None
    return snap, age


# --------------------------------------------------------------------------
# extraction helpers (tolerant: the watcher may hand us a trimmed ledger dict)
# --------------------------------------------------------------------------


def dig(obj, *path):
    """Walk a dotted path through nested dicts, returning None on any miss."""
    cur = obj
    for key in path:
        if not isinstance(cur, dict):
            return None
        cur = cur.get(key)
    return cur


def first(*values):
    """First value that is neither None nor an empty string/collection."""
    for value in values:
        if value is None:
            continue
        if isinstance(value, (str, list, tuple, dict)) and not value:
            continue
        return value
    return None


def as_float(value, default=None):
    try:
        if value is None or isinstance(value, bool):
            return default
        return float(value)
    except (TypeError, ValueError):
        return default


def as_int(value, default=0) -> int:
    try:
        if value is None or isinstance(value, bool):
            return default
        return int(float(value))
    except (TypeError, ValueError):
        return default


def normalize_model(model_id) -> str:
    """Reduce a wire id to a catalog key without importing ``re``.

    Same rules as ``pricing.normalize_model`` for the two shapes that actually
    reach a status line: a bracket suffix ('claude-opus-5[1m]') and a trailing
    release date ('-20251001').
    """
    if not model_id:
        return ""
    name = str(model_id).strip()
    cut = name.find("[")
    if cut > 0:
        name = name[:cut].strip()
    if len(name) > 9 and name[-9] == "-" and name[-8:].isdigit():
        name = name[:-9]
    return name


def rows_of(container):
    """Normalise a by_model/by_tool aggregate to a list of row dicts."""
    if isinstance(container, dict):
        out = []
        for key, value in container.items():
            if isinstance(value, dict):
                row = dict(value)
                row.setdefault("key", key)
                out.append(row)
        return out
    if isinstance(container, list):
        return [row for row in container if isinstance(row, dict)]
    return []


def model_view(snapshot: dict, model_id: str, headline):
    """(cost_usd, calls, display_name) for the model currently in use.

    The cost is the model's SHARE of the headline dollars, not the ledger's raw
    per-call sum. Those two differ whenever ``cost-state`` is the authority
    (which it is: it is the billing record, and on a resumed session it covers a
    different window than the transcript). Attributing by share keeps line 2
    arithmetically consistent with line 1 -- a status line whose second number
    contradicts its first is worse than no second number.
    """
    wanted = normalize_model(model_id)
    rows = rows_of(first(snapshot.get("by_model"), snapshot.get("models")) or {})
    if not rows:
        return None, None, None
    best = None
    for row in rows:
        key = normalize_model(first(row.get("model"), row.get("key"), row.get("id")))
        if wanted and key == wanted:
            best = row
            break
    if best is None:
        if wanted:
            # A model the snapshot has never seen (just switched, or the watcher
            # is behind). Attributing the priciest row's dollars to it would be
            # a confident lie; say nothing and let the caller fall back to the
            # session headline.
            return None, None, None
        # No model id anywhere: the priciest row is the one the session is about.
        best = max(rows, key=lambda r: as_float(r.get("cost_usd"), 0.0) or 0.0)
    measured = as_float(best.get("cost_usd"))
    total = sum(as_float(r.get("cost_usd"), 0.0) or 0.0 for r in rows)
    cost = measured
    if headline is not None and total > 0 and measured is not None:
        cost = headline * (measured / total)
    return cost, (as_int(best.get("calls"), 0) or None), best.get("display_name")


def top_tool(snapshot: dict):
    """(name, count) of the most-used tool, or (None, None)."""
    explicit = snapshot.get("top_tool")
    if isinstance(explicit, dict) and explicit.get("name"):
        return str(explicit["name"]), as_int(explicit.get("count"), 0)
    if isinstance(explicit, str) and explicit:
        return explicit, as_int(snapshot.get("top_tool_count"), 0)
    rows = rows_of(snapshot.get("by_tool"))
    if not rows:
        return None, None
    best = max(rows, key=lambda r: as_int(r.get("count"), 0))
    name = first(best.get("name"), best.get("key"))
    return (str(name), as_int(best.get("count"), 0)) if name else (None, None)


# --------------------------------------------------------------------------
# the three lines
# --------------------------------------------------------------------------


def layout_for(width: int) -> dict:
    """What fits, at this terminal width.

    Three tiers rather than a continuum: the left column has to stay a constant
    within a tier or the three rows stop lining up, which is the entire visual
    idea. Everything optional is dropped in order of how little it says --
    the model's wire id first, then the rate-limit countdowns, then the
    freshness marker, then the window label.
    """
    if width >= 84:
        return {"col": 24, "bar": min(30, max(10, width - 54)), "model_id": width >= 88,
                "resets": width >= 100, "source": True, "window": True}
    if width >= 66:
        return {"col": 18, "bar": min(18, max(8, width - 42)), "model_id": False,
                "resets": False, "source": True, "window": True}
    return {"col": 12, "bar": min(12, max(6, width - 30)), "model_id": False,
            "resets": False, "source": False, "window": False}


def build_lines(payload: dict, snapshot: dict, age, width: int) -> list:
    """Compose the three ``Line`` objects from stdin + snapshot.

    Precedence rule: stdin always wins for cost and context because it is
    regenerated for this very keystroke, while the snapshot is at best seconds
    old. The snapshot supplies only what stdin does not carry -- lifetime token
    counts, per-model attribution, tool usage, burn rate.
    """
    totals = snapshot.get("totals") if isinstance(snapshot.get("totals"), dict) else {}
    fresh = age is not None and age <= STALE_AFTER_S
    fit = layout_for(width)
    col = fit["col"]

    # ---- numbers -----------------------------------------------------------
    stdin_cost = as_float(dig(payload, "cost", "total_cost_usd"))
    snap_cost = as_float(first(totals.get("cost_usd_authoritative"),
                               totals.get("cost_usd_reported"),
                               totals.get("cost_usd"),
                               snapshot.get("cost_usd")))
    cost = stdin_cost if stdin_cost is not None else snap_cost
    # ...with one exception. stdin's cost is the CURRENT RUN's accumulator, and
    # resuming a session restarts it, so on a resumed transcript stdin's figure
    # can be a small fraction of what has actually been spent. When the
    # snapshot has priced requests
    # that predate this run's first checkpoint, the lifetime figure is the only
    # honest one for a meter to show, so it wins -- and only then.
    uncovered = as_float(totals.get("cost_usd_uncovered")) or 0.0
    if (stdin_cost is not None and snap_cost is not None
            and uncovered > 0.0 and snap_cost > stdin_cost):
        cost = snap_cost

    used = as_int(dig(payload, "context_window", "used_tokens"), 0)
    window = as_int(dig(payload, "context_window", "max_tokens"), 0)
    if not used:
        used = as_int(first(dig(snapshot, "context_window", "used_tokens"),
                            snapshot.get("context_used_tokens")), 0)
    if not window:
        window = as_int(first(dig(snapshot, "context_window", "max_tokens"),
                              snapshot.get("context_max_tokens")), 0)
    if not window:
        # Last resort only: the payload normally carries the real window.
        window = 1000000 if "opus-5" in normalize_model(
            dig(payload, "model", "id")) else 200000
    fraction = (used / window) if window else 0.0

    tokens = as_int(first(totals.get("total_tokens"), snapshot.get("total_tokens")), 0)
    approx_tokens = False
    if not tokens:
        # Without the watcher the only true token number on hand is what the
        # last request carried; flag it rather than pass it off as a lifetime
        # total.
        tokens = used
        approx_tokens = True

    calls = as_int(first(totals.get("calls"), snapshot.get("calls")), 0)

    model_id = first(dig(payload, "model", "id"),
                     dig(snapshot, "context_window", "model"),
                     snapshot.get("model")) or ""
    effort = first(dig(payload, "effort", "level"), snapshot.get("effort"))
    fast = bool(payload.get("fast_mode"))
    thinking = bool(dig(payload, "thinking", "enabled"))

    m_cost, m_calls, m_name = model_view(snapshot, model_id, cost) if snapshot \
        else (None, None, None)
    if m_cost is None:
        m_cost = cost  # no per-model split available: the session cost is it
    # Line 2 is about ONE model, so its call count is that model's, not the
    # session's; the session total is only a fallback when nothing is split out.
    model_calls = m_calls or calls
    model_name = first(dig(payload, "model", "display_name"),
                       snapshot.get("model_display"), m_name) or (
                           normalize_model(model_id) or "model")

    burn = as_float(first(snapshot.get("burn_rate_usd_per_hour"),
                          snapshot.get("burn_usd_per_hour"),
                          totals.get("cost_usd_per_hour")))
    if burn is None or not fresh:
        duration_ms = as_float(dig(payload, "cost", "total_duration_ms"), 0.0) or 0.0
        if cost is not None and duration_ms > 60000:
            burn = cost / (duration_ms / 3600000.0)
    tool_name, tool_count = top_tool(snapshot) if snapshot else (None, None)

    # ---- line 1: tokens / dollars / live context fill -----------------------
    l1 = Line()
    l1.add("~" if approx_tokens else " ", FAINT)
    l1.add(humanize_tokens(tokens).rjust(6), FG, bold=True)
    l1.add(" tok", MUTED)
    l1.add(" / ", FAINT)
    l1.add((money(cost) if cost is not None else "$-.--").rjust(9), GOLD, bold=True)
    l1.pad_to(col)
    l1.add(" ")
    context_bar(l1, fraction, fit["bar"])
    pct_colour = gradient_at(min(1.0, fraction / 0.95)) if window else MUTED
    l1.add((" %5.1f%%" % (fraction * 100.0)), pct_colour, bold=True)
    if fit["window"]:
        l1.add(" of ", FAINT)
        l1.add(humanize_tokens(window), MUTED)

    # ---- line 2: the model in use, and what it has cost ---------------------
    l2 = Line()
    l2.add(str(model_name), BLUE, bold=True)
    if effort:
        l2.add(" " + str(effort), MAUVE)
    elif thinking:
        l2.add(" think", MAUVE)
    if fast:
        l2.add(" fast", ORANGE, bold=True)
    l2.pad_to(col)
    l2.add(DOT, FAINT)
    l2.add(money(m_cost) if m_cost is not None else "$-.--", GOLD)
    if model_calls:
        l2.add(DOT, FAINT)
        l2.add("%d calls" % model_calls, FG)
    if model_id and fit["model_id"]:
        l2.add(DOT, FAINT)
        l2.add(str(model_id), FAINT)

    # ---- line 3: rate of spend, dominant tool, headroom ---------------------
    l3 = Line()
    if burn is not None and burn > 0:
        l3.add(money(burn), GOLD)
        l3.add("/h", MUTED)
    else:
        l3.add("--/h", FAINT)
    l3.pad_to(col)
    l3.add(DOT, FAINT)
    if tool_name:
        l3.add(str(tool_name), TEAL)
        if tool_count:
            l3.add(" %s%d" % (TIMES, tool_count), MUTED)
    else:
        l3.add("no tools yet", FAINT)
    limits = rate_limit_cells(payload, fit["resets"])
    for label, text, colour in limits:
        l3.add(DOT, FAINT)
        l3.add(label + " ", MUTED)
        l3.add(text, colour)
    if not limits:
        l3.add(DOT, FAINT)
        l3.add("limits n/a", FAINT)
    if fit["source"]:
        l3.add(DOT, FAINT)
        l3.add(source_marker(snapshot, age, fresh), FAINT)
    return [l1.clip(width), l2.clip(width), l3.clip(width)]


def rate_limit_cells(payload: dict, with_resets: bool = True) -> list:
    """(label, text, colour) for each rate limit the payload reports."""
    limits = payload.get("rate_limits")
    if not isinstance(limits, dict):
        return []
    now = time.time()
    out = []
    for key, label in (("five_hour", "5h"), ("seven_day", "7d"), ("spend_limit", "spend")):
        entry = limits.get(key)
        if not isinstance(entry, dict):
            continue
        pct = as_float(entry.get("used_percentage"))
        if pct is None:
            continue
        pct = max(0.0, min(100.0, pct))
        text = "%d%%" % round(pct)
        resets = as_float(entry.get("resets_at")) if with_resets else None
        if resets and now < resets < now + 40 * 86400:
            text += " " + short_duration(resets - now)
        out.append((label, text, gradient_at(pct / 100.0)))
    return out


def source_marker(snapshot: dict, age, fresh: bool) -> str:
    """Where the enriched numbers came from -- honest about staleness."""
    if not snapshot:
        return "stdin"
    if age is None:
        return "live"
    if fresh:
        return "live " + short_duration(age)
    return "stale " + short_duration(age)


SNAPSHOT_SCHEMA = 1


def snapshot_payload(ledger) -> dict:
    """Build the small live.json this status line reads, from a SessionLedger.

    Defined here, next to its only consumer, so the watcher cannot drift from
    the shape the reader expects: ``watcher.run_loop`` should write exactly
    ``json.dumps(snapshot_payload(ledger))`` to
    ``paths.live_snapshot_path(session_id)``. Everything is a plain subset of
    ``ledger.to_dict()`` keys, so a trimmed full ledger dump is also readable --
    but this stays a few hundred bytes no matter how long the session runs,
    which is the point.
    """
    totals = dict(ledger.totals)
    keep = ("calls", "total_tokens", "input_tokens", "output_tokens",
            "cache_read_tokens", "cache_write_tokens", "cost_usd",
            "cost_usd_reported", "cost_usd_authoritative", "cost_usd_per_hour",
            # Both of these are read by build_lines: they are what tells the
            # statusline that stdin's per-run cost understates the session.
            "cost_usd_uncovered", "uncovered_calls",
            "errors", "tool_calls", "wall_seconds")
    slim_totals = {k: totals.get(k) for k in keep if totals.get(k) is not None}

    by_model = {}
    for model, row in (ledger.by_model or {}).items():
        by_model[model] = {
            "model": row.get("model", model),
            "display_name": row.get("display_name"),
            "calls": row.get("calls", 0),
            "cost_usd": row.get("cost_usd", 0.0),
            "total_tokens": row.get("total_tokens", 0),
        }

    tool_rows = sorted((ledger.by_tool or {}).values(),
                       key=lambda r: r.get("count", 0), reverse=True)
    top = tool_rows[0] if tool_rows else None

    return {
        "schema": SNAPSHOT_SCHEMA,
        "session_id": ledger.session_id,
        "updated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "model": ledger.primary_model,
        "totals": slim_totals,
        "context_window": ledger.context_window_state,
        "by_model": by_model,
        "top_tool": ({"name": top.get("name"), "count": top.get("count", 0)}
                     if top else None),
        "burn_rate_usd_per_hour": totals.get("cost_usd_per_hour"),
    }


def terminal_width() -> int:
    """Best guess at the status line's usable width.

    stdout is a pipe here, so ask COLUMNS first and stderr second.
    """
    try:
        cols = int(os.environ.get("COLUMNS") or 0)
        if cols > 0:
            return max(24, min(240, cols))
    except (TypeError, ValueError):
        pass
    for fd in (2, 1, 0):
        try:
            cols = os.get_terminal_size(fd).columns
            if cols > 0:
                return max(24, min(240, cols))
        except Exception:
            continue
    return 96


def render(payload: dict, snapshot: dict, age) -> str:
    """The full three-line block, ANSI included, without a trailing newline."""
    width = terminal_width()
    paint = make_painter(colour_mode())
    return "\n".join(line.render(paint)
                     for line in build_lines(payload, snapshot, age, width))


def write_out(text: str) -> None:
    """Print the block, surviving a stdout that cannot encode the typography."""
    try:
        sys.stdout.write(text + "\n")
        sys.stdout.flush()
        return
    except UnicodeEncodeError:
        pass
    try:
        sys.stdout.write(asciify(text) + "\n")
        sys.stdout.flush()
        return
    except UnicodeEncodeError:
        pass
    encoding = getattr(sys.stdout, "encoding", None) or "ascii"
    data = (asciify(text) + "\n").encode(encoding, "replace")
    buffer = getattr(sys.stdout, "buffer", None)
    if buffer is not None:
        buffer.write(data)
        buffer.flush()


def minimal_line(payload: dict) -> str:
    """The last-resort output: plain, one line, always printable."""
    try:
        name = (payload.get("model") or {}).get("display_name") or "Claude"
        cost = as_float(dig(payload, "cost", "total_cost_usd"), 0.0) or 0.0
        used = as_int(dig(payload, "context_window", "used_tokens"), 0)
        window = as_int(dig(payload, "context_window", "max_tokens"), 0)
        pct = (100.0 * used / window) if window else 0.0
        return "%s %s %s ctx %.1f%%" % (name, money(cost),
                                        humanize_tokens(used), pct)
    except BaseException:
        return "Overwatch Enforcer"


def _install_backstop() -> None:
    """Turn a pathological overrun (a stalled NFS stat, say) into the minimal
    line instead of a hung status bar."""
    try:
        import signal

        def _blow(signum, frame):
            raise TimeoutError("statusline budget exceeded")

        signal.signal(signal.SIGALRM, _blow)
        signal.setitimer(signal.ITIMER_REAL, BUDGET_S * 3)
    except Exception:
        pass


def _cancel_backstop() -> None:
    try:
        import signal

        signal.setitimer(signal.ITIMER_REAL, 0)
    except Exception:
        pass


def main() -> int:
    """Read the Status payload on stdin, print three lines, return 0."""
    global _PAYLOAD, _ASCII
    _install_backstop()
    payload = read_stdin_payload()
    _PAYLOAD = payload
    encoding = getattr(sys.stdout, "encoding", None) or "ascii"
    if encoding.lower() not in ("utf-8", "utf8", "utf_8"):
        try:
            FULL.encode(encoding)
        except Exception:
            _ASCII = True
    session_id = payload.get("session_id") or ""
    snapshot, age = read_snapshot(str(session_id))
    text = render(payload, snapshot, age)
    if _ASCII:
        text = asciify(text)
    _cancel_backstop()
    write_out(text)
    if os.environ.get("OE_STATUSLINE_TIMING"):
        # Self-measurement for `oe doctor`: everything after interpreter start.
        sys.stderr.write("statusline %.2fms\n" % ((time.perf_counter() - _T0) * 1000.0))
    return 0


if __name__ == "__main__":
    try:
        main()
    except BaseException:
        # Any failure at all -- bad payload, missing tty, interrupted read, the
        # SIGALRM backstop -- still has to leave the user with a status line.
        # SystemExit deliberately does NOT reach here: raising it inside the
        # try would print the fallback line a second time under the good one.
        try:
            _cancel_backstop()
            sys.stdout.write(minimal_line(_PAYLOAD) + "\n")
            sys.stdout.flush()
        except BaseException:
            pass
    sys.exit(0)
