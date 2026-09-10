"""Render one session's ledger as a self-contained HTML report.

WHY this module exists in the shape it does:

* The report has to open from a file:// URL on a laptop with no network, so
  every byte -- CSS, JS, chart geometry, fonts -- is inline and there is not a
  single external reference. Charts are therefore computed here, in Python, and
  emitted as SVG path data; no charting library is loaded or vendored.

* The goal is to OPTIMISE, not to admire a total. So every dollar
  figure is printed next to the token counts and the per-1M rates that produced
  it (tokens x rate = USD, on the same row), and the report's centre of gravity
  is the ranked opportunity list rather than the headline number.

* Claude Code keeps its own billing record (cost-state). Where our arithmetic
  and its number disagree, the report says so in plain language, in dollars and
  in percent, on the front page -- hiding a 16% gap would make every other
  number in the document untrustworthy.

Custom-property names avoid a trailing '-<digit>' ('--ink2', not '--ink-2')
because that shape is indistinguishable from an issue key to the audit
scanner, and a page full of CSS false positives makes a real one invisible.

Palette note: the categorical hues below are the validated data-viz reference
palette (adjacent-pair CVD delta-E 9.1 light / 8.4 dark). Light-mode aqua,
yellow and magenta sit under 3:1 against the surface, so every chart that uses
them also ships direct labels and a table view.
"""

from __future__ import annotations

import csv
import html as _html
import io
import json
import math
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from . import SCHEMA_VERSION, accounts, paths, pricing, redact

__all__ = ["render_html", "render_markdown", "write_report",
           "optimization_opportunities", "CALL_CSV_COLUMNS"]

# How many raw API rows the HTML embeds. The complete set always goes to
# calls.csv; the table here exists to make the top of the distribution
# inspectable without turning a very long session into a multi-megabyte page.
MAX_HTML_CALL_ROWS = 300
MAX_TOOL_ROWS = 40
MAX_AGENT_ROWS = 15
# Path points beyond one per horizontal pixel are invisible but not free: the
# watcher rewrites this file every few seconds, so series are reduced to render
# resolution rather than dumped whole.
MAX_PATH_POINTS = 700

# Nominal SVG coordinate space. Every chart is emitted with a viewBox and
# width:100%, so these are aspect ratios, not pixel sizes.
CHART_W = 760

_KIND_LABELS = (
    ("input_tokens", "input_usd", "Fresh input", "input", "--s1"),
    ("output_tokens", "output_usd", "Output", "output", "--s2"),
    ("cache_write_5m_tokens", "cache_write_5m_usd", "Cache write (5m)", "cw_5m", "--s3"),
    ("cache_write_1h_tokens", "cache_write_1h_usd", "Cache write (1h)", "cw_1h", "--s4"),
    ("cache_read_tokens", "cache_read_usd", "Cache read", "cache_read", "--s5"),
    ("web_search_requests", "web_search_usd", "Web search", "web_search", "--s6"),
)


# ---------------------------------------------------------------------------
# formatting
# ---------------------------------------------------------------------------


def _e(value: Any) -> str:
    """HTML-escape, including quotes, so a value is safe in text or attribute.

    The scheme separator is additionally emitted as a numeric character
    reference. Echoed prompts and shell commands routinely contain URLs, and
    this document's contract is that it makes NO external references at all --
    encoding "://" keeps that verifiable by a plain grep while rendering the
    exact same characters to the reader.
    """
    escaped = _html.escape("" if value is None else str(value), quote=True)
    return escaped.replace("://", ":&#47;&#47;")


def _f(value: Any, default: float = 0.0) -> float:
    try:
        if value is None:
            return default
        return float(value)
    except (TypeError, ValueError):
        return default


def _i(value: Any, default: int = 0) -> int:
    try:
        if value is None:
            return default
        return int(value)
    except (TypeError, ValueError):
        return default


def _usd(value: Any, places: int = 2) -> str:
    amount = _f(value)
    sign = "-" if amount < 0 else ""
    amount = abs(amount)
    if amount and amount < 0.01 and places <= 2:
        return f"{sign}${amount:,.4f}"
    return f"{sign}${amount:,.{places}f}"


def _num(value: Any) -> str:
    return f"{_i(value):,}"


def _tok(value: Any) -> str:
    """Humanised token count: 632.9M, 4.83M, 172K, 940."""
    count = _i(value)
    sign = "-" if count < 0 else ""
    count = abs(count)
    if count >= 1_000_000_000:
        return f"{sign}{count / 1e9:,.2f}B"
    if count >= 1_000_000:
        return f"{sign}{count / 1e6:,.1f}M"
    if count >= 10_000:
        return f"{sign}{count / 1e3:,.0f}K"
    return f"{sign}{count:,}"


def _bytes(value: Any) -> str:
    size = float(_i(value))
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024 or unit == "GB":
            return f"{size:,.0f} {unit}" if unit == "B" else f"{size:,.1f} {unit}"
        size /= 1024.0
    return f"{size:,.1f} GB"


def _dur(seconds: Any) -> str:
    total = int(_f(seconds))
    if total <= 0:
        return "0s"
    hours, rest = divmod(total, 3600)
    minutes, secs = divmod(rest, 60)
    if hours:
        return f"{hours}h {minutes:02d}m"
    if minutes:
        return f"{minutes}m {secs:02d}s"
    return f"{secs}s"


def _pct(value: Any, places: int = 1) -> str:
    return f"{_f(value):,.{places}f}%"


def _share(part: Any, whole: Any) -> float:
    total = _f(whole)
    return (100.0 * _f(part) / total) if total else 0.0


def _clip(text: Any, limit: int = 60) -> str:
    value = "" if text is None else str(text)
    value = " ".join(value.split())
    return value if len(value) <= limit else value[: limit - 3] + "..."


def _parse_ts(value: Any) -> Optional[datetime]:
    if not value:
        return None
    try:
        raw = str(value).replace("Z", "+00:00")
        stamp = datetime.fromisoformat(raw)
        return stamp if stamp.tzinfo else stamp.replace(tzinfo=timezone.utc)
    except Exception:
        return None


def _hhmm(value: Any) -> str:
    stamp = _parse_ts(value)
    return stamp.strftime("%H:%M") if stamp else ""


def _stamp(value: Any) -> str:
    stamp = _parse_ts(value)
    return stamp.strftime("%Y-%m-%d %H:%M:%S UTC") if stamp else "-"


def _median(values: Sequence[float]) -> float:
    ordered = sorted(values)
    if not ordered:
        return 0.0
    middle = len(ordered) // 2
    if len(ordered) % 2:
        return float(ordered[middle])
    return (ordered[middle - 1] + ordered[middle]) / 2.0


# ---------------------------------------------------------------------------
# SVG primitives
# ---------------------------------------------------------------------------


def _nice_step(span: float, count: int) -> float:
    """A 1/2/2.5/5/10 x 10^n step that gives roughly `count` gridlines."""
    if span <= 0 or count <= 0:
        return 1.0
    raw = span / count
    magnitude = 10.0 ** math.floor(math.log10(raw)) if raw > 0 else 1.0
    for multiplier in (1.0, 2.0, 2.5, 5.0, 10.0):
        if raw <= multiplier * magnitude:
            return multiplier * magnitude
    return 10.0 * magnitude


def _ticks(vmax: float, count: int = 4) -> Tuple[List[float], float]:
    """(tick values, axis top). The axis top is rounded up to a whole step so
    the tallest mark ends on a gridline rather than floating between two."""
    if vmax <= 0:
        return [0.0, 1.0], 1.0
    step = _nice_step(vmax, count)
    top = math.ceil(vmax / step) * step
    values: List[float] = []
    current = 0.0
    while current <= top + step * 1e-9:
        values.append(round(current, 10))
        current += step
    return values, top


def _bar_path(x: float, y: float, width: float, height: float, radius: float,
              side: str) -> str:
    """Rectangle with only the data end rounded, per the mark spec: the
    baseline end stays square so bars sit flat on the axis."""
    radius = max(0.0, min(radius, width / 2.0 if side == "right" else height / 2.0,
                          height / 2.0 if side == "right" else width / 2.0))
    if width <= 0 or height <= 0:
        return ""
    if radius <= 0.5:
        return (f"M{x:.2f} {y:.2f}h{width:.2f}v{height:.2f}h{-width:.2f}Z")
    if side == "right":
        return (f"M{x:.2f} {y:.2f}"
                f"H{x + width - radius:.2f}"
                f"A{radius:.2f} {radius:.2f} 0 0 1 {x + width:.2f} {y + radius:.2f}"
                f"V{y + height - radius:.2f}"
                f"A{radius:.2f} {radius:.2f} 0 0 1 {x + width - radius:.2f} {y + height:.2f}"
                f"H{x:.2f}Z")
    return (f"M{x:.2f} {y + height:.2f}"
            f"V{y + radius:.2f}"
            f"A{radius:.2f} {radius:.2f} 0 0 1 {x + radius:.2f} {y:.2f}"
            f"H{x + width - radius:.2f}"
            f"A{radius:.2f} {radius:.2f} 0 0 1 {x + width:.2f} {y + radius:.2f}"
            f"V{y + height:.2f}Z")


def _svg(height: int, body: str, label: str, desc: str = "",
         extra: str = "", width: int = CHART_W) -> str:
    """Wrap chart geometry in a responsive, labelled SVG root."""
    described = ""
    if desc:
        described = f"<desc>{_e(desc)}</desc>"
    return (
        f'<svg class="chart" viewBox="0 0 {width} {height}" width="{width}" '
        f'height="{height}" role="img" preserveAspectRatio="xMidYMid meet" '
        f'aria-label="{_e(label)}"{extra}>'
        f"<title>{_e(label)}</title>{described}{body}</svg>"
    )


def _grid_and_axis(x0: float, y0: float, plot_w: float, plot_h: float,
                   ticks: Sequence[float], top: float,
                   fmt) -> str:
    """Solid hairline gridlines one shade off the surface, plus y labels."""
    parts = []
    for value in ticks:
        y = y0 + plot_h - (value / top * plot_h if top else 0)
        parts.append(f'<line class="grid" x1="{x0:.1f}" y1="{y:.2f}" '
                     f'x2="{x0 + plot_w:.1f}" y2="{y:.2f}"/>')
        parts.append(f'<text class="tick" x="{x0 - 8:.1f}" y="{y + 3.5:.2f}" '
                     f'text-anchor="end">{_e(fmt(value))}</text>')
    parts.append(f'<line class="axis" x1="{x0:.1f}" y1="{y0 + plot_h:.1f}" '
                 f'x2="{x0 + plot_w:.1f}" y2="{y0 + plot_h:.1f}"/>')
    return "".join(parts)


def _downsample(points: Sequence[Tuple[float, float]],
                limit: int = MAX_PATH_POINTS) -> List[Tuple[float, float]]:
    """Reduce a series to render resolution without moving any drawn pixel.

    Keeps, per horizontal bucket, both the extreme and the last value, so peaks
    and the compaction cliffs in the context chart survive the reduction.
    """
    points = list(points)
    if len(points) <= limit:
        return points
    first, last = points[0][0], points[-1][0]
    span = (last - first) or 1.0
    buckets: Dict[int, List[Tuple[float, float]]] = {}
    for point in points:
        index = int((point[0] - first) / span * (limit - 1))
        buckets.setdefault(index, []).append(point)
    reduced: List[Tuple[float, float]] = []
    for index in sorted(buckets):
        group = buckets[index]
        keep = {group[-1]}
        keep.add(max(group, key=lambda p: p[1]))
        keep.add(min(group, key=lambda p: p[1]))
        reduced.extend(sorted(keep, key=lambda p: p[0]))
    if reduced[0] != points[0]:
        reduced.insert(0, points[0])
    if reduced[-1] != points[-1]:
        reduced.append(points[-1])
    return reduced


def _no_data(label: str) -> str:
    return (f'<p class="empty">No data for {_e(label)} in this transcript.</p>')


# ---------------------------------------------------------------------------
# charts
# ---------------------------------------------------------------------------


def _chart_cost_over_time(series: Sequence[Sequence[float]], total_label: str,
                          request_count: int) -> str:
    """Cumulative spend against wall clock: where in the session the money went.

    One series, so no legend; the endpoint carries a direct label.

    `series` is [epoch_seconds, cumulative_usd] over EVERY request in the
    report payload's embedded call list, which to_dict() caps: on a session with
    more requests than that cap the chart would end partway up the session's
    bill, on a time axis that stopped days before the session did.
    """
    points: List[Tuple[float, float]] = []
    for row in series:
        if len(row) < 2:
            continue
        points.append((float(row[0]), float(row[1])))
    if len(points) < 2:
        return _no_data("cost over time")
    epoch0 = points[0][0]
    first = datetime.fromtimestamp(epoch0, tz=timezone.utc)
    points = [(stamp - epoch0, value) for stamp, value in points]
    running = points[-1][1]
    points = _downsample(points)
    drawn_points = request_count

    # pad_b holds two stacked rows -- the wall-clock ticks and the provenance
    # line beneath them -- so it is deeper than the other charts' bottom pad.
    height, pad_l, pad_r, pad_t, pad_b = 274, 62, 74, 16, 48
    plot_w = CHART_W - pad_l - pad_r
    plot_h = height - pad_t - pad_b
    span = max(points[-1][0], 1.0)
    ticks, top = _ticks(running, 4)

    def sx(seconds: float) -> float:
        return pad_l + seconds / span * plot_w

    def sy(value: float) -> float:
        return pad_t + plot_h - (value / top * plot_h if top else 0)

    body = [_grid_and_axis(pad_l, pad_t, plot_w, plot_h, ticks, top,
                           lambda v: f"${v:,.0f}")]

    line = "".join(f"{'M' if index == 0 else 'L'}{sx(x):.2f} {sy(y):.2f}"
                   for index, (x, y) in enumerate(points))
    body.append(f'<path class="area" d="{line}L{sx(points[-1][0]):.2f} '
                f'{pad_t + plot_h:.2f}L{sx(points[0][0]):.2f} {pad_t + plot_h:.2f}Z"/>')
    body.append(f'<path class="line" d="{line}"/>')

    # x ticks: five wall-clock labels across the session. The label at a given x
    # is the time AT that x -- interpolated along the axis, not the timestamp of
    # the request sitting at the same fraction of the request list. Those two
    # differ by up to 27 hours on a session with idle gaps, which is how this
    # axis came to read 22:14 -> 15:55 -> 15:43, apparently running backwards.
    # Bare HH:MM is also ambiguous once a session spans days, so a multi-day
    # axis gets the date too.
    multiday = span > 86400
    for index in range(5):
        fraction = index / 4.0
        seconds = span * fraction
        x = sx(seconds)
        when = first + timedelta(seconds=seconds)
        body.append(f'<text class="tick" x="{x:.1f}" y="{pad_t + plot_h + 18:.1f}" '
                    f'text-anchor="{"start" if index == 0 else "end" if index == 4 else "middle"}">'
                    f'{_e(when.strftime("%b %d %H:%M" if multiday else "%H:%M"))}</text>')

    end_x, end_y = sx(points[-1][0]), sy(points[-1][1])
    body.append(f'<circle class="dot" cx="{end_x:.2f}" cy="{end_y:.2f}" r="4"/>')
    body.append(f'<text class="value strong" x="{end_x + 9:.2f}" y="{end_y + 4:.2f}">'
                f'{_e(total_label)}</text>')
    body.append(f'<text class="tick" x="{pad_l:.1f}" y="{height - 4:.1f}">'
                f'{_e(first.strftime("%Y-%m-%d %H:%M UTC"))} onward &middot; '
                f'{drawn_points:,} requests</text>')
    return _svg(height, "".join(body),
                "Cumulative cost over the session",
                f"Cumulative USD across {drawn_points} API requests, "
                f"ending at {total_label}.")


def _chart_context(series: Sequence[dict]) -> str:
    """Context carried per main-loop request, with the window ceiling marked.

    Downward steps are compactions or /clear, and seeing them is the point.
    """
    points = [(float(index), float(_i(row.get("context_tokens"))))
              for index, row in enumerate(series) if _i(row.get("context_tokens"))]
    if len(points) < 2:
        return _no_data("context growth")
    window = _i(series[-1].get("max_tokens")) or pricing.DEFAULT_CONTEXT_WINDOW
    peak = max(value for _, value in points)
    drawn_points = len(points)
    points = _downsample(points)

    height, pad_l, pad_r, pad_t, pad_b = 240, 62, 74, 16, 34
    plot_w = CHART_W - pad_l - pad_r
    plot_h = height - pad_t - pad_b
    ticks, top = _ticks(max(peak, window * 0.1), 4)
    span = max(points[-1][0], 1)

    def sx(index: float) -> float:
        return pad_l + index / span * plot_w

    def sy(value: float) -> float:
        return pad_t + plot_h - (value / top * plot_h if top else 0)

    body = [_grid_and_axis(pad_l, pad_t, plot_w, plot_h, ticks, top, lambda v: _tok(v))]

    if window <= top:
        y = sy(window)
        body.append(f'<line class="limit" x1="{pad_l:.1f}" y1="{y:.2f}" '
                    f'x2="{pad_l + plot_w:.1f}" y2="{y:.2f}"/>')
        body.append(f'<text class="tick strong" x="{pad_l + plot_w + 6:.1f}" '
                    f'y="{y + 3.5:.2f}">window {_e(_tok(window))}</text>')

    line = "".join(f"{'M' if i == 0 else 'L'}{sx(x):.2f} {sy(y):.2f}"
                   for i, (x, y) in enumerate(points))
    body.append(f'<path class="area alt" d="{line}L{sx(points[-1][0]):.2f} '
                f'{pad_t + plot_h:.2f}L{sx(points[0][0]):.2f} {pad_t + plot_h:.2f}Z"/>')
    body.append(f'<path class="line alt" d="{line}"/>')

    end_x, end_y = sx(points[-1][0]), sy(points[-1][1])
    body.append(f'<circle class="dot alt" cx="{end_x:.2f}" cy="{end_y:.2f}" r="4"/>')
    body.append(f'<text class="value strong" x="{end_x + 9:.2f}" y="{end_y + 4:.2f}">'
                f'{_e(_tok(points[-1][1]))}</text>')
    body.append(f'<text class="tick" x="{pad_l:.1f}" y="{pad_t + plot_h + 18:.1f}">'
                f'request 1</text>')
    body.append(f'<text class="tick" x="{pad_l + plot_w:.1f}" '
                f'y="{pad_t + plot_h + 18:.1f}" text-anchor="end">'
                f'request {drawn_points:,} (main loop only)</text>')
    return _svg(height, "".join(body), "Context carried per main-loop request",
                f"Peak {peak:,} tokens against a {window:,} token window.")


def _chart_hbars(rows: Sequence[Tuple[str, float, str, str]], label: str,
                 gutter: int = 210, hue: str = "--s1", desc: str = "") -> str:
    """Horizontal bars for nominal categories: one hue for every bar, because
    length already encodes the magnitude and hue must not double-encode it.

    rows: (category, value, value label, tooltip)
    """
    rows = [row for row in rows if _f(row[1]) > 0]
    if not rows:
        return _no_data(label)
    bar_h, gap = 20, 12
    pad_t, pad_b = 10, 26
    height = pad_t + pad_b + len(rows) * (bar_h + gap) - gap
    plot_w = CHART_W - gutter - 96
    vmax = max(_f(row[1]) for row in rows)
    ticks, top = _ticks(vmax, 4)

    body = []
    for value in ticks:
        x = gutter + (value / top * plot_w if top else 0)
        body.append(f'<line class="grid" x1="{x:.1f}" y1="{pad_t:.1f}" '
                    f'x2="{x:.1f}" y2="{pad_t + len(rows) * (bar_h + gap) - gap:.1f}"/>')
    for index, (name, value, value_label, tip) in enumerate(rows):
        y = pad_t + index * (bar_h + gap)
        width = max(1.5, _f(value) / top * plot_w if top else 0)
        body.append(f'<g class="mark"><title>{_e(tip or name)}</title>'
                    f'<path fill="var({hue})" d="{_bar_path(gutter, y, width, bar_h, 4, "right")}"/>'
                    f'</g>')
        body.append(f'<text class="cat" x="{gutter - 10:.1f}" y="{y + bar_h / 2 + 4:.1f}" '
                    f'text-anchor="end">{_e(_clip(name, 34))}</text>')
        body.append(f'<text class="value" x="{gutter + width + 8:.1f}" '
                    f'y="{y + bar_h / 2 + 4:.1f}">{_e(value_label)}</text>')
    baseline = pad_t + len(rows) * (bar_h + gap) - gap
    body.append(f'<line class="axis" x1="{gutter:.1f}" y1="{pad_t:.1f}" '
                f'x2="{gutter:.1f}" y2="{baseline:.1f}"/>')
    for value in ticks:
        x = gutter + (value / top * plot_w if top else 0)
        body.append(f'<text class="tick" x="{x:.1f}" y="{baseline + 16:.1f}" '
                    f'text-anchor="middle">{_e(_axis_label(value, vmax))}</text>')
    return _svg(height, "".join(body), label, desc)


def _axis_label(value: float, vmax: float) -> str:
    if vmax >= 1000:
        return _tok(value)
    if vmax >= 10:
        return f"{value:,.0f}"
    return f"{value:,.2f}".rstrip("0").rstrip(".")


def _chart_vbars(rows: Sequence[Tuple[str, float, str, str]], label: str,
                 hue: str = "--s1", desc: str = "", value_fmt=None) -> str:
    """Vertical bars, used where the category is ordered (turn 1, 2, 3 ...)."""
    rows = list(rows)
    if not rows or all(_f(row[1]) <= 0 for row in rows):
        return _no_data(label)
    height, pad_l, pad_r, pad_t, pad_b = 250, 62, 20, 26, 46
    plot_w = CHART_W - pad_l - pad_r
    plot_h = height - pad_t - pad_b
    vmax = max(_f(row[1]) for row in rows)
    ticks, top = _ticks(vmax, 4)
    slot = plot_w / len(rows)
    bar_w = max(6.0, min(48.0, slot - 8.0))

    fmt = value_fmt or (lambda v: f"${v:,.2f}")
    body = [_grid_and_axis(pad_l, pad_t, plot_w, plot_h, ticks, top, fmt)]
    for index, (name, value, value_label, tip) in enumerate(rows):
        centre = pad_l + slot * (index + 0.5)
        magnitude = _f(value)
        bar_h = (magnitude / top * plot_h) if top else 0
        if bar_h > 0.5:
            y = pad_t + plot_h - bar_h
            body.append(
                f'<g class="mark"><title>{_e(tip or name)}</title>'
                f'<path fill="var({hue})" '
                f'd="{_bar_path(centre - bar_w / 2, y, bar_w, bar_h, 4, "top")}"/></g>')
            # Direct-label only the bars that can carry one without collision.
            if slot > 40 and value_label:
                body.append(f'<text class="value" x="{centre:.1f}" y="{y - 6:.1f}" '
                            f'text-anchor="middle">{_e(value_label)}</text>')
        body.append(f'<text class="tick" x="{centre:.1f}" '
                    f'y="{pad_t + plot_h + 18:.1f}" text-anchor="middle">'
                    f'{_e(_clip(name, 12))}</text>')
    return _svg(height, "".join(body), label, desc)


def _chart_stacked_kinds(segments: Sequence[Tuple[str, float, str, str]],
                         label: str) -> str:
    """One 100% bar over the six priced token kinds.

    Part-to-whole at a glance with <= 6 segments, 2px surface gaps between
    fills, direct labels only where they fit, and a legend that always names
    every segment so identity is never colour-alone.
    """
    segments = [seg for seg in segments if _f(seg[1]) > 0]
    if not segments:
        return _no_data(label)
    total = sum(_f(seg[1]) for seg in segments)
    height, pad_l, pad_r, pad_t = 128, 6, 6, 12
    bar_h = 46
    plot_w = CHART_W - pad_l - pad_r
    gap = 2.0

    body = []
    x = float(pad_l)
    for name, value, hue, tip in segments:
        width = max(1.0, _f(value) / total * plot_w - gap)
        body.append(f'<g class="mark"><title>{_e(tip)}</title>'
                    f'<rect x="{x:.2f}" y="{pad_t}" width="{width:.2f}" '
                    f'height="{bar_h}" rx="3" fill="var({hue})"/></g>')
        share = 100.0 * _f(value) / total
        if width > 62:
            body.append(f'<text class="onbar" x="{x + width / 2:.2f}" '
                        f'y="{pad_t + bar_h / 2 + 4:.1f}" text-anchor="middle">'
                        f'{share:,.0f}%</text>')
        x += width + gap

    legend_y = pad_t + bar_h + 26
    lx = float(pad_l)
    for name, value, hue, _tip in segments:
        body.append(f'<rect x="{lx:.1f}" y="{legend_y - 9:.1f}" width="10" height="10" '
                    f'rx="2" fill="var({hue})"/>')
        text = f"{name} {_usd(value)}"
        body.append(f'<text class="legend" x="{lx + 16:.1f}" y="{legend_y:.1f}">'
                    f'{_e(text)}</text>')
        lx += 20 + len(text) * 6.4
        if lx > CHART_W - 120:
            lx = float(pad_l)
            legend_y += 20
    return _svg(max(height, legend_y + 16), "".join(body), label,
                f"Share of {_usd(total)} by priced token kind.")


def _gauge(used: int, window: int, model: str) -> str:
    """A linear context meter with the same green/amber/red reading as the
    status line, so the two never tell different stories."""
    window = window or pricing.DEFAULT_CONTEXT_WINDOW
    fraction = min(1.0, (used / window) if window else 0.0)
    height, pad = 86, 8
    track_w = CHART_W - pad * 2
    bar_y, bar_h = 26, 26
    tone = "--good" if fraction < 0.6 else "--warn" if fraction < 0.85 else "--crit"
    body = [f'<rect x="{pad}" y="{bar_y}" width="{track_w}" height="{bar_h}" rx="6" '
            f'class="track"/>']
    fill_w = max(3.0, track_w * fraction)
    body.append(f'<g class="mark"><title>{_e(f"{used:,} of {window:,} tokens")}</title>'
                f'<path fill="var({tone})" '
                f'd="{_bar_path(pad, bar_y, fill_w, bar_h, 6, "right")}"/></g>')
    for mark in (0.25, 0.5, 0.75):
        x = pad + track_w * mark
        body.append(f'<line class="gaugetick" x1="{x:.1f}" y1="{bar_y}" '
                    f'x2="{x:.1f}" y2="{bar_y + bar_h}"/>')
        body.append(f'<text class="tick" x="{x:.1f}" y="{bar_y + bar_h + 16}" '
                    f'text-anchor="middle">{int(mark * 100)}%</text>')
    body.append(f'<text class="value strong" x="{pad}" y="{bar_y - 8}">'
                f'{_e(f"{used:,}")} tokens carried &middot; {fraction * 100:,.1f}% of the '
                f'{_e(_tok(window))} {_e(pricing.display_name(model) or "model")} window</text>')
    body.append(f'<text class="tick" x="{CHART_W - pad}" y="{bar_y + bar_h + 16}" '
                f'text-anchor="end">{_e(_tok(window))}</text>')
    return _svg(height, "".join(body), "Context window usage",
                f"{used:,} of {window:,} tokens carried by the last request.")


# ---------------------------------------------------------------------------
# optimisation opportunities -- the point of the whole report
# ---------------------------------------------------------------------------


def _rates(model: str, speed: str = "standard"):
    tier, name = pricing.tier_for(model, speed)
    if tier is None:
        tier = pricing.TIERS["tier_5_25"]
        name = "tier_5_25 (assumed)"
    return tier, name


def optimization_opportunities(payload: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Rank what could actually be done about the bill, by dollars.

    Every entry states its arithmetic in `basis` and its inputs in `evidence`,
    and carries a `confidence`:

      measured    -- the dollars were spent; the ledger has the receipts
      modeled     -- a counterfactual computed from measured tokens and real rates
      directional -- a stated fraction of a measured pool; the fraction is a judgement

    Nothing here is a guess about what the money *was*; the judgement is only
    ever about how much of a measured pool is recoverable.
    """
    # Redacted first: every evidence string below is built from these fields,
    # so scrubbing the inputs is what keeps the finished prose clean.
    payload = redact.ensure_redacted(payload or {})
    totals = payload.get("totals") or {}
    by_origin = payload.get("by_origin") or {}
    by_tool = payload.get("by_tool") or {}
    cache = payload.get("cache_efficiency") or {}
    waste = payload.get("waste") or {}
    series = payload.get("context_series") or []
    session = payload.get("session") or {}
    config = paths.load_config()

    model = session.get("primary_model") or "claude-opus-5"
    tier, _tier_name = _rates(model)
    cost = _f(totals.get("cost_usd"))
    opportunities: List[Dict[str, Any]] = []

    # How many times an average cached token is read back. Everything that adds
    # bytes to a context pays this multiplier, and it is measured, not assumed.
    written = max(1, _i(totals.get("cache_write_tokens")))
    carry = _i(totals.get("cache_read_tokens")) / written
    carry_rate = (tier.cw_5m + carry * tier.cache_read) / 1e6

    # -- 1. route fan-out work to a cheaper model ---------------------------
    fanout = {key: row for key, row in by_origin.items() if key != "main"}
    fanout_cost = sum(_f(row.get("cost_usd")) for row in fanout.values())
    if fanout_cost > 0.01:
        cheaper_name = "claude-sonnet-5"
        cheap = pricing.TIERS[pricing.MODEL_TIERS[cheaper_name]]
        repriced = 0.0
        tokens = {"input": 0, "output": 0, "cw5": 0, "cw1": 0, "read": 0}
        for row in fanout.values():
            tokens["input"] += _i(row.get("input_tokens"))
            tokens["output"] += _i(row.get("output_tokens"))
            tokens["cw5"] += _i(row.get("cache_write_5m_tokens"))
            tokens["cw1"] += _i(row.get("cache_write_1h_tokens"))
            tokens["read"] += _i(row.get("cache_read_tokens"))
        repriced = (tokens["input"] * cheap.input + tokens["output"] * cheap.output
                    + tokens["cw5"] * cheap.cw_5m + tokens["cw1"] * cheap.cw_1h
                    + tokens["read"] * cheap.cache_read) / 1e6
        saving = fanout_cost - repriced
        if saving > 0.01:
            names = sorted(fanout, key=lambda k: -_f(fanout[k].get("cost_usd")))[:4]
            opportunities.append({
                "id": "model-routing",
                "title": "Route mechanical fan-out to a cheaper model",
                "est_usd": saving,
                "confidence": "modeled",
                "basis": (f"the same {_tok(sum(tokens.values()))} tokens repriced from "
                          f"{pricing.display_name(model)} ({tier.input:g}/{tier.output:g}/"
                          f"{tier.cache_read:g} per 1M in/out/read) to Sonnet 5 "
                          f"({cheap.input:g}/{cheap.output:g}/{cheap.cache_read:g})"),
                "evidence": [
                    f"{_usd(fanout_cost)} ({_pct(_share(fanout_cost, cost), 0)} of spend) "
                    f"was billed inside subagents and workflow agents, not the main loop.",
                    "Heaviest groups: " + "; ".join(
                        f"{key} {_usd(fanout[key].get('cost_usd'))}" for key in names) + ".",
                    f"Repriced at Sonnet 5 the same token volume costs {_usd(repriced)}.",
                    f"Cache reads alone account for {_tok(tokens['read'])} tokens, and the "
                    f"read rate is where the tiers differ most "
                    f"({tier.cache_read:g} vs {cheap.cache_read:g} per 1M).",
                ],
                "action": ("Set a cheaper model on scanning/triage agents (grep-and-report, "
                           "test-runners, doc sweeps) and keep the expensive model for the "
                           "main loop and for agents that actually write code."),
            })

    # -- 2. stop paying to carry context that has already been read ---------
    main_ctx = [_i(row.get("context_tokens")) for row in series if _i(row.get("context_tokens"))]
    if len(main_ctx) >= 8:
        cap = _median(main_ctx)
        hit_ratio = _f(cache.get("hit_ratio"), 1.0) or 1.0
        excess = sum(max(0.0, value - cap) for value in main_ctx)
        saving = excess * hit_ratio * tier.cache_read / 1e6
        if saving > 0.01:
            peak = max(main_ctx)
            above = sum(1 for value in main_ctx if value > cap)
            opportunities.append({
                "id": "context-cap",
                "title": "Compact or split the session at its median context",
                "est_usd": saving,
                "confidence": "modeled",
                "basis": (f"sum of (context - {cap:,.0f}) over {above:,} main-loop requests "
                          f"= {_tok(excess)} token-carries, x {hit_ratio * 100:,.0f}% "
                          f"cache-read share x {tier.cache_read:g} per 1M"),
                "evidence": [
                    f"Main-loop context ran from {min(main_ctx):,} to {peak:,} tokens across "
                    f"{len(main_ctx):,} requests; the median request carried {cap:,.0f}.",
                    f"{above:,} requests carried more than the median, and every one of them "
                    "paid cache-read on the whole thing.",
                    f"Cache reads are {_pct(_share(totals.get('cache_read_usd'), cost), 0)} of "
                    f"this session's cost ({_usd(totals.get('cache_read_usd'))}).",
                ],
                "action": ("Land the finished work, /clear, and reopen with a short handoff. "
                           "The cost of a turn is linear in the context it drags along, so a "
                           "reset early is worth more than any prompt rewording."),
            })

    # -- 3. redundant reads --------------------------------------------------
    repeats = payload.get("redundant_work") or []
    if repeats:
        wasted_bytes = sum(_i(row.get("wasted_bytes")) for row in repeats)
        wasted_tokens = wasted_bytes / 4.0
        floor = wasted_tokens * tier.cw_5m / 1e6
        modeled = wasted_tokens * carry_rate
        if modeled > 0.01:
            worst = repeats[:4]
            opportunities.append({
                "id": "redundant-reads",
                "title": "Stop re-reading the same files and re-running the same commands",
                "est_usd": modeled,
                "confidence": "modeled",
                "basis": (f"{_bytes(wasted_bytes)} of repeated tool output = "
                          f"{_tok(wasted_tokens)} tokens, priced at one cache write "
                          f"({tier.cw_5m:g}/1M) plus {carry:,.0f} cache reads "
                          f"({tier.cache_read:g}/1M), the session's own measured re-read ratio"),
                "evidence": [
                    f"{len(repeats)} distinct targets were fetched at least "
                    f"{config['insights']['reread_threshold']} times.",
                    "Worst offenders: " + "; ".join(
                        f"{row.get('tool')} x{_i(row.get('count'))} on "
                        f"{redact.target_label(row.get('target'))}" for row in worst) + ".",
                    f"Floor if each repeat were paid once and never re-read: {_usd(floor)}. "
                    f"The multiplier is measured: {_tok(totals.get('cache_read_tokens'))} read "
                    f"against {_tok(totals.get('cache_write_tokens'))} written = "
                    f"{carry:,.0f}x.",
                ],
                "action": ("Read a file once and keep the finding in the plan, not in a "
                           "re-read. Where several agents need the same file, pass an "
                           "extract in the agent prompt instead of letting each one open it."),
            })

    # -- 4. fan-out width ----------------------------------------------------
    agent_types = payload.get("agent_type_costs") or []
    if agent_types:
        top = agent_types[0]
        trim = 0.25
        saving = _f(top.get("cost_usd")) * trim
        agents = payload.get("expensive_agents") or []
        priciest = [row for row in agents if row.get("agent_type") == top.get("agent_type")][:3]
        if saving > 0.01:
            opportunities.append({
                "id": "fanout-width",
                "title": f"Narrow the '{top.get('agent_type')}' fan-out",
                "est_usd": saving,
                "confidence": "directional",
                "basis": (f"{int(trim * 100)}% fewer agents of the priciest type: "
                          f"{_i(top.get('agents'))} agents x "
                          f"{_usd(top.get('cost_per_agent_usd'))} each = "
                          f"{_usd(top.get('cost_usd'))}; the 25% is the judgement, the "
                          f"per-agent cost is measured"),
                "evidence": [
                    f"{_i(top.get('agents'))} '{top.get('agent_type')}' agents ran "
                    f"{_i(top.get('calls')):,} requests for {_usd(top.get('cost_usd'))} "
                    f"({_pct(_share(top.get('cost_usd'), cost), 0)} of the session).",
                    f"Mean cost per agent {_usd(top.get('cost_per_agent_usd'))}; "
                    f"mean tokens per agent "
                    f"{_tok(_i(top.get('tokens')) / max(1, _i(top.get('agents'))))}.",
                ] + ([
                    "Priciest individual agents: " + "; ".join(
                        f"{row.get('agent') or '?'} {_usd(row.get('cost_usd'))}"
                        for row in priciest) + "."
                ] if priciest else []),
                "action": ("Every agent re-reads its own copy of the context it is given, so "
                           "fan-out width multiplies cache-read spend. Ask for fewer, "
                           "better-scoped agents and give each a narrower brief."),
            })

    # -- 5. thinking budget --------------------------------------------------
    thinking = _i(totals.get("thinking_tokens"))
    if thinking:
        thinking_usd = thinking * tier.output / 1e6
        trim = 0.35
        saving = thinking_usd * trim
        if saving > 0.01:
            opportunities.append({
                "id": "thinking-effort",
                "title": "Drop effort on mechanical turns",
                "est_usd": saving,
                "confidence": "directional",
                "basis": (f"{_tok(thinking)} thinking tokens x {tier.output:g} per 1M output "
                          f"= {_usd(thinking_usd)}; assume {int(trim * 100)}% of it sits on "
                          f"turns that did not need it"),
                "evidence": [
                    f"Thinking is {_pct(_share(thinking, totals.get('output_tokens')), 0)} of "
                    f"all output tokens ({_tok(thinking)} of "
                    f"{_tok(totals.get('output_tokens'))}).",
                    f"Output is {_pct(_share(totals.get('output_usd'), cost), 0)} of spend "
                    f"({_usd(totals.get('output_usd'))}), so this is a real but bounded lever.",
                ],
                "action": ("Thinking is billed at the output rate. Use a lower effort level "
                           "for edits, renames, test runs and status checks; keep the high "
                           "setting for design and debugging."),
            })

    # -- 6. tool output volume ----------------------------------------------
    tool_bytes = sum(_i(row.get("est_result_bytes")) for row in by_tool.values())
    if tool_bytes > 0:
        carrying = tool_bytes / 4.0 * carry_rate
        saving = carrying * 0.10
        if saving > 0.01:
            fattest = sorted(by_tool.values(), key=lambda r: -_i(r.get("est_result_bytes")))[:3]
            opportunities.append({
                "id": "tool-output",
                "title": "Trim what tools return into the context",
                "est_usd": saving,
                "confidence": "directional",
                "basis": (f"{_bytes(tool_bytes)} of tool results = "
                          f"{_tok(tool_bytes / 4.0)} tokens; carrying them costs "
                          f"{_usd(carrying)} at one write plus {carry:,.0f} reads. "
                          f"A 10% trim is the unit shown"),
                "evidence": [
                    "Biggest producers: " + "; ".join(
                        f"{row.get('name')} {_bytes(row.get('est_result_bytes'))} over "
                        f"{_i(row.get('count')):,} calls (avg "
                        f"{_bytes(row.get('avg_result_bytes'))})" for row in fattest) + ".",
                    f"Everything a tool prints is written to cache once and then re-read "
                    f"{carry:,.0f} times on average in this session.",
                ],
                "action": ("Pipe through head/rg/jq instead of cat; ask for the changed "
                           "hunk rather than the whole file; cap test output. Every 10% off "
                           "tool output is the figure above, repeatable."),
            })

    # -- 7. error and abort waste -------------------------------------------
    if _f(waste.get("error_cost_usd")) > 0.001 or _i(waste.get("tool_errors")):
        error_usd = _f(waste.get("error_cost_usd"))
        opportunities.append({
            "id": "errors",
            "title": "Requests that errored or aborted mid-stream",
            "est_usd": error_usd,
            "confidence": "measured",
            "basis": "the billed cost of API requests flagged as errored or aborted",
            "evidence": [
                f"{_i(waste.get('error_calls'))} API requests errored or aborted, burning "
                f"{_tok(waste.get('error_tokens'))} tokens for {_usd(error_usd)}.",
                f"{_i(waste.get('tool_errors')):,} tool calls failed "
                f"({_pct(waste.get('tool_error_pct'))} of all tool calls); each failure's "
                "error text is then carried in context for the rest of the session.",
            ],
            "action": ("Failed tool calls are cheap once and expensive forever after, because "
                       "the error text rides along in every later request. Fix the recurring "
                       "ones (wrong path, missing flag) rather than retrying them."),
        })

    # -- 8. cache TTL premium ------------------------------------------------
    hour_tokens = _i(totals.get("cache_write_1h_tokens"))
    if hour_tokens:
        premium = hour_tokens * (tier.cw_1h - tier.cw_5m) / 1e6
        if premium > 0.01:
            opportunities.append({
                "id": "cache-ttl",
                "title": "1-hour cache TTL premium",
                "est_usd": premium,
                "confidence": "conditional",
                "basis": (f"{_tok(hour_tokens)} tokens written at the 1h rate "
                          f"({tier.cw_1h:g}/1M) instead of the 5m rate ({tier.cw_5m:g}/1M)"),
                "evidence": [
                    f"{_tok(hour_tokens)} of {_tok(totals.get('cache_write_tokens'))} "
                    "cache writes used the 1-hour TTL.",
                    "The premium is 1.6x the 5-minute write. It pays for itself the moment a "
                    "single re-read lands more than five minutes later -- and the session's "
                    f"measured re-read ratio is {carry:,.0f}x.",
                ],
                "action": ("Recoverable only if those blocks were in fact re-read inside five "
                           "minutes. On a long session with gaps (this one ran "
                           f"{_dur(totals.get('wall_seconds'))}) the 1h TTL is almost "
                           "certainly the cheaper choice -- listed for completeness, not as "
                           "a recommendation."),
            })

    opportunities.sort(key=lambda row: -_f(row.get("est_usd")))
    for rank, row in enumerate(opportunities, start=1):
        row["rank"] = rank
        row["share_of_cost_pct"] = _share(row["est_usd"], cost)
    return opportunities



# ---------------------------------------------------------------------------
# the consolidated savings view
# ---------------------------------------------------------------------------

# A bm25 slice that answers a question costs a fraction of what reading the
# whole file costs, and these two ratios are what the savings view prices with.
# Both are RATIOS on purpose: the sample they came from is somebody's private
# transcript corpus, and an absolute token or byte total from it is a dollar
# figure one multiplication away at the cache-read list price. Anything that
# turns "open the file" into "open the part that answers it" is priced with
# them, and they are measurements, not targets.
#
# The printed span of a slice is a small fraction of the whole file: a median of
# roughly 4% and a mean of roughly 12%. The mean is kept, because the tail is real.
SLICE_COST_RATIO = 0.122
# Compaction threshold the advisor recommends, as a fraction of the window.
COMPACT_TARGET_FRACTION = 0.55
# Cost of the one extra request a find->slice round trip adds, as a
# per-round-trip rate. A shipped default, never a measurement of the reader's
# own data.
ROUNDTRIP_USD = 0.048

_STATUS_ORDER = {"active": 0, "partial": 1, "available": 2, "rejected": 3}


# Levers that monetise the SAME tokens. Summing them overstates what is
# achievable: "compact at a break" and "compact at the median context" are one
# saving described twice, and the three fan-out levers all shrink the same
# subagent bytes. Rows in a group are combined by taking the largest, never by
# adding -- see combined_saving().
LEVER_GROUPS: Dict[str, str] = {
    "compact-early": "context-size",
    "context-cap": "context-size",
    "slice-for-agents": "subagent-bytes",
    "fanout-width": "subagent-bytes",
    "guard-enforce": "reread-bytes",
    "redundant-reads": "reread-bytes",
}


def _lever(**row) -> Dict[str, Any]:
    row.setdefault("status", "available")
    row.setdefault("confidence", "modeled")
    row.setdefault("evidence", [])
    row.setdefault("setting", "-")
    row.setdefault("change", "")
    row.setdefault("group", LEVER_GROUPS.get(str(row.get("id") or ""), ""))
    return row


def combined_saving(levers: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
    """What is actually achievable if every available lever is pulled.

    Two corrections to a plain sum, both of which it gets wrong in the
    optimistic direction:

    * Levers in the same group are the same dollars counted twice. Take the
      largest in each group, not the sum.
    * Levers in different groups still compose multiplicatively against one
      bill, not additively: cutting the bytes an agent is sent AND running that
      agent on a cheaper model do not each save their full headline. Combine as
      1 - prod(1 - share).
    """
    groups: Dict[str, float] = {}
    singles: List[float] = []
    for row in levers:
        if row.get("status") == "rejected":
            continue
        usd = _f(row.get("est_usd"))
        if usd <= 0:
            continue
        gid = str(row.get("group") or "")
        if gid:
            groups[gid] = max(groups.get(gid, 0.0), usd)
        else:
            singles.append(usd)
    parts = list(groups.values()) + singles
    naive = sum(_f(r.get("est_usd")) for r in levers if r.get("status") != "rejected")
    deduped = sum(parts)
    return {"naive_sum": naive, "after_groups": deduped, "parts": parts}


def savings_levers(payload: Dict[str, Any], *,
                   rereads: Optional[Dict[str, Any]] = None,
                   context: Optional[Dict[str, Any]] = None,
                   opportunities: Optional[Sequence[Dict[str, Any]]] = None
                   ) -> List[Dict[str, Any]]:
    """Every lever known to this tool, priced on the data in `payload`.

    One list, ranked by dollars, each row carrying the CURRENT setting and what
    changing it would be worth -- so a lever that is already switched on shows
    up as `active` with its saving already banked, and one that has been
    measured and found not to pay shows up as `rejected` with the number that
    rejected it, instead of quietly not appearing.

    `context` is what the ledger cannot see: the guard's mode, whether an
    always-loaded MCP tool has downgraded the global prefix cache, how the
    session's compactions were triggered, whether the context store is indexed.
    bin/oe assembles it; everything else here is measured from the transcripts.
    """
    payload = redact.ensure_redacted(payload or {})
    context = dict(context or {})
    block = rereads if rereads is not None else (payload.get("rereads") or {})
    totals = payload.get("totals") or {}
    cost = _f(totals.get("cost_usd"))
    levers: List[Dict[str, Any]] = []

    reasons = {row.get("reason"): row for row in (block.get("by_reason") or [])}

    def _reason(name: str, field: str = "calibrated_usd") -> float:
        return _f((reasons.get(name) or {}).get(field))

    # -- 1. hand agents a slice, not a path ---------------------------------
    # Usually the biggest line, and the one the headline "most reads are
    # repeats" hides: the repeats are mostly not the main loop re-reading, they
    # are N different agents each opening the same file once into their own
    # fresh window. No cache can fix that. A slice can.
    # This row prices the MEASURED carry of this session's own reads, not the
    # calibrated default. The default is an average over whole sessions,
    # including the main loop's long-lived window; applied to subagent reads,
    # whose windows carry their bytes far fewer times, it overstates the saving.
    # `carry_usd` on each row is that row's own request stream.
    fanout_usd = _reason("subagent", "carry_usd") or _reason("subagent")
    # A slice does not replace a Read for free: the model runs `oe find`, reads
    # one-line hits, then runs `oe slice` -- one EXTRA request, which re-reads
    # the whole live prefix at cache-read price. That round trip costs several
    # times more in the main loop than in a subagent window, and on a small
    # enough read it wipes out the saving entirely.
    fanout_reads = _i((reasons.get("subagent") or {}).get("reads"))
    roundtrip_usd = fanout_reads * ROUNDTRIP_USD
    if fanout_usd > 0.01:
        agent_reads = _i((reasons.get("subagent") or {}).get("reads"))
        levers.append(_lever(
            id="slice-for-agents",
            title="Hand agents a slice, not a file path",
            est_usd=max(0.0, fanout_usd * (1.0 - SLICE_COST_RATIO) - roundtrip_usd),
            status=("available" if context.get("store_indexed") else "available"),
            confidence="modeled",
            setting=("context store indexed: "
                     + (f"{_num(context.get('store_files'))} files, "
                        f"{_num(context.get('store_chunks'))} chunks"
                        if context.get("store_indexed") else "NOT INDEXED -- run `oe index`")),
            change="oe index, then use oe slice instead of reading whole files",
            basis=(f"{_num(agent_reads)} reads landed in a context window that had "
                   f"never held the file, costing {_usd(fanout_usd)}; a bm25 slice that "
                   f"answers the same question measures {SLICE_COST_RATIO * 100:.1f}% of "
                   f"whole-file cost"),
            evidence=[
                f"{_num(agent_reads)} of {_num(block.get('reads'))} reads were a "
                f"different window's first sight of the file "
                f"({_bytes((reasons.get('subagent') or {}).get('bytes'))}).",
                "A residency guard cannot recover any of this: the bytes really are "
                "absent from that window. Only sending less can.",
                f"Priced at the calibrated slice ratio: a span that answers the "
                f"question costs about {SLICE_COST_RATIO * 100:.0f}% of the whole file "
                f"it replaces.",
            ],
            action=("Give a subagent the extract it needs in its prompt, or let the "
                    "guard rewrite the Read into the range that answers the question. "
                    "Fewer, better-scoped agents cuts the same line."),
        ))

    # -- 2. the guard, in enforce mode --------------------------------------
    avoidable = _f(block.get("avoidable_calibrated_usd"))
    guard_mode = str(context.get("guard_mode") or "warn")
    guard_block = block.get("guard") or {}
    # The read guard was cut from v1.0.0, so there is no lever to offer here: it
    # is not a setting the reader can change. The re-read measurement below
    # stands on its own without it.

    # -- 3. compact at a break, not at the ceiling --------------------------
    compactions = payload.get("compactions") or []
    auto = [row for row in compactions
            if str(row.get("trigger") or "").lower() in ("auto", "", "automatic")]
    # preTokens come from the transcript's own compactMetadata first, and only
    # then from context["compaction_pre_tokens"], which reads the PreCompact
    # hook journal -- a file that does not exist until those hooks are
    # installed. Without the transcript's own metadata the lever sees stale
    # journal rows instead of the session's real ceiling compactions, and prices
    # the whole thing at zero.
    pre = [_i(row.get("pre_tokens") or row.get("preTokens")) for row in compactions]
    pre = [v for v in pre if v]
    if not pre:
        pre = [_i(v) for v in (context.get("compaction_pre_tokens") or []) if _i(v)]
    post = [_i(row.get("post_tokens") or row.get("postTokens")) for row in compactions]
    post = [v for v in post if v]
    ceiling = pre
    if compactions or ceiling:
        mean_pre = (sum(pre) / len(pre)) if pre else 0
        mean_post = (sum(post) / len(post)) if post else (mean_pre * 0.025)
        window = (_i((payload.get("context_window") or {}).get("max_tokens"))
                  or pricing.DEFAULT_CONTEXT_WINDOW)
        tier, _n = _rates((payload.get("session") or {}).get("primary_model") or "")
        # The saving is NOT "the compaction request is smaller" -- that is one
        # request out of thousands, and rounding error against the rest. It is
        # that EVERY request in the cycle carries a smaller window. Context
        # sawtooths from post to the threshold, so the mean context per request
        # is (threshold + post)/2, and the cost of a request is linear in it.
        # This closed form stays within about 1% of a full simulation that
        # carries a regrowth penalty, which is why the cheap form is the one
        # that ships.
        target = window * COMPACT_TARGET_FRACTION
        series = [_i(row.get("context_tokens")) for row in (payload.get("context_series") or [])]
        series = [v for v in series if v]
        requests = len(series) or _i(totals.get("calls"))
        mean_now = (sum(series) / len(series)) if series else (mean_pre + mean_post) / 2.0
        mean_target = (target + target * (mean_post / mean_pre if mean_pre else 0.025)) / 2.0
        est = max(0.0, (mean_now - mean_target)) * requests * tier.cache_read / 1e6
        levers.append(_lever(
            id="compact-early",
            title="Compact at a break, not at the ceiling",
            est_usd=est,
            status=("available" if pre else "available"),
            confidence="modeled",
            setting=(f"{len(pre)} auto-compaction(s), mean pre-context "
                     f"{_tok(mean_pre)}" if pre else "no compaction recorded"),
            change="/compact at a natural break, or the PreCompact hook's advice",
            basis=(f"{_num(requests)} main-loop requests carried a mean of "
                   f"{_tok(mean_now)}; compacting at {COMPACT_TARGET_FRACTION * 100:.0f}% "
                   f"of the {_tok(window)} window puts the sawtooth between "
                   f"{_tok(mean_post)} and {_tok(target)}, a mean of "
                   f"{_tok(mean_target)} -- and the cost of a request is linear "
                   f"in the context it drags along"),
            evidence=[
                f"{len(auto)} of {len(compactions)} recorded compactions were automatic.",
                "An automatic compaction fires mid-task, so the summary it writes is "
                "also the one least likely to keep the right things.",
            ],
            action=("Land the work, then /compact -- or /clear and reopen with a short "
                    "handoff. /rewind truncates to an ALREADY CACHED prefix and so "
                    "costs nothing to re-establish."),
        ))

    # -- 4. the global prefix cache -----------------------------------------
    if context.get("prefix_cache") is not None:
        strategy = str(context.get("prefix_cache") or "unknown")
        fixed = _i(context.get("fixed_prefix_tokens"))
        requests = _i(totals.get("calls"))
        tier, _n = _rates((payload.get("session") or {}).get("primary_model") or "")
        est = fixed * requests * tier.cache_read / 1e6 if fixed and requests else 0.0
        offenders = context.get("mcp_always_loaded") or []
        levers.append(_lever(
            id="prefix-cache",
            title="Keep the global prefix cache on",
            est_usd=(est if strategy == "none" else 0.0),
            status=("available" if strategy == "none" else "active"),
            confidence="modeled",
            setting=f"globalCacheStrategy = {strategy}"
                    + (f" (downgraded by {len(offenders)} always-loaded MCP tool(s))"
                       if offenders else ""),
            change=("defer or remove the always-loaded MCP tools"
                    if strategy == "none" else "nothing to change"),
            basis=(f"{_tok(fixed)} of fixed prefix x {_num(requests)} requests at "
                   f"{tier.cache_read:g}/1M; one non-deferred MCP tool sets "
                   f"globalCacheStrategy to \"none\" for the whole session and forfeits "
                   f"cross-session reuse of that prefix"),
            evidence=([f"Always-loaded MCP tools: {', '.join(offenders[:6])}."]
                      if offenders else
                      ["No always-loaded MCP tool found; the prefix is cached as "
                       "\"system_prompt\"."]),
            action=("Mark MCP servers deferred so their tool definitions load on "
                    "demand. The saving is the fixed prefix stopping being re-billed "
                    "from cold on every new session."),
        ))

    # -- 5..n. the existing opportunity model -------------------------------
    for row in (opportunities if opportunities is not None
                else optimization_opportunities(payload)):
        levers.append(_lever(
            id=row.get("id"),
            title=row.get("title"),
            est_usd=_f(row.get("est_usd")),
            status=("rejected" if row.get("id") == "cache-ttl" else "available"),
            confidence=row.get("confidence") or "modeled",
            setting=("cache TTL is chosen by Claude Code, not by this tool"
                     if row.get("id") == "cache-ttl"
                     else "no setting -- this one is a way of working"),
            change=("do not change: cache READS are 0.1x at BOTH TTLs, so the TTL "
                    "cannot touch the read bill at all"
                    if row.get("id") == "cache-ttl" else row.get("action") or ""),
            basis=row.get("basis") or "",
            evidence=list(row.get("evidence") or []),
            action=row.get("action") or "",
        ))

    for row in levers:
        row["share_of_cost_pct"] = _share(row["est_usd"], cost)
    # Ranked by dollars, full stop. Sorting by status first reads better but
    # buries the point: the question this table answers is "where does the
    # money go", and a $1 lever that is already on does not belong above a
    # $500 one that is not. Status is a column, not the sort key.
    levers.sort(key=lambda r: (-_f(r["est_usd"]), _STATUS_ORDER.get(r["status"], 9)))
    for rank, row in enumerate(levers, start=1):
        row["rank"] = rank
    return levers


# ---------------------------------------------------------------------------
# HTML fragments
# ---------------------------------------------------------------------------


_CSS = """
:root{
  color-scheme: light;
  --bg:#f6f6f4; --surface:#fcfcfb; --surface2:#f1f0ed; --surface3:#e9e8e4;
  --line:#e2e1dc; --grid:#e8e7e3;
  --ink:#131312; --ink2:#54534f; --ink3:#83817b;
  --s1:#2a78d6; --s2:#eb6834; --s3:#1baf7a; --s4:#eda100; --s5:#e87ba4; --s6:#008300;
  --good:#0ca30c; --warn:#fab219; --serious:#ec835a; --crit:#d03b3b;
  --shadow:0 1px 2px rgba(16,16,15,.06), 0 8px 24px rgba(16,16,15,.05);
}
@media (prefers-color-scheme: dark){
  :root{
    color-scheme: dark;
    --bg:#111110; --surface:#1a1a19; --surface2:#232322; --surface3:#2c2c2a;
    --line:#33322f; --grid:#2a2a27;
    --ink:#ffffff; --ink2:#c3c2b7; --ink3:#918f87;
    --s1:#3987e5; --s2:#d95926; --s3:#199e70; --s4:#c98500; --s5:#d55181; --s6:#008300;
    --good:#0ca30c; --warn:#fab219; --serious:#ec835a; --crit:#d03b3b;
    --shadow:0 1px 2px rgba(0,0,0,.4), 0 8px 24px rgba(0,0,0,.35);
  }
}
*{box-sizing:border-box}
html{-webkit-text-size-adjust:100%}
body{
  margin:0; background:var(--bg); color:var(--ink);
  font:14px/1.55 ui-sans-serif,-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,
       "Helvetica Neue",Arial,sans-serif;
  font-variant-numeric: tabular-nums;
}
.wrap{max-width:1080px;margin:0 auto;padding:28px 20px 72px}
a{color:var(--s1)}
h1,h2,h3{line-height:1.25;margin:0;font-weight:650;letter-spacing:-.012em}
h1{font-size:26px}
h2{font-size:17px}
h3{font-size:14px}
p{margin:0 0 10px}
.muted{color:var(--ink2)}
.dim{color:var(--ink3)}
.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,"Liberation Mono",monospace;
      font-size:12px}

header.top{margin-bottom:22px}
header.top .eyebrow{font-size:11px;letter-spacing:.09em;text-transform:uppercase;
  color:var(--ink3);margin-bottom:8px}
header.top .meta{display:flex;flex-wrap:wrap;gap:6px 10px;margin-top:12px;
  font-size:12px;color:var(--ink2)}
header.top .meta span{background:var(--surface2);border:1px solid var(--line);
  border-radius:999px;padding:3px 9px;white-space:nowrap}
/* A provenance that is a guess must not wear the same chip as a record. */
header.top .meta span.guess{border-color:var(--warn);border-style:dashed;
  color:var(--warn);background:transparent}
header.top .metanote{margin-top:8px;font-size:12px;color:var(--ink2);
  border-left:3px solid var(--warn);padding-left:10px;max-width:78ch}

section{margin:30px 0 0}
section > h2{display:flex;align-items:baseline;gap:10px;margin-bottom:4px}
section > h2 .n{font-size:11px;color:var(--ink3);font-weight:600;letter-spacing:.08em}
section > .lede{color:var(--ink2);margin:0 0 14px;max-width:78ch}

.card{background:var(--surface);border:1px solid var(--line);border-radius:12px;
  padding:16px 18px;box-shadow:var(--shadow)}
.card + .card{margin-top:14px}

.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(168px,1fr));gap:12px}
.kpi{background:var(--surface);border:1px solid var(--line);border-radius:12px;
  padding:14px 16px;box-shadow:var(--shadow)}
.kpi .label{font-size:11px;letter-spacing:.06em;text-transform:uppercase;color:var(--ink3)}
.kpi .figure{font-size:27px;font-weight:640;letter-spacing:-.02em;margin-top:6px;
  font-variant-numeric:proportional-nums}
.kpi .sub{font-size:12px;color:var(--ink2);margin-top:4px}
.kpi.hero .figure{font-size:34px}

.chart{display:block;width:100%;height:auto;max-width:100%}
.chartbox{overflow-x:auto;-webkit-overflow-scrolling:touch}
.chartbox > svg{min-width:520px}
svg .grid{stroke:var(--grid);stroke-width:1}
svg .axis{stroke:var(--line);stroke-width:1}
svg .limit{stroke:var(--crit);stroke-width:1;stroke-opacity:.8}
svg .gaugetick{stroke:var(--surface);stroke-width:2}
svg .track{fill:var(--surface3)}
svg .tick{fill:var(--ink3);font-size:11px;font-family:inherit}
svg .cat{fill:var(--ink2);font-size:11.5px;font-family:inherit}
svg .value{fill:var(--ink2);font-size:11.5px;font-family:inherit}
svg .value.strong,svg .tick.strong{fill:var(--ink);font-weight:600}
svg .onbar{fill:#fff;font-size:11px;font-weight:600;font-family:inherit}
svg .legend{fill:var(--ink2);font-size:11.5px;font-family:inherit}
svg .line{fill:none;stroke:var(--s1);stroke-width:2;stroke-linejoin:round;
  stroke-linecap:round}
svg .line.alt{stroke:var(--s3)}
svg .area{fill:var(--s1);fill-opacity:.14;stroke:none}
svg .area.alt{fill:var(--s3);fill-opacity:.14}
svg .dot{fill:var(--s1);stroke:var(--surface);stroke-width:2}
svg .dot.alt{fill:var(--s3)}
svg .mark{cursor:default}
.empty{color:var(--ink3);font-style:italic;margin:12px 0}

.tablebox{overflow-x:auto;-webkit-overflow-scrolling:touch;border:1px solid var(--line);
  border-radius:10px;background:var(--surface)}
table{border-collapse:collapse;width:100%;font-size:12.5px;min-width:520px}
caption{caption-side:top;text-align:left;padding:10px 14px 8px;color:var(--ink2);
  font-size:12px}
th,td{padding:8px 12px;text-align:left;border-bottom:1px solid var(--line);
  white-space:nowrap;vertical-align:top}
th{font-weight:600;color:var(--ink2);font-size:11px;letter-spacing:.04em;
  text-transform:uppercase;background:var(--surface2);position:sticky;top:0;z-index:1}
tbody tr:last-child td{border-bottom:none}
tbody tr:hover{background:var(--surface2)}
td.n,th.n{text-align:right;font-variant-numeric:tabular-nums}
tfoot td{font-weight:650;background:var(--surface2);border-top:1px solid var(--line)}
td.wrap{white-space:normal;min-width:220px;max-width:460px}
.swatch{display:inline-block;width:9px;height:9px;border-radius:2px;margin-right:7px;
  vertical-align:baseline}

.chip{display:inline-block;font-size:10.5px;font-weight:650;letter-spacing:.04em;
  text-transform:uppercase;padding:2px 7px;border-radius:5px;border:1px solid var(--line);
  background:var(--surface2);color:var(--ink2);white-space:nowrap}
.chip.measured{border-color:var(--good);color:var(--good)}
.chip.modeled{border-color:var(--s1);color:var(--s1)}
.chip.directional{border-color:var(--serious);color:var(--serious)}
.chip.conditional{border-color:var(--ink3);color:var(--ink3)}
.chip.ok{border-color:var(--good);color:var(--good)}
.chip.drift{border-color:var(--crit);color:var(--crit)}
.chip.warnc{border-color:var(--warn);color:var(--ink2)}

.opp{background:var(--surface);border:1px solid var(--line);border-radius:12px;
  padding:16px 18px;box-shadow:var(--shadow);margin-bottom:12px}
.opp .head{display:flex;flex-wrap:wrap;align-items:baseline;gap:10px}
.opp .rank{font-size:12px;color:var(--ink3);font-weight:650;min-width:20px}
.opp .title{font-size:16px;font-weight:650;flex:1 1 260px}
.opp .amount{font-size:20px;font-weight:680;letter-spacing:-.02em;
  font-variant-numeric:proportional-nums}
.opp .meter{height:6px;border-radius:3px;background:var(--surface3);margin:12px 0 12px;
  overflow:hidden}
.opp .meter i{display:block;height:100%;border-radius:3px;background:var(--s1)}
.opp .basis{font-size:12px;color:var(--ink2);margin:0 0 10px}
.opp ul{margin:0 0 12px;padding-left:18px;color:var(--ink2)}
.opp li{margin:0 0 5px}
.opp .action{border-left:3px solid var(--s1);padding:8px 0 8px 12px;margin:0;
  background:linear-gradient(90deg,var(--surface2),transparent 70%);border-radius:0 6px 6px 0}

.callout{border:1px solid var(--line);border-left-width:3px;border-radius:0 10px 10px 0;
  padding:14px 16px;background:var(--surface)}
.callout.ok{border-left-color:var(--good)}
.callout.drift{border-left-color:var(--crit)}
.callout.info{border-left-color:var(--s1)}
.callout h3{margin-bottom:6px}

.grid2{display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:14px}
.statline{display:flex;justify-content:space-between;gap:16px;padding:7px 0;
  border-bottom:1px solid var(--line);font-size:13px}
.statline:last-child{border-bottom:none}
.statline b{font-weight:650}

details{background:var(--surface);border:1px solid var(--line);border-radius:12px;
  padding:0;box-shadow:var(--shadow);overflow:hidden}
summary{cursor:pointer;padding:14px 18px;font-weight:600;list-style:none;
  display:flex;justify-content:space-between;gap:12px;align-items:center}
summary::-webkit-details-marker{display:none}
summary::after{content:"show";font-size:11px;font-weight:600;letter-spacing:.06em;
  text-transform:uppercase;color:var(--ink3)}
details[open] summary::after{content:"hide"}
details[open] summary{border-bottom:1px solid var(--line)}
details .inner{padding:0}
details .inner .tablebox{border:none;border-radius:0}

ul.findings{margin:0;padding-left:18px;color:var(--ink2)}
ul.findings li{margin:0 0 7px}

footer.foot{margin-top:44px;padding-top:18px;border-top:1px solid var(--line);
  color:var(--ink3);font-size:12px}
footer.foot code{background:var(--surface2);padding:1px 5px;border-radius:4px}

@media (max-width:640px){
  .wrap{padding:20px 14px 56px}
  h1{font-size:21px}
  .kpi .figure{font-size:23px}
  .kpi.hero .figure{font-size:28px}
}
@media print{
  body{background:#fff}
  .card,.kpi,.opp,details{box-shadow:none}
  details{display:block}
  details > .inner{display:block !important}
}
"""

# Enhancement only: every value in this document is already reachable from a
# table or a direct label, so the page is complete with JS disabled.
_JS = """
(function(){
  try{
    var fmt=function(n){return n.toLocaleString();};
    document.querySelectorAll('table[data-sortable]').forEach(function(table){
      var head=table.tHead&&table.tHead.rows[0];
      if(!head)return;
      Array.prototype.forEach.call(head.cells,function(cell,index){
        cell.style.cursor='pointer';
        cell.title='Sort by '+cell.textContent.trim();
        var dir=1;
        cell.addEventListener('click',function(){
          var body=table.tBodies[0];
          if(!body)return;
          var rows=Array.prototype.slice.call(body.rows);
          rows.sort(function(a,b){
            var av=a.cells[index],bv=b.cells[index];
            if(!av||!bv)return 0;
            var an=parseFloat((av.dataset.v!==undefined?av.dataset.v:av.textContent)
                              .replace(/[^0-9eE.+-]/g,''));
            var bn=parseFloat((bv.dataset.v!==undefined?bv.dataset.v:bv.textContent)
                              .replace(/[^0-9eE.+-]/g,''));
            if(isNaN(an)&&isNaN(bn)){
              return dir*av.textContent.localeCompare(bv.textContent);
            }
            if(isNaN(an))return 1;
            if(isNaN(bn))return -1;
            return dir*(an-bn);
          });
          dir=-dir;
          rows.forEach(function(row){body.appendChild(row);});
        });
      });
    });
    void fmt;
  }catch(e){/* the document is fully readable without this */}
})();
"""


def _kpi(label: str, figure: str, sub: str = "", hero: bool = False) -> str:
    return (f'<div class="kpi{" hero" if hero else ""}">'
            f'<div class="label">{_e(label)}</div>'
            f'<div class="figure">{_e(figure)}</div>'
            + (f'<div class="sub">{sub}</div>' if sub else "")
            + "</div>")


# _prompt_text() and _prompt_label() lived here. They existed to render a user
# prompt into the turn table and the summary, which is exactly what an artifact
# may no longer carry, and both call sites now print the turn's pseudonym. They
# are deleted rather than left unused: a formatter for prompt text is an
# invitation to put prompt text back.


def _cell(html: str, value: Any) -> Tuple[str, float]:
    """A cell whose displayed text cannot be sorted as a number.

    The column sorter strips non-digits, so a humanised cell sorts on its
    mantissa alone and a kilobyte value can outrank a megabyte one -- exactly
    the wrong answer on the tool table's most useful column. Cells built through
    here carry the raw magnitude in data-v and sort on that instead.
    """
    return (html, _f(value))


def _table(headers: Sequence[Tuple[str, bool]], rows: Sequence[Sequence[Any]],
           caption: str = "", footer: Optional[Sequence[Any]] = None,
           sortable: bool = True) -> str:
    """headers: (label, numeric). Cells are pre-escaped HTML fragments, or
    (fragment, sort_value) pairs from _cell() for humanised magnitudes."""
    head = "".join(f'<th class="{"n" if numeric else ""}" scope="col">{_e(label)}</th>'
                   for label, numeric in headers)

    def _td(index: int, cell: Any) -> str:
        klass = "n" if headers[index][1] else ""
        if isinstance(cell, tuple):
            return f'<td class="{klass}" data-v="{cell[1]:.6f}">{cell[0]}</td>'
        return f'<td class="{klass}">{cell}</td>'

    body = []
    for row in rows:
        cells = "".join(_td(index, cell) for index, cell in enumerate(row))
        body.append(f"<tr>{cells}</tr>")
    foot = ""
    if footer:
        foot = "<tfoot><tr>" + "".join(
            _td(index, cell) for index, cell in enumerate(footer)) + "</tr></tfoot>"
    cap = f"<caption>{caption}</caption>" if caption else ""
    attr = ' data-sortable="1"' if sortable else ""
    return (f'<div class="tablebox"><table{attr}>{cap}<thead><tr>{head}</tr></thead>'
            f"<tbody>{''.join(body)}</tbody>{foot}</table></div>")


def _section(number: str, title: str, lede: str, body: str) -> str:
    return (f'<section><h2><span class="n">{_e(number)}</span>{_e(title)}</h2>'
            f'<p class="lede">{lede}</p>{body}</section>')


# ---------------------------------------------------------------------------
# the report
# ---------------------------------------------------------------------------


def _kind_rows(bucket: Dict[str, Any], model: str) -> List[Tuple[str, int, float, float, str]]:
    """(label, tokens, rate per 1M, usd, css hue) for the six priced kinds.

    Falls back to recomputing USD from tokens x rate when a bucket predates the
    per-kind cost fields, so the report never prints a blank money column.
    """
    tier, _name = _rates(model)
    rates = {
        "input_usd": tier.input, "output_usd": tier.output,
        "cache_write_5m_usd": tier.cw_5m, "cache_write_1h_usd": tier.cw_1h,
        "cache_read_usd": tier.cache_read, "web_search_usd": tier.web_search * 1e6,
    }
    rows = []
    for token_key, usd_key, label, _slug, hue in _KIND_LABELS:
        tokens = _i(bucket.get(token_key))
        rate = rates[usd_key]
        usd = bucket.get(usd_key)
        usd = _f(usd) if usd is not None else tokens * rate / 1e6
        rows.append((label, tokens, rate, usd, hue))
    return rows


def _cost_provenance(totals: Dict[str, Any], html: bool = False) -> str:
    """How much of the headline figure is Claude Code's own number.

    "Claude Code's own cost-state" is only true when every request in the file
    sits inside a checkpoint. On a resumed transcript most of the spend has no
    reported counterpart -- most of the total is ours, not the checkpoint's --
    and captioning that as the
    billing record is the kind of small lie that makes the whole report
    untrustworthy.
    """
    code = (lambda s: f"<code>{s}</code>") if html else (lambda s: s)
    if totals.get("cost_usd_reported") is None:
        return "our computed total; no " + code("cost-state") + " on disk"
    if totals.get("cost_fully_reported"):
        return "Claude Code's own " + code("cost-state") + " figure"
    uncovered = _f(totals.get("cost_usd_uncovered"))
    calls = _i(totals.get("uncovered_calls"))
    return (code("cost-state") + " for the checkpointed run plus our computed "
            + _usd(uncovered) + f" for {calls:,} requests it never covered")


def _unpriced_models(d: Dict[str, Any]) -> List[str]:
    """Model ids in this payload the pricing catalog has no tier for.

    The report is written either way -- a session that used a model this build
    has never heard of is a session whose cost is a FLOOR, not a session with no
    report -- so the gap is NAMED in the artifact instead of being left as a
    silent $0.00 under an exact-looking total. The ids come from by_model, which
    redaction emits verbatim on purpose: a model id identifies nobody, and a
    warning that cannot say which model it is about is not a warning.
    """
    rows = d.get("by_model") or {}
    values = list(rows.values()) if isinstance(rows, dict) else list(rows)
    out = set()
    for row in values:
        if isinstance(row, dict) and row.get("tier") == "unknown":
            name = str(row.get("model") or "").strip()
            if name:
                out.add(name)
    return sorted(out)


def render_html(ledger_dict: Dict[str, Any]) -> str:
    """One self-contained HTML document. No network, no external assets.

    Renders the REDACTED payload. A caller that hands over a raw ledger dict
    gets it scrubbed here, so there is no route by which prompt text, a path or
    a real id reaches the file.
    """
    d = redact.ensure_redacted(ledger_dict or {})
    session = d.get("session") or {}
    totals = d.get("totals") or {}
    recon = d.get("reconciliation") or {}
    cache = d.get("cache_efficiency") or {}
    window = d.get("context_window") or {}
    growth = d.get("context_growth") or {}
    waste = d.get("waste") or {}
    by_model = d.get("by_model") or {}
    by_origin = d.get("by_origin") or {}
    by_tool = d.get("by_tool") or {}
    by_turn = d.get("by_turn") or []
    calls = d.get("calls") or []
    cost_series = d.get("cost_series") or []
    model = session.get("primary_model") or ""

    computed = _f(totals.get("cost_usd"))
    reported = totals.get("cost_usd_reported")
    authoritative = _f(totals.get("cost_usd_authoritative"), computed)
    # The session's pseudonym, never its title: a title is prompt text.
    title = session.get("id") or "session"

    opportunities = optimization_opportunities(d)
    identified = sum(_f(row.get("est_usd")) for row in opportunities)

    parts: List[str] = []
    parts.append("<!doctype html>")
    parts.append('<html lang="en"><head><meta charset="utf-8">')
    parts.append('<meta name="viewport" content="width=device-width,initial-scale=1">')
    parts.append(f"<title>Usage report {_e(_clip(title, 48))}</title>")
    parts.append(f"<style>{_CSS}</style></head><body><div class=\"wrap\">")

    # -- header -------------------------------------------------------------
    # No cwd, no branch, no project path and no real session id: this document
    # is meant to be sent to other people. `oe whois session_07` maps the
    # pseudonym back to the real session, on the machine that produced it.
    # Label + provenance, never the address or the accountUuid: this document
    # is the artifact, and identity is PII. A provenance that is a GUESS is
    # marked as one and explained below the meta line: 'work (inferred)' set in
    # the same chip as 'work (recorded)' would read as a fact nobody checked.
    account_label = str(session.get("account_label") or "unknown")
    account_source = str(session.get("account_source") or "")
    account_guess = accounts.is_guess(account_source) if account_source else False
    account_text = "account " + account_label + (
        f" ({account_source}{', unverified' if account_guess else ''})"
        if account_source else "")
    meta = [
        (f"session {session.get('id') or '?'}", ""),
        (f"project {session.get('project') or '?'}", ""),
        (f"Claude Code {session.get('cc_version') or '?'}", ""),
        (f"model {pricing.display_name(model)}", ""),
        (account_text, "guess" if account_guess else ""),
        (f"{_stamp(session.get('started_at'))} -> {_stamp(session.get('last_activity'))}", ""),
    ]
    parts.append('<header class="top">')
    parts.append('<div class="eyebrow">Claude Code session usage report</div>')
    parts.append(f"<h1>Session {_e(_clip(title, 96))}</h1>")
    parts.append('<div class="meta">'
                 + "".join((f'<span class="{cls}">{_e(text)}</span>' if cls
                            else f"<span>{_e(text)}</span>")
                           for text, cls in meta) + "</div>")
    if account_guess:
        parts.append('<div class="metanote"><b>The account above is a guess, not a '
                     'record.</b> '
                     + _e(accounts.SOURCE_NOTE.get(account_source, "")) + "</div>")
    parts.append("</header>")

    # -- 01 headline --------------------------------------------------------
    # The two cards after the hero answer "where did it go?" on the first screen.
    # Without them the headline was six cards of magnitude -- cost, tokens, burn
    # rate, cost/request, tool calls, savings -- and naming the driver took a
    # scroll to section 04 and another to section 06.
    driver_rows = [row for row in _kind_rows(totals, model) if row[3] > 0]
    driver = max(driver_rows, key=lambda row: row[3]) if driver_rows else None
    agent_usd = sum(_f(row.get("cost_usd"))
                    for key, row in by_origin.items() if key != "main")
    main_usd = _f((by_origin.get("main") or {}).get("cost_usd"))
    agent_count = _i(session.get("agents"))

    kpis = [
        _kpi("Session cost", _usd(authoritative),
             _cost_provenance(totals, html=True),
             hero=True),
    ]
    if driver is not None:
        kpis.append(_kpi(
            "Biggest cost driver", driver[0],
            f"<b>{_e(_usd(driver[3]))}</b> &mdash; {_e(_pct(_share(driver[3], computed), 0))} "
            f"of computed spend, {_e(_tok(driver[1]))} tokens at ${driver[2]:,.2f}/1M "
            "(section 04)"))
    if agent_usd > 0.005 or agent_count:
        kpis.append(_kpi(
            "Spent inside agents", _usd(agent_usd),
            f"{_e(_pct(_share(agent_usd, computed), 0))} of computed spend across "
            f"{_num(agent_count)} spawned agents; the main loop you typed into cost "
            f"{_e(_usd(main_usd))} (section 06)"))
    kpis += [
        _kpi("Tokens billed", _tok(totals.get("total_tokens")),
             f"{_num(totals.get('calls'))} API requests"),
        _kpi("Burn rate", _usd(totals.get("cost_usd_per_hour")) + "/h",
             f"over {_e(_dur(totals.get('wall_seconds')))} of wall clock"),
        _kpi("Cost per request", _usd(computed / max(1, _i(totals.get("calls"))), 4),
             f"{_e(_tok(_i(totals.get('total_tokens')) / max(1, _i(totals.get('calls')))))} "
             "tokens each"),
        _kpi("Tool calls", _num(totals.get("tool_calls")),
             f"{_num(waste.get('tool_errors'))} failed"),
        _kpi("Identified savings", _usd(identified),
             f"{_pct(_share(identified, computed), 0)} of computed spend across "
             f"{len(opportunities)} <em>overlapping</em> levers &mdash; alternatives, "
             "not a sum to bank (section 11)"),
    ]
    headline_body = ['<div class="kpis">' + "".join(kpis) + "</div>"]

    if reported is not None and abs(_f(recon.get("delta_pct"))) > 2.0:
        headline_body.append(
            '<div class="card" style="margin-top:14px"><div class="callout drift">'
            f"<h3>The headline number is Claude Code's, not ours</h3>"
            f"<p class=\"muted\">Our per-request arithmetic totals {_e(_usd(computed))}; "
            f"Claude Code billed {_e(_usd(reported))}. That is a "
            f"{_e(_usd(abs(_f(recon.get('delta_usd')))))} "
            f"({_e(_pct(abs(_f(recon.get('delta_pct')))))}) gap, explained in full in "
            "section 10. Every dollar attributed below is measured per request, so the "
            "attribution adds up to our number, not to the headline.</p></div></div>")
    parts.append(_section(
        "01", "Headline",
        "What this session cost, how much of it moved through the model, and how much of "
        "it looks recoverable.", "".join(headline_body)))

    # -- 02 context window --------------------------------------------------
    used = _i(window.get("used_tokens"))
    max_tokens = _i(window.get("max_tokens")) or pricing.DEFAULT_CONTEXT_WINDOW
    ctx_body = ['<div class="card"><div class="chartbox">'
                + _gauge(used, max_tokens, window.get("model") or model)
                + "</div>"]
    per_turn = _f(growth.get("tokens_per_turn"))
    remaining = growth.get("turns_until_full")
    ctx_lines = [
        ("Carried by the last request", f"{used:,} tokens"),
        ("Window", f"{max_tokens:,} tokens ({pricing.display_name(window.get('model') or model)})"),
        ("Headroom", f"{_i(growth.get('headroom_tokens')):,} tokens"),
        ("Growth per turn (median)", f"{per_turn:,.0f} tokens"),
        ("Turns before the window fills",
         f"{remaining:,}" if remaining is not None else "not growing"),
        ("Context resets seen (compaction or /clear)", f"{_i(growth.get('resets'))}"),
    ]
    ctx_body.append('<div style="margin-top:14px">' + "".join(
        f'<div class="statline"><span class="muted">{_e(label)}</span>'
        f"<b>{_e(value)}</b></div>" for label, value in ctx_lines) + "</div></div>")
    ctx_body.append('<div class="card"><div class="chartbox">'
                    + _chart_context(d.get("context_series") or []) + "</div></div>")
    parts.append(_section(
        "02", "Context window",
        "The context meter is computed exactly the way Claude Code computes its own: "
        "input + cache_creation + cache_read on the last main-loop request. Cache-read "
        "cost is linear in this number, so the shape of this chart is the shape of the "
        "bill.", "".join(ctx_body)))

    # -- 03 cost over time --------------------------------------------------
    parts.append(_section(
        "03", "Where the money went, over time",
        "Cumulative measured spend across every recorded API request. Steep stretches are "
        "the expensive ones -- usually a wide fan-out or a long context being re-read.",
        '<div class="card"><div class="chartbox">'
        + _chart_cost_over_time(cost_series, _usd(cost_series[-1][1]) if cost_series
                                else _usd(computed), _i(totals.get("calls")))
        + "</div>"
        + '<p class="dim" style="margin-top:10px">Every request in the session, '
          "cumulative &mdash; the whole transcript, not a sample. "
        + ("The line ends at the session total. " if reported is None
           or abs(_f(recon.get("delta_pct"))) <= 2.0 else
           f"The line ends at {_e(_usd(computed))}, which is our per-request "
           f"arithmetic; the headline {_e(_usd(reported))} is Claude Code's own "
           "figure and the gap cannot be attributed to individual requests "
           "(section 10). ")
        + "The rows behind every point are in calls.csv.</p>"
        + "</div>"))

    # -- 04 token kinds -----------------------------------------------------
    kinds = _kind_rows(totals, model)
    kind_total = sum(row[3] for row in kinds)
    stacked = [(label, usd, hue, f"{label}: {_tok(tokens)} tokens at ${rate:,.2f}/1M "
                                 f"= {_usd(usd)}")
               for label, tokens, rate, usd, hue in kinds if usd > 0]
    kind_rows_html = []
    for label, tokens, rate, usd, hue in kinds:
        unit = "req" if label == "Web search" else "tokens"
        kind_rows_html.append([
            f'<span class="swatch" style="background:var({hue})"></span>{_e(label)}',
            f"{tokens:,}" if unit == "tokens" else f"{tokens:,} req",
            f"${rate:,.2f}" if label != "Web search" else f"${rate / 1e6:,.4f}/req",
            _e(_usd(usd, 4 if usd < 1 else 2)),
            _e(_pct(_share(usd, kind_total))),
        ])
    kind_body = ['<div class="card"><div class="chartbox">'
                 + _chart_stacked_kinds(stacked, "Cost by token kind") + "</div></div>"]
    kind_body.append(_table(
        [("Token kind", False), ("Tokens", True), ("Rate / 1M", True),
         ("USD", True), ("Share", True)],
        kind_rows_html,
        caption=("Every dollar in this report decomposes into these six terms. "
                 f"Rates are the {_e(pricing.display_name(model))} "
                 f"({_e(_rates(model)[1])}) tier from the "
                 f"{_e(pricing.PRICING_SOURCE_VERSION)} catalog."),
        footer=["<b>Total</b>", f"<b>{_num(totals.get('total_tokens'))}</b>", "",
                f"<b>{_e(_usd(kind_total))}</b>", "<b>100.0%</b>"]))
    if _i(totals.get("thinking_tokens")):
        kind_body.append(
            f'<p class="dim" style="margin-top:10px">Of the '
            f'{_num(totals.get("output_tokens"))} output tokens, '
            f'{_num(totals.get("thinking_tokens"))} '
            f'({_e(_pct(_share(totals.get("thinking_tokens"), totals.get("output_tokens"))))}) '
            "were thinking tokens, billed at the same output rate.</p>")
    parts.append(_section(
        "04", "Cost by token kind",
        "The traceability spine of the report: tokens x rate = dollars, for each of the six "
        "components Claude Code bills. Every later table is a regrouping of these same "
        "numbers.", "".join(kind_body)))

    # -- 05 by model --------------------------------------------------------
    model_rows_sorted = sorted(by_model.values(), key=lambda r: -_f(r.get("cost_usd")))
    model_table = []
    for row in model_rows_sorted:
        kinds_row = _kind_rows(row, row.get("model") or model)
        model_table.append([
            f'{_e(row.get("display_name") or row.get("model"))}'
            f'<div class="dim mono">{_e(row.get("model"))} &middot; {_e(row.get("tier"))}</div>',
            _num(row.get("calls")),
            _cell(_e(_tok(row.get("input_tokens"))), row.get("input_tokens")),
            _cell(_e(_tok(row.get("output_tokens"))), row.get("output_tokens")),
            _cell(_e(_tok(row.get("cache_write_tokens"))), row.get("cache_write_tokens")),
            _cell(_e(_tok(row.get("cache_read_tokens"))), row.get("cache_read_tokens")),
            _e(_usd(kinds_row[1][3])),
            _e(_usd(kinds_row[2][3] + kinds_row[3][3])),
            _e(_usd(kinds_row[4][3])),
            f"<b>{_e(_usd(row.get('cost_usd')))}</b>",
        ])
    model_chart = _chart_hbars(
        [(row.get("display_name") or row.get("model") or "?", _f(row.get("cost_usd")),
          _usd(row.get("cost_usd")),
          f"{row.get('model')}: {_num(row.get('calls'))} requests, "
          f"{_tok(row.get('total_tokens'))} tokens, {_usd(row.get('cost_usd'))}")
         for row in model_rows_sorted],
        "Cost by model", gutter=170,
        desc="Measured spend per model over the whole session.")
    parts.append(_section(
        "05", "By model",
        "Rates differ by model, so this is where a routing decision shows up. The three USD "
        "columns re-derive from the token columns at that model's tier rates.",
        '<div class="card"><div class="chartbox">' + model_chart + "</div></div>"
        + _table(
            [("Model", False), ("Requests", True), ("Input", True), ("Output", True),
             ("Cache write", True), ("Cache read", True), ("Output $", True),
             ("Write $", True), ("Read $", True), ("Total $", True)],
            model_table,
            caption="Token columns are humanised; the exact counts are in calls.csv.")))

    # -- 06 origin / subagents ---------------------------------------------
    origin_sorted = sorted(by_origin.values(), key=lambda r: -_f(r.get("cost_usd")))
    origin_chart = _chart_hbars(
        [(row.get("origin") or "?", _f(row.get("cost_usd")), _usd(row.get("cost_usd")),
          f"{row.get('origin')}: {_num(row.get('calls'))} requests across "
          f"{_i(row.get('agent_count'))} agents, {_usd(row.get('cost_usd'))}")
         for row in origin_sorted],
        "Cost by origin", gutter=250,
        desc="Main loop against each subagent and workflow-agent type.")
    origin_table = [[
        _e(row.get("origin")),
        _num(row.get("agent_count")),
        _num(row.get("calls")),
        _cell(_e(_tok(row.get("output_tokens"))), row.get("output_tokens")),
        _cell(_e(_tok(row.get("cache_read_tokens"))), row.get("cache_read_tokens")),
        _cell(_e(_tok(row.get("total_tokens"))), row.get("total_tokens")),
        _e(_usd(row.get("cost_usd"))),
        _e(_pct(_share(row.get("cost_usd"), computed))),
    ] for row in origin_sorted]
    origin_body = ['<div class="card"><div class="chartbox">' + origin_chart + "</div></div>",
                   _table([("Origin", False), ("Agents", True), ("Requests", True),
                           ("Output", True), ("Cache read", True), ("Tokens", True),
                           ("Cost", True), ("Share", True)],
                          origin_table,
                          caption="'main' is the conversation you typed into; everything else "
                                  "is an agent it spawned.")]

    agents = d.get("expensive_agents") or []
    if agents:
        agent_table = [[
            f'{_e(row.get("agent") or "-")}'
            + (f'<div class="dim mono">{_e(row.get("workflow"))}</div>'
               if row.get("workflow") else ""),
            _e(row.get("agent_type") or "-"),
            _num(row.get("calls")),
            _cell(_e(_tok(row.get("tokens"))), row.get("tokens")),
            _num(row.get("tools")),
            _e(_usd(row.get("cost_usd"))),
        ] for row in agents[:MAX_AGENT_ROWS]]
        origin_body.append("<div style='height:14px'></div>")
        origin_body.append(_table(
            [("Agent", False), ("Type", False), ("Requests", True), ("Tokens", True),
             ("Tool calls", True), ("Cost", True)],
            agent_table, caption="Most expensive individual agents."))

    agent_types = d.get("agent_type_costs") or []
    if agent_types:
        origin_body.append("<div style='height:14px'></div>")
        origin_body.append(_table(
            [("Agent type", False), ("Agents", True), ("Requests", True),
             ("Tokens", True), ("Cost", True), ("Cost / agent", True)],
            [[_e(row.get("agent_type")), _num(row.get("agents")), _num(row.get("calls")),
              _cell(_e(_tok(row.get("tokens"))), row.get("tokens")),
              _e(_usd(row.get("cost_usd"))),
              _e(_usd(row.get("cost_per_agent_usd")))] for row in agent_types],
            caption="Cost per agent is the number to watch: it is what one more unit of "
                    "fan-out costs."))

    workflows = d.get("workflows") or []
    if workflows:
        origin_body.append("<div style='height:14px'></div>")
        origin_body.append(_table(
            [("Workflow", False), ("Status", False), ("Agents", True),
             ("Journal tokens", True), ("Tool calls", True), ("Duration", True)],
            [[f'{_e(row.get("workflow") or "-")}',
              _e(row.get("status") or "-"), _num(row.get("agent_count")),
              _cell(_e(_tok(row.get("journal_total_tokens"))),
                    row.get("journal_total_tokens")),
              _num(row.get("journal_tool_calls")),
              _cell(_e(_dur(_i(row.get("duration_ms")) / 1000.0)),
                    _i(row.get("duration_ms")) / 1000.0)] for row in workflows],
            caption="Workflow runs in this session. Journal token counts come from the "
                    "workflow's own progress file, not from billing."))
    parts.append(_section(
        "06", "Main loop vs agents",
        "Every spawned agent carries its own context and pays its own cache reads, so "
        "fan-out width is usually the single largest cost decision in a session.",
        "".join(origin_body)))

    # -- 07 per turn --------------------------------------------------------
    turn_rows = [row for row in by_turn if _i(row.get("calls"))]
    turn_chart = _chart_vbars(
        [(f"#{_i(row.get('index'))}", _f(row.get("cost")), _usd(row.get("cost")),
          f"turn {_i(row.get('index'))}: {_usd(row.get('cost'))}, "
          f"{_num(row.get('calls'))} requests, {_tok(row.get('tokens'))} tokens")
         for row in turn_rows],
        "Cost per user turn",
        desc="One bar per user prompt, in order.")
    turn_table = [[
        f'<span class="mono">#{_i(row.get("index"))}</span>',
        _e(_hhmm(row.get("first_ts")) or "-"),
        f'<span class="mono dim">{_e(row.get("turn") or "-")}</span>',
        _num(row.get("calls")),
        _num(row.get("subagent_calls")),
        _cell(_e(_tok(row.get("tokens"))), row.get("tokens")),
        _cell(_e(_tok(row.get("context_end_tokens"))), row.get("context_end_tokens")),
        _num(row.get("tools")),
        _cell(_e(_dur(row.get("duration_s"))), row.get("duration_s")),
        f"<b>{_e(_usd(row.get('cost')))}</b>",
    ] for row in sorted(turn_rows, key=lambda r: _i(r.get("index")))]
    turn_footer = ["<b>Total</b>", "", "",
                   f"<b>{_num(sum(_i(r.get('calls')) for r in turn_rows))}</b>",
                   f"<b>{_num(sum(_i(r.get('subagent_calls')) for r in turn_rows))}</b>",
                   _cell(f"<b>{_e(_tok(sum(_i(r.get('tokens')) for r in turn_rows)))}</b>",
                         sum(_i(r.get("tokens")) for r in turn_rows)), "",
                   f"<b>{_num(sum(_i(r.get('tools')) for r in turn_rows))}</b>", "",
                   f"<b>{_e(_usd(sum(_f(r.get('cost')) for r in turn_rows)))}</b>"]
    parts.append(_section(
        "07", "Per turn",
        "One row per prompt you sent. The prompt text is not recorded -- what a turn costs "
        "is decided by how much context it drags in and how many agents it starts, and "
        "those are the columns below.",
        '<div class="card"><div class="chartbox">' + turn_chart + "</div></div>"
        + _table([("Turn", False), ("Started", False), ("Turn id", False), ("Requests", True),
                  ("Agent reqs", True), ("Tokens", True), ("Context end", True),
                  ("Tools", True), ("Wall", True), ("Cost", True)],
                 turn_table,
                 caption="Column headers sort. 'Context end' is the context carried by the "
                         "last main-loop request of that turn.",
                 footer=turn_footer)))

    # -- 08 tools -----------------------------------------------------------
    tools_by_count = sorted(by_tool.values(), key=lambda r: -_i(r.get("count")))
    tool_chart = _chart_hbars(
        [(row.get("name") or "?", float(_i(row.get("count"))), _num(row.get("count")),
          f"{row.get('name')}: {_num(row.get('count'))} calls, "
          f"{_bytes(row.get('est_result_bytes'))} returned")
         for row in tools_by_count[:14]],
        "Tool calls by frequency", gutter=230, hue="--s1",
        desc="The fourteen most-used tools.")
    tool_bytes_chart = _chart_hbars(
        [(row.get("name") or "?", float(_i(row.get("est_result_bytes"))),
          _bytes(row.get("est_result_bytes")),
          f"{row.get('name')}: {_bytes(row.get('est_result_bytes'))} across "
          f"{_num(row.get('count'))} calls (avg {_bytes(row.get('avg_result_bytes'))})")
         for row in sorted(by_tool.values(),
                           key=lambda r: -_i(r.get("est_result_bytes")))[:14]],
        "Bytes returned into context, by tool", gutter=230, hue="--s2",
        desc="What each tool actually pushed into the context window.")
    # Bytes are the input to the bill, not the bill. Every byte a tool returns is
    # written to the cache once and then re-read on every later request in that
    # context, so the dollars are bytes/4 tokens x (one write + `carry` reads).
    # Same arithmetic, same inputs, as opportunity "Trim what tools return", so
    # the per-tool column and that lever's total cannot disagree.
    tool_tier, _tool_tier_name = _rates(model)
    tool_carry = (_i(totals.get("cache_read_tokens"))
                  / max(1, _i(totals.get("cache_write_tokens"))))
    tool_carry_rate = (tool_tier.cw_5m + tool_carry * tool_tier.cache_read) / 1e6

    def _carry_usd(byte_count: Any) -> float:
        return _i(byte_count) / 4.0 * tool_carry_rate

    tool_table = [[
        _e(row.get("name")),
        _e(row.get("server") or "-"),
        _num(row.get("count")),
        _num(row.get("errors")),
        _cell(_e(_bytes(row.get("est_result_bytes"))), row.get("est_result_bytes")),
        _cell(_e(_bytes(row.get("avg_result_bytes"))), row.get("avg_result_bytes")),
        _cell(_e(_bytes(row.get("max_result_bytes"))), row.get("max_result_bytes")),
        f"<b>{_e(_usd(_carry_usd(row.get('est_result_bytes'))))}</b>",
        (f"{_i(row.get('avg_duration_ms')):,} ms"
         if row.get("avg_duration_ms") is not None else
         '<span class="dim">n/a</span>'),
    ] for row in tools_by_count[:MAX_TOOL_ROWS]]
    tool_bytes_all = sum(_i(row.get("est_result_bytes")) for row in by_tool.values())
    tool_footer = [
        "<b>All tools</b>", "",
        f"<b>{_num(sum(_i(r.get('count')) for r in by_tool.values()))}</b>",
        f"<b>{_num(sum(_i(r.get('errors')) for r in by_tool.values()))}</b>",
        _cell(f"<b>{_e(_bytes(tool_bytes_all))}</b>", tool_bytes_all), "", "",
        f"<b>{_e(_usd(_carry_usd(tool_bytes_all)))}</b>", "",
    ]
    tool_note = ""
    if all(row.get("avg_duration_ms") is None for row in by_tool.values()):
        tool_note = ('<p class="dim" style="margin-top:10px">Per-tool wall time is blank '
                     "because transcripts do not record it; it is populated by the "
                     "PostToolUse hook once installed.</p>")
    parts.append(_section(
        "08", "Tool usage",
        "Tool calls are free at the call site and expensive afterwards: whatever a tool "
        "returns is written to the cache once and then re-read on every subsequent request "
        "in that context.",
        '<div class="card"><div class="chartbox">' + tool_chart + "</div></div>"
        + '<div class="card"><div class="chartbox">' + tool_bytes_chart + "</div></div>"
        + _table([("Tool", False), ("MCP server", False), ("Calls", True), ("Errors", True),
                  ("Bytes returned", True), ("Avg", True), ("Max", True),
                  ("Context cost", True), ("Avg wall", True)],
                 tool_table,
                 caption=f"Top {min(MAX_TOOL_ROWS, len(tools_by_count))} of "
                         f"{len(by_tool)} tools by call count &mdash; click "
                         "&lsquo;Context cost&rsquo; to rank them by what they cost "
                         "instead. Context cost = bytes / 4 tokens, written to cache once "
                         f"at ${tool_tier.cw_5m:,.2f}/1M and re-read "
                         f"{tool_carry:,.0f}x at ${tool_tier.cache_read:,.2f}/1M, this "
                         "session's own measured re-read ratio. It is not billed "
                         "separately; it is the share of the bill above that this tool's "
                         "output put there.",
                 footer=tool_footer)
        + tool_note))

    # -- 09 cache -----------------------------------------------------------
    cache_stats = [
        ("Cache hit ratio",
         _pct(_f(cache.get("hit_ratio")) * 100.0),
         "share of all prompt tokens that arrived from cache"),
        ("Read from cache", _tok(cache.get("read_tokens")),
         f"cost {_usd(cache.get('cost_paid_on_reads_usd'))}"),
        ("Written to cache", _tok(cache.get("write_tokens")),
         f"cost {_usd(cache.get('cost_paid_on_writes_usd'))}"),
        ("Fresh input", _tok(cache.get("fresh_input_tokens")),
         "never cached; billed at the full input rate"),
        ("Saved vs no caching", _usd(cache.get("cost_saved_vs_uncached_usd")),
         "those reads at the full input rate, minus what they actually cost"),
        ("Net benefit", _usd(cache.get("net_usd")),
         "savings minus everything paid on cache writes"),
    ]
    written = max(1, _i(totals.get("cache_write_tokens")))
    reread = _i(totals.get("cache_read_tokens")) / written
    cache_body = ['<div class="kpis">' + "".join(
        _kpi(label, value, _e(sub)) for label, value, sub in cache_stats) + "</div>"]
    cache_body.append(
        f'<div class="card" style="margin-top:14px"><div class="callout info">'
        f"<h3>Every cached token was read back about {reread:,.0f} times</h3>"
        f'<p class="muted">{_e(_tok(totals.get("cache_read_tokens")))} read against '
        f'{_e(_tok(totals.get("cache_write_tokens")))} written. That ratio is the multiplier '
        "on every byte anything puts into the context: a file read once, a verbose test log, "
        f"an agent brief. At {_e(f'${_rates(model)[0].cache_read:g}')} per 1M read, "
        f"{reread:,.0f} re-reads cost "
        f"{_e(f'${reread * _rates(model)[0].cache_read:,.1f}')} per 1M tokens carried -- "
        f"which is why cache read is {_e(_pct(_share(totals.get('cache_read_usd'), computed), 0))} "
        "of this session's bill.</p></div></div>")
    parts.append(_section(
        "09", "Cache efficiency",
        "Caching is doing its job here; the question is not whether to cache but how much "
        "there is to cache in the first place.", "".join(cache_body)))

    # -- 10 reconciliation --------------------------------------------------
    parts.append(_section("10", "Reconciliation against Claude Code",
                          "Does our arithmetic agree with Claude Code's own billing record?",
                          _reconciliation_html(d, computed)))

    # -- 11 opportunities ---------------------------------------------------
    opp_body = []
    if opportunities:
        opp_chart = _chart_hbars(
            [(row["title"], _f(row["est_usd"]), _usd(row["est_usd"]),
              f"{row['title']}: {_usd(row['est_usd'])} ({row['confidence']})")
             for row in opportunities],
            "Estimated saving by opportunity", gutter=300, hue="--s1",
            desc="Ranked by the dollars each would have kept.")
        opp_body.append('<div class="card"><div class="chartbox">' + opp_chart + "</div>"
                        f'<p class="dim" style="margin-top:10px">These are alternatives, not '
                        f"a sum to bank: the levers overlap (narrowing fan-out also cuts the "
                        f"cache reads that the context lever counts). Total identified "
                        f"{_e(_usd(identified))} against {_e(_usd(computed))} computed "
                        "spend.</p></div>")
        for row in opportunities:
            width = 100.0 * _f(row["est_usd"]) / max(
                _f(opportunities[0]["est_usd"]), 1e-9)
            evidence = "".join(f"<li>{_e(line)}</li>" for line in row.get("evidence") or [])
            opp_body.append(
                '<div class="opp">'
                f'<div class="head"><span class="rank">#{row["rank"]}</span>'
                f'<span class="title">{_e(row["title"])}</span>'
                f'<span class="chip {_e(row["confidence"])}">{_e(row["confidence"])}</span>'
                f'<span class="amount">{_e(_usd(row["est_usd"]))}</span></div>'
                f'<div class="meter"><i style="width:{width:.1f}%"></i></div>'
                f'<p class="basis"><b>How this number was reached:</b> {_e(row["basis"])}.</p>'
                f"<ul>{evidence}</ul>"
                f'<p class="action">{_e(row["action"])}</p>'
                "</div>")
    else:
        opp_body.append('<p class="empty">No opportunities cleared the reporting threshold.</p>')

    repeats = d.get("redundant_work") or []
    if repeats:
        opp_body.append("<div style='height:6px'></div>")
        opp_body.append(_table(
            [("Tool", False), ("Target", False), ("Times", True), ("Callers", True),
             ("Bytes returned", True), ("Avoidable", True)],
            [[_e(row.get("tool")),
              f'<span class="mono">{_e(redact.target_label(row.get("target")))}</span>',
              _num(row.get("count")), _num(row.get("distinct_callers")),
              _cell(_e(_bytes(row.get("bytes"))), row.get("bytes")),
              _cell(_e(_bytes(row.get("wasted_bytes"))), row.get("wasted_bytes"))]
             for row in repeats],
            caption="Evidence for the redundant-read opportunity: the same target fetched "
                    "repeatedly. A target is a shape token, not a name: the same id is the "
                    "same file or command, so the repeat count survives without naming it. "
                    "'Callers' counts how many distinct agents each fetched it."))
    parts.append(_section(
        "11", "Optimisation opportunities",
        "Ranked by the dollars each would have kept in this session. Every entry states the "
        "arithmetic that produced its number and the measurement it rests on.",
        "".join(opp_body)))

    # -- 12 re-read ledger --------------------------------------------------
    parts.append(_rereads_html(d))

    # -- 13 findings --------------------------------------------------------
    findings = d.get("insights") or []
    if findings:
        parts.append(_section(
            "13", "Ledger findings",
            "The narrative version, generated by the ledger while it parsed the transcripts.",
            '<div class="card"><ul class="findings">'
            + "".join(f"<li>{_e(line)}</li>" for line in findings) + "</ul></div>"))

    # -- 14 raw calls -------------------------------------------------------
    parts.append(_raw_calls_html(d))

    # -- footer -------------------------------------------------------------
    parse = d.get("parse") or {}
    unpriced = _i(totals.get("unpriced_calls"))
    warn = ""
    if unpriced:
        gaps = _unpriced_models(d)
        named = (" (" + ", ".join(_e(m) for m in gaps) + ")") if gaps else ""
        warn = (f'<p><span class="chip drift">unpriced</span> {unpriced:,} requests used a '
                f"model missing from the pricing table{named} and were counted as $0. Run "
                "<code>oe reprice</code>; until then the totals here are a floor.</p>")
    parts.append(
        '<footer class="foot">'
        + warn
        + f"<p>Generated {_e(_stamp(d.get('generated_at')))} by Overwatch Enforcer "
          f"(schema {_i(d.get('schema_version'))}) from "
          f"{_i(parse.get('files_read'))} transcript files "
          f"({_e(_bytes(parse.get('bytes_read')))}, {_i(parse.get('bad_lines'))} unparseable "
          f"lines, {_f(parse.get('load_seconds')):.2f}s).</p>"
          f"<p>Prices are the model catalog embedded in Claude Code "
          f"{_e(pricing.PRICING_SOURCE_VERSION)}. Cost per request = "
          "input x rate + output x rate + cache_write_5m x rate + cache_write_1h x rate + "
          "cache_read x rate + web_search x per-request price, all per 1M tokens. "
          "No network requests were made to build this file, and it references no external "
          "resources.</p>"
        + "</footer>")

    parts.append(f"</div><script>{_JS}</script></body></html>")
    return "".join(parts)



# One line per re-read reason, in the order the ledger declares them, so the
# table always reads first -> legitimate -> avoidable no matter which reasons
# a given session happens to contain.
_REREAD_REASON_COPY = {
    "first": ("first read", "The session's first read of that path. Not a repeat."),
    "subagent": ("different window", "A context window that never held the file: a "
                 "subagent's own window, or the main window reading what until now "
                 "only an agent had read. Unavoidable by reading less; avoidable "
                 "only by handing the agent an extract instead of a path."),
    "post_compact": ("after compaction", "This window did hold it, and a compaction "
                     "dropped it. The re-read is the compaction's cost, not the "
                     "read's."),
    "new_range": ("new lines", "Resident, but this call asked for lines the window "
                  "had not seen. Real work."),
    "changed": ("file changed", "Resident and unchanged in range, but the file was "
                "written since -- the bytes genuinely differ. A residency guard "
                "cannot see this, which is why it is counted as a false block."),
    "avoidable": ("AVOIDABLE", "The exact bytes were already in this exact window and "
                  "were paid for twice."),
}


def _rereads_html(d: Dict[str, Any]) -> str:
    """Section 12: which files were read again, why, and what it cost."""
    block = d.get("rereads") or {}
    reads = _i(block.get("reads"))
    if not reads:
        return _section(
            "12", "Re-read ledger",
            "Every file read, classified by whether the bytes were already in the "
            "context window that asked for them.",
            '<div class="card"><p class="empty">No file reads in this session.</p></div>')

    total_bytes = _i(block.get("bytes"))
    repeat_pct = _f(block.get("repeat_pct"))
    measured = _f(block.get("repeat_carry_usd"))
    calibrated = _f(block.get("repeat_calibrated_usd"))
    avoidable_usd = _f(block.get("avoidable_calibrated_usd"))
    guard = block.get("guard") or {}

    kpis = "".join([
        _kpi("Reads", _num(reads),
             f"{_num(block.get('files'))} distinct files", hero=True),
        _kpi("Bytes into context", _bytes(total_bytes),
             f"{_tok(block.get('tokens'))} tokens"),
        _kpi("Repeat share", _pct(repeat_pct, 1),
             f"{_num(block.get('repeat_reads'))} of {_num(reads)} calls"),
        _kpi("Repeat cost", _usd(calibrated),
             f"{_usd(measured)} by this session's own carry"),
        _kpi("Of that, avoidable", _usd(avoidable_usd),
             f"{_num(block.get('avoidable_reads'))} calls"),
    ])

    reason_rows = []
    for row in block.get("by_reason") or []:
        name = str(row.get("reason") or "")
        label, blurb = _REREAD_REASON_COPY.get(name, (name, ""))
        cls = ' style="color:var(--crit)"' if name == "avoidable" else ""
        reason_rows.append([
            f"<b{cls}>{_e(label)}</b>",
            _num(row.get("reads")),
            _cell(_e(_bytes(row.get("bytes"))), row.get("bytes")),
            _cell(_e(_usd(row.get("calibrated_usd"))), row.get("calibrated_usd")),
            _cell(_e(_usd(row.get("carry_usd"))), row.get("carry_usd")),
            f'<span class="dim">{_e(blurb)}</span>',
        ])

    files = block.get("files_ranked") or []
    file_rows = []
    for row in files:
        reasons = row.get("reasons") or {}
        mix = ", ".join(
            f"{_REREAD_REASON_COPY.get(k, (k, ''))[0]} x{_i(v)}"
            for k, v in sorted(reasons.items(), key=lambda kv: -_i(kv[1]))
            if k != "first")
        file_rows.append([
            f'<span class="mono">{_e(redact.target_label(row.get("target")))}</span>',
            _num(row.get("reads")),
            _num(row.get("windows")),
            _cell(_e(_bytes(row.get("bytes"))), row.get("bytes")),
            _cell(f"<b>{_e(_usd(row.get('repeat_calibrated_usd')))}</b>",
                  row.get("repeat_calibrated_usd")),
            _cell(_e(_usd(row.get("repeat_carry_usd"))), row.get("repeat_carry_usd")),
            _cell(_e(_usd(row.get("avoidable_calibrated_usd"))),
                  row.get("avoidable_calibrated_usd")),
            f'<span class="dim">{_e(mix or "-")}</span>',
        ])

    would = _i(guard.get("would_block"))
    false_blocks = _i(guard.get("false_blocks"))
    guard_note = (
        f'<div class="card"><h3>What an enforcing guard would have done</h3>'
        f"<p>A guard that denies a read whose bytes are already resident in the same "
        f"window would have acted on <b>{_num(would)}</b> of {_num(reads)} calls: "
        f"<b>{_num(guard.get('correct_blocks'))}</b> correctly "
        f"({_usd(guard.get('saved_calibrated_usd'))} of forward context), and "
        f"<b>{_num(false_blocks)}</b> wrongly, because residency alone cannot see that "
        f"a file was written since it was read. That is a "
        f"{_pct(guard.get('false_block_pct'), 0)} false-block rate -- which is why "
        f"denying a read on residency alone is a measurement here and not an "
        f"enforcement this tool performs.</p></div>")

    lede = (
        "Bytes a tool returns are written to the cache once and then re-read by every "
        "later request in that context window, so a file read twice into the same "
        "window is paid for twice. This table splits every repeat by WHY it happened, "
        "because only the last row is waste.")

    method = (
        f'<p class="dim" style="margin-top:10px">Two prices per row. '
        f'<b>Carry cost</b> is measured from this session: each read\'s tokens x '
        f'(one 5-minute cache write + the {_f(block.get("carry_requests_mean")):,.0f} '
        f'requests that actually followed it in its own window, cut off at the next '
        f'compaction) = an effective '
        f'${_f(block.get("carry_rate_usd_per_1k_measured")):,.4f} per 1k tokens. '
        f'<b>Calibrated</b> prices the same tokens at '
        f'${_f(block.get("carry_rate_usd_per_1k_calibrated")):,.3f} per 1k, the '
        f'default forward-carry rate this tool ships with rather than anything '
        f'measured here, so it stays comparable across sessions. The two '
        f'differ because most reads here happen inside short-lived agent windows, '
        f'which carry their bytes far fewer times than the main loop does. Bytes are '
        f'the exact text the tool returned, not the transcript line that holds it.</p>')

    return _section(
        "12", "Re-read ledger", lede,
        f'<div class="kpis">{kpis}</div>'
        + _table([("Reason", False), ("Calls", True), ("Bytes", True),
                  ("Calibrated", True), ("Carry cost", True), ("What it means", False)],
                 reason_rows,
                 caption="Every read of the session, by reason. Exactly one applies "
                         "to each call.")
        + _table([("File", False), ("Reads", True), ("Windows", True), ("Bytes", True),
                  ("Repeat (calibrated)", True), ("Repeat (carry)", True),
                  ("Avoidable", True), ("Why it was re-read", False)],
                 file_rows,
                 caption=("Ranked by what the repeats cost. A target is a shape token, "
                          "not a name -- the same id is the same file, so the ranking "
                          "survives without naming it."
                          + (" Truncated to the top rows."
                             if block.get("files_truncated") else "")))
        + guard_note + method)


def _reconciliation_html(d: Dict[str, Any], computed: float) -> str:
    recon = d.get("reconciliation") or {}
    status = recon.get("status") or "unavailable"
    reported = recon.get("reported_usd")
    delta = _f(recon.get("delta_usd"))
    delta_pct = recon.get("delta_pct")

    if status == "unavailable":
        verdict = (
            '<div class="callout info"><h3>Nothing to reconcile against</h3>'
            '<p class="muted">This transcript carries no <code>cost-state</code> checkpoint, '
            f"so {_e(_usd(computed))} is our arithmetic alone. It is the sum of "
            f"{_num((d.get('totals') or {}).get('calls'))} priced requests and nothing "
            "cross-checks it.</p></div>")
    elif status == "ok":
        verdict = (
            '<div class="callout ok"><h3>Our math agrees with Claude Code</h3>'
            f'<p class="muted">We compute <b>{_e(_usd(recon.get("computed_usd_covered")))}</b>; '
            f"Claude Code's own <code>cost-state</code> records "
            f"<b>{_e(_usd(reported))}</b>. The difference is "
            f"{_e(_usd(abs(delta)))} "
            f"({_e(_pct(abs(_f(delta_pct)), 2))}), inside the 2% tolerance. "
            "Treat every number in this report as billing-accurate.</p></div>")
    else:
        direction = "under" if delta < 0 else "over"
        verdict = (
            '<div class="callout drift"><h3>Our math does <em>not</em> agree with '
            "Claude Code, and here is exactly how much</h3>"
            f'<p class="muted">We compute <b>{_e(_usd(recon.get("computed_usd_covered")))}</b> '
            f"from the requests written to disk. Claude Code billed "
            f"<b>{_e(_usd(reported))}</b>. We are <b>{_e(_usd(abs(delta)))} "
            f"{direction}</b>"
            + (f" ({_e(_pct(abs(_f(delta_pct)), 2))})" if delta_pct is not None else "")
            + ". The headline figure in section 1 is Claude Code's number, because "
              "<code>cost-state</code> is the billing record. The per-request attribution "
              "everywhere else sums to ours, because that is what the transcripts actually "
              "contain.</p></div>")

    body = ['<div class="card">' + verdict + "</div>"]

    per_kind = recon.get("per_kind") or {}
    if per_kind:
        labels = {"input": "Fresh input", "output": "Output",
                  "cache_read": "Cache read", "cache_write": "Cache write"}
        rows = []
        for key in ("input", "output", "cache_write", "cache_read"):
            row = per_kind.get(key) or {}
            coverage = row.get("coverage_pct")
            chip = ""
            if coverage is not None:
                tone = "ok" if coverage >= 99.0 else "warnc" if coverage >= 90.0 else "drift"
                chip = f'<span class="chip {tone}">{coverage:,.1f}%</span>'
            rows.append([
                _e(labels.get(key, key)),
                f"{_i(row.get('computed')):,}",
                f"{_i(row.get('reported')):,}",
                f"{_i(row.get('delta')):+,}",
                chip or '<span class="dim">n/a</span>',
            ])
        body.append(_table(
            [("Token kind", False), ("On disk (ours)", True), ("Billed (Claude Code)", True),
             ("Delta", True), ("Coverage", True)],
            rows,
            caption="Where the gap lives. A gap concentrated in one token kind is a "
                    "transcript-completeness problem, not an arithmetic one."))

    split = recon.get("origin_split") or {}
    if split:
        body.append("<div style='height:14px'></div>")
        body.append(_table(
            [("Origin", False), ("Requests", True), ("Output tokens", True),
             ("Cache read tokens", True)],
            [[_e("Main transcript" if key == "main" else "Sidechain (agent) transcripts"),
              _num(row.get("calls")), _num(row.get("output_tokens")),
              _num(row.get("cache_read_tokens"))]
             for key, row in split.items()],
            caption="Evidence, not assertion: which files the tokens we did find came from."))

    per_model = recon.get("per_model") or []
    if per_model:
        body.append("<div style='height:14px'></div>")
        body.append(_table(
            [("Model (as billed)", False), ("Billed USD", True), ("Our USD", True),
             ("Delta", True), ("Billed output", True), ("Our output", True),
             ("In transcript", False)],
            [[f'<span class="mono">{_e(row.get("model"))}</span>',
              _e(_usd(row["reported_usd"])) if row.get("reported_usd") is not None
              else '<span class="dim">-</span>',
              _e(_usd(row.get("computed_usd"))),
              _e(_usd(row["delta_usd"])) if row.get("delta_usd") is not None
              else '<span class="dim">-</span>',
              _num(row.get("reported_output_tokens"))
              if row.get("reported_output_tokens") is not None
              else '<span class="dim">-</span>',
              _num(row.get("computed_output_tokens")),
              "yes" if row.get("in_transcript") else
              '<span class="chip warnc">never written</span>']
             for row in per_model],
            caption="Per-model comparison against the summed cost-state modelUsage tables."))

    runs = recon.get("runs") or []
    if len(runs) > 1:
        body.append("<div style='height:14px'></div>")
        body.append(_table(
            [("Run started", False), ("Billed USD", True)],
            [[_e(_stamp(row.get("started_at"))), _e(_usd(row.get("reported_usd")))]
             for row in runs],
            caption="This transcript was resumed. Claude Code restarts its cost accumulator "
                    "on each run, so the reported total is the sum of these checkpoints.",
            sortable=False))

    diagnosis = recon.get("diagnosis") or []
    if diagnosis:
        body.append('<div class="card" style="margin-top:14px"><h3>Diagnosis</h3>'
                    '<ul class="findings" style="margin-top:8px">'
                    + "".join(f"<li>{_e(line)}</li>" for line in diagnosis) + "</ul></div>")

    if _i(recon.get("uncovered_calls")):
        body.append(
            f'<p class="dim" style="margin-top:10px">'
            f'{_i(recon.get("uncovered_calls")):,} requests '
            f'({_e(_usd(recon.get("computed_usd_uncovered")))}) fall outside every '
            "checkpoint's window -- before the earliest one, after the newest one, or both -- "
            "and are excluded from the comparison above, though they are counted "
            "in the computed total. See the diagnosis for which edge.</p>")

    reported_api = _i(recon.get("reported_api_duration_ms"))
    if reported_api:
        body.append(
            f'<p class="dim" style="margin-top:10px">Claude Code also records '
            f'{_e(_dur(reported_api / 1000.0))} of API time, '
            f'{_e(_dur(_i(recon.get("reported_tool_duration_ms")) / 1000.0))} of tool time, '
            f'and {_i(recon.get("reported_lines_added")):,} lines added / '
            f'{_i(recon.get("reported_lines_removed")):,} removed for this session.</p>')
    return "".join(body)


def _raw_calls_html(d: Dict[str, Any]) -> str:
    # `top_calls` is ranked by the ledger over EVERY request. `calls` is only
    # the first max_raw_calls of them, so ranking inside it produced a table
    # captioned "top N by cost" that was really the top N of the first page --
    # silently missing much of the true top N, and every request after the point
    # where the embedded call list was capped. Fall back to `calls` only for a
    # payload written by an older schema.
    calls = d.get("top_calls") or d.get("calls") or []
    if not calls:
        return ""
    totals = d.get("totals") or {}
    ranked = sorted(calls, key=lambda c: -_f(c.get("total_usd")))[:MAX_HTML_CALL_ROWS]
    rows = []
    for call in ranked:
        flags = []
        if call.get("is_error"):
            flags.append('<span class="chip drift">error</span>')
        if call.get("aborted"):
            flags.append('<span class="chip warnc">aborted</span>')
        if call.get("unpriced"):
            flags.append('<span class="chip drift">unpriced</span>')
        origin = call.get("origin") or "main"
        if origin != "main":
            origin = f"{origin}:{_clip(call.get('agent_type') or '?', 26)}"
        rows.append([
            f'<span class="mono">{_e(_hhmm(call.get("ts")))}</span>',
            f'<span class="mono">{_e(call.get("call") or "-")}</span>',
            _e(pricing.display_name(call.get("model"))),
            _e(origin),
            f'#{_i(call.get("turn_index"))}',
            _num(call.get("input_tokens")),
            _num(call.get("output_tokens")),
            _num(_i(call.get("cache_write_5m")) + _i(call.get("cache_write_1h"))),
            _num(call.get("cache_read")),
            _num(call.get("context_tokens")),
            _e(", ".join(call.get("tools") or []) or "-"),
            f"<b>{_e(_usd(call.get('total_usd'), 4))}</b>" + ("".join(flags)),
        ])
    cheapest = _f(ranked[-1].get("total_usd")) if ranked else 0.0
    note = (f"The {len(rows):,} most expensive of {_num(totals.get('calls'))} requests, "
            f"ranked across the whole session (every one of them cost at least "
            f"{_usd(cheapest, 4)}). The complete set, one row per request with every "
            "token kind and its dollars, is in calls.csv next to this file.")
    return ('<section><h2><span class="n">14</span>Raw API requests</h2>'
            '<p class="lede">Every dollar above traces back to rows like these.</p>'
            "<details><summary>Show the most expensive requests</summary>"
            '<div class="inner">'
            + _table([("Time", False), ("Request", False), ("Model", False), ("Origin", False),
                      ("Turn", True), ("Input", True), ("Output", True), ("Cache write", True),
                      ("Cache read", True), ("Context", True), ("Tools", False), ("Cost", True)],
                     rows, caption=note)
            + "</div></details></section>")


# ---------------------------------------------------------------------------
# markdown
# ---------------------------------------------------------------------------


def render_markdown(ledger_dict: Dict[str, Any]) -> str:
    """A terse summary for reading in a terminal -- the numbers, not the prose.

    Same contract as render_html: summary.md is a file, every file here is
    shareable, so it renders the redacted payload.
    """
    d = redact.ensure_redacted(ledger_dict or {})
    session = d.get("session") or {}
    totals = d.get("totals") or {}
    recon = d.get("reconciliation") or {}
    cache = d.get("cache_efficiency") or {}
    window = d.get("context_window") or {}
    growth = d.get("context_growth") or {}
    model = session.get("primary_model") or ""
    computed = _f(totals.get("cost_usd"))
    authoritative = _f(totals.get("cost_usd_authoritative"), computed)
    lines: List[str] = []

    lines.append(f"# Session {session.get('id') or 'session'}")
    lines.append("")
    lines.append(f"`{session.get('id')}` | "
                 f"{session.get('project')} | "
                 f"{pricing.display_name(model)} | "
                 f"Claude Code {session.get('cc_version') or '?'} | "
                 f"account {session.get('account_label') or 'unknown'}"
                 f" ({session.get('account_source') or 'unknown'}"
                 + (", unverified)"
                    if accounts.is_guess(session.get('account_source')) else ")"))
    lines.append(f"{_stamp(session.get('started_at'))} -> "
                 f"{_stamp(session.get('last_activity'))} "
                 f"({_dur(totals.get('wall_seconds'))})")
    if accounts.is_guess(session.get("account_source")):
        lines.append("")
        lines.append("> **The account above is a guess, not a record.** "
                     + accounts.SOURCE_NOTE.get(
                         str(session.get("account_source")), ""))
    lines.append("")
    lines.append("## Headline")
    lines.append("")
    lines.append(f"- **Cost: {_usd(authoritative)}**"
                 + " (" + _cost_provenance(totals) + ")")
    lines.append(f"- Tokens: {_tok(totals.get('total_tokens'))} over "
                 f"{_num(totals.get('calls'))} requests "
                 f"({_num(totals.get('requests_main'))} main, "
                 f"{_num(_i(totals.get('requests_subagent')) + _i(totals.get('requests_workflow')))}"
                 " in agents)")
    lines.append(f"- Burn rate: {_usd(totals.get('cost_usd_per_hour'))}/h")
    lines.append(f"- Tool calls: {_num(totals.get('tool_calls'))}, "
                 f"{_num((d.get('waste') or {}).get('tool_errors'))} failed")
    lines.append(f"- Context now: {_i(window.get('used_tokens')):,} / "
                 f"{_i(window.get('max_tokens')):,} ({_pct(window.get('pct'))}), "
                 f"growing ~{_f(growth.get('tokens_per_turn')):,.0f} tokens per turn")
    lines.append("")

    lines.append("## Cost by token kind")
    lines.append("")
    lines.append("| kind | tokens | $/1M | USD | share |")
    lines.append("|---|---:|---:|---:|---:|")
    kinds = _kind_rows(totals, model)
    kind_total = sum(row[3] for row in kinds) or 1.0
    for label, tokens, rate, usd, _hue in kinds:
        if not tokens and not usd:
            continue
        lines.append(f"| {label} | {tokens:,} | {rate:,.2f} | {_usd(usd, 4)} | "
                     f"{_share(usd, kind_total):,.1f}% |")
    lines.append("")

    origins = sorted((d.get("by_origin") or {}).values(),
                     key=lambda r: -_f(r.get("cost_usd")))
    if origins:
        lines.append("## By origin")
        lines.append("")
        lines.append("| origin | agents | requests | tokens | USD | share |")
        lines.append("|---|---:|---:|---:|---:|---:|")
        for row in origins:
            lines.append(f"| {row.get('origin')} | {_i(row.get('agent_count')):,} | "
                         f"{_i(row.get('calls')):,} | {_tok(row.get('total_tokens'))} | "
                         f"{_usd(row.get('cost_usd'))} | "
                         f"{_share(row.get('cost_usd'), computed):,.1f}% |")
        lines.append("")

    models = sorted((d.get("by_model") or {}).values(),
                    key=lambda r: -_f(r.get("cost_usd")))
    if models:
        lines.append("## By model")
        lines.append("")
        lines.append("| model | requests | tokens | USD | share |")
        lines.append("|---|---:|---:|---:|---:|")
        for row in models:
            lines.append(f"| {pricing.display_name(row.get('model'))} | "
                         f"{_i(row.get('calls')):,} | {_tok(row.get('total_tokens'))} | "
                         f"{_usd(row.get('cost_usd'))} | "
                         f"{_share(row.get('cost_usd'), computed):,.1f}% |")
        lines.append("")

    # The standalone summary carries tool usage too, so it can answer "what
    # tooling did I use, how often, and what did it cost" without the HTML
    # report. 'context $' is the same arithmetic as the "Trim what tools return"
    # lever: bytes/4 tokens, one cache write plus this session's measured
    # re-read count.
    by_tool = d.get("by_tool") or {}
    if by_tool:
        tier, _name = _rates(model)
        carry = (_i(totals.get("cache_read_tokens"))
                 / max(1, _i(totals.get("cache_write_tokens"))))
        carry_rate = (tier.cw_5m + carry * tier.cache_read) / 1e6
        ranked = sorted(by_tool.values(), key=lambda r: -_i(r.get("est_result_bytes")))
        lines.append("## Tool usage")
        lines.append("")
        lines.append(f"{_num(totals.get('tool_calls'))} calls across {len(by_tool)} tools. "
                     f"'context $' is what carrying that output cost: bytes / 4 tokens, "
                     f"written to cache once at ${tier.cw_5m:g}/1M and re-read {carry:,.0f}x "
                     f"at ${tier.cache_read:g}/1M.")
        lines.append("")
        lines.append("| tool | calls | errors | bytes returned | avg | context $ |")
        lines.append("|---|---:|---:|---:|---:|---:|")
        for row in ranked[:15]:
            lines.append(f"| {row.get('name')} | {_i(row.get('count')):,} | "
                         f"{_i(row.get('errors')):,} | "
                         f"{_bytes(row.get('est_result_bytes'))} | "
                         f"{_bytes(row.get('avg_result_bytes'))} | "
                         f"{_usd(_i(row.get('est_result_bytes')) / 4.0 * carry_rate)} |")
        total_bytes = sum(_i(row.get("est_result_bytes")) for row in by_tool.values())
        lines.append(f"| **all {len(by_tool)} tools** | "
                     f"**{sum(_i(r.get('count')) for r in by_tool.values()):,}** | "
                     f"**{sum(_i(r.get('errors')) for r in by_tool.values()):,}** | "
                     f"**{_bytes(total_bytes)}** | | "
                     f"**{_usd(total_bytes / 4.0 * carry_rate)}** |")
        if all(row.get("avg_duration_ms") is None for row in by_tool.values()):
            lines.append("")
            lines.append("Per-tool wall time is not recorded: transcripts carry no "
                         "duration for a tool call. It is the one thing the optional "
                         "PostToolUse hook adds.")
        lines.append("")

    turns = sorted([row for row in (d.get("by_turn") or []) if _i(row.get("calls"))],
                   key=lambda r: -_f(r.get("cost")))[:6]
    if turns:
        lines.append("## Most expensive turns")
        lines.append("")
        for row in turns:
            lines.append(f"- **{_usd(row.get('cost'))}** turn #{_i(row.get('index'))} "
                         f"({_i(row.get('calls')):,} requests, "
                         f"{_tok(row.get('tokens'))} tokens, "
                         f"{row.get('turn') or 'turn-?'})")
        lines.append("")

    opportunities = optimization_opportunities(d)
    if opportunities:
        lines.append("## Optimisation opportunities (ranked by USD)")
        lines.append("")
        for row in opportunities:
            lines.append(f"{row['rank']}. **{_usd(row['est_usd'])} -- {row['title']}** "
                         f"[{row['confidence']}]")
            lines.append(f"   - basis: {row['basis']}")
            for line in (row.get("evidence") or [])[:2]:
                lines.append(f"   - {line}")
            lines.append(f"   - action: {row['action']}")
        lines.append("")
        lines.append(f"Total identified: {_usd(sum(_f(r['est_usd']) for r in opportunities))} "
                     f"against {_usd(computed)} computed spend. These overlap; they are "
                     "alternatives, not a sum to bank.")
        lines.append("")

    lines.append("## Cache")
    lines.append("")
    lines.append(f"- Hit ratio {_pct(_f(cache.get('hit_ratio')) * 100.0)} "
                 f"({_tok(cache.get('read_tokens'))} read / "
                 f"{_tok(cache.get('write_tokens'))} written)")
    lines.append(f"- Saved vs uncached: {_usd(cache.get('cost_saved_vs_uncached_usd'))}; "
                 f"paid on writes {_usd(cache.get('cost_paid_on_writes_usd'))}; "
                 f"net {_usd(cache.get('net_usd'))}")
    lines.append("")

    lines.append("## Reconciliation")
    lines.append("")
    status = recon.get("status")
    if status == "ok":
        lines.append(f"**Agrees.** Computed {_usd(recon.get('computed_usd_covered'))} vs "
                     f"Claude Code {_usd(recon.get('reported_usd'))} "
                     f"({_pct(_f(recon.get('delta_pct')), 2)}), inside the 2% tolerance.")
    elif status == "drift":
        lines.append(f"**Does not agree.** Computed "
                     f"{_usd(recon.get('computed_usd_covered'))} vs Claude Code "
                     f"{_usd(recon.get('reported_usd'))}: "
                     f"{_usd(_f(recon.get('delta_usd')))} "
                     f"({_pct(_f(recon.get('delta_pct')), 2)}).")
    else:
        lines.append("**No cost-state checkpoint in this transcript**; the computed total is "
                     "unverified.")
    for line in (recon.get("diagnosis") or []):
        lines.append(f"- {line}")
    lines.append("")

    gaps = _unpriced_models(d)
    if gaps:
        lines.append("## Pricing gap")
        lines.append("")
        lines.append(f"{_i((d.get('totals') or {}).get('unpriced_calls')):,} request(s) used a "
                     "model this build's pricing catalog has no entry for "
                     f"({', '.join(gaps)}), and were counted as $0.00. Every dollar figure "
                     "above is therefore a FLOOR. `oe reprice` refreshes the catalog.")
        lines.append("")

    parse = d.get("parse") or {}
    lines.append("---")
    lines.append("")
    lines.append(f"Generated {_stamp(d.get('generated_at'))} from "
                 f"{_i(parse.get('files_read'))} transcript files "
                 f"({_bytes(parse.get('bytes_read'))}) in "
                 f"{_f(parse.get('load_seconds')):.2f}s. Pricing catalog "
                 f"{pricing.PRICING_SOURCE_VERSION}.")
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# csv + writing
# ---------------------------------------------------------------------------


# Identifier columns carry pseudonyms (call/agent/workflow/turn), which is what
# makes a pivot over this file still able to group by turn or by agent. The
# columns that only ever held an id or a description -- request_id, uuid,
# agent_description, workflow_label -- are gone: they carried no analysis.
CALL_CSV_COLUMNS = (
    "ts", "call", "model", "tier", "speed", "effort", "service_tier",
    "origin", "agent", "agent_type", "spawn_depth",
    "workflow", "attribution_skill", "attribution_plugin",
    "attribution_mcp_server", "turn", "turn_index",
    "input_tokens", "output_tokens", "thinking_tokens",
    "cache_write_5m", "cache_write_1h", "cache_read", "context_tokens",
    "web_search_requests", "web_fetch_requests", "total_tokens",
    "input_usd", "output_usd", "cache_write_5m_usd", "cache_write_1h_usd",
    "cache_read_usd", "web_search_usd", "total_usd",
    "stop_reason", "is_error", "error_status", "aborted", "unpriced", "tools",
)


def _csv_row(call: Dict[str, Any]) -> List[Any]:
    cost = call.get("cost") or {}
    row: List[Any] = []
    for column in CALL_CSV_COLUMNS:
        if column == "tools":
            row.append(" ".join(call.get("tools") or []))
        elif column.endswith("_usd"):
            # Prefer the unrounded component from the cost dict: ApiCall.to_dict
            # rounds total_usd to 6dp for display, and a few thousand of those
            # roundings stop the CSV summing back to the report's total.
            value = cost.get(column)
            if column == "total_usd" and value is None:
                value = call.get("total_usd")
            row.append(round(_f(value), 10))
        elif column == "is_error" or column == "aborted" or column == "unpriced":
            row.append(1 if call.get(column) else 0)
        else:
            value = call.get(column)
            row.append("" if value is None else value)
    return row


def render_calls_csv(calls: Iterable[Dict[str, Any]],
                     red: Optional["redact.Redactor"] = None) -> str:
    """One row per API request, so the whole session can be pivoted elsewhere.

    Rows are redacted through `red` -- the SAME Redactor the payload used, when
    the caller passes it, so `call_0413` in this file is `call_0413` in
    data.json and the two can still be joined.
    """
    red = red or redact.Redactor()
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow(CALL_CSV_COLUMNS)
    for call in calls:
        writer.writerow(_csv_row(redact.redact_call(call, red)))
    return buffer.getvalue()


def write_report(ledger: Any, out_dir: Path) -> Dict[str, Path]:
    """Write report.html, data.json, summary.md, calls.csv and row.json.

    Accepts a SessionLedger or an already-serialised payload. Given a ledger, the
    CSV covers every request; given a payload it covers whatever the payload
    kept, because to_dict() caps its embedded call list.

    Nothing is written until every artifact has been rendered AND has passed
    redact.audit(). Refusing to write is the correct outcome of a failed audit:
    a missing report is a visible problem, a shipped leak is not. The caller
    logs the RedactionError.
    """
    out_dir = Path(out_dir)
    paths.ensure_dir(out_dir)

    if isinstance(ledger, dict):
        raw = ledger
        calls: Iterable[Dict[str, Any]] = raw.get("calls") or []
    else:
        raw = ledger.to_dict()
        calls = (call.to_dict() for call in getattr(ledger, "calls", []))

    # One Redactor for the whole document set, so every artifact agrees on what
    # turn_03 and path_07 mean.
    red = redact.Redactor()
    payload = redact.redact_payload(raw, red)

    # Render everything first. A half-written report directory -- clean HTML
    # next to a leaking CSV -- would be worse than no report at all.
    documents = [
        ("json", "data.json", json.dumps(payload, ensure_ascii=False, default=str)),
        ("html", "report.html", render_html(payload)),
        ("markdown", "summary.md", render_markdown(payload)),
        ("csv", "calls.csv", render_calls_csv(calls, red)),
        ("row", "row.json", json.dumps(scan_row(payload), default=str)),
    ]
    for _key, name, text in documents:
        redact.guard(text, str(out_dir / name))

    written: Dict[str, Path] = {"dir": out_dir}
    for key, name, text in documents:
        written[key] = paths.atomic_write(out_dir / name, text)
    return written


def scan_row(payload: Dict[str, Any]) -> Dict[str, Any]:
    """The handful of fields the dashboard/session list needs, as a tiny file.

    data.json is the full ledger and grows to several MB on a heavy session --
    past the size cap scan_sessions() applies before it will parse a cached
    report. Left to fall through, such a session is scanned from its tail, and a
    transcript written by an older Claude Code carries no cost-state line, so it
    would list at $0.00 while its own report said otherwise. This file is what
    the scan reads.
    """
    payload = redact.ensure_redacted(payload or {})
    session = payload.get("session") or {}
    totals = payload.get("totals") or {}
    window = payload.get("context_window") or {}
    return {
        "schema_version": payload.get("schema_version"),
        # Pseudonyms, not ids: row.json is an artifact. The scan puts the real
        # session id back from the transcript filename it already holds.
        "session": session.get("id"),
        "project": session.get("project"),
        "context_tokens": _i(window.get("used_tokens")),
        "max_tokens": _i(window.get("max_tokens")),
        "cost_usd": _f(totals.get("cost_usd_authoritative")),
        "total_tokens": _i(totals.get("total_tokens")),
        "model": session.get("primary_model"),
        "calls": _i(totals.get("calls")),
        "started_at": session.get("started_at"),
        # Label + source only. row.json is read straight back into a scan row,
        # so carrying them here keeps a cached listing labelled without a
        # re-resolve -- and carrying anything MORE would put identity on disk
        # inside the reports tree.
        "account_label": session.get("account_label"),
        "account_source": session.get("account_source"),
    }
