"""The cross-session dashboard: <reports_root>/index.html.

One self-contained page, no external CSS/JS/fonts, so it works over file://.
It refreshes itself with <meta http-equiv="refresh">: the watcher rewrites the
file in the background, and a meta refresh is the only zero-JavaScript way to
show the new numbers. That is also why every "live" figure on the page is
rendered as an absolute value plus an age, never as a ticking clock.

Live sessions come first, because the question this page exists to answer is
"how full is the context window of the session I am in right now".
"""

from __future__ import annotations

import html
import json
import os
import time
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

try:
    from . import accounts, ledger, paths, pricing, redact
except ImportError:  # executed as a plain script
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from oe import accounts, ledger, paths, pricing, redact  # type: ignore

# "Live" is a statement about the transcript, not about our own bookkeeping: a
# session whose file was written in the last two minutes is one you are sitting
# in. A stale watcher or a missing live.json must not make it look dead.
LIVE_WINDOW_SECONDS = 120
REFRESH_SECONDS = 10
DAY_CHART_DAYS = 30


# ---------------------------------------------------------------------------
# formatting
# ---------------------------------------------------------------------------


def _esc(value: Any) -> str:
    return html.escape(str(value if value is not None else ""), quote=True)


def _tokens(value: Any) -> str:
    try:
        number = float(value or 0)
    except (TypeError, ValueError):
        return "0"
    if number >= 1_000_000_000:
        return f"{number / 1_000_000_000:.2f}B"
    if number >= 1_000_000:
        return f"{number / 1_000_000:.2f}M"
    if number >= 1_000:
        return f"{number / 1_000:.1f}k"
    return f"{int(number)}"


_SOURCE_NOTE = {
    "reported": "billed -- Claude Code's own cost-state total for this session",
    "mixed": ("billed for the runs Claude Code checkpointed, plus our measured price "
              "for the requests no checkpoint covers"),
    "computed": ("measured by us from the transcript. A FLOOR: sidechain files never write "
                 "back their final output tokens, so this reads 8-25% under the real bill"),
}


def _row_usd(row: Dict[str, Any]) -> str:
    """A row's cost, or a dash when the scan never measured it.

    A tail-scanned transcript with no cost-state line yields cost_usd 0.0 with
    nothing behind it; rendering that as $0.00 is a claim the data does not
    support and it drags the all-time rollup down with it.

    The leading tilde is not decoration. A billed figure and a measured floor
    differ by 8-25% on any subagent-heavy session, so both surfaces mark the
    floor: the CLI and this page must not make different claims about the same
    number.
    """
    if not row.get("cost_known", True):
        return "-"
    text = _usd(row.get("cost_usd"))
    return ("~" + text) if row.get("cost_is_estimate") else text


def _usd_cell(row: Dict[str, Any]) -> str:
    """_row_usd wrapped in the tooltip that says where the number came from."""
    text = _esc(_row_usd(row))
    note = _SOURCE_NOTE.get(str(row.get("cost_source") or ""))
    if row.get("cost_pending"):
        note = "not costed on the last pass; the next one picks it up"
    if not note:
        return text
    return f'<span title="{_esc(note)}">{text}</span>'


def _any_estimate(rows: List[Dict[str, Any]]) -> bool:
    return any(r.get("cost_is_estimate") for r in rows)


def _agg_usd(value: Any, rows: List[Dict[str, Any]]) -> str:
    """An aggregate carries the tilde as soon as ONE estimated row feeds it."""
    text = _usd(value)
    return ("~" + text) if _any_estimate(rows) else text


def _usd(value: Any, precise: bool = False) -> str:
    try:
        number = float(value or 0)
    except (TypeError, ValueError):
        number = 0.0
    if precise or 0 < abs(number) < 0.01:
        return f"${number:.4f}"
    if abs(number) >= 1000:
        return f"${number:,.0f}"
    return f"${number:,.2f}"


def _ago(epoch: Optional[float], now: Optional[float] = None) -> str:
    if not epoch:
        return "-"
    delta = max(0.0, (now if now is not None else time.time()) - float(epoch))
    if delta < 60:
        return f"{int(delta)}s ago"
    if delta < 3600:
        return f"{int(delta // 60)}m ago"
    if delta < 86400:
        return f"{int(delta // 3600)}h ago"
    if delta < 86400 * 14:
        return f"{int(delta // 86400)}d ago"
    return f"{int(delta // 86400)}d ago"


def _when(iso: Optional[str]) -> str:
    if not iso:
        return "-"
    try:
        text = str(iso)
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        stamp = datetime.fromisoformat(text).astimezone()
        return stamp.strftime("%b %d %H:%M")
    except Exception:
        return str(iso)[:16].replace("T", " ")


def _fill_class(pct: float) -> str:
    """Green under 60%, amber to 85%, red above: the point at which a session
    starts losing head-room for a big tool result."""
    if pct >= 85:
        return "hot"
    if pct >= 60:
        return "warm"
    return "ok"


def _short(value: Any, limit: int = 64) -> str:
    text = str(value or "")
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _label(row: Dict[str, Any]) -> str:
    """A row's name on the page: its pseudonym.

    index.html is an artifact, and a session title is prompt text -- it can
    carry a ticket id, a customer name or a path. `oe whois session_07` puts the
    name back on the machine that made the page.
    """
    return _short(row.get("session") or "session", 78)


def _report_href(root: Path, pseudonym: Any) -> Optional[str]:
    """A relative link to a session report, addressed by pseudonym.

    The href is content of a shareable file, so it may not carry a session
    uuid; the directory on disk is named for the pseudonym for exactly this
    reason (see paths.report_dir_name).
    """
    name = str(pseudonym or "")
    if not name:
        return None
    candidate = root / "sessions" / name / "report.html"
    if candidate.is_file():
        return f"sessions/{name}/report.html"
    return None


# ---------------------------------------------------------------------------
# charts (inline SVG, computed here -- no chart library, no CDN)
# ---------------------------------------------------------------------------


def _day_series(by_day: Dict[str, float], days: int = DAY_CHART_DAYS) -> List[Tuple[str, float]]:
    """A continuous run of the last N calendar days, zero-filled.

    Gaps matter: a bar chart that silently skips the days you did not work
    reads as steady spend when it was actually bursty.
    """
    today = date.today()
    series: List[Tuple[str, float]] = []
    for offset in range(days - 1, -1, -1):
        day = today - timedelta(days=offset)
        key = day.isoformat()
        series.append((key, float(by_day.get(key, 0.0) or 0.0)))
    return series


def _svg_day_chart(by_day: Dict[str, float]) -> str:
    series = _day_series(by_day)
    if not series:
        return '<p class="muted">No spend recorded yet.</p>'
    width, height = 1100.0, 190.0
    pad_left, pad_right, pad_top, pad_bottom = 58.0, 12.0, 16.0, 26.0
    plot_w = width - pad_left - pad_right
    plot_h = height - pad_top - pad_bottom
    peak = max((value for _, value in series), default=0.0)
    scale = plot_h / peak if peak > 0 else 0.0
    slot = plot_w / len(series)
    bar_w = max(3.0, slot * 0.68)

    parts: List[str] = [
        f'<svg class="chart" viewBox="0 0 {width:.0f} {height:.0f}" width="100%" '
        f'height="190" role="img" aria-label="Spend per day for the last '
        f'{len(series)} days">'
    ]
    baseline = pad_top + plot_h
    parts.append(f'<line class="axis" x1="{pad_left}" y1="{baseline}" '
                 f'x2="{width - pad_right}" y2="{baseline}"/>')
    for fraction in (0.5, 1.0):
        y = baseline - plot_h * fraction
        parts.append(f'<line class="grid" x1="{pad_left}" y1="{y:.1f}" '
                     f'x2="{width - pad_right}" y2="{y:.1f}"/>')
        parts.append(f'<text class="tick" x="{pad_left - 8}" y="{y + 4:.1f}" '
                     f'text-anchor="end">{_esc(_usd(peak * fraction))}</text>')

    today_key = date.today().isoformat()
    for index, (day, value) in enumerate(series):
        bar_h = value * scale
        x = pad_left + index * slot + (slot - bar_w) / 2.0
        y = baseline - bar_h
        classes = "daybar" + (" today" if day == today_key else "")
        title = f"{day}: {_usd(value)}"
        parts.append(f'<rect class="{classes}" x="{x:.1f}" y="{y:.1f}" '
                     f'width="{bar_w:.1f}" height="{max(bar_h, 0.0):.1f}" rx="2">'
                     f'<title>{_esc(title)}</title></rect>')
    for index in (0, len(series) // 2, len(series) - 1):
        day = series[index][0]
        x = pad_left + index * slot + slot / 2.0
        anchor = "start" if index == 0 else ("end" if index == len(series) - 1 else "middle")
        parts.append(f'<text class="tick" x="{x:.1f}" y="{height - 8:.0f}" '
                     f'text-anchor="{anchor}">{_esc(day[5:])}</text>')
    parts.append("</svg>")
    return "".join(parts)


def _rank_bars(mapping: Dict[str, float], limit: int = 8,
               transform=None) -> str:
    rows = sorted(mapping.items(), key=lambda kv: -kv[1])[:limit]
    if not rows:
        return '<p class="muted">Nothing recorded yet.</p>'
    peak = max(value for _, value in rows) or 1.0
    parts = ['<ul class="ranks">']
    for name, value in rows:
        label = transform(name) if transform else name
        pct = 100.0 * value / peak
        parts.append(
            f'<li><span class="rank-label" title="{_esc(name)}">{_esc(_short(label, 34))}</span>'
            f'<span class="rank-track"><span class="rank-fill" style="width:{pct:.1f}%"></span></span>'
            f'<span class="rank-value">{_esc(_usd(value))}</span></li>')
    parts.append("</ul>")
    return "".join(parts)


# ---------------------------------------------------------------------------
# page
# ---------------------------------------------------------------------------


_CSS = """
:root{color-scheme:light dark;--bg:#f6f6f4;--panel:#ffffff;--panel2:#fbfbfa;
--fg:#1b1b19;--muted:#70706a;--border:#e4e4df;--accent:#4c6ef5;--accent2:#9775fa;
--ok:#2f9e44;--warn:#e8930c;--hot:#e03131;--shadow:0 1px 2px rgba(0,0,0,.06);}
@media (prefers-color-scheme:dark){:root{--bg:#111211;--panel:#1a1c1a;--panel2:#202320;
--fg:#e9eae7;--muted:#93968f;--border:#2c2f2c;--accent:#748ffc;--accent2:#b197fc;
--ok:#51cf66;--warn:#ffc94d;--hot:#ff6b6b;--shadow:none;}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);
font:14px/1.5 ui-sans-serif,-apple-system,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;}
.wrap{max-width:1180px;margin:0 auto;padding:28px 20px 64px}
h1{font-size:20px;margin:0;letter-spacing:-.01em}
h2{font-size:13px;text-transform:uppercase;letter-spacing:.09em;color:var(--muted);
margin:34px 0 12px;font-weight:600}
a{color:var(--accent);text-decoration:none}
a:hover{text-decoration:underline}
.muted{color:var(--muted)}
.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:12px}
header{display:flex;flex-wrap:wrap;gap:12px;align-items:baseline;justify-content:space-between}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px;margin-top:18px}
.stat{background:var(--panel);border:1px solid var(--border);border-radius:10px;
padding:12px 14px;box-shadow:var(--shadow)}
.stat .k{font-size:11px;text-transform:uppercase;letter-spacing:.07em;color:var(--muted)}
.stat .v{font-size:22px;font-weight:650;letter-spacing:-.02em;margin-top:2px}
.stat .s{font-size:12px;color:var(--muted)}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(340px,1fr));gap:12px}
.card{background:var(--panel);border:1px solid var(--border);border-radius:12px;
padding:14px 16px;box-shadow:var(--shadow)}
.card.live{border-color:color-mix(in srgb,var(--accent) 45%,var(--border))}
.card-top{display:flex;gap:8px;align-items:center;justify-content:space-between}
.card-title{font-weight:620;letter-spacing:-.01em;overflow:hidden;text-overflow:ellipsis;
white-space:nowrap}
.badge{font-size:11px;padding:2px 7px;border-radius:999px;border:1px solid var(--border);
color:var(--muted);white-space:nowrap}
.dot{display:inline-block;width:7px;height:7px;border-radius:50%;background:var(--ok);
margin-right:5px;vertical-align:middle;animation:pulse 1.8s ease-in-out infinite}
@keyframes pulse{0%,100%{opacity:1;transform:scale(1)}50%{opacity:.35;transform:scale(.8)}}
.track{position:relative;height:12px;border-radius:999px;background:var(--panel2);
border:1px solid var(--border);overflow:hidden;margin:12px 0 7px}
.fill{position:relative;height:100%;border-radius:999px;min-width:2px;
transition:width .6s ease}
.fill.ok{background:linear-gradient(90deg,var(--ok),color-mix(in srgb,var(--ok) 60%,var(--accent)))}
.fill.warm{background:linear-gradient(90deg,var(--warn),color-mix(in srgb,var(--warn) 70%,var(--hot)))}
.fill.hot{background:linear-gradient(90deg,var(--hot),color-mix(in srgb,var(--hot) 65%,#000))}
.fill.flow::after{content:"";position:absolute;inset:0;
background-image:repeating-linear-gradient(115deg,rgba(255,255,255,.30) 0 8px,
rgba(255,255,255,0) 8px 18px);background-size:36px 100%;animation:flow 1.1s linear infinite}
@keyframes flow{from{background-position:0 0}to{background-position:36px 0}}
@media (prefers-reduced-motion:reduce){.fill.flow::after{animation:none}.dot{animation:none}}
.row{display:flex;justify-content:space-between;gap:10px;font-size:12.5px;color:var(--muted)}
.row b{color:var(--fg);font-weight:600}
.panel{background:var(--panel);border:1px solid var(--border);border-radius:12px;
padding:14px 16px;box-shadow:var(--shadow)}
.grid2{display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:12px}\n.acct-personal{border-color:#3f6212;color:#a3e635}\n.acct-work{border-color:#1e40af;color:#93c5fd}\n.acct-unknown{opacity:.65}\n/* A guessed provenance must not look like a recorded one. */\n.acct-guess{border-style:dashed;border-color:#a16207;color:#fbbf24}\n.guessmark{margin-left:3px;font-weight:700}
.chart .daybar{fill:var(--accent);opacity:.85}
.chart .daybar.today{fill:var(--accent2);opacity:1}
.chart .axis{stroke:var(--border);stroke-width:1}
.chart .grid{stroke:var(--border);stroke-width:1;stroke-dasharray:2 4}
.chart .tick{fill:var(--muted);font-size:11px;
font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
.ranks{list-style:none;margin:0;padding:0;display:grid;gap:7px}
.ranks li{display:grid;grid-template-columns:150px 1fr 74px;gap:10px;align-items:center;
font-size:12.5px}
.rank-label{overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:var(--muted)}
.rank-track{height:9px;border-radius:999px;background:var(--panel2);
border:1px solid var(--border);overflow:hidden}
.rank-fill{display:block;height:100%;background:linear-gradient(90deg,var(--accent),var(--accent2))}
.rank-value{text-align:right;font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
.tablewrap{overflow-x:auto;border:1px solid var(--border);border-radius:12px;background:var(--panel)}
table{border-collapse:collapse;width:100%;font-size:12.5px}
th{position:sticky;top:0;background:var(--panel);text-align:left;font-size:11px;
text-transform:uppercase;letter-spacing:.06em;color:var(--muted);font-weight:600;
padding:10px 12px;border-bottom:1px solid var(--border);white-space:nowrap}
td{padding:9px 12px;border-bottom:1px solid var(--border);vertical-align:middle;white-space:nowrap}
tr:last-child td{border-bottom:none}
tr:hover td{background:var(--panel2)}
td.num{text-align:right;font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
td.name{max-width:330px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.minitrack{width:104px;height:8px;border-radius:999px;background:var(--panel2);
border:1px solid var(--border);overflow:hidden;display:inline-block;vertical-align:middle}
.minitrack span{display:block;height:100%}
footer{margin-top:34px;color:var(--muted);font-size:12px}
"""


def _live_card(row: Dict[str, Any], root: Path, now: float) -> str:
    pct = float(row.get("context_pct") or 0.0)
    used = int(row.get("context_tokens") or 0)
    window = int(row.get("max_tokens") or pricing.DEFAULT_CONTEXT_WINDOW)
    href = _report_href(root, row.get("session"))
    title = _esc(_label(row))
    title_html = f'<a href="{href}">{title}</a>' if href else title
    model = pricing.display_name(row.get("model")) if row.get("model") else "-"
    calls = row.get("calls") or 0
    calls_text = f"{calls}+" if row.get("calls_partial") else f"{calls}"
    return (
        f'<div class="card live">'
        f'<div class="card-top"><span class="card-title">'
        f'<span class="dot" title="active"></span>{title_html}</span>'
        f'<span class="badge">{_esc(model)}</span></div>'
        f'<div class="row mono" style="margin-top:4px">'
        f'<span>{_esc(row.get("project") or "-")}</span>'
        f'<span>{_esc(_ago(row.get("mtime"), now))}</span></div>'
        f'<div class="track"><div class="fill flow {_fill_class(pct)}" '
        f'style="width:{min(100.0, max(1.0, pct)):.2f}%"></div></div>'
        f'<div class="row"><span><b>{_esc(_tokens(used))}</b> / {_esc(_tokens(window))} context'
        f'</span><span><b>{pct:.1f}%</b></span></div>'
        f'<div class="row" style="margin-top:5px"><span><b>{_usd_cell(row)}</b>'
        f' spent</span><span>{_esc(calls_text)} calls</span></div>'
        f'</div>'
    )


def _account_cell(row: Dict[str, Any], *, with_source: bool = True) -> str:
    """The label, with the provenance in the tooltip. Never the address.

    A label whose provenance is a GUESS carries a visible '?' and a dashed
    border, not just a different tooltip: the badge colour keys off the label, so
    an inferred 'work' and a recorded 'work' would otherwise be the same blue
    pill with nothing on the page saying which one you are reading. The tooltip
    text comes from accounts.SOURCE_NOTE, a fixed sentence per enum value --
    account_evidence is deliberately not in the artifact allowlist because it
    is generated prose that can name an organisation.

    `with_source=False` is for the per-label rollup rows, which summarise many
    provenances and therefore have none of their own to state.
    """
    label = str(row.get("account_label") or "unknown")
    if not with_source:
        return f'<span class="badge acct-{_esc(label)}">{_esc(label)}</span>'
    source = str(row.get("account_source") or "unknown")
    guess = accounts.is_guess(source)
    note = accounts.SOURCE_NOTE.get(source, "")
    hint = f"{label} -- source: {source}" + (f"; {note}" if note else "")
    cls = f"badge acct-{label}" + (" acct-guess" if guess else "")
    mark = '<span class="guessmark">?</span>' if guess else ""
    return (f'<span class="{_esc(cls)}" title="{_esc(hint)}">'
            f'{_esc(label)}{mark}</span>')


def _accounts_panel(rows: List[Dict[str, Any]]) -> str:
    """Spend, tokens, calls and sessions per account, plus how each was known.

    The provenance line is not decoration: 'personal' read out of a transcript
    and 'personal' inherited from a heuristic are different claims, and a rollup
    that hides which one it summed cannot be checked.
    """
    table = accounts.rollup(rows)
    order = [label for label in accounts.known_labels() if table.get(label, {}).get("sessions")]
    if not order:
        return '<div class="panel muted">No sessions to attribute.</div>'
    body = ['<div class="tablewrap"><table><thead><tr><th>Account</th>'
            "<th>Sessions</th><th>Calls</th><th>Tokens</th><th>Spend</th>"
            "<th>Known from</th></tr></thead><tbody>"]
    for label in order:
        bucket = table[label]
        sources = ", ".join(f"{name} {count}" for name, count
                            in sorted(bucket.get("sources", {}).items(),
                                      key=lambda kv: accounts.SOURCE_RANK.get(kv[0], 99)))
        spend = _usd(bucket.get("cost_usd"))
        if bucket.get("estimate"):
            spend = "~" + spend
        unpriced = bucket.get("unpriced") or 0
        note = f' <span class="muted">({unpriced} unpriced)</span>' if unpriced else ""
        body.append(
            f'<tr><td>{_account_cell({"account_label": label}, with_source=False)}</td>'
            f'<td class="num">{bucket.get("sessions", 0)}</td>'
            f'<td class="num">{bucket.get("calls", 0):,}</td>'
            f'<td class="num">{_esc(_tokens(bucket.get("total_tokens")))}</td>'
            f'<td class="num">{_esc(spend)}{note}</td>'
            f'<td class="mono muted">{_esc(sources)}</td></tr>')
    body.append("</tbody></table></div>")
    return "".join(body)


def _history_row(row: Dict[str, Any], root: Path, now: float) -> str:
    pct = float(row.get("context_pct") or 0.0)
    href = _report_href(root, row.get("session"))
    label = _esc(_label(row))
    name = f'<a href="{href}">{label}</a>' if href else f'{label} <span class="muted">(no report)</span>'
    live = '<span class="dot"></span>' if row.get("is_active") else ""
    tokens = row.get("total_tokens")
    calls = row.get("calls") or 0
    calls_text = f"{calls}+" if row.get("calls_partial") else f"{calls}"
    return (
        "<tr>"
        f'<td class="name">{live}{name}</td>'
        f'<td class="mono">{_esc(_short(row.get("project") or "-", 30))}</td>'
        f'<td>{_account_cell(row)}</td>'
        f'<td>{_esc(pricing.display_name(row.get("model")) if row.get("model") else "-")}</td>'
        f'<td class="mono">{_esc(_when(row.get("started_at")))}</td>'
        f'<td class="mono">{_esc(_ago(row.get("mtime"), now))}</td>'
        f'<td class="num">{_esc(calls_text)}</td>'
        f'<td class="num">{_esc(_tokens(tokens) if tokens else "-")}</td>'
        f'<td class="num">{_usd_cell(row)}</td>'
        f'<td><span class="minitrack"><span class="fill {_fill_class(pct)}" '
        f'style="width:{min(100.0, pct):.1f}%"></span></span> '
        f'<span class="mono muted">{pct:.0f}%</span></td>'
        "</tr>"
    )


def render(rows: List[Dict[str, Any]]) -> str:
    """The whole page as one string. Pure: give it rows, get HTML.

    Rows are redacted on the way in, so nothing below can render a title, a
    project path or a session id even by accident.
    """
    now = time.time()
    root = paths.reports_root()
    rows = redact.redact_scan_rows(rows or [])
    live = [r for r in rows if r.get("is_active")]
    live.sort(key=lambda r: -float(r.get("context_pct") or 0.0))
    history = sorted(rows, key=lambda r: -float(r.get("mtime") or 0.0))

    # Rows whose cost was never measured (tail-scanned, no cost-state on disk)
    # would otherwise contribute a hard 0.0 to every rollup below and make the
    # all-time figure quietly wrong. Count them, and say so under the headline.
    uncosted = [r for r in rows if not r.get("cost_known", True)]
    costed = [r for r in rows if r.get("cost_known", True)]
    # `rows` are already redacted, so daily_rollup keys by_project with the
    # pseudonyms it finds on them. Running redact_rollup here as well would
    # pseudonymise a pseudonym and mint a second name for the same project.
    rollup = ledger.daily_rollup(costed)
    by_day = rollup.get("by_day") or {}
    today_key = date.today().isoformat()
    spend_today = float(by_day.get(today_key, 0.0) or 0.0)
    week_cutoff = (date.today() - timedelta(days=6)).isoformat()
    spend_week = sum(value for day, value in by_day.items() if day >= week_cutoff)
    # Which rows actually put dollars into each headline -- an aggregate is only
    # an estimate if an estimated row contributed to THAT window.
    today_rows = [r for r in costed
                  if float((r.get("cost_by_day") or {}).get(today_key) or 0.0) > 0
                  or (not r.get("cost_by_day") and r.get("local_day") == today_key)]
    week_rows = [r for r in costed
                 if any(day >= week_cutoff and float(value or 0.0) > 0
                        for day, value in (r.get("cost_by_day") or {}).items())
                 or (not r.get("cost_by_day") and str(r.get("local_day") or "") >= week_cutoff)]
    total_calls = sum(int(r.get("calls") or 0) for r in rows)

    parts: List[str] = []
    # A real document, not a fragment. Without a doctype the browser renders this
    # in quirks mode, where a <table> does not inherit the font declared on body --
    # the sessions table, the main thing on the page, would come out in the default
    # serif. report.py already opens its output this way; this matches it.
    parts.append("<!doctype html>")
    parts.append('<html lang="en"><head><meta charset="utf-8">')
    parts.append('<meta name="viewport" content="width=device-width,initial-scale=1">')
    parts.append("<!-- generated by Overwatch Enforcer; do not edit, it is rewritten every few seconds -->")
    parts.append(f'<meta http-equiv="refresh" content="{REFRESH_SECONDS}">')
    parts.append("<title>Claude Code usage</title>")
    parts.append(f"<style>{_CSS}</style>")
    parts.append("</head><body>")
    parts.append('<div class="wrap">')
    parts.append(
        '<header><h1>Claude Code usage</h1>'
        f'<span class="muted mono">{len(live)} live &middot; {len(rows)} sessions &middot; '
        f'refreshed {_esc(datetime.now().strftime("%H:%M:%S"))} '
        f'(auto every {REFRESH_SECONDS}s)</span></header>')

    parts.append('<div class="stats">')
    for key, value, sub in (
        ("All-time spend", _agg_usd(rollup.get("total_usd"), costed),
         (f"{len(rows) - len(uncosted)} of {len(rows)} sessions costed"
          if uncosted else f"{len(rows)} sessions")),
        ("Today", _agg_usd(spend_today, today_rows), today_key),
        ("Last 7 days", _agg_usd(spend_week, week_rows), "rolling"),
        ("Live now", str(len(live)), f"active within {LIVE_WINDOW_SECONDS}s"),
        ("API calls", f"{total_calls:,}", "recorded across all sessions"),
    ):
        parts.append(f'<div class="stat"><div class="k">{_esc(key)}</div>'
                     f'<div class="v">{_esc(value)}</div><div class="s">{_esc(sub)}</div></div>')
    parts.append("</div>")

    parts.append("<h2>Live sessions</h2>")
    if live:
        parts.append('<div class="cards">')
        parts.extend(_live_card(row, root, now) for row in live)
        parts.append("</div>")
    else:
        parts.append('<div class="panel muted">No session has written to its transcript in the '
                     f'last {LIVE_WINDOW_SECONDS} seconds.</div>')

    parts.append("<h2>Spend per day</h2>")
    parts.append(f'<div class="panel">{_svg_day_chart(by_day)}</div>')

    parts.append("<h2>Where it goes</h2>")
    parts.append('<div class="grid2">')
    parts.append('<div class="panel"><div class="k muted mono" '
                 'style="margin-bottom:10px">BY PROJECT</div>'
                 + _rank_bars(rollup.get("by_project") or {}, 8)
                 + "</div>")
    parts.append('<div class="panel"><div class="k muted mono" '
                 'style="margin-bottom:10px">BY MODEL</div>'
                 + _rank_bars(rollup.get("by_model") or {}, 8,
                              transform=pricing.display_name)
                 + "</div>")
    parts.append("</div>")

    parts.append("<h2>By account</h2>")
    parts.append(_accounts_panel(rows))

    parts.append(f"<h2>History &middot; {len(history)} sessions</h2>")
    parts.append('<div class="tablewrap"><table><thead><tr>'
                 "<th>Session</th><th>Project</th><th>Account</th><th>Model</th><th>Started</th>"
                 "<th>Last active</th><th>Calls</th><th>Tokens</th><th>Cost</th>"
                 "<th>Context</th></tr></thead><tbody>")
    if history:
        parts.extend(_history_row(row, root, now) for row in history)
    else:
        parts.append('<tr><td colspan="10" class="muted">No transcripts found.</td></tr>')
    parts.append("</tbody></table></div>")

    parts.append(
        '<footer><b>$12.34</b> is Claude Code\'s own billed figure (a cost-state checkpoint '
        'covers every request in the file). <b>~$12.34</b> is ours, '
        'measured from the '
        'transcript, and it is a FLOOR: sidechain transcripts never write '
        'back their final output tokens, so a subagent-heavy session reads '
        '8-25% under the real bill. Hover any '
        'cost to see which it is. Context is the last main-loop '
        'request\'s input + cache_creation + cache_read, the same arithmetic the in-app meter '
        'uses.</footer>')
    parts.append("</div>")
    parts.append("</body></html>")
    return "\n".join(parts)


def write_dashboard(reports_root: Optional[str | os.PathLike] = None) -> Path:
    """Rebuild index.html + sessions.json. Returns the path to index.html."""
    previous = os.environ.get(paths.ENV_REPORTS_ROOT)
    if reports_root:
        paths.set_reports_root(reports_root)
    try:
        root = paths.ensure_dir(paths.reports_root())
        config = paths.load_config()
        window = int(((config.get("dashboard") or {}).get("live_window_seconds")
                      or LIVE_WINDOW_SECONDS))
        rows = ledger.scan_sessions(active_within_seconds=window)
        # Both files are shareable, so both are built from the redacted rows and
        # neither is written until it has passed its own audit. A refusal here
        # leaves the previous (also clean) dashboard in place, which is the
        # right failure: stale beats leaking.
        page = render(rows)
        listing = json.dumps({
            "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "live_window_seconds": window,
            "redaction": {"version": redact.REDACTION_VERSION, "policy": "allowlist",
                          "note": redact.REDACTION_NOTE},
            "rollup": redact.redact_rollup(ledger.daily_rollup(rows)),
            "sessions": redact.redact_scan_rows(rows),
        }, indent=2, default=str)
        redact.guard(page, str(root / "index.html"))
        redact.guard(listing, str(root / "sessions.json"))
        index = paths.atomic_write(root / "index.html", page)
        paths.atomic_write(root / "sessions.json", listing)
        return index
    finally:
        if reports_root:
            if previous is None:
                os.environ.pop(paths.ENV_REPORTS_ROOT, None)
            else:
                os.environ[paths.ENV_REPORTS_ROOT] = previous


def main(argv: Optional[List[str]] = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(prog="oe.dashboard")
    parser.add_argument("--reports-root", default=None)
    args = parser.parse_args(argv)
    print(write_dashboard(args.reports_root))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
