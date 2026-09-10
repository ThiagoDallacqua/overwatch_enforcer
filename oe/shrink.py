"""What a read cost, against what this machine's own index could have printed.

`oe rereads` answers "which files came back more than once". This answers a
different question: for every file read, was there a smaller thing on disk that
would have carried the same answer, and what is the gap worth?

WHAT THIS DELIBERATELY DOES NOT DO
----------------------------------
It never reports a saving. Which symbol a reader wanted is not recorded in any
artefact on this machine, so "the outline would have answered" is not knowable
after the fact. What IS knowable is the interval: the low end is zero, because
no outline can be assumed sufficient, and the high end is what those reads cost
minus what the outlines cost. A band is honest; a single number would not be.

Nor does it net the spanned rung into that band. When a read already names a
line range, the index's covering chunks are COARSER than the range asked for --
measurably dearer, not cheaper -- so that rung is reported as a loss on its own
line. Hiding it inside a net figure would flatter the tool.

Every alternative price here is produced by rendering the command the user would
have run and counting the tokens it prints. There is no ratio and no constant.
"""

from __future__ import annotations

import os
from typing import Any, Dict, List, Optional, Sequence, Tuple

# The rungs, in the order they are printed. First match wins, so the order is
# also the classification order.
RUNGS: Tuple[str, ...] = (
    "whole_file", "spanned", "span_unknown", "no_outline", "never_indexed",
)

RUNG_LABEL: Dict[str, str] = {
    "whole_file": "whole file, has outline",
    "spanned": "spanned, has outline",
    "span_unknown": "span unknown",
    "no_outline": "indexed, no outline",
    "never_indexed": "never indexed",
}

# Why a file the index knows about still cannot be priced. Each is counted and
# shown: an exclusion nobody can see is indistinguishable from a bug.
EXCLUSIONS: Tuple[str, ...] = ("stale", "missing")


def _retrieval():
    from oe import retrieval
    return retrieval


def _store():
    from oe import store
    return store


def _num(value: Any) -> float:
    try:
        return float(value or 0.0)
    except (TypeError, ValueError):
        return 0.0


class Index:
    """Everything the index can say about a path, looked up once per path.

    Rendering an outline costs a couple of milliseconds; a corpus asks for the
    same handful of paths hundreds of times, so both the file row and the
    rendered outline are memoised for the life of the call.
    """

    def __init__(self, conn=None) -> None:
        self._conn = conn
        self._files: Dict[str, Optional[Dict[str, Any]]] = {}
        self._outline: Dict[str, Optional[int]] = {}

    @property
    def conn(self):
        if self._conn is None:
            self._conn = _store().open_db()
        return self._conn

    def file_row(self, path: str) -> Optional[Dict[str, Any]]:
        key = _store().norm_path(path)
        if key in self._files:
            return self._files[key]
        row = None
        try:
            got = self.conn.execute(
                "SELECT file_id,path,lang,size,mtime_ns,lines,tokens,indexed_ts "
                "FROM files WHERE path=?", (key,)).fetchone()
            if got is not None:
                row = dict(got)
                # A row with no indexed_ts was minted by _file_id(create=True)
                # as an edge target and never scanned. It looks indexed and is
                # not: `oe slice` renders a well-formed EMPTY outline for it.
                if not row.get("indexed_ts"):
                    row = None
                else:
                    row["symbols"] = int(self.conn.execute(
                        "SELECT COUNT(*) FROM symbols WHERE file_id=?",
                        (row["file_id"],)).fetchone()[0] or 0)
        except Exception:
            row = None
        self._files[key] = row
        return row

    def outline_tokens(self, path: str) -> Optional[int]:
        """Tokens `oe slice <path>` prints with no target: MEASURED, by rendering it."""
        key = _store().norm_path(path)
        if key in self._outline:
            return self._outline[key]
        value: Optional[int] = None
        try:
            ret = _retrieval()
            res = ret.slice_(path)
            if res.get("mode") == "outline":
                value = int(ret.est_tokens(str(ret.render_slice(res))))
        except Exception:
            value = None
        self._outline[key] = value
        return value

    def chunk_cover(self, file_id: int, lo: int, hi: int) -> int:
        """Tokens of the chunks overlapping [lo,hi]. Chunks are disjoint, so
        summing them double-counts nothing."""
        try:
            got = self.conn.execute(
                "SELECT SUM(tokens) FROM chunk_meta WHERE file_id=? AND hi>=? AND lo<=?",
                (int(file_id), int(lo), int(hi))).fetchone()
            return int(got[0] or 0)
        except Exception:
            return 0

    def excluded(self, row: Dict[str, Any]) -> Optional[str]:
        """Why this file cannot be re-priced against today's index, if it cannot.

        The index is present tense. Nothing records what a file's outline looked
        like at the moment it was read, so a file that has since changed or gone
        is not evidence about that read either way.
        """
        path = row.get("path") or ""
        try:
            stat = os.stat(path)
        except OSError:
            return "missing"
        if row.get("size") is not None and int(row["size"]) != int(stat.st_size):
            return "stale"
        if row.get("mtime_ns") is not None and int(row["mtime_ns"]) != int(stat.st_mtime_ns):
            return "stale"
        return None


def rung_of(event: Dict[str, Any], row: Optional[Dict[str, Any]]) -> str:
    """Which rung this read sits on. First match wins."""
    if row is None:
        return "never_indexed"
    if not int(row.get("symbols") or 0):
        return "no_outline"
    if event.get("span_source") == "exact":
        return "whole_file" if event.get("whole_file") else "spanned"
    if event.get("span_lo") is not None:
        return "spanned"
    # No result block and no offset: genuinely unknown. It is counted and priced
    # so the totals stay whole, and it never enters the band.
    return "span_unknown"


def analyse(events: Sequence[Dict[str, Any]], *, measured: bool = False,
            index: Optional[Index] = None, limit: int = 12) -> Dict[str, Any]:
    """Group every read onto a rung and price the alternative for each."""
    idx = index or Index()
    money_key = "carry_usd" if measured else "calibrated_usd"
    rungs: Dict[str, Dict[str, Any]] = {
        name: {"rung": name, "calls": 0, "tokens": 0.0, "usd": 0.0,
               "alt_tokens": 0.0, "band_hi_usd": 0.0, "dearer_usd": 0.0}
        for name in RUNGS
    }
    excluded: Dict[str, Dict[str, Any]] = {
        name: {"reason": name, "calls": 0, "usd": 0.0} for name in EXCLUSIONS
    }
    per_file: Dict[str, Dict[str, Any]] = {}
    span_source: Dict[str, int] = {"exact": 0, "input": 0, "unknown": 0}
    outline_beat = outline_lost = 0
    ratios: List[float] = []
    total_calls = 0
    total_tokens = 0.0
    total_usd = 0.0
    sidechain_calls = 0
    unreachable: Dict[str, Dict[str, Any]] = {}

    for event in events:
        path = event.get("path") or ""
        if not path:
            continue
        tokens = _num(event.get("tokens"))
        usd = _num(event.get(money_key))
        total_calls += 1
        total_tokens += tokens
        total_usd += usd
        if str(event.get("window") or "main") != "main":
            sidechain_calls += 1
        source = str(event.get("span_source") or "unknown")
        if source in span_source:
            span_source[source] += 1

        row = idx.file_row(path)
        if row is not None:
            reason = idx.excluded(row)
            if reason:
                bucket = excluded[reason]
                bucket["calls"] += 1
                bucket["usd"] += usd
                continue

        name = rung_of(event, row)
        rung = rungs[name]
        rung["calls"] += 1
        rung["tokens"] += tokens
        rung["usd"] += usd

        if name in ("never_indexed", "no_outline"):
            why = ("extension" if (name == "never_indexed"
                                   and not _store().lang_of(path)) else name)
            slot = unreachable.setdefault(why, {"why": why, "calls": 0, "usd": 0.0})
            slot["calls"] += 1
            slot["usd"] += usd
            continue

        stats = per_file.setdefault(path, {
            "path": path, "calls": 0, "tokens": 0.0, "usd": 0.0,
            "band_hi_usd": 0.0, "whole": 0, "beat": 0,
            "symbols": int((row or {}).get("symbols") or 0),
            "outline_tokens": None,
        })
        stats["calls"] += 1
        stats["tokens"] += tokens
        stats["usd"] += usd

        if name == "whole_file":
            outline = idx.outline_tokens(path)
            stats["outline_tokens"] = outline
            stats["whole"] += 1
            if outline is None or tokens <= 0:
                continue
            rung["alt_tokens"] += outline
            ratios.append(outline / tokens)
            if outline < tokens:
                outline_beat += 1
                stats["beat"] += 1
            else:
                outline_lost += 1
            # The band's high end. max(0, ...) because an outline that is bigger
            # than the read it would have replaced is not a negative saving, it
            # is simply no opportunity.
            gain = max(0.0, usd * (1.0 - outline / tokens))
            rung["band_hi_usd"] += gain
            stats["band_hi_usd"] += gain
        elif name == "spanned":
            lo = int(event.get("span_lo") or 1)
            hi = event.get("span_hi") or lo
            cover = idx.chunk_cover(int(row["file_id"]), int(lo), int(hi))
            if cover and tokens > 0:
                rung["alt_tokens"] += cover
                # Positive means the index would have printed MORE.
                rung["dearer_usd"] += usd * (cover / tokens - 1.0)

    ratios.sort()
    median_ratio = (ratios[len(ratios) // 2] if ratios else None)
    files = sorted(per_file.values(), key=lambda r: -r["band_hi_usd"])
    return {
        "money": "measured" if measured else "calibrated",
        "totals": {"calls": total_calls, "tokens": total_tokens, "usd": total_usd,
                   "sidechain_calls": sidechain_calls},
        "span_source": span_source,
        "rungs": [rungs[name] for name in RUNGS],
        "band_lo_usd": 0.0,
        "band_hi_usd": rungs["whole_file"]["band_hi_usd"],
        "dearer_usd": rungs["spanned"]["dearer_usd"],
        "outline_ratio_median": median_ratio,
        "outline_beat": outline_beat,
        "outline_lost": outline_lost,
        "unreachable": sorted(unreachable.values(), key=lambda r: -r["usd"]),
        "excluded": [excluded[name] for name in EXCLUSIONS],
        "files": files[:limit],
        "file_count": len(per_file),
    }


def render(res: Dict[str, Any], *, width: int = 100, money=None,
           shorten=None, rule=None, dim=None) -> str:
    """The console block. Formatting helpers are injected so this module stays
    importable without bin/oe."""
    money = money or (lambda v, **kw: f"${_num(v):,.2f}")
    shorten = shorten or (lambda p: p)
    rule = rule or (lambda w, label="": f"-- {label} " + "-" * max(0, w - len(label) - 4))
    dim = dim or (lambda t: t)
    out: List[str] = []
    totals = res["totals"]
    src = res["span_source"]
    label_w = 26

    out.append(rule(width, "read shrink"))
    out.append("  %s reads  ·  %s tokens into context  ·  priced against the index "
               "AS IT STANDS NOW" % (f"{totals['calls']:,}", f"{totals['tokens']:,.0f}"))
    out.append(dim("  span source: %s exact · %s from the call's own offset · "
                   "%s unknown (counted, never classified)"
                   % (f"{src.get('exact', 0):,}", f"{src.get('input', 0):,}",
                      f"{src.get('unknown', 0):,}")))
    out.append("")
    out.append("  %-*s%7s%11s   %s" % (label_w, "rung", "calls", "read $",
                                       "what the index could print instead"))
    out.append("  " + "-" * (width - 4))
    ratio = res.get("outline_ratio_median")
    notes = {
        "whole_file": ("the outline: median %.0f%% of this" % (ratio * 100)
                       if ratio is not None else "the outline"),
        "spanned": "covering chunks — %s DEARER" % money(abs(res["dearer_usd"])),
        "span_unknown": "not classified: no result span, no offset",
        "no_outline": "nothing: no symbols were found in it",
        "never_indexed": "nothing",
    }
    shown = 0
    shown_usd = 0.0
    for row in res["rungs"]:
        if not row["calls"]:
            continue
        shown += row["calls"]
        shown_usd += row["usd"]
        out.append("  %-*s%7s%11s   %s" % (label_w, RUNG_LABEL[row["rung"]],
                                           f"{row['calls']:,}", money(row["usd"]),
                                           dim(notes.get(row["rung"], ""))))
    out.append("  " + "-" * (width - 4))
    out.append("  %-*s%7s%11s" % (label_w, "", f"{shown:,}", money(shown_usd)))
    out.append("")

    band = res["band_hi_usd"]
    beat, lost = res["outline_beat"], res["outline_lost"]
    out.append("  BAND   %s — %s" % (money(res["band_lo_usd"]), money(band)))
    for line in (
        "the low end is ZERO by construction: oe cannot know that an outline would",
        "have answered the question a read was asking, and will not assume it. The",
        "high end is what those reads cost minus what their outlines cost. It is the",
        "far end of an interval — not a forecast, and not a saving.",
        "the outline was smaller than the read in %d of %d." % (beat, beat + lost),
    ):
        out.append(dim("         " + line))
    out.append("")
    if res["dearer_usd"]:
        out.append("  DEARER  -%s" % money(abs(res["dearer_usd"])))
        for line in ("the spanned rung, reported on its own and never netted into the",
                     "band. A read that already names a range is finer-grained than the",
                     "index's chunks, so pricing it against them costs more, not less."):
            out.append(dim("         " + line))
        out.append("")
    if res["unreachable"]:
        reach_label = {"extension": "oe cannot index that file type",
                       "never_indexed": "not under an indexed root (`oe index <root>`)",
                       "no_outline": "indexed, but no symbols were found in it"}
        total = sum(_num(u["usd"]) for u in res["unreachable"])
        out.append("  OUT OF REACH  %s" % money(total))
        for item in res["unreachable"]:
            out.append(dim("         %9s  %s calls  %s"
                           % (money(item["usd"]), f"{item['calls']:,}",
                              reach_label.get(item["why"], item["why"]))))
        out.append("")
    excluded = [e for e in res["excluded"] if e["calls"]]
    if excluded:
        out.append(dim("  excluded before every figure above, because the "
                       "counterfactual does not hold:"))
        why = {"stale": "changed on disk since it was indexed (`oe index`)",
               "missing": "gone; its outline cannot be re-rendered"}
        for item in excluded:
            out.append(dim("      %4d reads  %8s  %s"
                           % (item["calls"], money(item["usd"]), why.get(item["reason"], ""))))
        out.append("")

    if res["files"]:
        out.append("  %9s%7s%7s%9s  %s" % ("band-hi", "reads", "whole", "outline", "file"))
        out.append("  " + "-" * (width - 4))
        for row in res["files"]:
            out.append("  %9s%7d%7d%9s  %s"
                       % (money(row["band_hi_usd"]), row["calls"], row["whole"],
                          ("%d tok" % row["outline_tokens"]
                           if row["outline_tokens"] is not None else "-"),
                          shorten(row["path"])))
        if res["file_count"] > len(res["files"]):
            out.append(dim("  ... %d more files (--limit N)"
                           % (res["file_count"] - len(res["files"]))))
        out.append("")

    out.append(dim("  reproduce any row with `oe slice <path>`. Every alternative price "
                   "above was made by"))
    out.append(dim("  RENDERING that command and counting what it printed — not from a "
                   "ratio, not a constant."))
    side = totals.get("sidechain_calls") or 0
    if side and totals["calls"]:
        out.append(dim("  %.0f%% of these reads happened in an agent window. oe injects only at "
                       "SessionStart" % (100.0 * side / totals["calls"])))
        out.append(dim("  and UserPromptSubmit, both main-loop, so it cannot hand a slice to "
                       "the window that"))
        out.append(dim("  paid. This is a command you run, not advice the tool can deliver."))
    out.append(dim("  Only `Read` is counted; cat/sed/head through Bash are invisible here."))
    out.append(dim("  A floor: an agent sidechain never writes back its final usage."))
    return "\n".join(out)
