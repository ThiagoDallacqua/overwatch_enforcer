"""Retrieval surface over the context store: `oe find`, `oe slice`, `oe deps`.

This is the constructive half of the context guard. A guard that only says "do
not re-read main.ts" makes the model poorer at its job; it has to be able to say
"do not re-read main.ts -- here is the 600-token span you actually wanted", and
these three commands are that span.

The unit of value is the RATIO between what a command prints and what the file
read it replaces would have cost, so every command measures and prints it. Two
numbers, deliberately, because they answer different questions:

* ``printed`` -- tokens of the text this command emitted. This is what actually
  enters the model's window, and it is the only number that maps to money.
* ``spans`` -- tokens of the chunk ranges the hits name. This is what a
  follow-up ``--body`` fetch would cost if the model reads every hit in full.

Reporting only ``spans`` (the tempting number, since it is smaller than a file)
would overstate the win for the default snippet mode and understate it for
``--body``; reporting only ``printed`` would hide the cost of the follow-up the
model is likely to make. Both are printed, against the same denominator: the
whole-file token total of the distinct files the hits touch.

Everything here fails soft. A retrieval command that raises is a command the
model stops trusting, and it will go back to reading whole files -- which is the
failure mode this whole subsystem exists to prevent.
"""

from __future__ import annotations

import json
import os
import sys
from typing import Any, Dict, List, Optional, Sequence, Tuple

# Deliberately no module-level `from . import store`: bin/oe builds its parser on
# every invocation, and store.py costs milliseconds to import. It is pulled in
# lazily by _store() so `oe status` does not pay for a command it did not run.

_STORE = None

# A snippet is orientation, not content. 200 chars is a line or two; at k=8 that
# is the whole snippet budget of one find, and it is what makes the default mode
# cheaper than the --body mode by roughly 4x.
SNIPPET_CHARS = 200
MAX_BODY_LINES = 400
MAX_BODY_CHARS = 24_000
CHARS_PER_TOKEN = 4.0

# Ceilings, and they are load-bearing rather than defensive. An unclamped
# `oe find <term> -k 10000` prints several whole files' worth of text -- many
# times the cost of the single Read it was meant to replace. A retrieval tool
# that can cost more than the Read it replaces is not a retrieval tool, so k is
# clamped and the rendered output is truncated with a visible notice rather than
# silently.
MAX_K = 50
DEFAULT_MAX_OUTPUT_TOKENS = 4_000


def _clamp_k(value: Any, default: int) -> int:
    try:
        return max(1, min(MAX_K, int(value)))
    except Exception:
        return default


class Rendered(str):
    """The rendered text, plus which of its spans are verbatim file CONTENT.

    A plain `str` everywhere it is read, so every existing caller, test and
    captured doc block is unaffected; `.segments` is what lets _emit() print the
    body of a slice past the CLI scrubber while the header, the paths and the
    ratio footer around it still go through it. Carrying the split on the value
    is deliberate: the alternative -- letting the printer guess which lines are
    content -- is the guess that produced the bug, since the scrubber cannot
    tell a printed line of Python from a printed path.
    """

    def __new__(cls, segments: Sequence[Tuple[str, str]]) -> "Rendered":
        obj = super().__new__(cls, "".join(text for _kind, text in segments))
        obj.segments = [(kind, text) for kind, text in segments]
        return obj


def _clip_segments(segments: Sequence[Tuple[str, str]],
                   keep_chars: int) -> List[Tuple[str, str]]:
    """The first `keep_chars` characters of a segment list, kinds preserved."""
    out: List[Tuple[str, str]] = []
    used = 0
    for kind, text in segments:
        if used >= keep_chars:
            break
        room = keep_chars - used
        out.append((kind, text if len(text) <= room else text[:room]))
        used += min(len(text), room)
    return out


def cap(text: str, max_tokens: int = DEFAULT_MAX_OUTPUT_TOKENS) -> str:
    """Truncate rendered output to a token ceiling, saying so on the way out."""
    try:
        limit = max(200, int(max_tokens))
    except Exception:
        limit = DEFAULT_MAX_OUTPUT_TOKENS
    budget = int(limit * CHARS_PER_TOKEN)
    raw = text.encode("utf-8", "replace")
    if len(raw) <= budget:
        return text
    kept = raw[:budget].decode("utf-8", "ignore")
    kept = kept[:kept.rfind("\n") + 1] or kept
    notice = ("\n-- TRUNCATED at %s tok (was ~%s tok). Narrow the query, lower -k, "
              "or raise --max-tokens.\n"
              % (f"{limit:,}", f"{int(len(raw) / CHARS_PER_TOKEN):,}"))
    segments = getattr(text, "segments", None)
    if segments is None:
        return kept + notice
    return Rendered(_clip_segments(segments, len(kept)) + [("chrome", notice)])


def _store():
    global _STORE
    if _STORE is None:
        try:
            from . import store as _s  # noqa: WPS433 (lazy by design; see above)
        except Exception:  # pragma: no cover - only when run as a loose script
            import store as _s  # type: ignore
        _STORE = _s
    return _STORE


def est_tokens(text: str) -> int:
    """bytes/4, the same estimator oe.report and oe.store use.

    Not a tokenizer. It is the estimator the rest of the meter prices with, and
    two halves of one tool disagreeing about token counts would be worse than
    both being 8% off in the same direction.
    """
    try:
        return int(round(len(text.encode("utf-8", "replace")) / CHARS_PER_TOKEN))
    except Exception:
        return 0


# --------------------------------------------------------------------------
# path shortening
# --------------------------------------------------------------------------

def _indexed_roots() -> List[str]:
    try:
        info = (_store().stats() or {}).get("last_index") or {}
        roots = info.get("roots") or []
        return [str(r) for r in roots if r]
    except Exception:
        return []


def path_base(extra: Sequence[str] = ()) -> str:
    """Longest directory prefix shared by the indexed roots (and `extra`).

    Repeating a long shared prefix such as '/srv/build/pkg/core/src/lib/x.ts' on
    every hit spends the reader's budget on a string they already know. Stripping
    the shared base and stating it once in the footer keeps the output
    unambiguous -- the model can still reconstruct an absolute path -- while
    cutting the per-hit path cost roughly in half on a typical repository layout.
    """
    roots = [r for r in list(_indexed_roots()) + [str(x) for x in extra if x] if r]
    if not roots:
        return ""
    try:
        if len(roots) == 1:
            base = os.path.dirname(os.path.normpath(roots[0]))
        else:
            base = os.path.commonpath([os.path.normpath(r) for r in roots])
    except Exception:
        return ""
    base = base.rstrip("/")
    # '/' or '/home' as a base saves nothing and reads as noise.
    return base if base.count("/") >= 2 else ""


def shorten(path: str, base: str) -> str:
    if not path:
        return ""
    if base and path.startswith(base + "/"):
        return path[len(base) + 1:]
    return path


# --------------------------------------------------------------------------
# shared measurement
# --------------------------------------------------------------------------

def _measure(hits: Sequence[Dict[str, Any]], printed: str) -> Dict[str, Any]:
    """Ratio block shared by find/slice/deps.

    The denominator is the whole-file token total of the DISTINCT files the hits
    touch, because that is the read the model would otherwise have made. Counted
    per file, not per hit: three hits in main.ts replace one read of main.ts, and
    charging main.ts three times would flatter the ratio.
    """
    seen: Dict[str, int] = {}
    span_tokens = 0
    for hit in hits:
        span_tokens += int(hit.get("tokens") or 0)
        path = hit.get("path") or ""
        if path and path not in seen:
            seen[path] = int(hit.get("file_tokens") or 0)
    whole = sum(seen.values())
    printed_tokens = est_tokens(printed)
    out = {
        "hits": len(hits),
        "files": len(seen),
        "printed_tokens": printed_tokens,
        "span_tokens": span_tokens,
        "whole_file_tokens": whole,
        "printed_pct": round(100.0 * printed_tokens / whole, 1) if whole else None,
        "span_pct": round(100.0 * span_tokens / whole, 1) if whole else None,
    }
    out["printed_x"] = round(whole / printed_tokens, 1) if printed_tokens and whole else None
    out["span_x"] = round(whole / span_tokens, 1) if span_tokens and whole else None
    return out


def _ratio_line(m: Dict[str, Any], base: str) -> str:
    whole = m.get("whole_file_tokens") or 0
    if not whole:
        return "-- %d hits" % m.get("hits", 0)
    bits = ["%d hits / %d files" % (m.get("hits", 0), m.get("files", 0))]
    bits.append("printed %s tok = %s%% of %s tok whole-file (%sx cheaper)" % (
        f"{m['printed_tokens']:,}", m.get("printed_pct"), f"{whole:,}", m.get("printed_x")))
    if m.get("span_tokens"):
        bits.append("full spans would be %s tok = %s%%" % (
            f"{m['span_tokens']:,}", m.get("span_pct")))
    line = "-- " + " | ".join(bits)
    if base:
        line += "\n-- paths relative to %s" % base
    return line


def _drop_final_newline(segs: List[Tuple[str, str]]) -> List[Tuple[str, str]]:
    """Undo the trailing newline of the last emitted line.

    Every line above is written with its own "\n" so the segment boundaries
    stay clean; the renderers historically built a list and "\n".join()ed it,
    which leaves no newline at the end. Removing it here keeps the rendered
    bytes -- and therefore the printed_tokens the ratio footer quotes -- exactly
    what they were before the split.
    """
    while segs and segs[-1][1] == "":
        segs.pop()
    if segs and segs[-1][0] == "chrome" and segs[-1][1].endswith("\n"):
        segs[-1] = ("chrome", segs[-1][1][:-1])
    return segs


def _body_for(hit: Dict[str, Any]) -> str:
    st = _store()
    lo, hi = int(hit.get("lo") or 1), int(hit.get("hi") or 1)
    if hi - lo + 1 > MAX_BODY_LINES:
        hi = lo + MAX_BODY_LINES - 1
    try:
        return st.file_slice(hit.get("path") or "", lo, hi, max_bytes=MAX_BODY_CHARS)
    except Exception:
        return ""


# --------------------------------------------------------------------------
# find
# --------------------------------------------------------------------------

def find(query: str, k: int = 8, *, path_glob: str = "", lang: str = "",
         body: bool = False) -> Dict[str, Any]:
    st = _store()
    try:
        hits = st.search(query, k=_clamp_k(k, 8), path_glob=path_glob, lang=lang,
                         snippet_chars=0 if body else SNIPPET_CHARS)
    except Exception:
        hits = []
    if body:
        for hit in hits:
            hit["body"] = _body_for(hit)
    return {"query": query, "hits": hits}


def render_find(res: Dict[str, Any], *, body: bool = False) -> str:
    hits = res.get("hits") or []
    base = path_base()
    if not hits:
        return ("no match for %r\n-- index may not cover this repo; "
                "`oe find --stats` to check" % res.get("query", ""))
    segs: List[Tuple[str, str]] = []
    for idx, hit in enumerate(hits, 1):
        head = "%d %s:%d-%d" % (idx, shorten(hit.get("path", ""), base),
                                hit.get("lo", 0), hit.get("hi", 0))
        sym = hit.get("symbol") or ""
        kind = hit.get("kind") or ""
        tail = "  %s%s  %s tok" % (sym, (" [%s]" % kind) if kind and sym else "",
                                   hit.get("tokens", 0))
        segs.append(("chrome", head + tail + "\n"))
        if body and hit.get("body"):
            segs.append(("verbatim", hit["body"]))
            segs.append(("chrome", "\n\n"))
        elif hit.get("snippet"):
            segs.append(("chrome", "   "))
            segs.append(("verbatim", hit["snippet"]))
            segs.append(("chrome", "\n"))
    segs = _drop_final_newline(segs)
    text = "".join(t for _k, t in segs)
    segs.append(("chrome", "\n" + _ratio_line(_measure(hits, text), base)))
    return Rendered(segs)


# --------------------------------------------------------------------------
# slice
# --------------------------------------------------------------------------

def _resolve_file(path: str) -> Dict[str, Any]:
    """file row for `path`, accepting a suffix ('main.ts') as well as a full path."""
    st = _store()
    info = st.file_info(path)
    if info:
        return info
    try:
        cx = st.open_db()
        row = cx.execute(
            "SELECT * FROM files WHERE path LIKE ? ORDER BY LENGTH(path) LIMIT 1",
            ("%" + str(path).lstrip("/"),)).fetchone()
        return dict(row) if row else {}
    except Exception:
        return {}


def _parse_span(target: str):
    """'120-180' -> (120, 180); '120' -> (120, 120); anything else -> None."""
    text = str(target or "").strip()
    if not text:
        return None
    if "-" in text:
        a, _, b = text.partition("-")
        if a.strip().isdigit() and b.strip().isdigit():
            lo, hi = int(a), int(b)
            return (lo, hi) if hi >= lo else (hi, lo)
        return None
    return (int(text), int(text)) if text.isdigit() else None


def _symbols_in_file(info: Dict[str, Any], name: str) -> List[Dict[str, Any]]:
    """Every symbol called `name` inside one indexed file, best first.

    Scoped by file_id rather than by filtering a global top-k, which silently
    loses the answer whenever the name is common.
    """
    file_id = info.get("file_id")
    if not file_id or not name:
        return []
    try:
        cx = _store().open_db()
        rows = cx.execute(
            "SELECT name,kind,lo,hi,exported FROM symbols WHERE file_id=? AND name=? "
            "ORDER BY exported DESC, (hi-lo) DESC LIMIT 20",
            (int(file_id), str(name))).fetchall()
        return [dict(r) for r in rows]
    except Exception:
        return []


def slice_(path: str, target: str = "", *, context: int = 0) -> Dict[str, Any]:
    """One span of one file: a named symbol, an explicit lo-hi, or the outline.

    With no target this prints the file's SYMBOL TABLE rather than the file.
    That case earns its place: "what is in this file" is the question most
    whole-file reads are actually asking, and the outline answers it for ~3% of
    the file's tokens.
    """
    st = _store()
    info = _resolve_file(path)
    if not info:
        return {"error": "not indexed", "path": path}
    real = info.get("path") or path
    file_tokens = int(info.get("tokens") or 0)
    file_lines = int(info.get("lines") or 0)

    span = _parse_span(target)
    if span is None and target:
        # Scope the lookup to THIS file first. st.symbol_lookup() ranks globally
        # and truncates at k, so for a name common enough to appear in dozens of
        # files the file's own definition never reaches the caller: filtering a
        # global top-20 by path can return nothing for a file that does define it.
        matches = _symbols_in_file(info, target)
        found = st.symbol_lookup(target, k=20)
        if matches:
            best = matches[0]
            span = (int(best.get("lo") or 1), int(best.get("hi") or 1))
            target_kind, target_name = best.get("kind") or "", best.get("name") or target
        else:
            # The symbol is not in the file that was asked for. NEVER answer with
            # another file's body: a name like `Props` is defined in dozens of
            # components, and returning the biggest of them cost about 4x the
            # read it was meant to replace, of content the caller did not ask
            # for. Name the other locations in one line each instead and let the
            # caller re-ask with a path it meant.
            return {"error": "symbol not in this file", "path": real,
                    "symbol": target, "file_tokens": file_tokens,
                    "file_lines": file_lines,
                    "elsewhere": [{"path": s.get("path") or "",
                                   "lo": int(s.get("lo") or 0),
                                   "hi": int(s.get("hi") or 0),
                                   "kind": s.get("kind") or "",
                                   "name": s.get("name") or target}
                                  for s in found[:8]]}
    else:
        target_kind, target_name = "", ""

    if span is None:
        try:
            cx = st.open_db()
            rows = cx.execute(
                "SELECT name,kind,lo,hi,exported FROM symbols WHERE file_id=? "
                "ORDER BY lo LIMIT 400", (int(info.get("file_id") or 0),)).fetchall()
            outline = [dict(r) for r in rows]
        except Exception:
            outline = []
        return {"mode": "outline", "path": real, "outline": outline,
                "file_tokens": file_tokens, "file_lines": file_lines}

    lo, hi = span
    if context:
        lo, hi = max(1, lo - context), hi + context
    text = st.file_slice(real, lo, hi, max_bytes=MAX_BODY_CHARS)
    return {"mode": "span", "path": real, "lo": lo, "hi": hi, "text": text,
            "symbol": target_name, "kind": target_kind,
            "tokens": est_tokens(text), "file_tokens": file_tokens,
            "file_lines": file_lines}


def render_slice(res: Dict[str, Any]) -> str:
    base = path_base()
    if res.get("error"):
        head = "-- %s: %s" % (res["error"], shorten(res.get("path", ""), base))
        if res.get("symbol"):
            head += " (symbol %r)" % res["symbol"]
        rows = res.get("elsewhere") or []
        if rows:
            head += "\n-- that name is defined in %d other indexed file(s); ask for one by path:" % len(rows)
            for row in rows:
                head += "\n   oe slice %s %s   # %s:%s-%s [%s]" % (
                    shorten(row.get("path", ""), base), row.get("name", ""),
                    shorten(row.get("path", ""), base),
                    row.get("lo", 0), row.get("hi", 0), row.get("kind", ""))
        if res.get("file_lines"):
            head += ("\n-- or the outline of the file you asked for: oe slice %s   "
                     "(%s tok / %s lines whole)" % (
                         shorten(res.get("path", ""), base),
                         f"{res.get('file_tokens', 0):,}", res.get("file_lines", 0)))
        return head
    path = shorten(res.get("path", ""), base)
    if res.get("mode") == "outline":
        rows = res.get("outline") or []
        lines = ["# %s outline -- %d symbols, file is %s tok / %s lines" % (
            path, len(rows), f"{res.get('file_tokens', 0):,}", res.get("file_lines", 0))]
        for row in rows:
            lines.append("%5d-%-5d %-10s %s%s" % (
                row.get("lo", 0), row.get("hi", 0), row.get("kind", ""),
                row.get("name", ""), "" if row.get("exported") else ""))
        text = "\n".join(lines)
        whole = res.get("file_tokens") or 0
        printed = est_tokens(text)
        if whole:
            text += "\n-- outline %s tok = %s%% of the file (%sx cheaper than reading it)" % (
                f"{printed:,}", round(100.0 * printed / whole, 1), round(whole / printed, 1))
        return text
    head = "# %s:%d-%d" % (path, res.get("lo", 0), res.get("hi", 0))
    if res.get("symbol"):
        head += "  %s%s" % (res["symbol"], (" [%s]" % res["kind"]) if res.get("kind") else "")
    body = res.get("text") or ""
    whole = res.get("file_tokens") or 0
    printed = est_tokens(head + "\n" + body)
    foot = "-- %s tok" % f"{printed:,}"
    if whole:
        foot += " = %s%% of the %s-tok file (%sx cheaper)" % (
            round(100.0 * printed / whole, 1), f"{whole:,}",
            round(whole / printed, 1) if printed else "-")
    # The body is the file, byte for byte. The header and the footer are ours.
    return Rendered([("chrome", head + "\n"), ("verbatim", body),
                     ("chrome", "\n" + foot)])


# --------------------------------------------------------------------------
# deps
# --------------------------------------------------------------------------

def deps(path: str, depth: int = 2, k: int = 24, *, direction: str = "out",
         per_file: int = 3, body: bool = False) -> Dict[str, Any]:
    st = _store()
    try:
        res = st.subtree(path, depth=depth, k=_clamp_k(k, 24), direction=direction,
                         per_file=per_file)
    except Exception:
        res = {}
    if body:
        for hit in (res.get("chunks") or []):
            hit["body"] = _body_for(hit)
    return res or {}


def render_deps(res: Dict[str, Any], *, body: bool = False) -> str:
    base = path_base()
    chunks = res.get("chunks") or []
    files = res.get("files") or []
    if not res.get("entry"):
        return "-- not indexed (or no import edges): pass a path this store knows"
    arrow = {"out": "imports", "in": "imported by", "both": "linked to"}.get(
        res.get("direction", "out"), "linked to")
    segs: List[Tuple[str, str]] = [("chrome", "# %s %s (depth %s): %d files\n" % (
        shorten(res.get("entry", ""), base), arrow, res.get("depth"), len(files)))]
    for entry in files:
        if isinstance(entry, dict):
            segs.append(("chrome", "  d%s %s\n" % (entry.get("depth", "?"),
                                                   shorten(entry.get("path", ""), base))))
        else:
            segs.append(("chrome", "  " + shorten(str(entry), base) + "\n"))
    segs.append(("chrome", "\n"))
    for hit in chunks:
        segs.append(("chrome", "%s:%d-%d  %s  %s tok\n" % (
            shorten(hit.get("path", ""), base), hit.get("lo", 0), hit.get("hi", 0),
            hit.get("symbol") or hit.get("kind") or "", hit.get("tokens", 0))))
        if body and hit.get("body"):
            segs.append(("verbatim", hit["body"]))
            segs.append(("chrome", "\n\n"))
    segs = _drop_final_newline(segs)
    text = "".join(t for _k, t in segs)
    measured = _measure(chunks, text)
    # subtree() reports the closure's whole-file total; it is a better
    # denominator than the touched-files total because the closure is what a
    # human would have opened to answer a "what does this depend on" question.
    closure = int(res.get("whole_files_tokens") or 0)
    if closure:
        measured["whole_file_tokens"] = closure
        printed = measured["printed_tokens"] or 0
        measured["printed_pct"] = round(100.0 * printed / closure, 1) if printed else None
        measured["printed_x"] = round(closure / printed, 1) if printed else None
        span = measured["span_tokens"] or 0
        measured["span_pct"] = round(100.0 * span / closure, 1) if span else None
        measured["span_x"] = round(closure / span, 1) if span else None
    segs.append(("chrome", "\n" + _ratio_line(measured, base)))
    return Rendered(segs)


# --------------------------------------------------------------------------
# the one-line advert the SessionStart hint quotes
# --------------------------------------------------------------------------

# These three print a small fraction of the whole file they replace -- roughly
# 1-5%, with deps at depth 1 the pessimistic case at around 12%. "1-5%" is the
# honest headline; the pessimistic case is named rather than hidden.
HINT = ("oe find <query> | oe slice <path> <symbol|lo-hi> | oe deps <path> "
        "-- indexed slices, typically 1-5% of a whole-file read")


def hint() -> str:
    return HINT


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

# Keys whose STRING VALUES are the caller's own file, byte for byte, rather
# than anything this tool composed: the span a slice returns, the body of a
# hit, the snippet under it. Everything else in a retrieval payload -- paths,
# symbol names, counts -- is chrome and still goes through the CLI scrubber.
_VERBATIM_KEYS = ("text", "body", "snippet")


def _write_segments(segments: Sequence[Tuple[str, str]]) -> None:
    from . import redact as _redact
    for kind, text in segments:
        if not text:
            continue
        if kind == "verbatim":
            _redact.write_verbatim(text)
        else:
            sys.stdout.write(text)


def _split_json(payload: Any) -> List[Tuple[str, str]]:
    """json.dumps(payload), split so file content is its own segment.

    Each verbatim value is swapped for a unique NUL-delimited token before the
    dump, then the dump is cut at those tokens and the token replaced by the
    JSON encoding of the real value. Doing it on the ENCODED form matters: the
    bytes handed to the stream have to be a valid JSON string either way, and
    the escaping is what makes the content survive a newline or a quote.
    """
    holes: List[Tuple[str, str]] = []

    def walk(obj: Any) -> Any:
        if isinstance(obj, dict):
            out = {}
            for key, value in obj.items():
                if key in _VERBATIM_KEYS and isinstance(value, str) and value:
                    token = "\x00OEV%d\x00" % len(holes)
                    holes.append((token, value))
                    out[key] = token
                else:
                    out[key] = walk(value)
            return out
        if isinstance(obj, list):
            return [walk(item) for item in obj]
        return obj

    dumped = json.dumps(walk(payload), indent=2, default=str)
    segments: List[Tuple[str, str]] = []
    rest = dumped
    for token, value in holes:
        head, sep, rest = rest.partition(json.dumps(token)[1:-1])
        segments.append(("chrome", head))
        if not sep:
            # The token did not survive the dump. Fail closed rather than
            # print an unbalanced document: put the value back scrubbed.
            rest = head + rest
            segments.pop()
            continue
        segments.append(("verbatim", json.dumps(value)[1:-1]))
    segments.append(("chrome", rest + "\n"))
    return segments


def _emit(payload: Any, text: str, as_json: bool) -> int:
    """Print a retrieval result, with the file content exempt from the scrubber.

    docs/privacy.md promises in bold that these three commands print the file's
    contents verbatim, piped or not; the process-wide stream scrubber that
    bin/oe installs for every non-tty caller did not know that, and rewrote them.
    Chrome still goes through sys.stdout (wrapped, therefore scrubbed); the body
    goes to the same stream underneath it. See redact.write_verbatim().
    """
    _write_segments(_split_json(payload) if as_json
                    else list(getattr(text, "segments", None)
                              or [("chrome", str(text))]) + [("chrome", "\n")])
    try:
        sys.stdout.flush()
    except Exception:
        pass
    return 0


def _max_tokens(args) -> int:
    return int(getattr(args, "max_tokens", DEFAULT_MAX_OUTPUT_TOKENS)
               or DEFAULT_MAX_OUTPUT_TOKENS)


def cmd_find(args) -> int:
    if getattr(args, "stats", False):
        return _emit(_store().stats(), json.dumps(_store().stats(), indent=2), True)
    query = " ".join(args.query or [])
    res = find(query, k=args.k, path_glob=args.path or "", lang=args.lang or "",
               body=bool(args.body))
    return _emit(res, cap(render_find(res, body=bool(args.body)), _max_tokens(args)),
                 bool(args.json))


def cmd_slice(args) -> int:
    res = slice_(args.path, " ".join(args.target or []).strip(), context=args.context)
    return _emit(res, cap(render_slice(res), _max_tokens(args)), bool(args.json))


def cmd_deps(args) -> int:
    direction = "in" if args.incoming else ("both" if args.both else "out")
    res = deps(args.path, depth=args.depth, k=args.k, direction=direction,
               body=bool(args.body))
    return _emit(res, cap(render_deps(res, body=bool(args.body)), _max_tokens(args)),
                 bool(args.json))


def cmd_index(args) -> int:
    st = _store()
    roots = list(args.roots or [])
    if not roots:
        roots = _indexed_roots() or [os.getcwd()]
    res = st.index_paths(roots, full=bool(args.full), prune=True)
    if getattr(args, "json", False):
        print(json.dumps(res, indent=2, default=str))
        return 0
    print("indexed %s of %s scanned files in %.2fs (%s unchanged) -- roots: %s"
          % (f"{res.get('indexed', 0):,}", f"{res.get('scanned', 0):,}",
             float(res.get("seconds") or res.get("elapsed") or 0),
             f"{res.get('unchanged', 0):,}", ", ".join(roots)))
    return 0


def register(sub) -> None:
    """Attach find/slice/deps/index to an existing argparse subparser collection.

    A function rather than inline parser code so bin/oe needs one import and one
    call, which keeps this file's footprint in a file three other agents are
    editing down to two lines.
    """
    find_p = sub.add_parser("find", help="bm25 slices from the context index (cheaper than Read)")
    find_p.add_argument("query", nargs="*")
    find_p.add_argument("-k", type=int, default=8, help="hits (default 8)")
    find_p.add_argument("--path", help="restrict with a GLOB, e.g. '*/ui/v2/*'")
    find_p.add_argument("--lang", help="restrict to one language (ts, cs, svelte...)")
    find_p.add_argument("--body", action="store_true", help="print the full span, not a snippet")
    find_p.add_argument("--stats", action="store_true", help="index stats instead of a search")
    find_p.add_argument("--max-tokens", type=int, default=DEFAULT_MAX_OUTPUT_TOKENS,
                        help="output ceiling (default %d)" % DEFAULT_MAX_OUTPUT_TOKENS)
    find_p.add_argument("--json", action="store_true")
    find_p.set_defaults(func=cmd_find)

    slice_p = sub.add_parser("slice", help="one symbol / line span of one file, or its outline")
    slice_p.add_argument("path")
    slice_p.add_argument("target", nargs="*", help="symbol name or lo-hi; omit for the outline")
    slice_p.add_argument("--context", type=int, default=0, help="extra lines each side")
    slice_p.add_argument("--max-tokens", type=int, default=DEFAULT_MAX_OUTPUT_TOKENS,
                        help="output ceiling (default %d)" % DEFAULT_MAX_OUTPUT_TOKENS)
    slice_p.add_argument("--json", action="store_true")
    slice_p.set_defaults(func=cmd_slice)

    deps_p = sub.add_parser("deps", help="directional import subtree as a ranked slice")
    deps_p.add_argument("path")
    deps_p.add_argument("--depth", type=int, default=2)
    deps_p.add_argument("-k", type=int, default=24, help="chunks returned (default 24)")
    deps_p.add_argument("--in", dest="incoming", action="store_true", help="who imports this")
    deps_p.add_argument("--both", action="store_true")
    deps_p.add_argument("--body", action="store_true")
    deps_p.add_argument("--max-tokens", type=int, default=DEFAULT_MAX_OUTPUT_TOKENS,
                        help="output ceiling (default %d)" % DEFAULT_MAX_OUTPUT_TOKENS)
    deps_p.add_argument("--json", action="store_true")
    deps_p.set_defaults(func=cmd_deps)

    index_p = sub.add_parser("index", help="build/refresh the context index (incremental)")
    index_p.add_argument("roots", nargs="*", help="default: the roots already indexed")
    index_p.add_argument("--full", action="store_true", help="re-parse every file")
    index_p.add_argument("--json", action="store_true")
    index_p.set_defaults(func=cmd_index)


def main(argv: Optional[List[str]] = None) -> int:
    import argparse
    import sys
    parser = argparse.ArgumentParser(prog="oe-retrieval")
    register(parser.add_subparsers(dest="command"))
    args = parser.parse_args(list(sys.argv[1:] if argv is None else argv))
    if not hasattr(args, "func"):
        parser.print_help()
        return 0
    return args.func(args)


if __name__ == "__main__":  # pragma: no cover
    import sys
    raise SystemExit(main(sys.argv[1:]))
