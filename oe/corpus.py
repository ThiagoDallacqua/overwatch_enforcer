"""Tier 5: does a shipped figure EQUAL a figure measured on THIS machine?

Tiers 2 and 3 ask shape questions -- "does this string look like an
identifier", "does this number look like a measurement". Both are guesses, and
both are guesses about a number whose provenance they cannot see. That is why
rule-based rounds over this tree did not converge: every rule was a heuristic
about appearance, and appearance is exactly what an ordinary number does not
have.

This tier asks a different question, and it is not a guess:

    Does this number appear, at the precision it is written, in the runtime
    state this machine has actually accumulated?

That is an EXACT comparison against real data. A figure copied out of a real
run -- a session total, a token count, a call count, a burn rate -- is in the
local state files by construction, because the local state files are where the
tool put it. So this tier catches the case tier 3 was built to guess at, and
catches it with evidence rather than with phrasing.

WHAT IT ALSO CATCHES, WHICH NOTHING ELSE DID: a figure divided by a constant.
The published docs of this tree were once uniformly scaled, and every rule
above reads a scaled figure as an ordinary number, because that is what it is.
Dividing does not launder a measurement, so the SCALED bucket below re-derives
the small quotients of every local figure and looks for those too. It is
reported separately and is NOT fatal on its own: a quotient collides far more
easily than an exact value, and a rule nobody keeps protects nothing.

MACHINE-LOCAL BY CONSTRUCTION, exactly like the denylist tier. The state files
it reads do not exist on a runner, so this tier CANNOT run in CI and the
caller must say so out loud rather than let a green result imply it ran.

WHAT IT CANNOT SEE
  * a figure this machine never wrote to disk -- one read off a terminal, or
    computed in a head, or measured on a machine that is not this one
  * a figure rounded further than the local value survives (a 3-significant
    figure is below the distinctiveness floor and is deliberately ignored,
    because `100`, `15.00` and `1.23` are everybody's numbers)
  * a figure spelled in words, or split across lines
  * a figure transformed by anything other than division by a small constant
"""

from __future__ import annotations

import json
import re

from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple

#: A number as it would be written in prose or source: optional thousands
#: separators, optional decimal part. Deliberately the same shape the content
#: tier uses, so the two tiers disagree about provenance and never about what
#: counts as a number.
_NUM_RE = re.compile(r"(?<![\w.,$#])(?<!-)"
                     r"(?:\d{1,3}(?:,\d{3})+(?:\.\d+)?|\d+(?:\.\d+)?)"
                     r"(?![\w.]|,\d)")

#: Below this many significant digits a number is not distinctive enough to be
#: evidence of anything. It is the line between an ABSOLUTE and a RATIO, and
#: the policy for this tree already draws it there: a measured absolute runs
#: long, while the ratios and multipliers that are allowed to ship are short.
#: Lowering it to four makes a published per-Mtok list price collide with any
#: rate in local state, which is a rule nobody would keep.
#:
#: NO ILLUSTRATION OF "LONG" BELONGS IN THIS COMMENT. Spelling one out means
#: writing a real session total into the file that defines the rule against
#: writing real session totals. That is how the class arrives: not through
#: carelessness, but through explanation.
MIN_SIGNIFICANT = 5

#: Numbers that are units, not quantities. They collide with real values by
#: coincidence and mean nothing when they do; oe/package.py excludes the same
#: three from its content tier, for the same reason.
_UNIT_ANCHORS = frozenset({"1024", "1024.0", "1000", "1000.0", "1000000",
                           "1048576", "1073741824", "65536", "262144"})

#: Divisors to re-derive. A published figure that is a real one over a small
#: constant is still a real one; this is the reconstruction the content tier's
#: percentage-beside-a-rate rule only half covers.
SCALES: Tuple[int, ...] = (2, 3, 4, 5, 10, 100, 1000)

#: Local state files worth reading, and a size ceiling. `context.db` and the
#: transcripts are deliberately absent: they are large, they are binary or
#: line-oriented rather than figure-oriented, and the figures that matter have
#: already been written into the JSON summaries beside them.
_SOURCE_GLOBS = (
    "*.live.json", "*.checkpoint.json", "session-map.json", "accounts.json",
    "prefix-baseline.json", "supervisor.json", "cost-cache/*.json",
)
_MAX_SOURCE_BYTES = 8 * 1024 * 1024


def _significant(text: str) -> int:
    """Significant digits of a number AS WRITTEN, ignoring separators."""
    digits = text.replace(",", "")
    if "." in digits:
        whole, _, frac = digits.partition(".")
        whole = whole.lstrip("0")
        if whole:
            return len(whole) + len(frac)
        # 0.00123 -- leading zeros in the fraction are not significant
        return len(frac.lstrip("0"))
    return len(digits.strip("0")) or len(digits)


def _key(value: Decimal, places: int) -> Optional[str]:
    """A local value rounded to `places`, as the string a document would use."""
    try:
        quant = value.quantize(Decimal(1).scaleb(-places))
    except (InvalidOperation, ValueError):
        return None
    return format(quant, "f")


def _walk_numbers(node, out: List[Decimal]) -> None:
    if isinstance(node, dict):
        for item in node.values():
            _walk_numbers(item, out)
    elif isinstance(node, list):
        for item in node:
            _walk_numbers(item, out)
    elif isinstance(node, bool):
        return
    elif isinstance(node, (int, float)):
        try:
            out.append(Decimal(repr(node)))
        except (InvalidOperation, ValueError):
            return


def source_paths(state: Path) -> List[Path]:
    """The local state files this tier reads, smallest first."""
    found: Set[Path] = set()
    for pattern in _SOURCE_GLOBS:
        for path in state.glob(pattern):
            if path.is_file() and path.stat().st_size <= _MAX_SOURCE_BYTES:
                found.add(path)
    return sorted(found)


def local_figures(state: Path) -> Tuple[Dict[str, str], Dict[str, str], int]:
    """(exact index, scaled index, how many source values were read).

    Both indexes map a WRITTEN spelling -- the string a document would contain
    -- to a one-word provenance label. The label never carries a path: this
    function reads the author's private state and its output is printed.
    """
    values: List[Tuple[Decimal, str]] = []
    for path in source_paths(state):
        label = path.parent.name + "/" + path.name if path.parent.name == \
            "cost-cache" else path.name
        # A session id is a filename here; the label is only ever printed on
        # the author's own machine, but there is no reason for it to name a
        # session, so it is reduced to the kind of file it is.
        label = re.sub(r"^[0-9a-f-]{8,}\.", "", label) or label
        try:
            raw = json.loads(path.read_text(encoding="utf-8", errors="replace"))
        except Exception:
            continue
        found: List[Decimal] = []
        _walk_numbers(raw, found)
        values.extend((value, label) for value in found)

    exact: Dict[str, str] = {}
    scaled: Dict[str, str] = {}
    for value, label in values:
        if value <= 0:
            continue
        for places in range(0, 5):
            spelling = _key(value, places)
            if spelling and _significant(spelling) >= MIN_SIGNIFICANT:
                exact.setdefault(spelling, label)
        for divisor in SCALES:
            try:
                quotient = value / Decimal(divisor)
            except (InvalidOperation, ZeroDivisionError):
                continue
            for places in range(0, 5):
                spelling = _key(quotient, places)
                if spelling and _significant(spelling) >= MIN_SIGNIFICANT \
                        and spelling not in exact:
                    scaled.setdefault(spelling, f"{label}/{divisor}")
    return exact, scaled, len(values)


class Hit:
    __slots__ = ("rel", "line", "bucket", "sample", "origin")

    def __init__(self, rel: str, line: int, bucket: str, sample: str,
                 origin: str) -> None:
        self.rel, self.line, self.bucket = rel, line, bucket
        self.sample, self.origin = sample, origin

    def describe(self) -> str:
        return (f"{self.rel}:{self.line}  {self.bucket}  {self.sample!r} "
                f"== {self.origin}")


def scan(text: str, rel: str, exact: Dict[str, str],
         scaled: Dict[str, str]) -> Tuple[List[Hit], List[Hit]]:
    """Numbers in `text` that this machine has actually measured."""
    hard: List[Hit] = []
    soft: List[Hit] = []
    for number, line in _iter_numbers(text):
        written = number.replace(",", "")
        if _significant(written) < MIN_SIGNIFICANT:
            continue
        if written in _UNIT_ANCHORS:
            continue
        origin = exact.get(written)
        if origin:
            hard.append(Hit(rel, line, "corpus", number, origin))
            continue
        origin = scaled.get(written)
        if origin:
            soft.append(Hit(rel, line, "corpus-scaled", number, origin))
    return hard, soft


def _iter_numbers(text: str) -> Iterable[Tuple[str, int]]:
    line = 1
    pos = 0
    for match in _NUM_RE.finditer(text):
        line += text.count("\n", pos, match.start())
        pos = match.start()
        yield match.group(0), line


def selftest(state: Path) -> List[str]:
    """Prove the tier fails on a planted positive and passes benign numbers.

    A tier that has never been shown to fire is not evidence.
    """
    bad: List[str] = []
    exact, scaled, count = local_figures(state)
    if not exact:
        return ["no local figures: this tier asserted nothing"]

    # The planted positive is a REAL local figure, chosen at runtime. Writing
    # one into this file would be the leak the tier exists to find.
    probe = sorted(exact)[len(exact) // 2]
    hard, _soft = scan(f"# the run came to {probe} in the end\n", "probe.py",
                       exact, scaled)
    if not hard:
        bad.append(f"blind to a value that is in local state ({len(exact)} "
                   f"spellings indexed from {count} values)")

    for benign in ("15.00", "1.23", "429", "1024", "3.46.1", "200000"):
        hard, soft = scan(f"# {benign} is a published fact\n", "probe.py",
                          exact, scaled)
        if hard:
            bad.append(f"eats a benign number: {benign}")
        # A scaled collision on a short benign number is expected and is why
        # the scaled bucket is advisory; it is not asserted here.
    return bad
