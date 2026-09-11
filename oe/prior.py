"""How read-heavy this machine's recent subagents have been.

WHY A PRIOR AND NOT A PROMPT HEURISTIC
--------------------------------------
The obvious way to decide whether a spawning agent deserves a context brief is
to read its prompt -- is it specific, does it name files, how long is it. That
was measured on this machine's own history and it does not work. Pooled, prompt
specificity looks strongly predictive; stratified by period it collapses to
noise in both strata. The pooled signal was a confound between two eras of usage
that differed in BOTH prompt style and read behaviour, and a heuristic trained
on it would be reading the calendar.

What does predict is behaviour: how much the last few agents actually read. A
rolling window over that separates read-heavy stretches from light ones by
roughly an order of magnitude, and it is strictly causal -- every input is an
agent that already finished.

WHY IT IS A CACHE
-----------------
Deriving this means touching transcripts, and the consumer is a `PreToolUse`
hook, which runs on the tool-call path where latency is a correctness concern
rather than a comfort. So the deriving happens where there is already a budget
for it -- `SessionEnd`, which rebuilds reports anyway -- and the hook only reads
a small JSON file.

It costs no tokens. Nothing here enters a context window: it is local file I/O
over transcripts Claude Code has already written. The only thing in this feature
that costs tokens is the brief itself, and this file exists to decide when NOT
to pay for one.
"""

from __future__ import annotations

import json
import os
import time
from typing import Any, Dict, Optional

#: How many recently-finished agents the rolling window covers. Short on
#: purpose: usage regimes change over hours, not weeks, and a long window is
#: still describing the previous regime when the current one has moved on.
DEFAULT_WINDOW = 5

#: Distinct `Read` calls at or above which an agent counts as read-heavy. This
#: is the one arbitrary number in the file. It sits in the gap between the two
#: regimes observed here, but it was CHOSEN rather than derived, and it is the
#: first thing to revisit once there is live data to revisit it with.
DEFAULT_HEAVY_READS = 8

#: Share of the window that must be read-heavy before a brief is worth paying
#: for. Above this the measured win rate roughly doubles; below it, injecting
#: loses money on average.
DEFAULT_THRESHOLD = 0.35

#: A prior older than this is not trusted -- usage may have changed regime since.
#: A stale prior fails CLOSED (no injection), because the cost of not briefing
#: is zero and the cost of briefing wrongly is not.
MAX_AGE_SECONDS = 6 * 3600

_CACHE_NAME = "agent-prior.json"


def cache_path():
    from oe import paths
    # state_dir() migrates a legacy location on first resolve, so it is the
    # accessor rather than a module constant. Never build this path by hand.
    return paths.state_dir() / _CACHE_NAME


def _read_count(path, limit_lines: int = 20_000) -> int:
    """`Read` tool calls in one agent transcript.

    PARSES rather than counting substrings, and the difference is not academic.
    Every transcript carries a tool-schema line that DECLARES the Read tool, so
    a substring count returns a constant floor on a transcript where the agent
    read nothing -- measured at exactly +2 on every file checked here. A
    constant additive bias does nothing EXCEPT move transcripts across the
    threshold, which is the one thing this figure is used for.

    Only `type == "assistant"` lines carry tool_use blocks, so the JSON cost is
    paid on a fraction of the file. Bounded by line count so a pathological
    transcript cannot stall the caller.
    """
    total = 0
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            for index, line in enumerate(handle):
                if index >= limit_lines:
                    break
                if '"Read"' not in line or '"tool_use"' not in line:
                    continue
                try:
                    obj = json.loads(line)
                except ValueError:
                    continue
                message = obj.get("message")
                content = message.get("content") if isinstance(message, dict) else None
                if not isinstance(content, list):
                    continue
                for block in content:
                    if (isinstance(block, dict) and block.get("type") == "tool_use"
                            and block.get("name") == "Read"):
                        total += 1
    except OSError:
        return 0
    return total


def compute(window: int = DEFAULT_WINDOW,
            heavy_reads: int = DEFAULT_HEAVY_READS) -> Dict[str, Any]:
    """Measure the prior from the newest finished agent transcripts."""
    from oe import paths
    try:
        agents = sorted(paths.PROJECTS_ROOT.rglob("agent-*.jsonl"),
                        key=lambda p: p.stat().st_mtime, reverse=True)[:window]
    except OSError:
        agents = []
    heavy = sum(1 for path in agents if _read_count(path) >= heavy_reads)
    seen = len(agents)
    return {
        "window": window,
        "heavy_reads": heavy_reads,
        "agents_seen": seen,
        "heavy": heavy,
        # An empty window is not evidence of a light regime, so rate is None
        # rather than 0.0 and the gate below refuses it.
        "rate": (heavy / seen) if seen else None,
        "computed_ts": time.time(),
    }


def write(state: Optional[Dict[str, Any]] = None) -> Optional[Dict[str, Any]]:
    """Refresh the cache. Returns what was written, or None if it could not be."""
    state = state or compute()
    target = cache_path()
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        tmp = target.with_suffix(".json.part")
        tmp.write_text(json.dumps(state), encoding="utf-8")
        os.replace(str(tmp), str(target))
    except OSError:
        return None
    return state


def read() -> Optional[Dict[str, Any]]:
    """The cached prior, or None. Never raises, never computes."""
    try:
        with open(cache_path(), "r", encoding="utf-8") as handle:
            state = json.load(handle)
    except (OSError, ValueError):
        return None
    return state if isinstance(state, dict) else None


def should_brief(state: Optional[Dict[str, Any]] = None,
                 threshold: float = DEFAULT_THRESHOLD,
                 max_age: float = MAX_AGE_SECONDS) -> Dict[str, Any]:
    """Is a brief worth paying for right now? Fails CLOSED on every doubt.

    Returns the decision AND why, because a gate whose reasoning cannot be
    printed is a gate nobody can argue with.
    """
    if state is None:
        state = read()
    if not state:
        return {"brief": False, "why": "no prior recorded yet"}
    # compute() can only ever write a float in [0,1] or None, so anything else
    # is a corrupt, hand-edited or foreign cache -- exactly the "doubt" this
    # function promises to fail closed on. Coerce ONCE and use the coerced value
    # everywhere: formatting the raw object is how a string rate turned a
    # refusal into a traceback.
    try:
        raw = state.get("rate")
        # A STRING that parses is still not something compute() can write, so it
        # is a foreign or hand-edited cache. Type-check rather than coerce: the
        # contract is "a float in [0,1] or None", and anything else is doubt.
        if isinstance(raw, bool) or not isinstance(raw, (int, float)):
            return {"brief": False, "why": "no usable rate recorded"}
        value = float(raw)
        age = time.time() - float(state.get("computed_ts") or 0)
    except (TypeError, ValueError):
        return {"brief": False, "why": "prior is unreadable"}
    if value != value or value in (float("inf"), float("-inf")) \
            or not 0.0 <= value <= 1.0:
        return {"brief": False, "why": "recorded rate is out of range"}
    # Two-sided: a clock that jumped forward would otherwise make a stale prior
    # look permanently fresh, and freshness is this figure's only provenance.
    if not 0.0 <= age <= max_age:
        return {"brief": False, "rate": value,
                "why": (f"prior is stale ({age / 3600:.1f}h old)" if age > 0
                        else "prior is timestamped in the future")}
    if value < threshold:
        return {"brief": False, "rate": value,
                "why": f"recent agents are read-light ({value:.0%} heavy, "
                       f"needs {threshold:.0%})"}
    return {"brief": True, "rate": value,
            "why": f"recent agents are read-heavy ({value:.0%} heavy)"}
