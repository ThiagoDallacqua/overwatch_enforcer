#!/usr/bin/env python3
"""UserPromptSubmit -> one compact budget line, into the model AND onto the screen.

"Where the money goes, and how much", delivered where it can change behaviour:

* ``hookSpecificOutput.additionalContext`` -- text the MODEL reads. This is the
  half that changes what the next turn does, and the half that costs money.
* ``systemMessage`` -- text the USER reads. Free: it is rendered by the CLI and
  never enters the request.

The whole design is governed by one arithmetic fact. A token placed in the
window is re-sent as a cache read on every subsequent request of the session, so
carrying tokens forward costs hundreds of times what it costs to read them once.
A short nag on every prompt is therefore real money per session, so it has to be
earning its place, not decorating the transcript. Three rules follow:

1. SILENT by default. No finding, no additionalContext key at all.
2. ONE action, never a list. The action is chosen by descending stake.
3. Never the same nag twice in a row. A repeated nag is a nag the model already
   declined to act on; charging for it again buys nothing.

The screen line is not rate-limited, because it is free and because "how much am
I spending" was the actual request.

Exits 0 on every input. Writes nothing but the deliberate hook JSON to stdout.
"""

import json
import os
import sys
import time

# Derived, never hardcoded: hooks/<this file> -> the install root is two levels
# up. An absolute literal here is what makes a tool work on exactly one machine.
# OE_INSTALL_ROOT overrides it for a hook script copied out of the tree.
INSTALL_ROOT = os.environ.get("OE_INSTALL_ROOT") or os.path.dirname(
    os.path.dirname(os.path.abspath(__file__)))
STATE_DIR = os.environ.get("OE_STATE_DIR") or os.path.join(INSTALL_ROOT, "state")

# Context thresholds against the 1M window. Left to itself, auto-compaction
# fires at the ceiling, mid-task, at a moment nobody chose. These thresholds
# exist to move that decision to a moment the user chooses.
CTX_NUDGE = 0.60
CTX_WARN = 0.75
CTX_URGENT = 0.85

# Re-read pressure. NOTE the units: store.ranges.tokens ACCUMULATES across the
# reads that merge into one interval (record_read does `mtok += row["tokens"]`),
# so it is tokens SPENT on the file, not the file's footprint in the window.
# Reading it as a footprint doubles the figure for a file that was read twice --
# in the direction that flatters the tool. The threshold and the wording both
# talk about spend.
REREAD_MIN_TOKENS = 3_000
REREAD_MIN_READS = 2

# Hard cap on what may be injected. Enforced on the rendered string, not
# assumed, because an over-long line is a silent recurring cost.
MAX_CONTEXT_CHARS = 320

FORWARD_CARRY_USD_PER_1K = 0.126
CACHE_READ_USD_PER_MTOK = 0.50
MAX_SNAPSHOT_BYTES = 4_000_000


def _state_path(session_id):
    safe = "".join(c for c in str(session_id or "unknown") if c.isalnum() or c in "-_")[:128]
    return os.path.join(STATE_DIR, "%s.injector.json" % (safe or "unknown"))


def _load_state(path):
    try:
        with open(path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _save_state(path, data):
    """Best effort, atomic. Losing this file only costs one duplicate nag."""
    tmp = "%s.%d.tmp" % (path, os.getpid())
    try:
        os.makedirs(STATE_DIR, exist_ok=True)
        with open(tmp, "w", encoding="utf-8") as handle:
            json.dump(data, handle, separators=(",", ":"))
        os.replace(tmp, path)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass


def _snapshot(session_id):
    """The watcher's live ledger for this session: one stat, one read, one parse."""
    if not session_id:
        return {}
    path = os.path.join(STATE_DIR, "%s.live.json" % session_id)
    try:
        info = os.stat(path)
        if info.st_size <= 0 or info.st_size > MAX_SNAPSHOT_BYTES:
            return {}
        with open(path, "rb") as handle:
            snap = json.loads(handle.read().decode("utf-8", "replace"))
    except Exception:
        return {}
    if not isinstance(snap, dict):
        return {}
    # A stale file under a reused name would quietly report another session's
    # spend, which is worse than reporting nothing.
    sid = snap.get("session_id") or (snap.get("session") or {}).get("session_id")
    if sid and sid != session_id:
        return {}
    return snap


def _money(value):
    try:
        value = float(value)
    except (TypeError, ValueError):
        return "$0"
    if value >= 100:
        return "$%d" % round(value)
    if value >= 10:
        return "$%.1f" % value
    return "$%.2f" % value


def _tokens(value):
    try:
        value = int(value)
    except (TypeError, ValueError):
        return "0"
    if value >= 1_000_000:
        return "%.2fM" % (value / 1e6)
    if value >= 1_000:
        return "%dk" % round(value / 1000.0)
    return str(value)


def _reread_candidate(session_id):
    """Heaviest file already resident that has been read more than once.

    Imported lazily and inside its own try: the store is not free to import, and
    an unbuilt or unreachable store must degrade to "no nag", never to a crash.
    """
    try:
        if INSTALL_ROOT not in sys.path:
            sys.path.insert(0, INSTALL_ROOT)
        from oe import store
        rows = store.epoch_residency(session_id, limit=40) or []
    except Exception:
        return None
    best = None
    for row in rows:
        try:
            tokens = int(row.get("tokens") or 0)
            reads = int(row.get("reads") or 0)
        except Exception:
            continue
        if tokens < REREAD_MIN_TOKENS or reads < REREAD_MIN_READS:
            continue
        if best is None or tokens > best["tokens"]:
            best = {"path": row.get("path") or "", "tokens": tokens, "reads": reads}
    return best


def _choose_action(ctx_frac, session_id, state):
    """(kind, text) or (None, None). Descending stake; exactly one is returned.

    The kind carries the SEVERITY, not just the topic ("compact:urgent", not
    "compact"). That is load-bearing: the suppression below keys on the kind, and
    with a topic-only key the 92% "compact NOW" would be silenced by the 62%
    nudge that fired two prompts earlier -- the injector would go quiet exactly
    as it became worth listening to.
    """
    # These are raw-fraction rules: they read the context percentage and nothing
    # else. A break-qualified advisory would outrank them -- it prices the
    # choice instead of asserting it, which is strictly better information --
    # but delivering it costs about one request's worth of money to warn about
    # the cost of a request. If one is ever added, it belongs ahead of these
    # rules, not beside them.
    if ctx_frac >= CTX_URGENT:
        return ("compact:urgent",
                "context %d%% - /compact NOW at the next clean boundary; auto-compaction "
                "fires at ~97%% mid-task and costs a full-window request"
                % round(ctx_frac * 100))
    if ctx_frac >= CTX_WARN:
        return ("compact:warn", "context %d%% - plan a /compact at the next natural break"
                % round(ctx_frac * 100))

    candidate = _reread_candidate(session_id)
    if candidate:
        name = os.path.basename(candidate["path"]) or candidate["path"]
        return ("reread:" + name,
                "%s is already in context - read %dx, ~%s tok spent on it so far; "
                "`oe slice %s <symbol>` instead of re-reading it"
                % (name, candidate["reads"], _tokens(candidate["tokens"]), name))

    if ctx_frac >= CTX_NUDGE:
        return ("compact:nudge",
                "context %d%% - a /compact at the next natural break is cheaper than the "
                "automatic one" % round(ctx_frac * 100))

    if not state.get("hint_done"):
        return ("hint", "retrieval: `oe find <q>` / `oe slice <path> <sym>` / `oe deps "
                        "<path>` return indexed slices at 1-5% of a whole-file read")
    return (None, None)


def _suppressed(kind, state):
    """True when this exact kind is still inside its cooldown.

    A plain "not twice in a row" rule turns a persistent condition into an
    every-other-prompt flicker -- the same compaction line switching on and off
    for the rest of the session. It costs real money and it trains the reader to
    ignore the line. So the cooldown doubles each time the same kind repeats
    (1, 2, 4, capped at 8 prompts), which keeps a standing condition audible
    without it becoming wallpaper. A DIFFERENT kind resets the ladder, so an
    escalation is never delayed.
    """
    if kind != state.get("last"):
        return False
    return int(state.get("cooldown") or 0) > 0


def main():
    raw = sys.stdin.read()
    try:
        payload = json.loads(raw or "{}")
    except Exception:
        payload = {}
    if not isinstance(payload, dict):
        payload = {}

    session_id = payload.get("session_id")
    if not isinstance(session_id, str) or "/" in session_id:
        session_id = ""

    snap = _snapshot(session_id)
    cost = snap.get("cost_usd")
    if cost is None:
        cost = (snap.get("totals") or {}).get("cost_usd_authoritative")
    used = snap.get("context_used_tokens") or 0
    window = snap.get("context_max_tokens") or 1_000_000
    try:
        ctx_frac = float(used) / float(window) if window else 0.0
    except Exception:
        ctx_frac = 0.0
    burn = snap.get("burn_rate_usd_per_hour") or snap.get("burn_usd_per_hour") or 0

    state_path = _state_path(session_id)
    state = _load_state(state_path)
    kind, action = _choose_action(ctx_frac, session_id, state)

    # Rule 3. The hint is one-shot (hint_done retires it), so it needs no ladder.
    # The cooldown is READ before it is decremented: decrementing first would
    # take a freshly-set cooldown of 1 straight back to 0 and let the same nag
    # fire on the very next prompt, which is the flicker the ladder exists to
    # stop.
    hushed = bool(kind) and kind != "hint" and _suppressed(kind, state)
    state["cooldown"] = max(0, int(state.get("cooldown") or 0) - 1)
    if hushed:
        kind, action = None, None

    money = "%s spent | ctx %d%% | %s/h" % (_money(cost), round(ctx_frac * 100),
                                            _money(burn))

    out = {}
    # No snapshot means the watcher has not written this session yet (the first
    # prompt of a fresh session, or a session it does not track). Printing a
    # zeroed money-and-context line there is not a cheap approximation, it is a
    # wrong number on the user's screen, so say nothing instead.
    if snap and os.environ.get("OE_INJECTOR_SCREEN") != "0":
        out["systemMessage"] = "oe: " + money + (("  |  " + action) if action else "")

    if action:
        text = ("[oe] %s. %s" % (money, action)) if snap else ("[oe] " + action)
        if len(text) > MAX_CONTEXT_CHARS:
            text = text[:MAX_CONTEXT_CHARS - 1] + "…"
        out["hookSpecificOutput"] = {"hookEventName": "UserPromptSubmit",
                                     "additionalContext": text}
        step = int(state.get("backoff") or 1) if kind == state.get("last") else 1
        state["last"] = kind
        state["backoff"] = min(step * 2, 8)
        state["cooldown"] = step
        if kind == "hint":
            state["hint_done"] = True
        state["injected"] = int(state.get("injected") or 0) + 1
        state["injected_tokens"] = int(state.get("injected_tokens") or 0) + \
            int(round(len(text.encode("utf-8", "replace")) / 4.0))
    state["prompts"] = int(state.get("prompts") or 0) + 1
    state["ts"] = time.time()
    _save_state(state_path, state)

    if out:
        sys.stdout.write(json.dumps(out, separators=(",", ":")))


try:
    main()
except Exception:
    pass
sys.exit(0)
