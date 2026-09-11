#!/usr/bin/env python3
"""PreToolUse, matched on `Agent`: hand a spawning subagent a context brief.

READ THIS BEFORE CHANGING ANYTHING HERE
=======================================
This is the only hook in the tool that runs on a TOOL CALL. A fault in the other
three degrades a report; a fault here stops work. Every rule below exists for
that reason.

1. IT FAILS OPEN, ALWAYS. Every path exits 0. A hook that raises, stalls or
   writes malformed JSON on `PreToolUse` interrupts the call it was inspecting.
   Nothing this hook could say is worth that, so the bare `except` at the bottom
   is deliberate and must stay.

2. IT NEVER DENIES. It writes `updatedInput` or nothing. `permissionDecision` is
   never emitted. An enforcement layer on this path was built once in this
   project, measured at a 40.4% false-block rate, and removed.

3. IT IS OFF UNLESS ASKED FOR. `install.py` registers it only when config's
   `brief.enabled` is true, and the default is false.

4. IT IS GATED ON MEASURED BEHAVIOUR, NOT ON THE PROMPT. Prompt specificity was
   tested as a gate and is a confound -- pooled it looks predictive, stratified
   by period it is noise. `oe/prior.py` decides, from how much recent agents
   actually read, and it fails CLOSED on any doubt.

5. DELETING THIS FILE WHILE IT IS REGISTERED BREAKS EVERY TOOL CALL ON THIS
   MACHINE, with an error naming the hook rather than whoever removed it. Set
   `brief.enabled` false, run `install.py --yes`, confirm no settings file still
   references it, and only then delete.

WHAT IT COSTS
-------------
The brief is resident for the agent's whole life and re-billed on every request
that agent makes. The gate exists to decide when not to pay that. The gate
itself costs nothing: it reads one small JSON file that `SessionEnd` wrote.
"""

import json
import os
import sys


def _emit(payload=None):
    """Write at most one JSON object and leave. The exit code is always 0."""
    if payload:
        try:
            sys.stdout.write(json.dumps(payload))
        except Exception:
            pass
    sys.exit(0)


def _journal(row) -> None:
    """One line per decision, refusals included. Best effort, never fatal.

    Refusals matter more than injections here: retuning the gate needs the
    distribution of rates it declined at, and a file holding only the
    injections is a numerator with no denominator.
    """
    try:
        import time
        from oe import prior as prior_mod
        row["ts"] = time.time()
        with open(prior_mod.cache_path().with_name("agent-brief.ndjson"),
                  "a", encoding="utf-8") as handle:
            handle.write(json.dumps(row) + "\n")
    except Exception:
        pass


def main() -> None:
    try:
        raw = sys.stdin.read()
    except Exception:
        _emit()
    if not raw:
        _emit()
    try:
        event = json.loads(raw)
    except Exception:
        _emit()

    # Matched on the tool name, but never trust the matcher: a hand-edited
    # settings file can point any tool at this script, and rewriting the input
    # of a tool whose shape is unknown is how a hook corrupts a call.
    if str(event.get("tool_name") or "") != "Agent":
        _emit()

    tool_input = event.get("tool_input")
    if not isinstance(tool_input, dict):
        _emit()
    prompt = tool_input.get("prompt")
    if not isinstance(prompt, str) or not prompt.strip():
        _emit()

    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if here not in sys.path:
        sys.path.insert(0, here)

    from oe import paths
    config = paths.load_config()
    section = config.get("brief") if isinstance(config.get("brief"), dict) else {}
    # `is not True`, matching install.py: config.json is hand-edited and the
    # string "false" is truthy.
    if section.get("enabled") is not True:
        # Registered but switched off: one process start, nothing else.
        _emit()

    from oe import prior
    # `is None`, not `or`: 0 is a meaningful value for both of these and `or`
    # would silently replace it with the default. The threshold is clamped
    # because it arrives from a hand-edited file, and a negative one would open
    # the gate on every spawn while still reporting an honest-looking rate.
    raw_threshold = section.get("gate_threshold")
    try:
        threshold = (prior.DEFAULT_THRESHOLD if raw_threshold is None
                     else min(1.0, max(0.0, float(raw_threshold))))
    except (TypeError, ValueError):
        threshold = prior.DEFAULT_THRESHOLD
    decision = prior.should_brief(threshold=threshold)
    _journal({"event": "refused" if not decision.get("brief") else "considered",
              "session_id": event.get("session_id"),
              "rate": decision.get("rate"), "why": decision.get("why")})
    if not decision.get("brief"):
        _emit()

    from oe import brief as brief_mod
    raw_budget = section.get("budget_tokens")
    try:
        budget = (brief_mod.DEFAULT_BUDGET_TOKENS if raw_budget is None
                  else max(0, int(raw_budget)))
    except (TypeError, ValueError):
        budget = brief_mod.DEFAULT_BUDGET_TOKENS
    built = brief_mod.build(prompt, budget_tokens=budget)
    text = brief_mod.render(built)
    if not text:
        # Retrieval found nothing worth saying. Saying so anyway would spend
        # prefix tokens to report an absence.
        _emit()

    # Journalled so the next round can be argued from what actually happened
    # rather than from a simulation. Best effort: a failed write must not cost
    # the tool call.
    _journal({"event": "injected", "session_id": event.get("session_id"),
              "rate": decision.get("rate"), "tokens": built.get("tokens"),
              "files": len(built.get("files") or []),
              "considered": built.get("considered")})

    updated = dict(tool_input)
    updated["prompt"] = prompt + text
    _emit({"hookSpecificOutput": {
        "hookEventName": "PreToolUse",
        "updatedInput": updated,
    }})


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except BaseException:
        # Deliberately bare. See rule 1 at the top of this file: nothing this
        # hook could report is worth interrupting a tool call for.
        sys.exit(0)
