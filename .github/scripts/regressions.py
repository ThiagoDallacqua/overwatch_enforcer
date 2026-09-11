#!/usr/bin/env python3
"""Behaviour regressions: each check reproduces a bug that shipped, in isolation.

    python .github/scripts/regressions.py

WHY THIS FILE EXISTS
--------------------
The other scripts in this directory ask "is anything forbidden published?". None
of them runs the tool's own logic against a known state and checks the answer,
and that is how a two-label check survived the move to self-configuring labels:
every session whose owner was recorded in its own transcript resolved as
'unknown', and nothing anywhere failed.

HOW IT RUNS
-----------
Every scenario runs in a FRESH interpreter with its own throwaway state
directory, Claude home and reports root, so:

  * nothing here can read or write this machine's real state;
  * paths.PROJECTS_ROOT, which is fixed at import time, points where the
    scenario says it does;
  * results come back in a JSON file, never on stdout -- bin/oe installs its
    output scrubber at import, and a scrubbed result would test the scrubber by
    accident.

Every check was shown to FAIL against the code it guards before its fix landed.
A check that has never been seen failing is not evidence.

Addresses are assembled at runtime on the reserved example domains, so this file
carries no address-shaped literal for the leak gate to argue with.
"""

import json
import os
import re
import subprocess
import sys
import tempfile
import textwrap
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

ROOT = Path(__file__).resolve().parents[2]
AT = "@"


def addr(local: str, domain: str = "example.com") -> str:
    return local + AT + domain


E1, E2, E3, E4 = (addr("owner"), addr("second.login", "example.org"),
                  addr("third.login", "example.net"), addr("colleague"))
# An issue key for the scrubber's control case, assembled for the same reason.
TICKET = "ABC" + "-" + "123"

PRELUDE = f"""
import json, os, sys
sys.path.insert(0, {str(ROOT)!r})
ARGS = json.loads(os.environ["REGRESSION_ARGS"])
def emit(value):
    with open(os.environ["REGRESSION_OUT"], "w", encoding="utf-8") as handle:
        json.dump(value, handle)
"""


def _transcript(session_id: str) -> str:
    """The smallest session the scanner will turn into a row."""
    user = {"type": "user", "sessionId": session_id, "cwd": "/tmp/regression",
            "timestamp": "2026-01-01T10:00:00Z",
            "message": {"role": "user", "content": "hello"}}
    reply = {"type": "assistant", "sessionId": session_id, "cwd": "/tmp/regression",
             "timestamp": "2026-01-01T10:00:05Z", "requestId": "req_" + session_id[:8],
             "message": {"id": "msg_" + session_id[:8], "role": "assistant",
                         "model": "claude-opus-5",
                         "content": [{"type": "text", "text": "ok"}],
                         "usage": {"input_tokens": 10, "output_tokens": 5,
                                   "cache_read_input_tokens": 0,
                                   "cache_creation_input_tokens": 0}}}
    return json.dumps(user) + "\n" + json.dumps(reply) + "\n"


def _sandbox(tmp: Path, state: Optional[Dict[str, Any]], sessions: int,
             args: Dict[str, Any]) -> Tuple[Dict[str, str], Path]:
    state_dir = tmp / "state"
    home = tmp / "claude"
    reports = tmp / "reports"
    for folder in (state_dir, home / "projects", reports):
        folder.mkdir(parents=True)
    if state is not None:
        (state_dir / "accounts.json").write_text(json.dumps(state), encoding="utf-8")
    if sessions:
        project = home / "projects" / "-tmp-regression"
        project.mkdir()
        for index in range(sessions):
            sid = f"0000000{index}-0000-4000-8000-00000000000{index}"
            path = project / f"{sid}.jsonl"
            path.write_text(_transcript(sid), encoding="utf-8")
            # Distinct, old mtimes: newest-first order is part of what is tested,
            # and nothing here may look like a live session.
            stamp = 1_700_000_000 + index * 3600
            os.utime(path, (stamp, stamp))
    out = tmp / "out.json"
    env = dict(os.environ, OE_STATE_DIR=str(state_dir), CLAUDE_CONFIG_DIR=str(home),
               OE_REPORTS_ROOT=str(reports), OE_REDACT="0",
               REGRESSION_OUT=str(out), REGRESSION_ARGS=json.dumps(args))
    return env, out


def scenario(body: str, *, state: Optional[Dict[str, Any]] = None, sessions: int = 0,
             args: Optional[Dict[str, Any]] = None) -> Any:
    """Run `body` in a fresh interpreter; return what it emit()ted."""
    with tempfile.TemporaryDirectory() as raw:
        env, out = _sandbox(Path(raw), state, sessions, args or {})
        proc = subprocess.run([sys.executable, "-c", PRELUDE + textwrap.dedent(body)],
                              env=env, capture_output=True, text=True, timeout=180)
        if not out.exists():
            return {"__error__": (proc.stderr or proc.stdout or "no output")[-600:]}
        return json.loads(out.read_text(encoding="utf-8"))


def cli(argv: List[str], *, state: Optional[Dict[str, Any]] = None,
        sessions: int = 0) -> str:
    """Run bin/oe in the same kind of sandbox; return stdout + stderr."""
    with tempfile.TemporaryDirectory() as raw:
        env, _ = _sandbox(Path(raw), state, sessions, {})
        proc = subprocess.run([sys.executable, str(ROOT / "bin" / "oe"), *argv],
                              env=env, capture_output=True, text=True, timeout=180)
        return proc.stdout + proc.stderr


def _identity(email: str, label: str) -> Dict[str, Any]:
    return {"email": email, "label": label, "first_seen": 0, "last_seen": 0}


# --- the checks ---------------------------------------------------------------
# Each returns (passed, what was observed). Observations are printed on failure,
# so a red run says what the code did rather than only that it was wrong.

def check_recorded_owner_with_allocated_label() -> Tuple[bool, Any]:
    """A session whose transcript names its owner resolves to that owner.

    Shipped bug: resolve() accepted a recorded owner only if its label was one of
    the two pre-allocation names, so on every machine using 'primary' the owner
    was read, found, and thrown away.
    """
    state = {"version": 1, "identities": {"uuid-a": _identity(E1, "primary")},
             "label_map": {E1: "primary"},
             "recorded": {"session-one": {"uuid": "uuid-a", "scanned_bytes": 10}}}
    got = scenario("""
        from oe import accounts
        answer = accounts.resolve("session-one", None)
        emit({"label": answer["label"], "source": answer["source"]})
    """, state=state)
    return got == {"label": "primary", "source": "recorded"}, got


def check_assign_accepts_allocated_label() -> Tuple[bool, Any]:
    """`oe account assign <selector> primary` finds the label.

    Shipped bug: the free-order parser recognised only the two old names, so the
    label its own error message offered was rejected.
    """
    state = {"version": 1, "identities": {"uuid-a": _identity(E1, "primary")},
             "label_map": {E1: "primary"}}
    got = scenario("""
        import importlib.machinery, importlib.util
        path = os.path.join(sys.path[0], "bin", "oe")
        loader = importlib.machinery.SourceFileLoader("oe_cli", path)
        module = importlib.util.module_from_spec(importlib.util.spec_from_loader("oe_cli", loader))
        loader.exec_module(module)
        label, rest = module._split_target(["abc123", "primary"])
        emit([label, rest])
    """, state=state)
    return got == ["primary", ["abc123"]], got


def check_scrub_does_not_allocate_labels() -> Tuple[bool, Any]:
    """Scrubbing somebody else's address neither labels nor stores it.

    Shipped bug: the scrubber asked for the label of every address it met, and
    asking allocated one -- so a colleague's address in a transcript became one of
    YOUR accounts ('<account:secondary>'), was persisted to state, and pushed the
    next real login down to secondary-N.
    """
    state = {"version": 1, "identities": {"uuid-a": _identity(E1, "primary")},
             "label_map": {E1: "primary"}}
    got = scenario("""
        from oe import accounts, redact
        other = redact.scrub("please cc " + ARGS["other"] + " on this")
        own = redact.scrub(ARGS["own"])
        emit({"other": other, "own": own,
              "labels": sorted(set(accounts.load_state()["label_map"].values()))})
    """, state=state, args={"other": E4, "own": E1})
    ok = (isinstance(got, dict) and got.get("labels") == ["primary"]
          and "<account:" not in str(got.get("other")) and E4 not in str(got.get("other"))
          and got.get("own") == "<account:primary>")
    return ok, got


def check_known_label_is_not_a_ticket() -> Tuple[bool, Any]:
    """An allocated account label survives the scrubber, and the write gate
    downgrades it to 'review' instead of blocking the artifact.

    Shipped bug: 'secondary-2' matched the ticket rule and printed as '<ticket>',
    including inside the error message listing the labels you may type. The
    label in the text is deliberately NOT one this machine holds: the exemption
    is a pattern, so the verdict cannot depend on local state -- CI has none.
    The control keeps the fix honest: a real issue key is still caught.
    """
    state = {"version": 1,
             "identities": {"uuid-a": _identity(E1, "primary"),
                            "uuid-c": _identity(E3, "secondary-2")},
             "label_map": {E1: "primary", E3: "secondary-2"}}
    got = scenario("""
        from oe import redact
        emit({"label": redact.scrub("the secondary-7 account"),
              "address": redact.scrub(ARGS["third"]),
              "control": redact.scrub("see " + ARGS["ticket"]),
              "audit_label": [[f.kind, f.severity] for f in redact.audit("the secondary-7 account")],
              "audit_control": [[f.kind, f.severity] for f in redact.audit("see " + ARGS["ticket"])]})
    """, state=state, args={"third": E3, "ticket": TICKET})
    want = {"label": "the secondary-7 account", "address": "<account:secondary-2>",
            "control": "see <ticket>", "audit_label": [["ticket", "review"]],
            "audit_control": [["ticket", "block"]]}
    return got == want, got


def check_legacy_labels_migrate_without_collision() -> Tuple[bool, Any]:
    """An install that still holds 'personal'/'work' moves to the current names,
    and an address that only ever appeared in text is pruned from the map.

    'work' cannot simply become 'secondary': an install that allocated after the
    rename can hold both, and a blind rename would merge two accounts into one.
    The org-hint bucket, whose only output was a guessed 'work', goes too.
    """
    # E3 is a third real login already allocated 'secondary', so 'work' must go
    # to secondary-2. E4 never logged in -- the scrubber allocated it a label --
    # so the upgrade prunes it, and its label must not block the rename.
    state = {"version": 1,
             "identities": {"uuid-a": _identity(E1, "personal"),
                            "uuid-b": _identity(E2, "work"),
                            "uuid-c": _identity(E3, "secondary")},
             "label_map": {E1: "personal", E2: "work", E3: "secondary", E4: "secondary-2"},
             "stamped": {"s1": {"uuid": "uuid-a", "label": "personal", "ts": 0}},
             "assigned": {"s2": {"label": "work", "ts": 0}},
             "inferred": {"s3": {"hint": "org_quota", "scanned_bytes": 5}}}
    got = scenario("""
        from oe import accounts
        state = accounts.load_state()
        with open(accounts.state_path(), encoding="utf-8") as handle:
            after_read = json.load(handle)
        accounts._mutate(lambda _state: False)   # the next genuine write persists it
        with open(accounts.state_path(), encoding="utf-8") as handle:
            disk = json.load(handle)
        emit({"label_map": state["label_map"],
              "identities": {k: v["label"] for k, v in state["identities"].items()},
              "stamped": state["stamped"]["s1"]["label"],
              "assigned": state["assigned"]["s2"]["label"],
              "read_wrote": after_read.get("version") != 1,
              "disk_version": disk.get("version"),
              "disk_has_inferred": "inferred" in disk,
              "known": list(accounts.known_labels())})
    """, state=state)
    if not isinstance(got, dict) or "__error__" in got:
        return False, got
    ok = (got["label_map"] == {E1: "primary", E2: "secondary-2", E3: "secondary"}
          and got["identities"] == {"uuid-a": "primary", "uuid-b": "secondary-2",
                                    "uuid-c": "secondary"}
          and got["stamped"] == "primary" and got["assigned"] == "secondary-2"
          and not got["read_wrote"]
          and got["disk_version"] == 2 and not got["disk_has_inferred"]
          and "personal" not in got["known"] and "work" not in got["known"])
    return ok, got


def check_reading_state_never_writes_it() -> Tuple[bool, Any]:
    """Looking at labels -- loading state, listing labels, scrubbing text,
    auditing text -- leaves the state file byte-for-byte as it was.

    Caught before release, on a real machine: the one-time upgrade was persisted
    from load_state(), so a leak-gate run rewrote its user's state file before
    anybody had reviewed the change.
    """
    state = {"version": 1,
             "identities": {"uuid-a": _identity(E1, "personal")},
             "label_map": {E1: "personal", E4: "secondary"},
             "inferred": {"s3": {"hint": "org_quota", "scanned_bytes": 5}}}
    got = scenario("""
        import hashlib
        from oe import accounts, redact
        path = accounts.state_path()
        def digest():
            with open(path, "rb") as handle:
                return hashlib.sha256(handle.read()).hexdigest()
        before = digest()
        accounts.load_state()
        accounts.known_labels()
        text = "cc " + ARGS["other"] + " about secondary-2 and " + ARGS["own"]
        redact.scrub(text)
        redact.audit(text)
        emit(before == digest())
    """, state=state, args={"other": E4, "own": E1})
    return got is True, got


def check_legacy_config_pin_maps_to_primary() -> Tuple[bool, Any]:
    """The old `accounts.personal_email` key still means 'this one is primary',
    and every other address is allocated around it instead of becoming 'work'."""
    got = scenario("""
        from oe import accounts, paths
        base = paths.load_config()
        paths.load_config = lambda: dict(base, accounts={"personal_email": ARGS["own"]})
        emit([accounts.label_for_email(ARGS["own"]),
              accounts.label_for_email(ARGS["other"])])
    """, state={"version": 1}, args={"own": E1, "other": E4})
    return got == ["primary", "secondary"], got


def check_scan_reports_what_the_cap_dropped() -> Tuple[bool, Any]:
    """A capped scan says how many sessions existed, not only how many it kept.

    Shipped bug: max_sessions silently truncated the oldest sessions, so every
    total built on the scan -- the all-time figure, the account rollup, the
    dashboard -- quietly became "the most recent N" with nothing saying so.
    """
    got = scenario("""
        from oe import ledger, paths
        base = paths.load_config()
        scan = dict(base.get("scan") or {}, max_sessions=3)
        paths.load_config = lambda: dict(base, scan=scan)
        rows = ledger.scan_sessions()
        emit({"rows": len(rows), "found": getattr(rows, "found", None),
              "cap": getattr(rows, "cap", None)})
    """, sessions=5)
    return got == {"rows": 3, "found": 5, "cap": 3}, got


def check_sessions_footer_names_its_scope() -> Tuple[bool, Any]:
    """`oe sessions --limit 2` says it is showing 2 OF the sessions there are.

    Shipped bug: the footer led with '2 sessions', which reads as a total, and
    put '(listed rows only)' at the end of the line where a narrow pane drops it.
    """
    out = cli(["sessions", "--limit", "2"], sessions=5)
    footer = [line.strip() for line in out.splitlines() if "session" in line and "$" in line]
    return any(line.startswith("2 of 5 sessions") for line in footer), footer or out[-400:]


def check_palette_is_readable_on_light_backgrounds() -> Tuple[bool, Any]:
    """No palette colour is a fixed near-white.

    Shipped bug: labels printed in 256-colour 255 vanished on a light terminal.
    A source check, and it knows it: it proves no constant is near-white, not
    that every call site picked a sensible one.
    """
    text = (ROOT / "bin" / "oe").read_text(encoding="utf-8")
    bad = [m.group(0) for m in re.finditer(r'^[A-Z_]+ = "38;5;(\d+)"', text, re.M)
           if 250 <= int(m.group(1)) <= 255]
    return not bad, bad


CHECKS: List[Callable[[], Tuple[bool, Any]]] = [
    check_recorded_owner_with_allocated_label,
    check_assign_accepts_allocated_label,
    check_scrub_does_not_allocate_labels,
    check_known_label_is_not_a_ticket,
    check_legacy_labels_migrate_without_collision,
    check_reading_state_never_writes_it,
    check_legacy_config_pin_maps_to_primary,
    check_scan_reports_what_the_cap_dropped,
    check_sessions_footer_names_its_scope,
    check_palette_is_readable_on_light_backgrounds,
]


def main() -> int:
    failed = 0
    for check in CHECKS:
        try:
            ok, seen = check()
        except Exception as exc:  # a crashing check is a failing check
            ok, seen = False, f"{type(exc).__name__}: {exc}"
        name = check.__name__[len("check_"):].replace("_", " ")
        print(f"  [{'PASS' if ok else 'FAIL'}] {name}")
        if not ok:
            failed += 1
            print("         saw: " + json.dumps(seen, default=str)[:600])
    print(f"\n{len(CHECKS) - failed}/{len(CHECKS)} regression checks passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
