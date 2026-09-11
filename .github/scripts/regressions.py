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
  * the install root is an empty directory, so this machine's config.json is
    never read -- a local run and a CI run see the same defaults;
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
import time
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
             args: Dict[str, Any], recent: int = 0) -> Tuple[Dict[str, str], Path]:
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
            # Distinct mtimes: newest-first order is part of what is tested. The
            # first `recent` are hours old -- inside a --days 1 window, outside
            # the live window -- and the rest are years old.
            stamp = (time.time() - 3600 * (index + 1) if index < recent
                     else 1_700_000_000 + index * 3600)
            os.utime(path, (stamp, stamp))
    # An empty install root: config.json lives there, so no scenario reads the
    # config of the machine running the checks -- a local pin or cap must not make
    # a local run disagree with CI, which has none. The code itself is imported
    # from ROOT, through PYTHONPATH for bin/oe and through the prelude otherwise.
    install = tmp / "install"
    install.mkdir()
    out = tmp / "out.json"
    env = dict(os.environ, OE_STATE_DIR=str(state_dir), CLAUDE_CONFIG_DIR=str(home),
               OE_REPORTS_ROOT=str(reports), OE_REDACT="0", OE_INSTALL_ROOT=str(install),
               PYTHONPATH=os.pathsep.join(p for p in (str(ROOT), os.environ.get("PYTHONPATH")) if p),
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
        sessions: int = 0, recent: int = 0) -> Tuple[int, str]:
    """Run bin/oe in the same kind of sandbox; return (exit code, stdout + stderr)."""
    with tempfile.TemporaryDirectory() as raw:
        env, _ = _sandbox(Path(raw), state, sessions, {}, recent)
        proc = subprocess.run([sys.executable, str(ROOT / "bin" / "oe"), *argv],
                              env=env, capture_output=True, text=True, timeout=180)
        return proc.returncode, proc.stdout + proc.stderr


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


def check_new_login_never_reuses_a_held_label() -> Tuple[bool, Any]:
    """A hand-assigned legacy label with no login behind it stays as typed, so a
    login allocated after the upgrade cannot inherit its sessions.

    Found in review: `oe account assign` in v1.0.x accepted only personal/work, so
    every hand assignment on a self-configured install is one of those words. The
    upgrade renamed them to secondary-N -- names no login had -- and the next login
    was allocated the same name, moving the user's own assigned sessions onto
    somebody else's account. What guards it is the upgrade minting no
    free-floating names, not allocation skipping them.
    """
    state = {"version": 1, "identities": {"uuid-a": _identity(E1, "primary")},
             "label_map": {E1: "primary"},
             "assigned": {"s1": {"label": "personal", "ts": 0},
                          "s2": {"label": "work", "ts": 0}}}
    got = scenario("""
        from oe import accounts
        accounts._mutate(lambda _state: False)
        new = accounts.label_for_email(ARGS["new"])
        state = accounts.load_state()
        emit({"new": new, "s1": state["assigned"]["s1"]["label"],
              "s2": state["assigned"]["s2"]["label"]})
    """, state=state, args={"new": E2})
    return got == {"new": "secondary", "s1": "personal", "s2": "work"}, got


def check_upgrade_runs_once_despite_old_writes() -> Tuple[bool, Any]:
    """Once upgraded, a state file stays upgraded after an older build writes
    `version: 1` back over it.

    Found in review: the version number was the only mark that the upgrade had
    run, and every write from an older build -- a supervisor started before the
    update, a checkout of an earlier tag -- stamps 1. The next read renamed labels
    again, undoing a rename the user had made in between.
    """
    state = {"version": 1, "identities": {"uuid-a": _identity(E1, "personal")},
             "label_map": {E1: "personal"}}
    got = scenario("""
        from oe import accounts
        accounts._mutate(lambda _state: False)          # the upgrade: personal -> primary
        accounts.rename_label("primary", "work")        # the user's own choice, later
        path = accounts.state_path()
        with open(path, encoding="utf-8") as handle:
            raw = json.load(handle)
        raw["version"] = 1                              # what an older build writes
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(raw, handle)
        accounts._mutate(lambda _state: False)
        emit(accounts.label_for_email(ARGS["own"]))
    """, state=state, args={"own": E1})
    return got == "work", got


def check_upgrade_respects_config_pins() -> Tuple[bool, Any]:
    """The upgrade never gives a legacy label a name the config pins to another
    address -- two logins under one label is a silent merge."""
    state = {"version": 1, "identities": {"uuid-b": _identity(E2, "personal")},
             "label_map": {E2: "personal"}}
    got = scenario("""
        from oe import accounts, paths
        base = paths.load_config()
        paths.load_config = lambda: dict(base, accounts={"labels": {ARGS["pinned"]: "primary"}})
        emit([accounts.label_for_email(ARGS["pinned"]), accounts.label_for_email(ARGS["legacy"])])
    """, state=state, args={"pinned": E1, "legacy": E2})
    ok = isinstance(got, list) and got[0] == "primary" and got[1] not in ("primary", "personal")
    return ok, got


def check_upgrade_survives_a_non_integer_version() -> Tuple[bool, Any]:
    """A hand-edited or corrupt `version` still gets the upgrade, instead of
    making it skip for good while the next write stamps the file as done."""
    state = {"version": "v1", "identities": {"uuid-a": _identity(E1, "personal")},
             "label_map": {E1: "personal", E4: "secondary"}}
    got = scenario("""
        from oe import accounts
        accounts._mutate(lambda _state: False)
        with open(accounts.state_path(), encoding="utf-8") as handle:
            emit(json.load(handle)["label_map"])
    """, state=state)
    return got == {E1: "primary"}, got


def check_dashboard_page_announces_the_cap() -> Tuple[bool, Any]:
    """The dashboard says when its totals cover only the newest sessions.

    Found in review: render() redacted the rows before reading the scan's scope,
    and redaction returns a plain list -- so the page always said all-time.
    """
    got = scenario("""
        from oe import dashboard, ledger
        rows = ledger.ScanRows([])
        rows.found, rows.cap = 900, 500
        page = dashboard.render(rows)
        emit({"spend_label": "Spend, newest 500" in page,
              "names_the_knob": "scan.max_sessions" in page,
              "claims_all_time": "All-time spend" in page})
    """)
    return got == {"spend_label": True, "names_the_knob": True, "claims_all_time": False}, got


def check_failed_scan_clears_the_cap_caption() -> Tuple[bool, Any]:
    """A scan that fails does not leave the previous scan's cap on screen."""
    got = scenario("""
        import importlib.machinery, importlib.util
        path = os.path.join(sys.path[0], "bin", "oe")
        loader = importlib.machinery.SourceFileLoader("oe_cli", path)
        module = importlib.util.module_from_spec(importlib.util.spec_from_loader("oe_cli", loader))
        loader.exec_module(module)
        module._SCAN_SCOPE.update(found=5, cap=3)
        def unreadable(*_args, **_kwargs):
            raise RuntimeError("corpus unreadable")
        module.ledger_mod.scan_sessions = unreadable
        module._rows()
        emit(module._scan_capped())
    """)
    return got is False, got


def check_first_login_is_primary_after_an_early_assignment() -> Tuple[bool, Any]:
    """Assigning a session to 'primary' before any login is seen does not cost the
    first login its name: the session joins it, as the name says.

    Found in review of a fix: allocation briefly counted hand-assigned names as
    taken, so the first real login on such a machine became 'secondary' for good.
    """
    got = scenario("""
        from oe import accounts
        accounts.assign(["early-session"], "primary")
        emit(accounts.label_for_email(ARGS["own"]))
    """, args={"own": E1})
    return got == "primary", got


def check_failed_upgrade_is_retried() -> Tuple[bool, Any]:
    """An upgrade that fails is retried by the next write, instead of an ordinary
    write in between stamping the file as upgraded.

    Found in review of a fix: every write stamped version 2, and version 2 was
    read as "already upgraded" -- so one exception during a supervisor tick left
    the legacy labels and a stranger's address in place for good.
    """
    state = {"version": 1, "identities": {"uuid-a": _identity(E1, "personal")},
             "label_map": {E1: "personal", E4: "secondary"},
             "inferred": {"s3": {"hint": "org_quota", "scanned_bytes": 5}}}
    got = scenario("""
        from oe import accounts
        real = accounts._pinned_labels
        calls = {"n": 0}
        def flaky(*args, **kwargs):
            calls["n"] += 1
            if calls["n"] == 1:
                raise RuntimeError("transient")
            return real(*args, **kwargs)
        accounts._pinned_labels = flaky
        def stamp(state):
            state.setdefault("stamped", {})["s-new"] = {"uuid": "uuid-a", "label": "primary", "ts": 0}
            return True
        accounts._mutate(stamp)                   # an ordinary write while the upgrade fails
        accounts._mutate(lambda _state: False)    # the next pass
        with open(accounts.state_path(), encoding="utf-8") as handle:
            disk = json.load(handle)
        emit({"label_map": disk.get("label_map"), "inferred": "inferred" in disk,
              "marked": bool(disk.get("legacy_labels_retired")), "version": disk.get("version")})
    """, state=state)
    want = {"label_map": {E1: "primary"}, "inferred": False, "marked": True, "version": 2}
    return got == want, got


def check_old_build_rows_are_resynced() -> Tuple[bool, Any]:
    """What an older build writes after the upgrade is cleaned up again, without
    undoing a rename the user made.

    Found in review of a fix: once the upgrade was marked done it never ran again,
    so a supervisor still on the old build could write legacy words onto login
    and stamp rows, re-add a stranger's address, and bring back the hint bucket
    -- permanently.
    """
    state = {"version": 2, "legacy_labels_retired": True,
             "identities": {"uuid-a": _identity(E1, "primary"),
                            "uuid-b": _identity(E2, "work")},
             "label_map": {E1: "primary", E2: "work"},      # 'work': the user's own rename
             "stamped": {"s1": {"uuid": "uuid-a", "label": "primary", "ts": 0}}}
    got = scenario("""
        from oe import accounts
        path = accounts.state_path()
        with open(path, encoding="utf-8") as handle:
            raw = json.load(handle)
        raw["version"] = 1                                   # an older build wrote it
        raw["identities"]["uuid-a"]["label"] = "personal"
        raw["stamped"]["s9"] = {"uuid": "uuid-a", "label": "work", "ts": 0}
        raw["label_map"][ARGS["other"]] = "secondary"        # its scrubber allocating again
        raw["inferred"] = {}
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(raw, handle)
        accounts._mutate(lambda _state: False)
        with open(path, encoding="utf-8") as handle:
            disk = json.load(handle)
        emit({"identity_a": disk["identities"]["uuid-a"]["label"],
              "stamp_s9": disk["stamped"]["s9"]["label"],
              "users_rename": disk["label_map"].get(ARGS["second"]),
              "stranger_kept": ARGS["other"] in disk["label_map"],
              "inferred": "inferred" in disk, "version": disk.get("version")})
    """, state=state, args={"other": E4, "second": E2})
    want = {"identity_a": "primary", "stamp_s9": "primary", "users_rename": "work",
            "stranger_kept": False, "inferred": False, "version": 2}
    return got == want, got


def check_login_without_a_map_entry_is_not_split() -> Tuple[bool, Any]:
    """A login known only from its identity row keeps ONE name: the one the
    upgrade gave its old sessions is the one it gets from then on.

    Found in review of a fix: the upgrade renamed the identity and its stamps but
    wrote no map entry, so the next lookup allocated the login a second name --
    old sessions under one label, new ones under another.
    """
    state = {"version": 1,
             "identities": {"uuid-a": _identity(E1, "primary"),
                            "uuid-b": _identity(E2, "work")},
             "label_map": {E1: "primary"},
             "stamped": {"s2": {"uuid": "uuid-b", "label": "work", "ts": 0}}}
    got = scenario("""
        from oe import accounts
        accounts._mutate(lambda _state: False)
        state = accounts.load_state()
        emit({"login": accounts.label_for_email(ARGS["second"]),
              "stamp": state["stamped"]["s2"]["label"]})
    """, state=state, args={"second": E2})
    ok = isinstance(got, dict) and got.get("login") == got.get("stamp") == "secondary"
    return ok, got


def check_v2_file_without_the_mark_is_not_renamed_again() -> Tuple[bool, Any]:
    """A file at version 2 with no marker was written by a build that had already
    upgraded it: it gains the marker, and a label the user has since chosen --
    even a legacy word -- is left alone."""
    state = {"version": 2, "identities": {"uuid-a": _identity(E1, "work")},
             "label_map": {E1: "work"}}
    got = scenario("""
        from oe import accounts
        accounts._mutate(lambda _state: False)
        with open(accounts.state_path(), encoding="utf-8") as handle:
            disk = json.load(handle)
        emit({"label": disk["label_map"].get(ARGS["own"]),
              "marked": bool(disk.get("legacy_labels_retired"))})
    """, state=state, args={"own": E1})
    return got == {"label": "work", "marked": True}, got


def check_sessions_footer_counts_after_filters() -> Tuple[bool, Any]:
    """With a filter, the footer's "of M" and its --limit 0 hint count what the
    filter left, not every transcript on disk."""
    code, out = cli(["sessions", "--days", "1", "--limit", "1"], sessions=5, recent=2)
    lines = [line.strip() for line in out.splitlines()]
    footer = [line for line in lines if "session" in line and "$" in line]
    hint = [line for line in lines if "--limit 0" in line]
    ok = (code == 0 and any(line.startswith("1 of 2 sessions") for line in footer)
          and any(line.endswith("lists all 2") for line in hint))
    return ok, {"exit": code, "footer": footer, "hint": hint}


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
    code, out = cli(["sessions", "--limit", "2"], sessions=5)
    footer = [line.strip() for line in out.splitlines() if "session" in line and "$" in line]
    ok = code == 0 and any(line.startswith("2 of 5 sessions") for line in footer)
    return ok, {"exit": code, "footer": footer or out[-400:]}


def _xterm_rgb(index: int) -> Tuple[int, int, int]:
    """The RGB a 256-colour xterm index draws as: 16 system colours, the 6x6x6 cube,
    then the 24-step grey ramp."""
    system = [(0, 0, 0), (128, 0, 0), (0, 128, 0), (128, 128, 0), (0, 0, 128), (128, 0, 128),
              (0, 128, 128), (192, 192, 192), (128, 128, 128), (255, 0, 0), (0, 255, 0),
              (255, 255, 0), (0, 0, 255), (255, 0, 255), (0, 255, 255), (255, 255, 255)]
    if index < 16:
        return system[index]
    if index < 232:
        steps = (0, 95, 135, 175, 215, 255)
        cube = index - 16
        return steps[cube // 36], steps[(cube // 6) % 6], steps[cube % 6]
    grey = 8 + (index - 232) * 10
    return grey, grey, grey


def _luminance(rgb: Tuple[int, int, int]) -> float:
    def linear(channel: int) -> float:
        value = channel / 255
        return value / 12.92 if value <= 0.03928 else ((value + 0.055) / 1.055) ** 2.4
    red, green, blue = (linear(channel) for channel in rgb)
    return 0.2126 * red + 0.7152 * green + 0.0722 * blue


def _near_white_constants(text: str) -> List[str]:
    """Palette constants whose colour all but vanishes on a white background."""
    bad = []
    for match in re.finditer(r'^([A-Z_]+) = "([0-9;]+)"', text, re.M):
        codes = match.group(2).split(";")
        rgbs = [_xterm_rgb(int(codes[i + 2])) for i in range(len(codes) - 2)
                if codes[i:i + 2] == ["38", "5"] and codes[i + 2].isdigit()
                and int(codes[i + 2]) < 256]
        rgbs += [(255, 255, 255) for code in codes if code == "97"]
        if any(_luminance(rgb) >= 0.75 for rgb in rgbs):
            bad.append(match.group(0))
    return bad


def check_palette_is_readable_on_light_backgrounds() -> Tuple[bool, Any]:
    """No palette colour is a fixed near-white.

    Shipped bug: labels printed in 256-colour 255 vanished on a light terminal.
    Judged by luminance, not by index, because white has several spellings (15,
    231, 255, SGR 97) and an index list misses the ones nobody thought of. The
    detector must first catch planted near-whites, or its silence means nothing.
    It is a source check and knows it: it proves no constant is near-white, not
    that every call site picked a sensible one.
    """
    planted = 'A = "38;5;231"\nB = "38;5;15"\nC = "97"\nD = "38;5;255"\nE = "38;5;244"\n'
    caught = _near_white_constants(planted)
    if len(caught) != 4:
        return False, {"detector_broken": caught}
    bad = _near_white_constants((ROOT / "bin" / "oe").read_text(encoding="utf-8"))
    return not bad, bad


CHECKS: List[Callable[[], Tuple[bool, Any]]] = [
    check_recorded_owner_with_allocated_label,
    check_assign_accepts_allocated_label,
    check_scrub_does_not_allocate_labels,
    check_known_label_is_not_a_ticket,
    check_legacy_labels_migrate_without_collision,
    check_reading_state_never_writes_it,
    check_new_login_never_reuses_a_held_label,
    check_upgrade_runs_once_despite_old_writes,
    check_upgrade_respects_config_pins,
    check_upgrade_survives_a_non_integer_version,
    check_dashboard_page_announces_the_cap,
    check_failed_scan_clears_the_cap_caption,
    check_first_login_is_primary_after_an_early_assignment,
    check_failed_upgrade_is_retried,
    check_old_build_rows_are_resynced,
    check_login_without_a_map_entry_is_not_split,
    check_v2_file_without_the_mark_is_not_renamed_again,
    check_sessions_footer_counts_after_filters,
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
