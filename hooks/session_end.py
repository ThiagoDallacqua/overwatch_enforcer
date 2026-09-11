#!/usr/bin/env python3
"""SessionEnd -> stop the watcher, rebuild the report for real, refresh the dashboard.

This is the only synchronous full parse in the system: subagent transcripts
included, tool-event ndjson folded in, cost-state reconciled. It is also the only
hook allowed to be slow, which is why its configured timeout is generous.

"Generous" is not "unbounded": SIGALRM caps the work at 80% of the configured
timeout so that a pathological transcript degrades to "no final rebuild" rather
than to a hook Claude Code has to kill. Every write underneath is atomic, so an
alarm mid-flight leaves the previous report intact rather than a half-written one.
"""

import os
import signal
import sys

# Derived, never hardcoded: hooks/<this file> -> the install root is two levels
# up. An absolute literal here is what makes a tool work on exactly one machine.
# OE_INSTALL_ROOT overrides it for a hook script copied out of the tree.
INSTALL_ROOT = os.environ.get("OE_INSTALL_ROOT") or os.path.dirname(
    os.path.dirname(os.path.abspath(__file__)))
# settings.json gives this hook 180s; stop ourselves before Claude Code has to.
DEADLINE_SECONDS = 145


class _Deadline(Exception):
    pass


def _silence_stdout() -> None:
    try:
        sys.stdout = open(os.devnull, "w")
    except Exception:
        pass


def _stop_watcher(paths, session_id: str) -> None:
    """Ask the watcher to finish, then rebuild ourselves.

    Removing the pidfile is the documented shutdown signal (the loop checks it);
    SIGTERM is the follow-up for a watcher parked in its sleep.
    """
    try:
        from oe import watcher
        watcher.stop(session_id)
        return
    except Exception:
        pass
    pidfile = paths.watcher_pidfile(session_id)
    pid = None
    try:
        pid = int(pidfile.read_text().split()[0])
    except Exception:
        pid = None
    try:
        pidfile.unlink()
    except Exception:
        pass
    if pid:
        try:
            os.kill(pid, signal.SIGTERM)
        except Exception:
            pass


def main() -> None:
    import json

    try:
        payload = json.loads(sys.stdin.read() or "{}")
    except Exception:
        payload = {}
    if not isinstance(payload, dict):
        payload = {}

    if INSTALL_ROOT not in sys.path:
        sys.path.insert(0, INSTALL_ROOT)
    from oe import paths
    from oe import redact

    session_id = str(payload.get("session_id") or "").strip()
    transcript = str(payload.get("transcript_path") or "").strip()
    if not transcript and session_id:
        found = paths.find_transcript(session_id)
        transcript = str(found) if found else ""
    if not session_id and transcript:
        session_id = os.path.basename(transcript).rsplit(".", 1)[0]
    if not session_id:
        return

    _stop_watcher(paths, session_id)

    from datetime import datetime, timezone
    ended_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    report_dir = paths.session_report_dir(session_id)

    meta = {}
    try:
        meta = json.loads((report_dir / "meta.json").read_text(encoding="utf-8"))
        if not isinstance(meta, dict):
            meta = {}
    except Exception:
        meta = {}
    # Same rule as SessionStart: pseudonym in the artifact, real identity only
    # in the local map.
    meta.pop("session_id", None)
    meta.pop("transcript_path", None)
    meta.update({
        "session": redact.record_local(session_id, transcript_path=transcript or None),
        "ended_at": ended_at,
        "end_reason": payload.get("reason"),
    })
    try:
        # Same gate as the report documents: meta.json is an artifact, and this
        # merges into whatever SessionStart and the supervisor already put in
        # the file. A finding raises, the except swallows it, and the previous
        # (clean) meta.json stays -- stale beats leaking.
        text = json.dumps(meta, indent=2) + "\n"
        redact.guard(text, str(report_dir / "meta.json"))
        paths.atomic_write(report_dir / "meta.json", text)
    except Exception:
        pass

    # The live snapshot describes a session that no longer exists; leaving it
    # would make `oe watch` and the statusline show a ghost. This runs BEFORE
    # the rebuild, and unconditionally: the rebuild is the part that can fail
    # (a single malformed transcript line can raise straight out of
    # ledger.load(), and the module-level catch below would then skip everything
    # after it -- the report, the dashboard, and this unlink -- leaving the
    # ghost behind for good). Cleanup must not depend on the report succeeding.
    try:
        paths.live_snapshot_path(session_id).unlink()
    except Exception:
        pass

    if not transcript or not os.path.exists(transcript):
        return

    ledger = None
    try:
        from oe import ledger as ledger_mod
        ledger = ledger_mod.load(transcript, include_subagents=True)
    except Exception:
        ledger = None

    if ledger is not None:
        try:
            from oe import report as report_mod
            report_mod.write_report(ledger, report_dir)
        except Exception:
            # report.py absent or unhappy: still leave the machine-readable
            # payload, which is what everything else can be rebuilt from.
            try:
                text = json.dumps(redact.redact_payload(ledger.to_dict()),
                                  indent=2, default=str) + "\n"
                redact.guard(text, str(report_dir / "data.json"))
                paths.atomic_write(report_dir / "data.json", text)
            except Exception:
                pass

    try:
        from oe import dashboard as dashboard_mod
        dashboard_mod.write_dashboard(paths.reports_root())
    except Exception:
        pass

    # Refresh the rolling agent-read prior. It belongs HERE rather than in the
    # spawn hook that consumes it: this hook already has a budget and already
    # touches transcripts, whereas its consumer runs on the tool-call path where
    # a slow scan would be a correctness problem. Costs no tokens -- it is local
    # file I/O over transcripts Claude Code has already written.
    try:
        from oe import prior as prior_mod
        prior_mod.write()
    except Exception:
        pass


def _on_alarm(signum, frame):
    raise _Deadline()


_silence_stdout()
try:
    signal.signal(signal.SIGALRM, _on_alarm)
    signal.alarm(DEADLINE_SECONDS)
except Exception:
    pass
try:
    main()
except Exception:
    pass
finally:
    try:
        signal.alarm(0)
    except Exception:
        pass
sys.exit(0)
