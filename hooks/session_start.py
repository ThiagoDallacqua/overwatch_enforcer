#!/usr/bin/env python3
"""SessionStart -> create the session's report dir, record meta, start the watcher.

The watcher is the background process that keeps report.html current while the
session runs. It is started detached (double fork + setsid) so that Claude Code
never waits on it and killing the session never kills it mid-write; its stdio
goes to the per-session watcher log.

Everything is wrapped so a failure here can never take the session with it, and
stdout is redirected to /dev/null on entry: a SessionStart hook's stdout is fed
back into the model's context, so the accounting body must never reach it.

The one deliberate exception is the retrieval hint, emitted after main() to the
stashed real stdout as a single hook JSON object: one line of
`hookSpecificOutput.additionalContext`, which the model is charged for over the
whole session and which exists to offer it a cheaper option than reading a whole
file.
"""

import os
import sys
import time

# Derived, never hardcoded: hooks/<this file> -> the install root is two levels
# up. An absolute literal here is what makes a tool work on exactly one machine.
# OE_INSTALL_ROOT overrides it for a hook script copied out of the tree.
INSTALL_ROOT = os.environ.get("OE_INSTALL_ROOT") or os.path.dirname(
    os.path.dirname(os.path.abspath(__file__)))


# The real stdout, stashed before main() is silenced. SessionStart's stdout is
# fed back into the model, so the body of this hook must never reach it -- but
# the retrieval hint has one deliberate JSON object to put there, and it needs a
# handle that main() cannot have polluted.
_REAL_STDOUT = sys.stdout


def _silence_stdout() -> None:
    try:
        sys.stdout = open(os.devnull, "w")
    except Exception:
        pass


def _read_payload() -> dict:
    """stdin, once. main() and the hint emitter both need it; it is not seekable."""
    import json
    try:
        payload = json.loads(sys.stdin.read() or "{}")
    except Exception:
        payload = {}
    return payload if isinstance(payload, dict) else {}


_PAYLOAD = _read_payload()


def _spawn_detached(argv, log_path: str) -> None:
    """Double-fork so the child reparents to init and outlives this hook."""
    try:
        if os.fork() != 0:
            # Reap the intermediate child (it exits immediately) so this hook
            # does not leave a zombie behind for the moment it stays alive.
            try:
                os.waitpid(-1, 0)
            except Exception:
                pass
            return
    except OSError:
        return
    # --- intermediate child ---
    try:
        os.setsid()
    except Exception:
        pass
    try:
        if os.fork() != 0:
            os._exit(0)
    except OSError:
        os._exit(0)
    # --- grandchild: reparented to init ---
    try:
        null = os.open(os.devnull, os.O_RDONLY)
        os.dup2(null, 0)
        log = os.open(log_path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o644)
        os.dup2(log, 1)
        os.dup2(log, 2)
        for fd in (null, log):
            if fd > 2:
                os.close(fd)
        os.chdir(INSTALL_ROOT)
        os.environ["PYTHONPATH"] = INSTALL_ROOT + os.pathsep + os.environ.get("PYTHONPATH", "")
        os.execv(argv[0], argv)
    except Exception:
        pass
    os._exit(0)


def _watcher_already_running(pidfile) -> bool:
    """Fallback-only liveness check. The pidfile is JSON when the watcher wrote
    it, a bare pid when this fallback did; accept either."""
    try:
        text = pidfile.read_text()
        try:
            import json as _json
            pid = int((_json.loads(text) or {}).get("pid") or 0)
        except Exception:
            pid = int(text.split()[0])
        if not pid:
            return False
    except Exception:
        return False
    try:
        os.kill(pid, 0)
        return True
    except Exception:
        try:
            pidfile.unlink()
        except Exception:
            pass
        return False


def main() -> None:
    import json

    payload = _PAYLOAD

    if INSTALL_ROOT not in sys.path:
        sys.path.insert(0, INSTALL_ROOT)
    from oe import paths  # noqa: E402  (deliberately after the path fix-up)
    from oe import redact  # noqa: E402  (meta.json is an artifact; see below)

    session_id = str(payload.get("session_id") or "").strip()
    transcript = str(payload.get("transcript_path") or "").strip()
    if not transcript and session_id:
        found = paths.find_transcript(session_id)
        transcript = str(found) if found else ""
    if not session_id and transcript:
        session_id = os.path.basename(transcript).rsplit(".", 1)[0]
    if not session_id:
        return

    from datetime import datetime, timezone

    now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    report_dir = paths.session_report_dir(session_id)
    meta_path = report_dir / "meta.json"

    # Resumes and forks re-fire SessionStart for a session we already know, so
    # keep the first-seen stamp and append the source instead of overwriting.
    meta = {}
    try:
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
        if not isinstance(meta, dict):
            meta = {}
    except Exception:
        meta = {}

    starts = meta.get("starts") if isinstance(meta.get("starts"), list) else []
    starts.append({
        "ts": now,
        "source": payload.get("source"),
        "model": payload.get("model"),
        "permission_mode": payload.get("permission_mode"),
        "context_tokens": payload.get("context_tokens"),
        "seconds_since_last_response": payload.get("seconds_since_last_response"),
        "agent_type": payload.get("agent_type"),
    })
    # meta.json lives in the session's report directory, which is the tree the
    # user shares, so it may not carry the session id, the cwd, the transcript
    # path or the session title (a title is prompt text). The real identity goes
    # to the LOCAL map instead, where `oe whois` can reach it.
    slug = paths.project_of(transcript) if transcript else None
    meta.pop("session_id", None)
    meta.pop("transcript_path", None)
    meta.pop("cwd", None)
    meta.pop("session_title", None)
    meta.update({
        "session": redact.record_local(
            session_id, title=payload.get("session_title"), project=slug,
            transcript_path=transcript or None),
        "project": redact.project_pseudonym(slug) if slug else None,
        "first_seen": meta.get("first_seen") or now,
        "last_start": now,
        "starts": starts[-20:],
    })
    try:
        # meta.json is an artifact in the session's report directory, so it gets
        # the same gate as the five report documents. The keys above are picked
        # by hand, but their VALUES come out of the hook payload, and
        # `agent_type` / `model` / `permission_mode` are strings Claude Code
        # hands us -- a project-local subagent named after a ticket is enough to
        # put one in here. On a finding this raises, the except swallows it, and
        # meta.json stays as it was: stale beats leaking.
        text = json.dumps(meta, indent=2) + "\n"
        redact.guard(text, str(meta_path))
        paths.atomic_write(meta_path, text)
    except Exception:
        pass

    if not transcript:
        return

    # Preferred: the watcher module owns the spawn and the pidfile contract
    # (including the race between two hooks starting at once), so let it.
    try:
        from oe import watcher  # noqa: WPS433 (optional dependency at runtime)
        if watcher.is_running(session_id):
            return
        watcher.start(session_id, transcript, str(paths.reports_root()))
        return
    except Exception:
        pass

    # Fallback: the module is unusable (not written yet, or broken). Start the
    # daemon ourselves through its own CLI, detached, if it exists at all.
    if _watcher_already_running(paths.watcher_pidfile(session_id)):
        return
    watcher_py = os.path.join(INSTALL_ROOT, "oe", "watcher.py")
    if os.path.exists(watcher_py):
        _spawn_detached(
            [sys.executable, watcher_py, "start", "--session-id", session_id,
             "--transcript", transcript],
            str(paths.watcher_log(session_id)),
        )


def _open_epoch(payload: dict) -> None:
    """Start a fresh residency epoch for the window this launch begins.

    Only for the sources that genuinely reset the window (startup, clear,
    compact, fork). A `resume` re-attaches to a window that still holds
    everything it held, so opening a new epoch there would erase residency the
    guard depends on and re-permit every read.

    Guarded against a duplicate: a sibling hook may also open one, and two
    epochs for one window would split residency in half. If an epoch for this
    session opened within the last 30 seconds, that IS this launch's epoch.
    """
    source = str(payload.get("source") or "")
    if source and source not in ("startup", "clear", "compact", "fork"):
        return
    session_id = str(payload.get("session_id") or "").strip()
    if not session_id:
        return
    try:
        from oe import store
        existing = store.current_epoch(session_id, create=False)
        if existing:
            info = store.epoch_info(existing) or {}
            if time.time() - float(info.get("started_ts") or 0) < 30:
                return
        store.new_epoch(session_id, reason=source or "startup",
                        pre_tokens=payload.get("context_tokens"))
    except Exception:
        pass


def _emit_hint(payload: dict) -> None:
    """The one thing this hook says out loud.

    additionalContext is charged for the whole session, so this is deliberately
    one line: the retrieval hint, which exists to give the model a cheaper
    option than reading a whole file.
    """
    import json
    try:
        from oe import retrieval
        hint = retrieval.hint()
    except Exception:
        return
    if not hint:
        return
    out = {"hookSpecificOutput": {"hookEventName": "SessionStart",
                                  "additionalContext": hint}}
    try:
        _REAL_STDOUT.write(json.dumps(out, separators=(",", ":")))
        _REAL_STDOUT.flush()
    except Exception:
        pass


_silence_stdout()
try:
    main()
except Exception:
    pass
try:
    if INSTALL_ROOT not in sys.path:
        sys.path.insert(0, INSTALL_ROOT)
    _open_epoch(_PAYLOAD)
    _emit_hint(_PAYLOAD)
except Exception:
    pass
sys.exit(0)
