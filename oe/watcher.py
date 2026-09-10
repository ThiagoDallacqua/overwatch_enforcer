"""Per-session background daemon: the thread that writes the report as you work.

One watcher process per session. It is spawned detached by the SessionStart
hook, tails the session's transcripts, and keeps three artefacts current:

  1. state_dir()/<sid>.live.json  -- tiny, every tick, the only file the
     statusline is allowed to read (its whole budget is 80 ms).
  2. <reports>/sessions/<sid>/report.html + data.json -- the full document.
  3. <reports>/index.html -- the cross-session dashboard.

Two parsing paths, deliberately:

  * The TICK path is incremental. Every source file keeps a byte offset, so a
    large transcript is read once and then only its new bytes. Cost is
    proportional to what the session just produced, not to its size, which is
    what makes a 5 s poll affordable for hours.
  * The REBUILD path calls ledger.load(), which re-reads everything. That is
    the accurate, reconciled document, and it is the expensive one, so it is
    throttled: at most once per report_interval_seconds, only when new bytes
    actually arrived, and it backs itself off further on sessions where a load
    is slow (see _next_full_due) to hold the daemon's duty cycle to a small
    fraction of one core.

Nothing here may take the session down with it: every tick body is wrapped,
every failure is logged to a size-capped log, and the loop keeps going.
"""

from __future__ import annotations

import json
import os
import signal
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    from . import paths, pricing, redact
    from .ledger import _int, _line_type, _parse_ts
except ImportError:  # executed as a plain script: python3 oe/watcher.py
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from oe import paths, pricing, redact  # type: ignore
    from oe.ledger import _int, _line_type, _parse_ts  # type: ignore

SCHEMA_VERSION = 1

LOG_MAX_BYTES = 1_048_576
LOG_KEEP_BYTES = 262_144

# A single read() per source per tick is capped so that a pathological file
# cannot make one tick unbounded; the remainder is picked up next tick.
MAX_READ_PER_TICK = 64 * 1024 * 1024


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(value: Optional[datetime]) -> Optional[str]:
    return value.isoformat().replace("+00:00", "Z") if value else None


# ---------------------------------------------------------------------------
# process identity
# ---------------------------------------------------------------------------


def _proc_starttime(pid: int) -> Optional[int]:
    """Field 22 of /proc/<pid>/stat: process start time in clock ticks.

    Stored in the pidfile so a recycled PID cannot be mistaken for our daemon.
    The comm field can contain spaces and parentheses, so split after the last
    ')' rather than on the whole line.
    """
    try:
        raw = Path(f"/proc/{pid}/stat").read_text(encoding="utf-8", errors="replace")
        tail = raw[raw.rindex(")") + 2:].split()
        return int(tail[19])
    except Exception:
        return None


def _alive(pid: int) -> bool:
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return False


def read_pidfile(session_id: str) -> Optional[Dict[str, Any]]:
    try:
        return json.loads(paths.watcher_pidfile(session_id).read_text(encoding="utf-8"))
    except Exception:
        return None


def is_running(session_id: str) -> Optional[int]:
    """PID of the live watcher for this session, or None (clearing a stale file).

    'Matches' means: the PID is alive AND its /proc start time is the one we
    recorded. A claim with no PID yet is an in-flight start(), honoured for a
    few seconds so two hooks racing cannot both spawn a daemon.
    """
    record = read_pidfile(session_id)
    if not record:
        return None
    pid = _int(record.get("pid"))
    if not pid:
        claimed = float(record.get("claimed_epoch") or 0.0)
        if time.time() - claimed < 15.0:
            return -1  # someone is mid-spawn; treat as running, pid unknown
        _clear_pidfile(session_id)
        return None
    if not _alive(pid):
        _clear_pidfile(session_id)
        return None
    recorded = record.get("proc_starttime")
    actual = _proc_starttime(pid)
    if recorded is not None and actual is not None and int(recorded) != int(actual):
        _clear_pidfile(session_id)  # PID reused by an unrelated process
        return None
    if record.get("supervisor") and pid != os.getpid():
        # The start-time check above is the recycled-PID guard, and it is the one
        # thing that needs /proc: without it _proc_starttime() returns None, the
        # comparison is skipped, and a claim left by a SIGKILLed supervisor whose
        # PID has since been handed to any unrelated process reads as "still
        # owned" forever -- the session is then skipped on every discover pass
        # and no report is ever written.
        #
        # A supervisor-stamped claim carries its own answer, though, and it needs
        # no /proc: there is at most ONE supervisor per reports root, held by an
        # flock the kernel drops even on SIGKILL. So a claim that says
        # "supervisor" and names a PID that is not the supervisor is stale by
        # construction. -1 means "held, pidfile not landed yet" -- genuinely
        # unknown, so leave that claim alone rather than steal it.
        try:
            owner = supervisor_running()
        except Exception:
            owner = -1
        if owner is None or (owner > 0 and owner != pid):
            _clear_pidfile(session_id)
            return None
    return pid


def _clear_pidfile(session_id: str) -> None:
    try:
        paths.watcher_pidfile(session_id).unlink()
    except OSError:
        pass


def _claim_pidfile(session_id: str, transcript_path: str) -> bool:
    """Atomically reserve the right to spawn. False when someone else holds it."""
    path = paths.watcher_pidfile(session_id)
    payload = json.dumps({
        "pid": None,
        "session_id": session_id,
        "transcript": str(transcript_path),
        "claimed_by": os.getpid(),
        "claimed_epoch": time.time(),
    })
    try:
        fd = os.open(str(path), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o644)
    except FileExistsError:
        return False
    except OSError:
        return False
    try:
        os.write(fd, payload.encode("utf-8"))
    finally:
        os.close(fd)
    return True


def _upgrade_claim(session_id: str, transcript_path: str, reports_root: Path) -> bool:
    """Turn our claim into a real pidfile. False when the claim was revoked.

    stop() deletes the pidfile; if that happened while we were forking, the
    daemon must not resurrect it, or a stop would leave an orphan behind.
    """
    if not paths.watcher_pidfile(session_id).exists():
        return False
    _write_pidfile(session_id, transcript_path, reports_root)
    return True


def _write_pidfile(session_id: str, transcript_path: str, reports_root: Path,
                   extra: Optional[Dict[str, Any]] = None) -> None:
    """Publish the owner of this session's tail loop.

    `extra` exists for the supervisor, which owns many sessions from ONE
    process: it stamps {"supervisor": True} so stop() can revoke a single
    session without SIGTERMing the process that is tailing all the others.
    """
    record: Dict[str, Any] = {
        "pid": os.getpid(),
        "proc_starttime": _proc_starttime(os.getpid()),
        "session_id": session_id,
        "transcript": str(transcript_path),
        "reports_root": str(reports_root),
        "started_at": _iso(_now()),
        "started_epoch": time.time(),
    }
    if extra:
        record.update(extra)
    paths.atomic_write(paths.watcher_pidfile(session_id), json.dumps(record, indent=2) + "\n")


# ---------------------------------------------------------------------------
# incremental ingest
# ---------------------------------------------------------------------------


class _Cursor:
    """A byte offset into one transcript file, plus the half-written tail.

    The last line of a live transcript is routinely incomplete; we hold the
    fragment in memory and only hand a line to the parser once its newline has
    arrived, so a torn write is never mistaken for a corrupt record.
    """

    __slots__ = ("path", "origin", "agent_id", "offset", "inode", "partial", "size", "mtime")

    def __init__(self, path: Path, origin: str, agent_id: Optional[str] = None) -> None:
        self.path = path
        self.origin = origin
        self.agent_id = agent_id
        self.offset = 0
        self.inode: Optional[int] = None
        self.partial = b""
        self.size = 0
        self.mtime = 0.0

    def reset(self) -> None:
        self.offset = 0
        self.partial = b""
        self.inode = None

    def read_new(self) -> tuple[List[str], bool]:
        """(complete new lines, truncated?).

        Truncated is True when the file shrank or was replaced (fork, clear,
        rotation); the caller must then rebuild all aggregate state, because
        records we already counted may no longer be in the file.
        """
        try:
            stat = self.path.stat()
        except OSError:
            return [], False
        truncated = False
        if self.inode is not None and (stat.st_ino != self.inode or stat.st_size < self.offset):
            truncated = True
            self.reset()
        self.inode = stat.st_ino
        self.size = stat.st_size
        self.mtime = stat.st_mtime
        if stat.st_size <= self.offset:
            return [], truncated
        try:
            with open(self.path, "rb") as handle:
                handle.seek(self.offset)
                chunk = handle.read(MAX_READ_PER_TICK)
        except OSError:
            return [], truncated
        if not chunk:
            return [], truncated
        self.offset += len(chunk)
        data = self.partial + chunk
        self.partial = b""
        if not data.endswith(b"\n"):
            cut = data.rfind(b"\n")
            if cut < 0:
                self.partial = data
                return [], truncated
            self.partial = data[cut + 1:]
            data = data[:cut + 1]
        text = data.decode("utf-8", errors="replace")
        return [line for line in text.split("\n") if line], truncated


def _compact_usage(usage: Dict[str, Any]) -> Dict[str, Any]:
    """Keep only the billing fields.

    One of these is retained per request for the daemon's whole life, and the
    raw record carries an iterations[] array that can hold hundreds of entries.
    """
    out: Dict[str, Any] = {
        "input_tokens": _int(usage.get("input_tokens")),
        "output_tokens": _int(usage.get("output_tokens")),
        "cache_creation_input_tokens": _int(usage.get("cache_creation_input_tokens")),
        "cache_read_input_tokens": _int(usage.get("cache_read_input_tokens")),
    }
    creation = usage.get("cache_creation")
    if isinstance(creation, dict):
        out["cache_creation"] = {
            "ephemeral_5m_input_tokens": _int(creation.get("ephemeral_5m_input_tokens")),
            "ephemeral_1h_input_tokens": _int(creation.get("ephemeral_1h_input_tokens")),
        }
    server = usage.get("server_tool_use")
    if isinstance(server, dict):
        out["server_tool_use"] = {
            "web_search_requests": _int(server.get("web_search_requests")),
            "web_fetch_requests": _int(server.get("web_fetch_requests")),
        }
    details = usage.get("output_tokens_details")
    if isinstance(details, dict):
        out["output_tokens_details"] = {"thinking_tokens": _int(details.get("thinking_tokens"))}
    # inference_geo is a BILLING field, not metadata: pricing.price() applies
    # the binary's `Tee` multiplier (US inference bills tokens at 1.1x). Drop it
    # here and the daemon's dollars silently diverge from the ledger's.
    for key in ("speed", "service_tier", "inference_geo"):
        value = usage.get(key)
        if value:
            out[key] = value
    return out


# Slack between a cost-state startTime and the first request it covers, in
# seconds. Mirrors ledger._RUN_START_GRACE; a genuine resume is hours away.
_RUN_START_GRACE_SECONDS = 120.0

_TOTAL_KEYS = (
    "calls", "requests_main", "requests_subagent", "requests_workflow",
    "input_tokens", "output_tokens", "thinking_tokens",
    "cache_write_5m_tokens", "cache_write_1h_tokens", "cache_read_tokens",
    "web_search_requests", "web_fetch_requests",
    "errors", "aborted", "unpriced_calls",
)


class _Aggregator:
    """Running totals maintained as lines arrive, never recomputed from scratch.

    Each requestId keeps its priced contribution; when a later line for the
    same request carries a bigger output_tokens (sidechain files store growing
    mid-stream snapshots, and taking the first one under-counts output ~3x)
    the old contribution is subtracted and the new one added. That keeps a tick
    O(new lines) instead of O(session).
    """

    def __init__(self) -> None:
        self.requests: Dict[str, Dict[str, Any]] = {}
        self.totals: Dict[str, Any] = {key: 0 for key in _TOTAL_KEYS}
        self.totals["cost_usd"] = 0.0
        self.by_model: Dict[str, Dict[str, Any]] = {}
        self.tool_counts: Dict[str, int] = {}
        self.tool_ids: set = set()
        self.cost_states: Dict[int, Dict[str, Any]] = {}
        # epoch-second -> dollars priced at that second. The daemon never keeps
        # per-call rows, but the covered/uncovered split needs to know how much
        # spend predates the earliest cost-state checkpoint, and a checkpoint
        # can arrive long after the calls it does NOT cover. A few thousand
        # float buckets is the cheapest way to answer that after the fact.
        self.cost_by_second: Dict[int, float] = {}
        self.prompt_ids: set = set()
        self.prompt_lines = 0
        self.context_tokens = 0
        self.context_model: Optional[str] = None
        self.context_ts: Optional[datetime] = None
        self.first_ts: Optional[datetime] = None
        self.last_ts: Optional[datetime] = None
        self.title: Optional[str] = None
        self.last_prompt: Optional[str] = None
        self.cwd: Optional[str] = None
        self.git_branch: Optional[str] = None
        self.cc_version: Optional[str] = None
        self.slug: Optional[str] = None
        self.effort: Optional[str] = None
        self.lines_seen = 0
        self.bad_lines = 0

    # -- request bookkeeping ------------------------------------------------

    def _apply(self, record: Dict[str, Any], sign: int) -> None:
        totals = self.totals
        usage = record["usage"]
        cost = record["cost"]
        five, hour = pricing.split_cache_creation(usage)
        details = usage.get("output_tokens_details") or {}
        server = usage.get("server_tool_use") or {}
        totals["calls"] += sign
        totals["requests_" + record["origin"]] += sign
        totals["input_tokens"] += sign * _int(usage.get("input_tokens"))
        totals["output_tokens"] += sign * _int(usage.get("output_tokens"))
        totals["thinking_tokens"] += sign * _int(details.get("thinking_tokens"))
        totals["cache_write_5m_tokens"] += sign * five
        totals["cache_write_1h_tokens"] += sign * hour
        totals["cache_read_tokens"] += sign * _int(usage.get("cache_read_input_tokens"))
        totals["web_search_requests"] += sign * _int(server.get("web_search_requests"))
        totals["web_fetch_requests"] += sign * _int(server.get("web_fetch_requests"))
        totals["errors"] += sign if record["is_error"] else 0
        totals["aborted"] += sign if record["aborted"] else 0
        totals["unpriced_calls"] += sign if cost.get("unpriced") else 0
        amount = float(cost.get("total_usd") or 0.0)
        totals["cost_usd"] += sign * amount
        bucket = record.get("second")
        if bucket is not None and amount:
            self.cost_by_second[bucket] = self.cost_by_second.get(bucket, 0.0) + sign * amount

        model = record["model"]
        row = self.by_model.get(model)
        if row is None:
            row = {
                "model": model,
                "display_name": pricing.display_name(model),
                "tier": cost.get("tier"),
                "calls": 0, "input_tokens": 0, "output_tokens": 0,
                "cache_write_tokens": 0, "cache_read_tokens": 0, "cost_usd": 0.0,
            }
            self.by_model[model] = row
        row["calls"] += sign
        row["input_tokens"] += sign * _int(usage.get("input_tokens"))
        row["output_tokens"] += sign * _int(usage.get("output_tokens"))
        row["cache_write_tokens"] += sign * (five + hour)
        row["cache_read_tokens"] += sign * _int(usage.get("cache_read_input_tokens"))
        row["cost_usd"] += sign * float(cost.get("total_usd") or 0.0)

    def add_request(self, request_id: str, obj: Dict[str, Any], usage: Dict[str, Any],
                    origin: str) -> None:
        message = obj.get("message") or {}
        stamp = _parse_ts(obj.get("timestamp"))
        second = int(stamp.timestamp()) if stamp else None
        model = message.get("model") or ""
        speed = usage.get("speed") or "standard"
        is_error = bool(obj.get("isApiErrorMessage") or obj.get("apiErrorStatus")
                        or obj.get("error"))
        aborted = bool(obj.get("isAbortedMidStream") or obj.get("truncatedAfterOutput"))
        output = _int(usage.get("output_tokens"))

        existing = self.requests.get(request_id)
        if existing is not None and output <= existing["output"]:
            # A repeat of a request we already have. Only the sticky flags can
            # still change (an error can be reported on a later line).
            if (is_error and not existing["is_error"]) or (aborted and not existing["aborted"]):
                self._apply(existing, -1)
                existing["is_error"] = existing["is_error"] or is_error
                existing["aborted"] = existing["aborted"] or aborted
                self._apply(existing, +1)
            return

        compact = _compact_usage(usage)
        record = {
            "usage": compact,
            "cost": pricing.price(compact, model, speed),
            "model": pricing.normalize_model(model) or (model or "unknown"),
            "origin": origin,
            "output": output,
            "is_error": is_error or (existing["is_error"] if existing else False),
            "aborted": aborted or (existing["aborted"] if existing else False),
            "second": second if second is not None else (existing or {}).get("second"),
        }
        if existing is not None:
            self._apply(existing, -1)
        self.requests[request_id] = record
        self._apply(record, +1)

    # -- line dispatch ------------------------------------------------------

    def add_line(self, raw: str, origin: str, is_main: bool) -> None:
        self.lines_seen += 1
        if len(raw) < 12:
            return
        kind = _line_type(raw)
        if kind == "assistant":
            self._on_assistant(raw, origin, is_main)
        elif kind == "cost-state":
            self._on_cost_state(raw)
        elif kind == "ai-title":
            self.title = self._field(raw, "aiTitle") or self.title
        elif kind == "last-prompt":
            self.prompt_lines += 1
            self.last_prompt = self._field(raw, "lastPrompt") or self.last_prompt
        # Everything else (user/tool_result/attachment/file-history) is skipped
        # without parsing: those lines carry no billing data and are the bulk of
        # a transcript's bytes.

    def _field(self, raw: str, key: str) -> Optional[str]:
        try:
            value = (json.loads(raw) or {}).get(key)
        except Exception:
            self.bad_lines += 1
            return None
        return str(value) if value else None

    def _on_cost_state(self, raw: str) -> None:
        try:
            state = json.loads(raw)
        except Exception:
            self.bad_lines += 1
            return
        if not isinstance(state, dict):
            return
        start = _int(state.get("startTime"))
        previous = self.cost_states.get(start)
        # cost-state is per RUN: a resumed session appends a fresh series under
        # a new startTime, so keep the latest checkpoint of each run and sum.
        if previous is None or _int(state.get("totalDuration")) >= _int(
                previous.get("totalDuration")):
            self.cost_states[start] = state

    def _on_assistant(self, raw: str, origin: str, is_main: bool) -> None:
        try:
            obj = json.loads(raw)
        except Exception:
            self.bad_lines += 1
            return
        if not isinstance(obj, dict):
            return
        message = obj.get("message") or {}
        usage = message.get("usage")
        timestamp = _parse_ts(obj.get("timestamp"))
        if timestamp:
            if self.first_ts is None or timestamp < self.first_ts:
                self.first_ts = timestamp
            if self.last_ts is None or timestamp > self.last_ts:
                self.last_ts = timestamp
        if is_main:
            self.cwd = obj.get("cwd") or self.cwd
            self.git_branch = obj.get("gitBranch") or self.git_branch
            self.cc_version = obj.get("version") or self.cc_version
            self.slug = obj.get("slug") or self.slug
            self.effort = obj.get("effort") or self.effort
        prompt_id = obj.get("promptId") or obj.get("prompt_id")
        if prompt_id:
            self.prompt_ids.add(prompt_id)

        for block in (message.get("content") or []):
            if isinstance(block, dict) and block.get("type") == "tool_use":
                key = block.get("id") or f"{obj.get('uuid')}:{block.get('name')}"
                if key in self.tool_ids:
                    continue
                self.tool_ids.add(key)
                name = block.get("name") or "unknown"
                self.tool_counts[name] = self.tool_counts.get(name, 0) + 1

        if not isinstance(usage, dict):
            return
        request_id = obj.get("requestId") or obj.get("uuid")
        if not request_id:
            return
        self.add_request(str(request_id), obj, usage, origin)

        # The context meter is the LAST main-loop message's carried tokens --
        # exactly how Claude Code computes it. Sidechains have their own window.
        if is_main and not obj.get("isSidechain"):
            carried = (_int(usage.get("input_tokens"))
                       + _int(usage.get("cache_creation_input_tokens"))
                       + _int(usage.get("cache_read_input_tokens")))
            if carried:
                self.context_tokens = carried
                self.context_model = message.get("model") or self.context_model
                self.context_ts = timestamp or self.context_ts

    # -- derived ------------------------------------------------------------

    @property
    def reported_usd(self) -> Optional[float]:
        """Sum of every run's cost-state checkpoint, or None.

        float() is guarded per run: this property is reached from
        snapshot_totals() -> live_payload() -> write_live(), and write_live()
        catches the exception and moves on -- so one cost-state line whose
        totalCostUSD is not a number would stop the live snapshot being written
        for the rest of the daemon's life, silently demoting the status line to
        its stdin fallback. Skip the unusable checkpoint, keep the rest.
        """
        if not self.cost_states:
            return None
        total = 0.0
        for state in self.cost_states.values():
            try:
                total += float(state.get("totalCostUSD") or 0.0)
            except (TypeError, ValueError):
                continue
        return total

    def snapshot_totals(self) -> Dict[str, Any]:
        totals = dict(self.totals)
        totals["cache_write_tokens"] = (totals["cache_write_5m_tokens"]
                                        + totals["cache_write_1h_tokens"])
        totals["total_tokens"] = (totals["input_tokens"] + totals["output_tokens"]
                                  + totals["cache_write_tokens"] + totals["cache_read_tokens"])
        totals["tool_calls"] = sum(self.tool_counts.values())
        reported = self.reported_usd
        uncovered, uncovered_calls = self.uncovered_split()
        totals["cost_usd_reported"] = reported
        totals["cost_usd_uncovered"] = round(uncovered, 6)
        totals["uncovered_calls"] = uncovered_calls
        # Same rule as SessionLedger.totals: a checkpoint only accounts for its
        # own run, so anything priced before the earliest checkpoint has to be
        # ADDED to the reported figure, not replaced by it. Without this a
        # resumed session's statusline reads a small fraction of what has been spent.
        totals["cost_usd_authoritative"] = (totals["cost_usd"] if reported is None
                                            else reported + uncovered)
        totals["cost_fully_reported"] = reported is not None and not uncovered_calls
        return totals

    def uncovered_split(self) -> tuple:
        """(dollars, requests) priced before the earliest checkpoint's window.

        Buckets are whole seconds, so a bucket counts as uncovered only when it
        ENDS before the window opens -- the split never over-claims.
        """
        starts = [s for s in self.cost_states if s]
        if not starts or not self.cost_by_second:
            return 0.0, 0
        window = min(starts) / 1000.0 - _RUN_START_GRACE_SECONDS
        uncovered = 0.0
        seconds = 0
        for bucket, amount in self.cost_by_second.items():
            if bucket + 1 <= window:
                uncovered += amount
                seconds += 1
        if uncovered <= 0.0:
            return 0.0, 0
        calls = sum(1 for r in self.requests.values()
                    if r.get("second") is not None and r["second"] + 1 <= window)
        return uncovered, calls


# ---------------------------------------------------------------------------
# the daemon
# ---------------------------------------------------------------------------


class Watcher:
    """The loop. One instance per process; see module docstring for the design."""

    def __init__(self, session_id: str, transcript_path: str | os.PathLike,
                 reports_root: Optional[str | os.PathLike] = None,
                 refresh_seconds: Optional[float] = None,
                 idle_exit_seconds: Optional[float] = None,
                 report_interval_seconds: Optional[float] = None,
                 dashboard_interval_seconds: Optional[float] = None,
                 rescan_seconds: Optional[float] = None) -> None:
        if reports_root:
            paths.set_reports_root(reports_root)
        config = paths.load_config()
        watcher_cfg = config.get("watcher") or {}
        self.config = config
        self.session_id = str(session_id)
        self.transcript_path = Path(transcript_path)
        self.reports_root = paths.reports_root()
        self.refresh = float(refresh_seconds or config.get("refresh_seconds") or 5)
        self.idle_exit = float(idle_exit_seconds or config.get("idle_exit_seconds") or 1800)
        self.report_interval = float(report_interval_seconds
                                     or watcher_cfg.get("report_interval_seconds") or 15)
        # A turn that has just finished is exactly when the report gets read, so
        # a short quiet period triggers one rebuild ahead of the interval. It
        # cannot fire twice for the same quiet period (the dirty flag clears)
        # and never during streaming, when quiet stays below settle_seconds.
        self.settle_seconds = float(watcher_cfg.get("settle_seconds") or 3)
        self.min_full_gap = float(watcher_cfg.get("min_full_gap_seconds") or 8)
        self.dashboard_interval = float(dashboard_interval_seconds
                                        or watcher_cfg.get("dashboard_interval_seconds") or 30)
        self.rescan_seconds = float(rescan_seconds or watcher_cfg.get("rescan_seconds") or 10)
        self.log_path = paths.watcher_log(self.session_id)
        self.report_dir = paths.session_report_dir(self.session_id)
        # The name a Stop hook writes: "<sid>.checkpoint.json" in the state
        # directory. v1.0.0 registers no Stop hook, so this path normally never
        # appears and _checkpoint_touched() simply stays False; anything that
        # does write it must use exactly this name or the signal is lost.
        self.checkpoint_path = (
            paths.state_dir()
            / f"{paths.safe_session_id(self.session_id)}.checkpoint.json")

        self.agg = _Aggregator()
        self.cursors: Dict[str, _Cursor] = {}
        self.cursors[str(self.transcript_path)] = _Cursor(self.transcript_path, "main")

        self._stop = False
        self._stop_reason = "unknown"
        self._last_discover = 0.0
        self._last_full = 0.0
        self._last_dashboard = 0.0
        self._next_full_due = 0.0
        self._last_checkpoint_mtime = 0.0
        self._dirty = True
        self.last_change = time.time()
        self.ticks = 0
        self.full_builds = 0
        self.bytes_ingested = 0
        self.tick_ms: List[float] = []
        self.full_ms: List[float] = []
        self.last_report: Dict[str, Any] = {}
        self.cost_samples: List[tuple] = []
        self.started_epoch = time.time()

    # -- logging ------------------------------------------------------------

    def log(self, message: str, level: str = "info") -> None:
        line = f"{_iso(_now())} {level:<5} {message}\n"
        try:
            with open(self.log_path, "a", encoding="utf-8") as handle:
                handle.write(line)
        except Exception:
            pass

    def _truncate_log(self) -> None:
        """Keep the log bounded: a watcher can live for a working day.

        Called from every tick rather than metered against our own writes: the
        daemon's stdout and stderr are redirected into this same file, so
        anything it calls can grow it without our bookkeeping ever noticing.
        A stat() per tick costs microseconds.
        """
        try:
            if self.log_path.stat().st_size <= LOG_MAX_BYTES:
                return
            with open(self.log_path, "rb") as handle:
                handle.seek(-LOG_KEEP_BYTES, os.SEEK_END)
                tail = handle.read()
            cut = tail.find(b"\n")
            tail = tail[cut + 1:] if cut >= 0 else tail
            # Truncate IN PLACE rather than rename a replacement over the top.
            # _daemon_body() dup2'd fd 1 and fd 2 onto this file at start-up, so
            # a rename would leave the daemon's stdout/stderr pointing at an
            # unlinked inode: every traceback after the first rotation would be
            # invisible and would still hold disk until the process exited.
            # O_APPEND on both ends means the seek position does not matter.
            with open(self.log_path, "r+b") as handle:
                handle.seek(0)
                handle.write(b"... log truncated ...\n")
                handle.write(tail)
                handle.truncate()
        except Exception:
            pass

    # -- sources ------------------------------------------------------------

    def discover(self, force: bool = False) -> int:
        """Pick up subagent transcripts that appeared mid-session.

        Agent files land in two places: subagents/agent-<id>.jsonl and, for
        Workflow-tool agents, subagents/workflows/wf_<id>/agent-<id>.jsonl.
        Missing the nested ones under-counts a heavy session several-fold, so
        this rglobs the whole subtree.
        """
        now = time.time()
        if not force and (now - self._last_discover) < self.rescan_seconds:
            return 0
        self._last_discover = now
        dirs = paths.session_dirs(self.transcript_path)
        subagents = dirs.get("subagents")
        if not subagents:
            return 0
        try:
            found = sorted(subagents.rglob("agent-*.jsonl"))
        except OSError:
            return 0
        added = 0
        for path in found:
            key = str(path)
            if key in self.cursors:
                continue
            origin = "workflow" if any(p.startswith("wf_") for p in path.parts) else "subagent"
            agent_id = path.name[len("agent-"):-len(".jsonl")]
            self.cursors[key] = _Cursor(path, origin, agent_id)
            added += 1
        if added:
            self.log(f"discovered {added} new agent transcript(s), {len(self.cursors)} sources")
        return added

    def ingest(self) -> int:
        """Read the new bytes of every source. Returns bytes consumed."""
        consumed = 0
        truncated = False
        for cursor in list(self.cursors.values()):
            before = cursor.offset
            lines, was_truncated = cursor.read_new()
            truncated = truncated or was_truncated
            if was_truncated:
                break
            consumed += max(0, cursor.offset - before)
            is_main = cursor.origin == "main"
            for raw in lines:
                self.agg.add_line(raw, cursor.origin, is_main)
        if truncated:
            self.log("transcript shrank or was replaced -- rebuilding state from offset 0",
                     "warn")
            self.agg = _Aggregator()
            for cursor in self.cursors.values():
                cursor.reset()
            return self.ingest()
        self.bytes_ingested += consumed
        return consumed

    # -- outputs ------------------------------------------------------------

    def _burn_rates(self, cost: float) -> Dict[str, float]:
        now = time.time()
        # One sample per tick: live_payload() runs twice on a rebuild tick and a
        # double sample would bias the recent-rate window.
        if not self.cost_samples or (now - self.cost_samples[-1][0]) >= 1.0:
            self.cost_samples.append((now, cost))
        cutoff = now - 900.0
        while len(self.cost_samples) > 2 and self.cost_samples[0][0] < cutoff:
            self.cost_samples.pop(0)
        rates = {"burn_usd_per_hour": 0.0, "burn_usd_per_hour_recent": 0.0}
        started = self.agg.first_ts
        if started:
            elapsed = max(1.0, (_now() - started).total_seconds())
            if elapsed > 60:
                rates["burn_usd_per_hour"] = cost / (elapsed / 3600.0)
        first_t, first_c = self.cost_samples[0]
        window = now - first_t
        if window >= 120:
            rates["burn_usd_per_hour_recent"] = (cost - first_c) / (window / 3600.0)
        return rates

    def live_payload(self) -> Dict[str, Any]:
        agg = self.agg
        totals = agg.snapshot_totals()
        cost = float(totals["cost_usd_authoritative"] or 0.0)
        model_id = agg.context_model or ""
        if not model_id and agg.by_model:
            model_id = max(agg.by_model.items(), key=lambda kv: kv[1]["cost_usd"])[0]
        window = pricing.context_window(model_id) or pricing.DEFAULT_CONTEXT_WINDOW
        used = agg.context_tokens
        model_row = agg.by_model.get(pricing.normalize_model(model_id), {})
        top = sorted(agg.tool_counts.items(), key=lambda kv: -kv[1])[:6]
        rates = self._burn_rates(cost)
        budget = self.config.get("budget") or {}
        budget_limit = float(budget.get("session_usd") or 0.0)
        transcript_mtime = self.cursors[str(self.transcript_path)].mtime

        wall = ((agg.last_ts - agg.first_ts).total_seconds()
                if agg.first_ts and agg.last_ts else 0.0)
        totals["cost_usd_per_hour"] = (cost / (wall / 3600.0)) if wall > 60 else 0.0
        context_block = {
            "used_tokens": used,
            "max_tokens": window,
            "pct": round(100.0 * used / window, 2) if window else 0.0,
            "model": pricing.normalize_model(model_id) or model_id,
            "ts": _iso(agg.context_ts),
        }

        payload: Dict[str, Any] = {
            "schema_version": SCHEMA_VERSION,
            # statusline.snapshot_payload() names a few of these differently;
            # both spellings are published so either reader works unchanged.
            "schema": SCHEMA_VERSION,
            # Flat keys first: the statusline reads a handful of numbers under a
            # hard 80 ms budget and should not have to walk the tree for them.
            "session_id": self.session_id,
            "updated_at": _iso(_now()),
            "updated_epoch": time.time(),
            "transcript_path": str(self.transcript_path),
            "transcript_mtime": transcript_mtime,
            "cost_usd": cost,
            "total_tokens": totals["total_tokens"],
            "calls": totals["calls"],
            "context_used_tokens": used,
            "context_max_tokens": window,
            "context_pct": round(100.0 * used / window, 2) if window else 0.0,
            "model": pricing.normalize_model(model_id) or model_id,
            "model_display": pricing.display_name(model_id),
            "effort": agg.effort,
            "top_tool": (top[0][0] if top else None),
            "top_tool_count": (top[0][1] if top else 0),
            "burn_usd_per_hour": rates["burn_usd_per_hour"],
            "burn_usd_per_hour_recent": rates["burn_usd_per_hour_recent"],

            "burn_rate_usd_per_hour": rates["burn_usd_per_hour"],
            "context": context_block,
            "context_window": context_block,
            "totals": totals,
            "model_row": {
                "id": pricing.normalize_model(model_id) or model_id,
                "display_name": pricing.display_name(model_id),
                "calls": model_row.get("calls", 0),
                "cost_usd": model_row.get("cost_usd", 0.0),
                "tier": model_row.get("tier"),
            },
            "by_model": agg.by_model,
            "top_tools": [{"name": name, "count": count} for name, count in top],
            "session": {
                "session_id": self.session_id,
                "project": paths.project_of(self.transcript_path),
                "project_display": paths.project_display(paths.project_of(self.transcript_path)),
                "cwd": agg.cwd,
                "git_branch": agg.git_branch,
                "cc_version": agg.cc_version,
                "title": agg.title,
                "last_prompt": (agg.last_prompt or "")[:200] or None,
                "started_at": _iso(agg.first_ts),
                "last_activity": _iso(agg.last_ts),
                "wall_seconds": wall,
                "turns": max(len(agg.prompt_ids), agg.prompt_lines),
                "agents": sum(1 for c in self.cursors.values() if c.origin != "main"),
            },
            "budget": {
                "session_usd": budget_limit,
                "pct": round(100.0 * cost / budget_limit, 1) if budget_limit else 0.0,
                "warn_pct": budget.get("warn_pct", 80),
            },
            "report": dict(self.last_report),
            "watcher": {
                "pid": os.getpid(),
                "ticks": self.ticks,
                "full_builds": self.full_builds,
                "sources": len(self.cursors),
                "bytes_ingested": self.bytes_ingested,
                "lines_seen": self.agg.lines_seen,
                "bad_lines": self.agg.bad_lines,
                "refresh_seconds": self.refresh,
                "idle_exit_seconds": self.idle_exit,
                "idle_seconds": round(time.time() - self.last_change, 1),
                "tick_ms_last": round(self.tick_ms[-1], 3) if self.tick_ms else 0.0,
                "tick_ms_avg": round(sum(self.tick_ms) / len(self.tick_ms), 3)
                if self.tick_ms else 0.0,
                "tick_ms_max": round(max(self.tick_ms), 3) if self.tick_ms else 0.0,
                "full_ms_last": round(self.full_ms[-1], 1) if self.full_ms else 0.0,
                "full_ms_avg": round(sum(self.full_ms) / len(self.full_ms), 1)
                if self.full_ms else 0.0,
                "uptime_seconds": round(time.time() - self.started_epoch, 1),
            },
        }
        return payload

    def write_live(self) -> None:
        try:
            paths.atomic_write(paths.live_snapshot_path(self.session_id),
                               json.dumps(self.live_payload(), separators=(",", ":")))
        except Exception as exc:  # never let a snapshot failure kill the loop
            self.log(f"live snapshot failed: {exc!r}", "error")

    def full_rebuild(self, reason: str = "tick") -> None:
        """The accurate document: a real ledger.load() plus report.py.

        report.py may not exist yet (it is built alongside this module); in that
        case we still write data.json so the dashboard and scan_sessions have
        something authoritative to read.
        """
        started = time.perf_counter()
        try:
            from . import ledger as ledger_mod
        except ImportError:
            from oe import ledger as ledger_mod  # type: ignore
        try:
            led = ledger_mod.load(
                self.transcript_path,
                include_subagents=True,
                tool_events_path=paths.tool_events_path(self.session_id),
            )
        except Exception as exc:
            self.log(f"ledger load failed: {exc!r}", "error")
            return
        written: Dict[str, Any] = {}
        try:
            try:
                from . import report as report_mod
            except ImportError:
                from oe import report as report_mod  # type: ignore
            written = {k: str(v) for k, v in (report_mod.write_report(led, self.report_dir)
                                              or {}).items()}
        except ImportError:
            try:
                # report.py is missing, but the tree is still shareable: redact
                # and audit before this fallback writes anything.
                text = json.dumps(redact.redact_payload(led.to_dict()),
                                  indent=2, default=str)
                redact.guard(text, str(self.report_dir / "data.json"))
                paths.atomic_write(self.report_dir / "data.json", text)
                written = {"data": str(self.report_dir / "data.json")}
            except Exception as exc:
                self.log(f"data.json fallback failed: {exc!r}", "error")
        except Exception as exc:
            self.log(f"report render failed: {exc!r}", "error")
        elapsed_ms = (time.perf_counter() - started) * 1000.0
        self.full_ms.append(elapsed_ms)
        del self.full_ms[:-32]
        self.full_builds += 1
        self._last_full = time.time()
        # Back off on sessions where a load is genuinely slow, so the daemon's
        # duty cycle stays near 1-2% of a core no matter how big the transcript.
        self._next_full_due = self._last_full + max(self.report_interval,
                                                    (elapsed_ms / 1000.0) * 40.0)
        written["generated_at"] = _iso(_now())
        written["build_ms"] = round(elapsed_ms, 1)
        written["reason"] = reason
        self.last_report = written
        self.log(f"rebuild ({reason}) in {elapsed_ms:.0f} ms -- "
                 f"{led.totals['calls']} calls, ${led.totals['cost_usd_authoritative']:.4f}")

    def refresh_dashboard(self) -> None:
        try:
            try:
                from . import dashboard as dashboard_mod
            except ImportError:
                from oe import dashboard as dashboard_mod  # type: ignore
            dashboard_mod.write_dashboard(self.reports_root)
            self._last_dashboard = time.time()
        except Exception as exc:
            self.log(f"dashboard refresh failed: {exc!r}", "error")

    # -- loop ---------------------------------------------------------------

    def _checkpoint_touched(self) -> bool:
        """stop.py touches a checkpoint file to ask for a prompt rebuild."""
        try:
            mtime = self.checkpoint_path.stat().st_mtime
        except OSError:
            return False
        if mtime > self._last_checkpoint_mtime:
            self._last_checkpoint_mtime = mtime
            return True
        return False

    def tick(self) -> float:
        started = time.perf_counter()
        self.ticks += 1
        self._truncate_log()
        self.discover()
        consumed = self.ingest()
        forced = self._checkpoint_touched()
        if consumed or forced:
            self.last_change = time.time()
            self._dirty = True
        self.write_live()
        incremental_ms = (time.perf_counter() - started) * 1000.0
        self.tick_ms.append(incremental_ms)
        del self.tick_ms[:-128]

        now = time.time()
        settled = (now - self.last_change) >= self.settle_seconds and (
            now - self._last_full) >= self.min_full_gap
        if self._dirty and (forced or now >= self._next_full_due or settled):
            self.full_rebuild("checkpoint" if forced else "settled" if settled else "tick")
            self._dirty = False
            self.write_live()  # publish the fresh report paths
            if (now - self._last_dashboard) >= self.dashboard_interval:
                self.refresh_dashboard()
        return incremental_ms

    def _sleep(self, seconds: float) -> None:
        """Sleep in slices so SIGTERM is acted on promptly."""
        deadline = time.time() + seconds
        while not self._stop:
            remaining = deadline - time.time()
            if remaining <= 0:
                return
            time.sleep(min(0.25, remaining))

    def _install_signals(self) -> None:
        def handler(signum, _frame):
            self._stop = True
            self._stop_reason = f"signal {signum}"
        for sig in (signal.SIGTERM, signal.SIGINT):
            try:
                signal.signal(sig, handler)
            except (ValueError, OSError):
                pass
        try:
            signal.signal(signal.SIGHUP, signal.SIG_IGN)
        except (AttributeError, ValueError, OSError):
            pass

    def run(self, max_ticks: Optional[int] = None, require_pidfile: bool = True) -> int:
        self._install_signals()
        self.log(f"watcher up pid={os.getpid()} transcript={self.transcript_path} "
                 f"refresh={self.refresh}s idle_exit={self.idle_exit}s "
                 f"report_interval={self.report_interval}s")
        self.discover(force=True)
        try:
            while not self._stop:
                try:
                    self.tick()
                except Exception as exc:
                    self.log(f"tick failed: {exc!r}", "error")
                if max_ticks is not None and self.ticks >= max_ticks:
                    self._stop_reason = "max_ticks"
                    break
                if require_pidfile and not self._pidfile_is_ours():
                    self._stop_reason = "pidfile removed"
                    break
                idle = time.time() - self.last_change
                if idle >= self.idle_exit:
                    self._stop_reason = f"idle {idle:.0f}s"
                    break
                self._sleep(self.refresh)
        finally:
            self._shutdown()
        return 0

    def _pidfile_is_ours(self) -> bool:
        record = read_pidfile(self.session_id)
        if not record:
            return False
        return _int(record.get("pid")) == os.getpid()

    def _shutdown(self) -> None:
        avg = (sum(self.tick_ms) / len(self.tick_ms)) if self.tick_ms else 0.0
        self.log(f"stopping ({self._stop_reason}); {self.ticks} ticks, "
                 f"{self.full_builds} rebuilds, tick avg {avg:.2f} ms")
        try:
            self.ingest()
            if self._dirty:
                self.full_rebuild("shutdown")
            self.refresh_dashboard()
            self.write_live()
        except Exception as exc:
            self.log(f"final rebuild failed: {exc!r}", "error")
        if self._pidfile_is_ours():
            _clear_pidfile(self.session_id)
        self.log("stopped")


# ---------------------------------------------------------------------------
# public API
# ---------------------------------------------------------------------------


def run_loop(session_id: str, transcript_path: str | os.PathLike,
             reports_root: Optional[str | os.PathLike] = None, *,
             refresh_seconds: Optional[float] = None,
             idle_exit_seconds: Optional[float] = None,
             report_interval_seconds: Optional[float] = None,
             max_ticks: Optional[int] = None,
             claim_pidfile: bool = True,
             require_pidfile: bool = True) -> int:
    """Run the watch loop in THIS process (the daemon's body, and the test seam)."""
    watcher = Watcher(session_id, transcript_path, reports_root,
                      refresh_seconds=refresh_seconds,
                      idle_exit_seconds=idle_exit_seconds,
                      report_interval_seconds=report_interval_seconds)
    if claim_pidfile:
        _write_pidfile(session_id, str(transcript_path), watcher.reports_root)
    return watcher.run(max_ticks=max_ticks, require_pidfile=require_pidfile)


def _daemon_body(session_id: str, transcript_path: str, reports_root: Optional[str],
                 refresh_seconds: Optional[float], idle_exit_seconds: Optional[float],
                 claim_pidfile: bool = False) -> None:
    """Grandchild entry point: detach the std streams, then loop forever."""
    if reports_root:
        paths.set_reports_root(reports_root)
    log_path = paths.watcher_log(session_id)
    try:
        os.chdir("/")
    except OSError:
        pass
    try:
        devnull = os.open(os.devnull, os.O_RDONLY)
        os.dup2(devnull, 0)
        os.close(devnull)
        paths.ensure_dir(log_path.parent)
        out = os.open(str(log_path), os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o644)
        os.dup2(out, 1)
        os.dup2(out, 2)
        if out > 2:
            os.close(out)
    except OSError:
        pass
    run_loop(session_id, transcript_path, reports_root,
             refresh_seconds=refresh_seconds, idle_exit_seconds=idle_exit_seconds,
             claim_pidfile=claim_pidfile)


def _await_pid(session_id: str, timeout: float = 2.0) -> int:
    """Wait out an in-flight start() by another caller and report its PID."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        pid = _int((read_pidfile(session_id) or {}).get("pid"))
        if pid:
            return pid
        time.sleep(0.05)
    return 0


def start(session_id: str, transcript_path: str | os.PathLike,
          reports_root: Optional[str | os.PathLike] = None, *,
          refresh_seconds: Optional[float] = None,
          idle_exit_seconds: Optional[float] = None) -> int:
    """Spawn the detached watcher for a session. Idempotent.

    Returns the daemon PID (an existing one if it is already running, 0 if the
    spawn could not be completed). Safe to call from a hook: the caller returns
    as soon as the double fork is done, never waiting on the daemon.
    """
    if reports_root:
        paths.set_reports_root(reports_root)
    session_id = str(session_id)
    transcript_path = str(transcript_path)

    existing = is_running(session_id)
    if existing:
        return existing if existing > 0 else _await_pid(session_id)
    if not _claim_pidfile(session_id, transcript_path):
        # Lost the race to a concurrent start(): the winner owns the daemon.
        other = is_running(session_id)
        if other and other > 0:
            return other
        return _await_pid(session_id)

    if not hasattr(os, "fork"):  # pragma: no cover - Linux/WSL only in practice
        return _start_via_subprocess(session_id, transcript_path, reports_root)

    read_fd, write_fd = os.pipe()
    try:
        first = os.fork()
    except OSError:
        os.close(read_fd)
        os.close(write_fd)
        _clear_pidfile(session_id)
        return 0

    if first == 0:
        # child: detach from the session, fork again so the daemon is orphaned
        # and can never become a zombie of the hook process.
        try:
            os.close(read_fd)
            os.setsid()
            if os.fork() > 0:
                os._exit(0)
            os.write(write_fd, str(os.getpid()).encode("ascii"))
            os.close(write_fd)
            if not _upgrade_claim(session_id, transcript_path, paths.reports_root()):
                os._exit(0)  # stopped before we finished starting
            _daemon_body(session_id, transcript_path,
                         str(reports_root) if reports_root else None,
                         refresh_seconds, idle_exit_seconds)
        except BaseException:
            os._exit(1)
        os._exit(0)

    os.close(write_fd)
    try:
        os.waitpid(first, 0)
    except OSError:
        pass
    pid = 0
    try:
        import select
        ready, _, _ = select.select([read_fd], [], [], 5.0)
        if ready:
            data = os.read(read_fd, 32)
            pid = int(data or 0)
    except Exception:
        pid = 0
    finally:
        try:
            os.close(read_fd)
        except OSError:
            pass
    if not pid:
        _clear_pidfile(session_id)
    return pid


def _start_via_subprocess(session_id: str, transcript_path: str,
                          reports_root: Optional[str | os.PathLike]) -> int:
    """Fallback spawn for platforms without fork. Same contract as start()."""
    import subprocess  # imported lazily: the fork path must not pay for it
    env = dict(os.environ)
    if reports_root:
        env[paths.ENV_REPORTS_ROOT] = str(reports_root)
    env["PYTHONPATH"] = str(paths.INSTALL_ROOT) + os.pathsep + env.get("PYTHONPATH", "")
    try:
        proc = subprocess.Popen(
            [sys.executable, "-m", "oe.watcher", "run", "--session-id", session_id,
             "--transcript", str(transcript_path)],
            cwd=str(paths.INSTALL_ROOT), env=env,
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            start_new_session=True)
    except Exception:
        _clear_pidfile(session_id)
        return 0
    return proc.pid


def stop(session_id: str, timeout: float = 5.0) -> bool:
    """Ask the watcher to exit and wait for it. True when nothing is left running.

    The pidfile goes first: that alone makes the loop exit at its next check,
    so a SIGTERM that is missed (or a process that ignores it) still terminates.
    """
    record = read_pidfile(str(session_id))
    pid = _int((record or {}).get("pid"))
    _clear_pidfile(str(session_id))
    if not pid or not _alive(pid):
        return True
    if (record or {}).get("supervisor"):
        # The owner is the multi-session supervisor. Removing its claim above is
        # the whole shutdown protocol for one session -- the supervisor notices
        # at its next poll and drops the tracker. Signalling that PID would kill
        # the tail loop of every OTHER live session with it, so never do it.
        return True
    try:
        os.kill(pid, signal.SIGTERM)
    except OSError:
        return True
    deadline = time.time() + timeout
    while time.time() < deadline:
        if not _alive(pid):
            return True
        time.sleep(0.1)
    try:
        os.kill(pid, signal.SIGKILL)
    except OSError:
        pass
    return not _alive(pid)


def status(session_id: str) -> Dict[str, Any]:
    pid = is_running(str(session_id))
    record = read_pidfile(str(session_id)) or {}
    live_path = paths.live_snapshot_path(str(session_id))
    live: Dict[str, Any] = {}
    try:
        live = json.loads(live_path.read_text(encoding="utf-8"))
    except Exception:
        live = {}
    return {
        "session_id": str(session_id),
        "running": bool(pid),
        "pid": pid,
        "pidfile": str(paths.watcher_pidfile(str(session_id))),
        "record": record,
        "live_snapshot": str(live_path) if live else None,
        "live_age_seconds": (round(time.time() - float(live.get("updated_epoch") or 0), 1)
                             if live else None),
        "watcher": live.get("watcher") if live else None,
    }


# ===========================================================================
# ZERO-CONFIG SUPERVISOR
#
# Everything above assumes something told us a session exists: the SessionStart
# hook spawns start(), SessionEnd calls stop(). In the zero-config world there
# are no hooks, so the two ends of a session have to be OBSERVED instead:
#
#   birth  -> a transcript under ~/.claude/projects/ is being written to
#   death  -> it stopped being written to AND no `claude` process is open on
#             its project directory
#
# The supervisor is one process that watches all of that and drives the same
# Watcher.tick() machinery per session. It writes nothing to any settings file
# and needs nothing installed.
# ===========================================================================

# comm(2) is truncated to 15 bytes; these are the whole values we may see.
_CLAUDE_COMMS = ("claude",)
_RUNTIME_COMMS = ("node", "bun", "deno")

# A transcript written this long before its project's oldest claude process
# started is still counted as belonging to that process: `claude --resume` and
# `--continue` reattach to a file whose last write predates the new PID.
_PROC_START_GRACE = 6 * 3600.0

_SUPERVISOR_SCHEMA = 1

_BOOT_EPOCH: Optional[float] = None


def _clock_ticks() -> float:
    try:
        return float(os.sysconf("SC_CLK_TCK")) or 100.0
    except (ValueError, OSError, AttributeError):
        return 100.0


def _boot_epoch() -> Optional[float]:
    """Wall-clock epoch of the last boot, from /proc/stat btime. Cached.

    Needed to turn /proc/<pid>/stat's start time (in ticks since boot) into a
    real timestamp we can compare against a file mtime.
    """
    global _BOOT_EPOCH
    if _BOOT_EPOCH is not None:
        return _BOOT_EPOCH or None
    _BOOT_EPOCH = 0.0
    try:
        with open("/proc/stat", "r", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                if line.startswith("btime "):
                    _BOOT_EPOCH = float(line.split()[1])
                    break
    except (OSError, ValueError, IndexError):
        _BOOT_EPOCH = 0.0
    return _BOOT_EPOCH or None


def _proc_start_epoch(pid: int) -> Optional[float]:
    ticks = _proc_starttime(pid)
    boot = _boot_epoch()
    if ticks is None or boot is None:
        return None
    return boot + (ticks / _clock_ticks())


def _proc_cmdline(pid: int) -> List[str]:
    try:
        with open(f"/proc/{pid}/cmdline", "rb") as handle:
            raw = handle.read(8192)
    except OSError:
        return []
    return [part.decode("utf-8", "replace") for part in raw.split(b"\x00") if part]


def _argv_is_claude(comm: str, argv: List[str]) -> bool:
    """Is this process the Claude Code CLI, not merely something with the word?

    A substring search over the whole command line is NOT good enough: every
    shell Claude Code itself spawns carries
    `source ~/.claude/shell-snapshots/...` in its argv and would be
    counted as a live session, which would keep every project permanently
    "live" and nothing would ever finalize. So: trust comm == "claude", and for
    a JS runtime only accept the script it was actually asked to run.
    """
    if comm in _CLAUDE_COMMS:
        return True
    if comm not in _RUNTIME_COMMS:
        return False
    script = argv[1] if len(argv) > 1 else ""
    base = script.rsplit("/", 1)[-1]
    if base == "claude":
        return True
    for token in argv[1:]:
        if "@anthropic-ai/claude-code" in token or "/claude/versions/" in token:
            return True
    return False


def claude_processes() -> Optional[List[Dict[str, Any]]]:
    """Every open Claude Code CLI process with its cwd, or None if /proc is mute.

    None and [] are deliberately different answers. [] is a confident "no
    session is open anywhere", which lets a quiet transcript be finalized. None
    means this machine will not tell us (no /proc, a hardened container, a
    different user's processes) and the caller must fall back to mtime alone --
    where a merely-thinking session looks identical to a closed one, so we
    finalize on idle only and say so.
    """
    try:
        os.readlink("/proc/self/cwd")  # capability probe, not a result
    except OSError:
        return None
    try:
        entries = os.listdir("/proc")
    except OSError:
        return None
    me = os.getpid()
    found: List[Dict[str, Any]] = []
    candidates = 0
    unreadable = 0
    for entry in entries:
        if not entry.isdigit():
            continue
        pid = int(entry)
        if pid == me:
            continue
        try:
            with open(f"/proc/{entry}/comm", "rb") as handle:
                comm = handle.read(64).strip().decode("utf-8", "replace")
        except OSError:
            continue  # the process exited between listdir and open; normal
        if comm not in _CLAUDE_COMMS and comm not in _RUNTIME_COMMS:
            continue
        if not _argv_is_claude(comm, _proc_cmdline(pid)):
            continue
        candidates += 1
        try:
            cwd = os.readlink(f"/proc/{entry}/cwd")
        except OSError:
            unreadable += 1
            continue
        found.append({
            "pid": pid,
            "comm": comm,
            "cwd": cwd,
            "start_epoch": _proc_start_epoch(pid) or 0.0,
        })
    if candidates and not found and unreadable:
        # We can see Claude Code running but not where -- that is "mute", not
        # "nothing is open". Reporting [] here would finalize a live session.
        return None
    return found


def _slug_candidates(cwd: str) -> List[str]:
    """Every project-directory name Claude Code might have derived from `cwd`.

    paths.slug_for_cwd() only maps '/' -> '-', which is right for most paths but
    not all: the real directory for
    <project>/webapp/.claude/local_docs/plans/ui is
    -home-u-myrepo-webapp--claude-local-docs-plans-ui, so '.' and
    '_' collapse to '-' too. Rather than change the shared helper (other code
    depends on its exact behaviour) we try each spelling and match against the
    directory names that actually exist.
    """
    text = str(cwd or "")
    plain = text.replace("/", "-")
    wide = "".join("-" if ch in "/._" else ch for ch in text)
    out = [plain]
    if wide != plain:
        out.append(wide)
    return out


def live_project_slugs() -> Optional[Dict[str, Dict[str, Any]]]:
    """slug -> {"pids": [...], "since": epoch of the OLDEST claude there}.

    None when the process table is unusable; see claude_processes().
    """
    procs = claude_processes()
    if procs is None:
        return None
    out: Dict[str, Dict[str, Any]] = {}
    now = time.time()
    for proc in procs:
        start = float(proc.get("start_epoch") or 0.0) or now
        for slug in _slug_candidates(str(proc.get("cwd") or "")):
            row = out.get(slug)
            if row is None:
                out[slug] = {"pids": [proc["pid"]], "since": start, "cwd": proc.get("cwd")}
            else:
                row["pids"].append(proc["pid"])
                row["since"] = min(row["since"], start)
    return out


# ---------------------------------------------------------------------------
# supervisor state files
# ---------------------------------------------------------------------------


def supervisor_pidfile() -> Path:
    return paths.state_dir() / "supervisor.pid"


def supervisor_lockfile() -> Path:
    return paths.state_dir() / "supervisor.lock"


def supervisor_statusfile() -> Path:
    return paths.state_dir() / "supervisor.json"


def supervisor_log() -> Path:
    return paths.state_dir() / "supervisor.log"


def _truncate_file(path: Path) -> None:
    """Keep a log bounded, truncating IN PLACE.

    In place because the detached supervisor dup2()s its stdout and stderr onto
    this file: renaming a replacement over it would leave those fds pointing at
    an unlinked inode, so every traceback after the first rotation would vanish.
    """
    try:
        if path.stat().st_size <= LOG_MAX_BYTES:
            return
        with open(path, "rb") as handle:
            handle.seek(-LOG_KEEP_BYTES, os.SEEK_END)
            tail = handle.read()
        cut = tail.find(b"\n")
        tail = tail[cut + 1:] if cut >= 0 else tail
        with open(path, "r+b") as handle:
            handle.seek(0)
            handle.write(b"... log truncated ...\n")
            handle.write(tail)
            handle.truncate()
    except Exception:
        pass


def _rss_mb() -> float:
    """Resident set size of this process in MiB, from /proc/self/statm."""
    try:
        with open("/proc/self/statm", "r", encoding="utf-8") as handle:
            pages = int(handle.read().split()[1])
        return round(pages * (os.sysconf("SC_PAGE_SIZE") / 1048576.0), 2)
    except Exception:
        return 0.0


# ---------------------------------------------------------------------------
# a report path that exists from the first second of a session
# ---------------------------------------------------------------------------

# How often the supervisor sweeps ~/.claude/projects for files that were not
# there before. Cheap enough (see _NewTranscriptScanner) to run once a second,
# which is what puts the report skeleton on disk inside the 3 s budget.
NEW_SESSION_SCAN_SECONDS = 1.0

# A transcript can exist for a moment before it has any content. It is kept on
# the "seen but not adopted" list this long, retried every scan, before being
# left to the ordinary 5 s discover() sweep.
NEW_SESSION_PENDING_SECONDS = 60.0


def report_paths(session_id: str) -> Dict[str, Path]:
    """Every artefact path for a session, derived from the id ALONE.

    Pure: it creates nothing, so `oe path <id>` on a typo does not leave an
    empty directory behind, and a link to the report can be handed out before
    the session has written its first byte.
    """
    base = paths.reports_root() / "sessions" / paths.report_dir_name(session_id)
    return {
        "dir": base,
        "html": base / "report.html",
        "json": base / "data.json",
        "markdown": base / "summary.md",
        "row": base / "row.json",
        "csv": base / "calls.csv",
    }


def _skeleton_html(session_name: str, project_name: str, started_at: str) -> str:
    """The placeholder page: a real document, not an error and not a blank.

    Self-contained like report.py's output (file:// with no network), and it
    carries a 5 s meta refresh so the tab a user opened in the first second of a
    session turns into the real report by itself. The real report has no such
    tag, so the refreshing stops the moment there is something to read.

    No zero-valued figures anywhere: a page that said "$0.00" would be read as a
    measurement. The placeholders are em dashes with the reason underneath.
    """
    # Pseudonyms only: this page is written into the shareable reports tree
    # within a second of a session appearing, so it is an artifact like any
    # other and may not name the session, the project or the transcript.
    rows = [
        ("session", session_name),
        ("project", project_name or "unknown"),
        ("first seen", started_at),
    ]
    meta = "".join(
        f'<div class="row"><span class="k">{_esc(key)}</span>'
        f'<span class="v">{_esc(value)}</span></div>'
        for key, value in rows)
    cards = "".join(
        f'<div class="card"><div class="fig">&mdash;</div>'
        f'<div class="lab">{_esc(label)}</div></div>'
        for label in ("cost", "tokens", "requests"))
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="refresh" content="5">
<title>Usage report {_esc(session_name)} -- starting</title>
<style>
:root {{ color-scheme: light dark;
  --bg:#f7f7f5; --surface:#fff; --ink:#1a1a19; --muted:#6b6b66; --line:#e3e3df;
  --accent:#b5652a; }}
@media (prefers-color-scheme: dark) {{ :root {{
  --bg:#141413; --surface:#1c1c1a; --ink:#f0efec; --muted:#96968f; --line:#2c2c29;
  --accent:#d97757; }} }}
* {{ box-sizing:border-box; }}
body {{ margin:0; background:var(--bg); color:var(--ink);
  font:15px/1.55 ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,sans-serif; }}
.wrap {{ max-width:820px; margin:0 auto; padding:56px 24px 72px; }}
.eyebrow {{ font-size:12px; letter-spacing:.09em; text-transform:uppercase;
  color:var(--muted); }}
h1 {{ font-size:27px; line-height:1.2; margin:10px 0 12px; font-weight:600; }}
.lede {{ color:var(--muted); max-width:60ch; margin:0 0 26px; }}
.pill {{ display:inline-flex; align-items:center; gap:8px; font-size:13px;
  border:1px solid var(--line); background:var(--surface); color:var(--muted);
  border-radius:999px; padding:5px 13px; margin-bottom:26px; }}
.dot {{ width:7px; height:7px; border-radius:50%; background:var(--accent);
  animation:pulse 1.6s ease-in-out infinite; }}
@keyframes pulse {{ 0%,100% {{ opacity:1; }} 50% {{ opacity:.25; }} }}
@media (prefers-reduced-motion:reduce) {{ .dot {{ animation:none; }} }}
.cards {{ display:grid; grid-template-columns:repeat(3,1fr); gap:12px;
  margin-bottom:26px; }}
.card {{ background:var(--surface); border:1px solid var(--line);
  border-radius:10px; padding:16px 18px; }}
.fig {{ font-size:26px; font-weight:600; color:var(--muted); line-height:1.1; }}
.lab {{ font-size:12px; letter-spacing:.05em; text-transform:uppercase;
  color:var(--muted); margin-top:6px; }}
.meta {{ background:var(--surface); border:1px solid var(--line);
  border-radius:10px; overflow:hidden; }}
.row {{ display:flex; gap:16px; padding:10px 18px; border-top:1px solid var(--line);
  font-size:13px; }}
.row:first-child {{ border-top:0; }}
.k {{ width:110px; flex:none; color:var(--muted); }}
.v {{ font-family:ui-monospace,SFMono-Regular,Menlo,monospace; word-break:break-all; }}
.foot {{ color:var(--muted); font-size:13px; margin-top:26px; }}
@media (max-width:560px) {{ .cards {{ grid-template-columns:1fr; }} }}
</style></head><body><div class="wrap">
<div class="eyebrow">Claude Code session usage report</div>
<h1>This session just started</h1>
<p class="lede">Overwatch Enforcer picked up the transcript the moment it appeared and is
measuring the session now. Nothing has been billed yet -- the first numbers land
with the first API response. This page reloads every 5 seconds and replaces itself
with the full report as soon as there is one.</p>
<div class="pill"><span class="dot"></span>measuring &mdash; awaiting the first API response</div>
<div class="cards">{cards}</div>
<div class="meta">{meta}</div>
<p class="foot">This file keeps its path for the life of the session:
<code>sessions/{_esc(session_name)}/report.html</code>, relative to the reports
root. It carries no absolute path, because this page is shareable.</p>
</div></body></html>
"""


def _esc(value: Any) -> str:
    text = str(value if value is not None else "")
    return (text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            .replace('"', "&quot;"))


def write_skeleton_report(session_id: str, transcript_path: Optional[Path] = None,
                          *, force: bool = False) -> Optional[Dict[str, Path]]:
    """Publish the placeholder report.html/data.json/summary.md/row.json.

    Called the instant a transcript appears, so the report URL is openable from
    the first second of a session rather than from the first rebuild.

    NOTE the deliberate omission: none of these files carry `schema_version`.
    That key is what ledger._row_from_row_file() and _row_from_cache() check
    before they will believe a cached number, so a placeholder can never be
    mistaken for a measurement -- the session listing falls through to its own
    scan and reports the truth even while the placeholder sits on disk. The
    marker `"skeleton": true` is there for a human reading the file.

    Returns the paths written, or None when a real report already exists (this
    never overwrites measured output) or when the write failed.
    """
    try:
        targets = report_paths(session_id)
        if not force and targets["html"].is_file():
            return None
        transcript = Path(transcript_path) if transcript_path else None
        slug = transcript.parent.name if transcript else ""
        stamp = time.time()
        if transcript is not None:
            try:
                stamp = transcript.stat().st_mtime
            except OSError:
                pass
        started_at = (datetime.fromtimestamp(stamp, tz=timezone.utc)
                      .isoformat().replace("+00:00", "Z"))
        # These four files land in the shareable reports tree seconds after a
        # session starts, so they carry pseudonyms and no path -- exactly like
        # the measured report that replaces them. record_local() keeps the real
        # identity in the LOCAL map so `oe whois` can still resolve it.
        session_name = redact.record_local(
            session_id, project=slug,
            project_display=paths.project_display(slug) if slug else None,
            transcript_path=str(transcript) if transcript else None,
            started_at=started_at)
        project_name = redact.project_pseudonym(slug) if slug else ""
        payload: Dict[str, Any] = {
            "skeleton": True,
            "state": "starting",
            "generated_at": _iso(_now()),
            "note": ("Placeholder written when the transcript first appeared. "
                     "Replaced by the measured report on the first rebuild."),
            "redaction": {"version": redact.REDACTION_VERSION, "policy": "allowlist",
                          "note": redact.REDACTION_NOTE},
            "session": {
                "id": session_name,
                "project": project_name,
                "started_at": started_at,
            },
            "totals": {"calls": 0, "total_tokens": 0,
                       "cost_usd": None, "cost_usd_authoritative": None},
        }
        row = {
            "skeleton": True,
            "session": session_name,
            "project": project_name,
            "context_tokens": 0,
            "max_tokens": pricing.DEFAULT_CONTEXT_WINDOW,
            "cost_usd": None,
            "total_tokens": 0,
            "model": None,
            "calls": 0,
            "started_at": started_at,
        }
        markdown = (
            f"# Session {session_name}\n\n"
            "**This session just started.** Overwatch Enforcer is measuring it now; no\n"
            "API response has been recorded yet, so there is nothing to total.\n\n"
            f"- project: `{project_name or 'unknown'}`\n"
            f"- first seen: {started_at}\n\n"
            "This file is replaced by the measured summary on the first rebuild.\n"
        )
        documents = [
            (targets["html"], _skeleton_html(session_name, project_name, started_at)),
            (targets["json"], json.dumps(payload, indent=2, default=str)),
            (targets["markdown"], markdown),
            (targets["row"], json.dumps(row, default=str)),
        ]
        # Same gate as report.py: render, audit, then write -- or write nothing.
        for target, text in documents:
            redact.guard(text, str(target))
        paths.ensure_dir(targets["dir"])
        for target, text in documents:
            paths.atomic_write(target, text)
        return targets
    except Exception:
        # A placeholder is a convenience; failing to write one must never stop
        # the supervisor from going on to measure the session for real.
        return None


class _NewTranscriptScanner:
    """Notices new session transcripts within a second, for one stat per project.

    Creating a file updates its directory's mtime, so one os.scandir of
    ~/.claude/projects answers "did anything appear anywhere?" at the cost of a
    stat per project directory -- and only the directories whose mtime actually
    moved are listed. That is what makes a 1 s interval affordable where the
    supervisor's full candidates() sweep (a stat per transcript plus a /proc
    sweep) is not.

    st_mtime_ns, not st_mtime: two files landing in the same directory inside
    one second is ordinary, and a float-seconds comparison would miss the
    second one until something else touched the directory.
    """

    __slots__ = ("_dir_mtime", "_known", "primed")

    def __init__(self) -> None:
        self._dir_mtime: Dict[str, int] = {}
        self._known: Dict[str, set] = {}
        self.primed = False

    def scan(self) -> List[Path]:
        """Transcripts that appeared since the previous call. Never raises.

        The first call primes and returns nothing: everything already on disk
        belongs to the ordinary discover() sweep, not to "a session just
        started".
        """
        found: List[Path] = []
        try:
            entries = list(os.scandir(paths.PROJECTS_ROOT))
        except OSError:
            return found
        alive: set = set()
        for entry in entries:
            try:
                if not entry.is_dir():
                    continue
                # Read the directory's mtime BEFORE listing it: a file created
                # between the two is either seen now or leaves the stored mtime
                # behind the real one, so the next scan lists again. Reading it
                # afterwards would record a change we never looked at.
                stamp = entry.stat().st_mtime_ns
            except OSError:
                continue
            alive.add(entry.path)
            if self._dir_mtime.get(entry.path) == stamp:
                continue
            names = set()
            try:
                for item in os.scandir(entry.path):
                    name = item.name
                    if not name.endswith(".jsonl") or ":" in name:
                        continue
                    names.add(name)
            except OSError:
                continue
            previous = self._known.get(entry.path)
            if previous is None:
                # A project directory nobody has seen before. Once primed, that
                # can only mean the directory itself was just created -- which
                # is exactly what the FIRST session in a new project looks like,
                # directory and transcript appearing together -- so everything
                # in it is new. Treating it as a baseline instead loses that
                # session's placeholder entirely: it falls through to the
                # ordinary discover() sweep with nothing written for it.
                previous = set() if self.primed else names
            for name in sorted(names - previous):
                found.append(Path(entry.path) / name)
            self._known[entry.path] = names
            self._dir_mtime[entry.path] = stamp
        for gone in [key for key in self._dir_mtime if key not in alive]:
            self._dir_mtime.pop(gone, None)
            self._known.pop(gone, None)
        if not self.primed:
            # Belt and braces: the loop above already yields nothing on the
            # priming pass, and this makes that a guarantee rather than a
            # consequence of one branch.
            self.primed = True
            return []
        return found


class _Tracked:
    """One live session the supervisor is tailing."""

    __slots__ = ("session_id", "transcript", "slug", "watcher", "mtime",
                 "size", "added_epoch", "last_growth_epoch", "owns_pidfile")

    def __init__(self, session_id: str, transcript: Path, slug: str,
                 watcher: Watcher, mtime: float, size: int) -> None:
        self.session_id = session_id
        self.transcript = transcript
        self.slug = slug
        self.watcher = watcher
        self.mtime = mtime
        self.size = size
        self.added_epoch = time.time()
        self.last_growth_epoch = time.time()
        self.owns_pidfile = False


class Supervisor:
    """One process, every live session, no configuration.

    The loop is four cheap steps and one expensive one:

      fast_scan() every new_session_scan_seconds -- one os.scandir of
                  ~/.claude/projects. A transcript that was not there before
                  gets its placeholder report written immediately, so the
                  report path is openable inside a second of the session
                  starting, and then hands off to discover() to adopt it.
      discover()  every discover_seconds -- one /proc sweep plus a stat() per
                  transcript. Adds new sessions, in any project.
      tick()      every poll_seconds, per tracked session -- the SAME
                  incremental machinery the per-session daemon uses, so cost is
                  proportional to bytes the session just wrote.
      reap()      every discover_seconds -- finalizes anything that has gone
                  quiet with no claude process left on its project.
      dashboard   every dashboard_interval_seconds, once for all sessions
                  (a per-session watcher would rebuild it N times over), plus
                  once immediately whenever fast_scan() adopts a new session.
    """

    def __init__(self, reports_root: Optional[str | os.PathLike] = None, *,
                 poll_seconds: Optional[float] = None,
                 discover_seconds: Optional[float] = None,
                 idle_finalize_seconds: Optional[float] = None,
                 activate_within_seconds: Optional[float] = None,
                 hard_idle_seconds: Optional[float] = None,
                 max_sessions: Optional[int] = None,
                 dashboard_interval_seconds: Optional[float] = None,
                 report_interval_seconds: Optional[float] = None,
                 max_track_age_seconds: Optional[float] = None,
                 new_session_scan_seconds: Optional[float] = None,
                 log_path: Optional[Path] = None) -> None:
        if reports_root:
            paths.set_reports_root(reports_root)
        config = paths.load_config()
        block = config.get("supervisor") or {}
        self.config = config
        self.reports_root = paths.reports_root()

        def _pick(explicit, key, fallback, top_level=None):
            if explicit is not None:
                return explicit
            if key in block:
                return block[key]
            if top_level and top_level in config:
                return config[top_level]
            return fallback

        self.poll = max(0.25, float(_pick(poll_seconds, "poll_seconds", 2.0)))
        self.discover_interval = max(1.0, float(
            _pick(discover_seconds, "discover_seconds", 5.0)))
        # Separate from discover_interval because the two answer different
        # questions at different prices: this one is "did a file appear?"
        # (one os.scandir) and can run every second; discover() is "which
        # sessions are live?" (a /proc sweep plus a stat per transcript) and
        # cannot. Clamped at 0.2 s so a config typo cannot spin the loop.
        self.new_session_scan = max(0.2, float(
            _pick(new_session_scan_seconds, "new_session_scan_seconds",
                  NEW_SESSION_SCAN_SECONDS)))
        # The pivot names this one at the top level of config.json, so honour
        # both spellings rather than making the user guess which nesting wins.
        self.idle_finalize = max(5.0, float(
            _pick(idle_finalize_seconds, "idle_finalize_seconds", 300.0,
                  "idle_finalize_seconds")))
        self.activate_within = float(
            _pick(activate_within_seconds, "activate_within_seconds", 900.0))
        # Backstop for the one thing PID->project cannot resolve: two sessions
        # in the same directory, one abandoned. The process signal keeps the
        # abandoned one "live" forever, so idle alone finalizes it eventually.
        self.hard_idle = float(_pick(hard_idle_seconds, "hard_idle_seconds", 4 * 3600.0))
        self.max_sessions = max(1, int(_pick(max_sessions, "max_sessions", 8)))
        self.dashboard_interval = float(
            _pick(dashboard_interval_seconds, "dashboard_interval_seconds", 30.0))
        self.max_track_age = float(
            _pick(max_track_age_seconds, "max_track_age_seconds", 24 * 3600.0))
        # How often report.html is rebuilt WHILE a session keeps writing. None
        # leaves the per-session default (config.watcher.report_interval_seconds,
        # 15 s); a rebuild also fires ~3 s after any pause, which is when the
        # document is actually read.
        self.report_interval: Optional[float] = (
            float(report_interval_seconds) if report_interval_seconds is not None
            else (float(block["report_interval_seconds"])
                  if "report_interval_seconds" in block else None))

        self.log_path = Path(log_path) if log_path else supervisor_log()
        self.tracked: Dict[str, _Tracked] = {}
        # session_id -> transcript mtime at the moment we finalized it. A later
        # mtime means the session was resumed and must be picked up again.
        self._final_mtime: Dict[str, float] = {}

        self._lock_handle: Any = None
        self._owns_lock = False
        self._stop = False
        self._stop_reason = "unknown"
        self.started_epoch = time.time()
        self.ticks = 0
        self.discoveries = 0
        self.finalized = 0
        self.skipped_owned = 0
        self.proc_available: Optional[bool] = None
        self.live_slugs: Dict[str, Dict[str, Any]] = {}
        self._last_discover = 0.0
        self._last_dashboard = 0.0
        self._last_status = 0.0
        self._last_pass = 0.0
        self._last_fast_scan = 0.0
        self.tick_ms: List[float] = []
        self.discover_ms: List[float] = []
        self.dashboard_ms: List[float] = []
        self.scan_ms: List[float] = []
        # New-session machinery: the scanner remembers what was on disk, and
        # _pending_new holds files seen but not yet adoptable (a transcript can
        # exist for a beat before it has a byte in it, and candidates() skips
        # anything under 2 bytes).
        self._scanner = _NewTranscriptScanner()
        self._pending_new: Dict[str, tuple] = {}
        self.new_sessions = 0

    # -- logging ------------------------------------------------------------

    def log(self, message: str, level: str = "info") -> None:
        try:
            paths.ensure_dir(self.log_path.parent)
            with open(self.log_path, "a", encoding="utf-8") as handle:
                handle.write(f"{_iso(_now())} {level:<5} {message}\n")
        except Exception:
            pass

    # -- single instance ----------------------------------------------------

    def acquire(self) -> bool:
        """Take the process-wide lock. False when another supervisor holds it.

        flock is the real guarantee: the kernel drops it when the holder dies,
        including on SIGKILL, so a crashed supervisor never wedges the feature.
        The pidfile beside it is only a human/CLI-readable record -- it is
        written after the lock is won, never consulted to decide the race.
        """
        if self._owns_lock:
            return True
        try:
            import fcntl
        except ImportError:  # pragma: no cover - not Linux
            return self._acquire_via_pidfile()
        path = supervisor_lockfile()
        try:
            paths.ensure_dir(path.parent)
            handle = open(path, "a+", encoding="utf-8")
        except OSError:
            return self._acquire_via_pidfile()
        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            try:
                handle.close()
            except OSError:
                pass
            return False
        self._lock_handle = handle
        self._owns_lock = True
        try:
            handle.seek(0)
            handle.truncate()
            handle.write(json.dumps({"pid": os.getpid(), "at": _iso(_now())}) + "\n")
            handle.flush()
        except OSError:
            pass
        self._write_supervisor_pidfile()
        return True

    def _acquire_via_pidfile(self) -> bool:
        """Fallback exclusion where flock is unavailable. Racier, still correct
        for the ordinary case of a second `oe watch` pane seconds later."""
        running = supervisor_running()
        if running:
            return False
        self._owns_lock = True
        self._write_supervisor_pidfile()
        return True

    def _write_supervisor_pidfile(self) -> None:
        try:
            paths.atomic_write(supervisor_pidfile(), json.dumps({
                "pid": os.getpid(),
                "proc_starttime": _proc_starttime(os.getpid()),
                "reports_root": str(self.reports_root),
                "started_at": _iso(_now()),
                "started_epoch": self.started_epoch,
                "schema": _SUPERVISOR_SCHEMA,
            }, indent=2) + "\n")
        except Exception as exc:
            self.log(f"supervisor pidfile write failed: {exc!r}", "error")

    def release(self) -> None:
        if not self._owns_lock:
            return
        try:
            record = json.loads(supervisor_pidfile().read_text(encoding="utf-8"))
            if _int(record.get("pid")) == os.getpid():
                supervisor_pidfile().unlink()
        except Exception:
            pass
        handle, self._lock_handle = self._lock_handle, None
        self._owns_lock = False
        if handle is not None:
            try:
                handle.close()  # closing releases the flock
            except OSError:
                pass

    # -- discovery ----------------------------------------------------------

    def _meta_path(self, session_id: str) -> Path:
        return paths.session_report_dir(session_id) / "meta.json"

    def _read_meta(self, session_id: str) -> Dict[str, Any]:
        try:
            meta = json.loads(self._meta_path(session_id).read_text(encoding="utf-8"))
            return meta if isinstance(meta, dict) else {}
        except Exception:
            return {}

    def _already_final(self, session_id: str, mtime: float) -> bool:
        """True when this session was finalized and has not been resumed since.

        The mtime comparison is what makes a resume work: a finalized session
        whose transcript grows again is a NEW life, and must be tracked and
        finalized again. Without it, `claude --resume` would silently stop
        producing a report.
        """
        remembered = self._final_mtime.get(session_id)
        if remembered is not None:
            return mtime <= remembered + 0.5
        meta = self._read_meta(session_id)
        if not meta.get("final"):
            return False
        recorded = float(meta.get("final_transcript_mtime") or 0.0)
        self._final_mtime[session_id] = recorded
        self._trim_final_memory()
        return mtime <= recorded + 0.5

    def _trim_final_memory(self, cap: int = 512) -> None:
        while len(self._final_mtime) > cap:
            self._final_mtime.pop(next(iter(self._final_mtime)))

    def _claim(self, session_id: str, transcript: Path) -> bool:
        """Take ownership of this session's tail, unless someone already has it.

        The optional hook path spawns a per-session daemon; if one is alive we
        leave the session to it rather than tail the same bytes twice.
        """
        owner = is_running(session_id)
        if owner:
            self.skipped_owned += 1
            return False
        if not _claim_pidfile(session_id, str(transcript)):
            return False
        try:
            _write_pidfile(session_id, str(transcript), self.reports_root,
                           extra={"supervisor": True, "supervisor_pid": os.getpid()})
        except Exception as exc:
            self.log(f"pidfile write failed for {session_id}: {exc!r}", "error")
            _clear_pidfile(session_id)
            return False
        return True

    def _release_claim(self, record: _Tracked) -> None:
        if not record.owns_pidfile:
            return
        current = read_pidfile(record.session_id) or {}
        if _int(current.get("pid")) == os.getpid():
            _clear_pidfile(record.session_id)
        record.owns_pidfile = False

    def candidates(self, now: float) -> List[tuple]:
        """(mtime, size, transcript, slug) for every transcript worth tracking.

        Two independent reasons to consider one live, because either alone is
        wrong: recent bytes (a session mid-turn, whose claude we may not be able
        to see) OR an open claude process on its project (a session the user is
        reading, which has written nothing for ten minutes).
        """
        rows: List[tuple] = []
        for transcript in paths.iter_transcripts():
            try:
                stat = transcript.stat()
            except OSError:
                continue
            if stat.st_size < 2:
                continue
            age = now - stat.st_mtime
            if age > self.max_track_age:
                continue
            slug = transcript.parent.name
            here = self.live_slugs.get(slug)
            fresh = age <= self.activate_within
            held = bool(here) and stat.st_mtime >= (here["since"] - _PROC_START_GRACE)
            if fresh or held:
                rows.append((stat.st_mtime, stat.st_size, transcript, slug))
        rows.sort(key=lambda row: -row[0])
        return rows

    def fast_scan(self, now: Optional[float] = None) -> int:
        """Catch transcripts that appeared since the last sweep. Returns how many.

        Ordered the way it is for one reason: the PLACEHOLDER IS WRITTEN FIRST,
        before any adoption is attempted, because the promise being kept here is
        that the report path opens from the first second of a session. Adoption
        can wait a beat -- a report path that 404s cannot.

        A transcript can exist with nothing in it, and candidates() skips
        anything under 2 bytes, so a file that is not adoptable yet stays on
        _pending_new and is retried every scan for a minute; after that the
        ordinary discover() sweep owns it.
        """
        started = time.perf_counter()
        now = time.time() if now is None else now
        self._last_fast_scan = now
        try:
            for path in self._scanner.scan():
                session_id = path.stem
                if session_id in self._pending_new or session_id in self.tracked:
                    continue
                self._pending_new[session_id] = (path, now)
                if write_skeleton_report(session_id, path) is not None:
                    self.log(f"new session {session_id} project={path.parent.name}; "
                             f"skeleton report published")
        finally:
            self.scan_ms.append((time.perf_counter() - started) * 1000.0)
            del self.scan_ms[:-64]

        if not self._pending_new:
            return 0
        ready = 0
        for session_id, (path, first_seen) in list(self._pending_new.items()):
            if session_id in self.tracked:
                self._pending_new.pop(session_id, None)
                continue
            if (now - first_seen) > NEW_SESSION_PENDING_SECONDS:
                self._pending_new.pop(session_id, None)
                continue
            try:
                if path.stat().st_size < 2:
                    continue  # created but still empty; try again next scan
            except OSError:
                self._pending_new.pop(session_id, None)
                continue
            ready += 1
        if not ready:
            return 0
        # discover() is cheap and already does claiming, the max_sessions cap
        # and the resume check; duplicating any of that here would be a second
        # copy of the rules that decide who owns a session.
        added = self.discover(now)
        for session_id in list(self._pending_new):
            if session_id in self.tracked:
                self._pending_new.pop(session_id, None)
        if added:
            self.new_sessions += added
            # The dashboard is on a 30 s cadence, which is not "immediately".
            self.refresh_dashboard()
        return added

    def discover(self, now: Optional[float] = None) -> int:
        """Find sessions that became live. Returns how many were added."""
        started = time.perf_counter()
        now = time.time() if now is None else now
        self._last_discover = now
        self.discoveries += 1
        slugs = live_project_slugs()
        self.proc_available = slugs is not None
        self.live_slugs = slugs or {}
        added = 0
        for mtime, size, transcript, slug in self.candidates(now):
            session_id = transcript.stem
            if session_id in self.tracked:
                continue
            if self._already_final(session_id, mtime):
                continue
            if len(self.tracked) >= self.max_sessions:
                break  # bounded: the newest max_sessions win, oldest are ignored
            if not self._claim(session_id, transcript):
                continue
            try:
                watcher = Watcher(
                    session_id, transcript,
                    refresh_seconds=self.poll,
                    idle_exit_seconds=self.idle_finalize,
                    report_interval_seconds=self.report_interval,
                    # The supervisor owns the dashboard; a per-session refresh
                    # would rebuild the same index.html once per live session.
                    dashboard_interval_seconds=10 ** 9,
                )
            except Exception as exc:
                self.log(f"cannot watch {session_id}: {exc!r}", "error")
                _clear_pidfile(session_id)
                continue
            record = _Tracked(session_id, transcript, slug, watcher, mtime, size)
            record.owns_pidfile = True
            self.tracked[session_id] = record
            self._final_mtime.pop(session_id, None)
            watcher.log(f"supervised by pid={os.getpid()} (no hooks)")
            try:
                watcher.discover(force=True)
            except Exception as exc:
                self.log(f"agent discovery failed for {session_id}: {exc!r}", "warn")
            added += 1
            self.log(f"tracking {session_id} project={slug} "
                     f"size={size} age={now - mtime:.0f}s "
                     f"proc={'yes' if slug in self.live_slugs else 'no'}")
        elapsed = (time.perf_counter() - started) * 1000.0
        self.discover_ms.append(elapsed)
        del self.discover_ms[:-64]
        return added

    # -- per-session work ---------------------------------------------------

    def tick_sessions(self) -> float:
        """One incremental pass over every tracked session. Returns ms spent."""
        started = time.perf_counter()
        for session_id, record in list(self.tracked.items()):
            try:
                record.watcher.tick()
            except Exception as exc:
                self.log(f"tick failed for {session_id}: {exc!r}", "error")
                continue
            cursor = record.watcher.cursors.get(str(record.transcript))
            if cursor is None:
                continue
            if cursor.size > record.size or cursor.mtime > record.mtime:
                record.last_growth_epoch = time.time()
            record.mtime = max(record.mtime, cursor.mtime)
            record.size = cursor.size
        elapsed = (time.perf_counter() - started) * 1000.0
        self.tick_ms.append(elapsed)
        del self.tick_ms[:-256]
        self.ticks += 1
        return elapsed

    def _current_mtime(self, record: _Tracked) -> float:
        try:
            return record.transcript.stat().st_mtime
        except OSError:
            return record.mtime

    def reap(self, now: Optional[float] = None) -> int:
        """Finalize every session that has gone quiet. Returns how many."""
        now = time.time() if now is None else now
        done = 0
        for session_id, record in list(self.tracked.items()):
            claim = read_pidfile(session_id) or {}
            if _int(claim.get("pid")) != os.getpid():
                # Our claim is gone or now belongs to somebody else: a
                # SessionEnd hook ran stop(), or a per-session daemon took over.
                # Hand the session across WITHOUT finalizing it -- marking it
                # final here would stop the new owner's work from ever being
                # picked up again. Testing existence alone was not enough: a
                # pidfile rewritten by another owner still exists.
                self.log(f"claim revoked for {session_id} "
                         f"(now pid={claim.get('pid')}); dropping")
                record.owns_pidfile = False
                self.tracked.pop(session_id, None)
                continue
            mtime = self._current_mtime(record)
            record.mtime = max(record.mtime, mtime)
            idle = now - max(record.mtime, record.last_growth_epoch)
            if idle < self.idle_finalize:
                continue
            has_process = record.slug in self.live_slugs
            if has_process and idle < self.hard_idle:
                continue
            reason = "idle" if not has_process else "idle-hard"
            if not self.proc_available:
                reason = "idle-no-proc"
            self.finalize(record, reason, idle)
            done += 1
        return done

    def finalize(self, record: _Tracked, reason: str, idle: float) -> None:
        """The last, accurate build. Replaces what the SessionEnd hook did.

        Exactly once per session life: the session id is remembered with the
        transcript mtime it had here, and discover() will not pick it up again
        until the file grows past that -- which is precisely a resume.
        """
        session_id = record.session_id
        started = time.perf_counter()
        exists = record.transcript.exists()
        if exists:
            try:
                record.watcher.ingest()
            except Exception as exc:
                self.log(f"final ingest failed for {session_id}: {exc!r}", "error")
            try:
                # full_rebuild() already loads with include_subagents=True, which
                # is the whole point of the final pass: the incremental tail sees
                # agent files, but only a real load reconciles them.
                record.watcher.full_rebuild("finalize")
            except Exception as exc:
                self.log(f"final rebuild failed for {session_id}: {exc!r}", "error")
        final_mtime = self._current_mtime(record)
        self._write_final_meta(record, reason, final_mtime, exists)
        try:
            paths.live_snapshot_path(session_id).unlink()
        except OSError:
            pass  # a stale live.json would show the session as open forever
        self._release_claim(record)
        self.tracked.pop(session_id, None)
        self._final_mtime[session_id] = final_mtime
        self._trim_final_memory()
        self.finalized += 1
        self.log(f"finalized {session_id} reason={reason} idle={idle:.0f}s "
                 f"in {(time.perf_counter() - started) * 1000.0:.0f} ms")

    def _write_final_meta(self, record: _Tracked, reason: str, final_mtime: float,
                          exists: bool) -> None:
        session_id = record.session_id
        meta = self._read_meta(session_id)
        events = paths.tool_events_path(session_id)
        try:
            has_timing = events.stat().st_size > 0
        except OSError:
            has_timing = False
        meta.update({
            # meta.json sits inside the session's report directory, so it is an
            # artifact: pseudonyms, and no transcript path. The real identity is
            # in the local session map, reachable with `oe whois`.
            "session": redact.session_pseudonym(session_id),
            "project": redact.project_pseudonym(record.slug) if record.slug else None,
            "final": True,
            "finalized_at": _iso(_now()),
            "finalized_by": "supervisor",
            "finalize_reason": reason,
            "end_reason": reason,
            "final_transcript_mtime": final_mtime,
            "final_transcript_exists": exists,
            "supervisor_pid": os.getpid(),
            "process_signal_available": bool(self.proc_available),
            # Stated, not implied: without the optional PostToolUse hook there
            # is no per-tool wall time anywhere in a transcript, so the report's
            # tool table shows counts and bytes and no duration. Recording it
            # here keeps the report honest instead of printing a zero.
            "tool_timing": "hook" if has_timing else "unavailable",
        })
        try:
            # meta.json lands in the session's report directory, so it goes
            # through the same gate as the five report documents. It MERGES into
            # whatever the SessionStart hook and oe/accounts.py already put
            # there, which is why guarding the merged text matters rather than
            # only the keys added above. A finding raises, this logs it, and the
            # previous meta.json stays: stale beats leaking.
            text = json.dumps(meta, indent=2, default=str) + "\n"
            redact.guard(text, str(self._meta_path(session_id)))
            paths.atomic_write(self._meta_path(session_id), text)
        except Exception as exc:
            self.log(f"meta write failed for {session_id}: {exc!r}", "error")

    # -- shared outputs -----------------------------------------------------

    def refresh_dashboard(self) -> None:
        started = time.perf_counter()
        try:
            try:
                from . import dashboard as dashboard_mod
            except ImportError:
                from oe import dashboard as dashboard_mod  # type: ignore
            dashboard_mod.write_dashboard(self.reports_root)
        except Exception as exc:
            self.log(f"dashboard refresh failed: {exc!r}", "error")
        self._last_dashboard = time.time()
        self.dashboard_ms.append((time.perf_counter() - started) * 1000.0)
        del self.dashboard_ms[:-32]

    def snapshot(self) -> Dict[str, Any]:
        def avg(values: List[float]) -> float:
            return round(sum(values) / len(values), 3) if values else 0.0
        return {
            "schema": _SUPERVISOR_SCHEMA,
            "pid": os.getpid(),
            "reports_root": str(self.reports_root),
            "updated_at": _iso(_now()),
            "updated_epoch": time.time(),
            "uptime_seconds": round(time.time() - self.started_epoch, 1),
            "ticks": self.ticks,
            "discoveries": self.discoveries,
            "finalized": self.finalized,
            "skipped_owned_by_hook": self.skipped_owned,
            "process_signal": ("available" if self.proc_available
                               else "unavailable (mtime-only fallback)"),
            "live_projects": sorted(self.live_slugs.keys()),
            "poll_seconds": self.poll,
            "discover_seconds": self.discover_interval,
            "new_session_scan_seconds": self.new_session_scan,
            "new_sessions": self.new_sessions,
            "pending_new": sorted(self._pending_new),
            "idle_finalize_seconds": self.idle_finalize,
            "max_sessions": self.max_sessions,
            "rss_mb": _rss_mb(),
            # pass_ms is the WHOLE pass over every tracked session and includes
            # any full rebuild that happened to fire inside it; the cheap
            # incremental cost is per-session tick_ms below. Reporting only the
            # combined figure would make a cheap tail look like an expensive one.
            "pass_ms_avg": avg(self.tick_ms),
            "pass_ms_max": round(max(self.tick_ms), 3) if self.tick_ms else 0.0,
            "discover_ms_avg": avg(self.discover_ms),
            "scan_ms_avg": avg(self.scan_ms),
            "dashboard_ms_avg": avg(self.dashboard_ms),
            "tracked": [{
                "session_id": record.session_id,
                "project": record.slug,
                "transcript": str(record.transcript),
                "size_bytes": record.size,
                "idle_seconds": round(time.time() - max(record.mtime,
                                                        record.last_growth_epoch), 1),
                "ticks": record.watcher.ticks,
                "full_builds": record.watcher.full_builds,
                "sources": len(record.watcher.cursors),
                "requests": len(record.watcher.agg.requests),
                "tick_ms_avg": avg(record.watcher.tick_ms),
                "tick_ms_max": (round(max(record.watcher.tick_ms), 3)
                                if record.watcher.tick_ms else 0.0),
                "full_ms_avg": avg(record.watcher.full_ms),
                "full_ms_max": (round(max(record.watcher.full_ms), 1)
                                if record.watcher.full_ms else 0.0),
                "cost_usd": round(float(
                    record.watcher.agg.snapshot_totals()["cost_usd_authoritative"] or 0.0), 4),
                "cost_usd_computed": round(float(
                    record.watcher.agg.totals.get("cost_usd") or 0.0), 4),
            } for record in self.tracked.values()],
        }

    def write_status(self) -> None:
        try:
            paths.atomic_write(supervisor_statusfile(),
                               json.dumps(self.snapshot(), indent=2, default=str) + "\n")
        except Exception as exc:
            self.log(f"status write failed: {exc!r}", "error")
        self._last_status = time.time()

    # -- loop ---------------------------------------------------------------

    def _install_signals(self) -> None:
        def handler(signum, _frame):
            self._stop = True
            self._stop_reason = f"signal {signum}"
        for sig in (signal.SIGTERM, signal.SIGINT):
            try:
                signal.signal(sig, handler)
            except (ValueError, OSError):
                pass  # not the main thread: the caller drives stop() instead
        try:
            signal.signal(signal.SIGHUP, signal.SIG_IGN)
        except (AttributeError, ValueError, OSError):
            pass

    def request_stop(self, reason: str = "requested") -> None:
        """Thread-safe stop, for the inline/threaded mode where signals cannot
        be installed."""
        self._stop_reason = reason
        self._stop = True

    def _sleep(self, seconds: float) -> None:
        deadline = time.time() + seconds
        while not self._stop:
            remaining = deadline - time.time()
            if remaining <= 0:
                return
            time.sleep(min(0.2, remaining))

    def run(self, max_ticks: Optional[int] = None, *, acquire: bool = True) -> int:
        """The loop. Returns 0, or 3 when another supervisor already holds the lock."""
        if acquire and not self.acquire():
            other = supervisor_running()
            self.log(f"another supervisor is running (pid={other}); exiting", "warn")
            return 3
        self._install_signals()
        _truncate_file(self.log_path)
        self.log(f"supervisor up pid={os.getpid()} root={self.reports_root} "
                 f"poll={self.poll}s discover={self.discover_interval}s "
                 f"new_session_scan={self.new_session_scan}s "
                 f"idle_finalize={self.idle_finalize}s max_sessions={self.max_sessions}")
        # The loop turns over at the FASTER of the two intervals so a new
        # transcript is seen within new_session_scan seconds. Everything else is
        # gated on self.poll, so its cadence -- and the meaning of max_ticks --
        # is unaffected by the faster turn.
        loop_interval = min(self.poll, self.new_session_scan)
        try:
            self.discover()
            while not self._stop:
                now = time.time()
                if (now - self._last_fast_scan) >= self.new_session_scan:
                    try:
                        self.fast_scan(now)
                    except Exception as exc:
                        self.log(f"new-session scan failed: {exc!r}", "error")
                if (now - self._last_discover) >= self.discover_interval:
                    try:
                        self.discover(now)
                    except Exception as exc:
                        self.log(f"discover failed: {exc!r}", "error")
                    try:
                        self.reap(now)
                    except Exception as exc:
                        self.log(f"reap failed: {exc!r}", "error")
                if (time.time() - self._last_pass) >= self.poll:
                    self._last_pass = time.time()
                    try:
                        self.tick_sessions()
                    except Exception as exc:
                        self.log(f"session tick failed: {exc!r}", "error")
                    if (time.time() - self._last_dashboard) >= self.dashboard_interval:
                        self.refresh_dashboard()
                    self.write_status()
                    _truncate_file(self.log_path)
                if max_ticks is not None and self.ticks >= max_ticks:
                    self._stop_reason = "max_ticks"
                    break
                self._sleep(loop_interval)
        finally:
            self._shutdown()
        return 0

    def _shutdown(self) -> None:
        self.log(f"stopping ({self._stop_reason}); {self.ticks} ticks, "
                 f"{self.finalized} finalized, {len(self.tracked)} still live")
        for record in list(self.tracked.values()):
            # Live sessions are NOT finalized on our way out -- they are still
            # running, and marking them final would stop the next supervisor
            # from ever picking them up again. Just publish and let go.
            try:
                record.watcher.ingest()
                record.watcher.write_live()
            except Exception:
                pass
            self._release_claim(record)
        self.tracked.clear()
        try:
            self.write_status()
        except Exception:
            pass
        self.release()
        self.log("stopped")


# ---------------------------------------------------------------------------
# supervisor: public API
# ---------------------------------------------------------------------------


def supervisor_running() -> Optional[int]:
    """PID of the live supervisor, or None (clearing a stale pidfile).

    Trusts flock first: a supervisor that was SIGKILLed leaves its pidfile
    behind but not its lock, and a lock we can take is proof nobody is holding
    it. The PID check is the fallback when flock is unavailable.
    """
    record: Dict[str, Any] = {}
    try:
        record = json.loads(supervisor_pidfile().read_text(encoding="utf-8"))
    except Exception:
        record = {}
    pid = _int(record.get("pid")) if isinstance(record, dict) else 0
    if not pid and not supervisor_lockfile().exists():
        return None  # never held; do not create the lock file just to probe it
    try:
        import fcntl
        with open(supervisor_lockfile(), "a+", encoding="utf-8") as handle:
            try:
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError:
                return pid or -1  # held; -1 when the pidfile has not landed yet
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
    except (ImportError, OSError):
        pass
    else:
        if pid:
            try:
                supervisor_pidfile().unlink()  # lock free => the record is stale
            except OSError:
                pass
        return None
    if not pid or not _alive(pid):
        try:
            supervisor_pidfile().unlink()
        except OSError:
            pass
        return None
    recorded = record.get("proc_starttime")
    actual = _proc_starttime(pid)
    if recorded is not None and actual is not None and int(recorded) != int(actual):
        try:
            supervisor_pidfile().unlink()
        except OSError:
            pass
        return None
    return pid


def supervise(reports_root: Optional[str | os.PathLike] = None, *,
              poll_seconds: Optional[float] = None,
              discover_seconds: Optional[float] = None,
              idle_finalize_seconds: Optional[float] = None,
              max_sessions: Optional[int] = None,
              max_ticks: Optional[int] = None,
              acquire: bool = True,
              **kwargs) -> int:
    """Run the zero-config supervisor IN THIS PROCESS (foreground/inline).

    This is the whole zero-config path: no hooks, no settings.json, nothing to
    install. Returns 0 on a clean exit, 3 when another supervisor holds the lock.
    """
    supervisor = Supervisor(reports_root,
                            poll_seconds=poll_seconds,
                            discover_seconds=discover_seconds,
                            idle_finalize_seconds=idle_finalize_seconds,
                            max_sessions=max_sessions,
                            **kwargs)
    return supervisor.run(max_ticks=max_ticks, acquire=acquire)


def _supervisor_daemon_body(reports_root: Optional[str], poll_seconds: Optional[float],
                            idle_finalize_seconds: Optional[float]) -> None:
    """Grandchild entry point for the detached supervisor."""
    if reports_root:
        paths.set_reports_root(reports_root)
    try:
        os.chdir("/")
    except OSError:
        pass
    log_path = supervisor_log()
    try:
        devnull = os.open(os.devnull, os.O_RDONLY)
        os.dup2(devnull, 0)
        os.close(devnull)
    except OSError:
        pass
    # stdout/stderr MUST leave the caller's fds behind, log or no log. Keeping
    # an inherited pipe alive here wedges the caller: `oe supervise --ensure |
    # head` never sees EOF, and a command substitution around it hangs for the
    # life of the daemon. So /dev/null is the fallback, not "keep what we got".
    out = -1
    try:
        paths.ensure_dir(log_path.parent)
        out = os.open(str(log_path), os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o644)
    except OSError:
        out = -1
    if out < 0:
        try:
            out = os.open(os.devnull, os.O_WRONLY)
        except OSError:
            out = -1
    if out >= 0:
        try:
            os.dup2(out, 1)
            os.dup2(out, 2)
        except OSError:
            pass
        if out > 2:
            try:
                os.close(out)
            except OSError:
                pass
    supervise(reports_root, poll_seconds=poll_seconds,
              idle_finalize_seconds=idle_finalize_seconds)


def start_supervisor(reports_root: Optional[str | os.PathLike] = None, *,
                     poll_seconds: Optional[float] = None,
                     idle_finalize_seconds: Optional[float] = None) -> int:
    """Spawn the DETACHED supervisor. Idempotent; returns its PID (0 on failure).

    Detached rather than threaded is the default for `oe watch` because the
    report is supposed to keep being written after the pane is closed.
    """
    if reports_root:
        paths.set_reports_root(reports_root)
    existing = supervisor_running()
    if existing:
        return existing if existing > 0 else 0

    if not hasattr(os, "fork"):  # pragma: no cover - Linux/WSL only in practice
        import subprocess
        env = dict(os.environ)
        if reports_root:
            env[paths.ENV_REPORTS_ROOT] = str(reports_root)
        env["PYTHONPATH"] = str(paths.INSTALL_ROOT) + os.pathsep + env.get("PYTHONPATH", "")
        try:
            proc = subprocess.Popen(
                [sys.executable, "-m", "oe.watcher", "supervise"],
                cwd=str(paths.INSTALL_ROOT), env=env,
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL, start_new_session=True)
        except Exception:
            return 0
        return proc.pid

    read_fd, write_fd = os.pipe()
    try:
        first = os.fork()
    except OSError:
        os.close(read_fd)
        os.close(write_fd)
        return 0
    if first == 0:
        try:
            os.close(read_fd)
            os.setsid()
            if os.fork() > 0:
                os._exit(0)
            os.write(write_fd, str(os.getpid()).encode("ascii"))
            os.close(write_fd)
            _supervisor_daemon_body(str(reports_root) if reports_root else None,
                                    poll_seconds, idle_finalize_seconds)
        except BaseException:
            os._exit(1)
        os._exit(0)

    os.close(write_fd)
    try:
        os.waitpid(first, 0)
    except OSError:
        pass
    pid = 0
    try:
        import select
        ready, _, _ = select.select([read_fd], [], [], 5.0)
        if ready:
            pid = int(os.read(read_fd, 32) or 0)
    except Exception:
        pid = 0
    finally:
        try:
            os.close(read_fd)
        except OSError:
            pass
    return pid


def stop_supervisor(timeout: float = 6.0) -> bool:
    """SIGTERM the supervisor and wait. True when nothing is left running."""
    pid = supervisor_running()
    if not pid or pid < 0:
        return not pid
    try:
        os.kill(pid, signal.SIGTERM)
    except OSError:
        return True
    deadline = time.time() + timeout
    while time.time() < deadline:
        if not _alive(pid):
            return True
        time.sleep(0.1)
    try:
        os.kill(pid, signal.SIGKILL)
    except OSError:
        pass
    return not _alive(pid)


def ensure_supervisor(reports_root: Optional[str | os.PathLike] = None, *,
                      mode: str = "detached", **kwargs) -> Dict[str, Any]:
    """Make sure exactly one supervisor is running. Never raises.

    mode="detached"  a daemon that outlives the caller (default: the report must
                     keep being written after the `oe watch` pane is closed).
    mode="thread"    a daemon THREAD inside the caller, which dies with it. Use
                     when the viewer should leave no process behind.
    mode="none"      report only.

    The returned dict always has "running" and "pid"; "thread" and "supervisor"
    are present only for mode="thread", so the caller can stop it.
    """
    try:
        existing = supervisor_running()
    except Exception:
        existing = None
    if existing:
        return {"running": True, "pid": existing if existing > 0 else 0,
                "started": False, "mode": "existing"}
    if mode == "none":
        return {"running": False, "pid": 0, "started": False, "mode": "none"}
    if mode == "thread":
        import threading
        supervisor = Supervisor(reports_root, **kwargs)
        if not supervisor.acquire():
            return {"running": True, "pid": supervisor_running() or 0,
                    "started": False, "mode": "existing"}
        thread = threading.Thread(target=lambda: supervisor.run(acquire=False),
                                  name="oe-supervisor", daemon=True)
        thread.start()
        return {"running": True, "pid": os.getpid(), "started": True,
                "mode": "thread", "thread": thread, "supervisor": supervisor}
    pid = start_supervisor(reports_root, **kwargs)
    return {"running": bool(pid), "pid": pid, "started": bool(pid), "mode": "detached"}


def supervisor_status() -> Dict[str, Any]:
    """What the running supervisor last published, plus whether it is alive."""
    pid = supervisor_running()
    snapshot: Dict[str, Any] = {}
    try:
        snapshot = json.loads(supervisor_statusfile().read_text(encoding="utf-8"))
        if not isinstance(snapshot, dict):
            snapshot = {}
    except Exception:
        snapshot = {}
    age = None
    if snapshot.get("updated_epoch"):
        age = round(time.time() - float(snapshot["updated_epoch"]), 1)
    return {
        "running": bool(pid),
        "pid": pid,
        "pidfile": str(supervisor_pidfile()),
        "lockfile": str(supervisor_lockfile()),
        "statusfile": str(supervisor_statusfile()),
        "log": str(supervisor_log()),
        "status_age_seconds": age,
        "snapshot": snapshot,
    }


# ---------------------------------------------------------------------------
# CLI: python3 -m oe.watcher {start|stop|status|run} --session-id <id> [...]
# ---------------------------------------------------------------------------


def main(argv: Optional[List[str]] = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(prog="oe.watcher", description="Overwatch Enforcer session watcher")
    parser.add_argument("command", choices=("start", "stop", "status", "run",
                                            "supervise", "supervise-start",
                                            "supervise-stop", "supervise-status"))
    parser.add_argument("--session-id", "-s", default=None)
    parser.add_argument("--transcript", "-t", default=None)
    parser.add_argument("--reports-root", default=None)
    parser.add_argument("--refresh", type=float, default=None)
    parser.add_argument("--idle-exit", type=float, default=None)
    parser.add_argument("--report-interval", type=float, default=None)
    parser.add_argument("--ticks", type=int, default=None, help="run this many ticks then exit")
    parser.add_argument("--poll", type=float, default=None,
                        help="supervisor: seconds between incremental passes")
    parser.add_argument("--discover", type=float, default=None,
                        help="supervisor: seconds between liveness sweeps")
    parser.add_argument("--new-session-scan", type=float, default=None,
                        help="supervisor: seconds between os.scandir sweeps for "
                             "transcripts that did not exist before")
    parser.add_argument("--idle-finalize", type=float, default=None,
                        help="supervisor: quiet seconds before a session is finalized")
    parser.add_argument("--max-sessions", type=int, default=None,
                        help="supervisor: cap on concurrently tracked sessions")
    args = parser.parse_args(argv)

    if args.reports_root:
        paths.set_reports_root(args.reports_root)

    # The supervisor commands are session-less by construction: discovering the
    # sessions IS the job, so they must run before the session-id resolution.
    if args.command == "supervise":
        return supervise(args.reports_root,
                         poll_seconds=args.poll,
                         discover_seconds=args.discover,
                         idle_finalize_seconds=args.idle_finalize,
                         max_sessions=args.max_sessions,
                         new_session_scan_seconds=args.new_session_scan,
                         max_ticks=args.ticks)
    if args.command == "supervise-start":
        pid = start_supervisor(args.reports_root, poll_seconds=args.poll,
                               idle_finalize_seconds=args.idle_finalize)
        print(pid)
        return 0 if pid else 1
    if args.command == "supervise-stop":
        print("stopped" if stop_supervisor() else "still running")
        return 0
    if args.command == "supervise-status":
        print(json.dumps(supervisor_status(), indent=2, default=str))
        return 0

    session_id = args.session_id
    transcript = args.transcript
    if transcript and not session_id:
        session_id = Path(transcript).stem
    if session_id and not transcript:
        found = paths.find_transcript(session_id)
        transcript = str(found) if found else None
    if not session_id:
        print("need --session-id or --transcript", file=sys.stderr)
        return 2

    if args.command == "stop":
        print("stopped" if stop(session_id) else "still running")
        return 0
    if args.command == "status":
        print(json.dumps(status(session_id), indent=2, default=str))
        return 0
    if not transcript:
        print(f"no transcript found for session {session_id}", file=sys.stderr)
        return 2
    if args.command == "start":
        pid = start(session_id, transcript, args.reports_root,
                    refresh_seconds=args.refresh, idle_exit_seconds=args.idle_exit)
        print(pid)
        return 0 if pid else 1
    return run_loop(session_id, transcript, args.reports_root,
                    refresh_seconds=args.refresh,
                    idle_exit_seconds=args.idle_exit,
                    report_interval_seconds=args.report_interval,
                    max_ticks=args.ticks,
                    require_pidfile=args.ticks is None)


if __name__ == "__main__":
    raise SystemExit(main())
