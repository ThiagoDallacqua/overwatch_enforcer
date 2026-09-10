"""Build a billing ledger for one Claude Code session from its transcripts.

WHY the parsing is shaped the way it is (all verified against real transcripts):

* One API request is written as SEVERAL assistant JSONL lines -- one per content
  block (thinking / text / tool_use), each repeating the same requestId. So the
  unit of billing is the requestId, not the line, and tool_use blocks must be
  unioned across every line that shares a requestId.

* In the MAIN transcript every line of a requestId carries identical usage, and
  that usage matches Claude Code's own cost-state to ~1%. In SIDECHAIN
  (subagent) transcripts the lines carry a growing mid-stream snapshot and the
  final message_delta usage is never written back, so the last snapshot
  under-reports output_tokens. We therefore keep the highest-output snapshot per
  requestId -- the best value the file actually contains -- and surface the
  residual gap in .reconciliation instead of hiding it.

* Subagent transcripts live in TWO places: <session>/subagents/agent-*.jsonl and,
  for Workflow tool runs, <session>/subagents/workflows/wf_*/agent-*.jsonl. Miss
  the nested ones and a workflow-heavy session under-counts by 5x.

* Session dir names are derived from cwd, and cwd can change mid-session, so the
  sidecar directory is always resolved from the transcript path, never rebuilt
  from a cwd field.
"""

from __future__ import annotations

import json
import os
import re
import time
from bisect import bisect_left, bisect_right
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from . import SCHEMA_VERSION, accounts, paths, pricing, redact

# ---------------------------------------------------------------------------
# low level parsing helpers
# ---------------------------------------------------------------------------

# The top-level "type" is NOT always the first "type" in the line: assistant
# lines put the whole `message` object first, so the first match is
# message.type == "message". Match against a whitelist of top-level kinds
# instead, and fall back to the assistant-only `"role":"assistant"` marker.
_TOP_TYPES = ("assistant", "user", "attachment", "cost-state", "ai-title",
              "last-prompt", "system", "summary", "mode", "permission-mode",
              "atis-latch", "bridge-session", "queue-operation", "frame-link",
              "pr-link", "agent-name", "file-history-delta",
              "file-history-snapshot")
_TYPE_RE = re.compile(r'"type"\s*:\s*"(' + "|".join(_TOP_TYPES) + r')"')
_ROLE_ASSISTANT_RE = re.compile(r'"role"\s*:\s*"assistant"')
_TOOL_USE_ID_RE = re.compile(r'"tool_use_id"\s*:\s*"([^"]+)"')
_PROMPT_ID_RE = re.compile(r'"promptId"\s*:\s*"([^"]+)"')
_IS_ERROR_RE = re.compile(r'"is_error"\s*:\s*true')
_COMPACT_MARK_RE = re.compile(
    r'"isCompactSummary"\s*:\s*true|"subtype"\s*:\s*"compact_boundary"')
_UUID_RE = re.compile(r'"uuid"\s*:\s*"([^"]+)"')
_TS_RE = re.compile(r'"timestamp"\s*:\s*"([^"]+)"')
_WS_RE = re.compile(r"\s+")

# Lines above this size are classified by regex instead of json.loads. Big lines
# are almost always tool_result payloads, where we only need id + byte size, and
# parsing them is the single most expensive thing this module could do.
_BIG_LINE = 8192

# Slack between a cost-state startTime and the first request it covers.
_RUN_START_GRACE = timedelta(seconds=120)
# The RIGHT edge takes no grace. _RUN_START_GRACE exists to absorb the skew
# between a run's startTime (a clock reading) and the first request it covers;
# the right edge is an actual request timestamp read out of the file, so there
# is no skew to absorb, and 120 seconds of slack there silently folds every
# request issued in the two minutes after a checkpoint into that checkpoint's
# total. On a LIVE session -- checkpoint written, work continuing -- that is the
# steady state, not a corner case. The epsilon only keeps the marked request
# itself on the covered side of a "strictly before" scan.
_RIGHT_EDGE_EPS = 0.001

# How far the context window must fall in one step to count as emptied rather
# than merely smaller. See the comment in context_growth() for why this is not
# a calibrated figure.
_RESET_FRACTION = 0.25

# The six priced components of one request, in the order the report prints them.
_COST_KEYS = ("input_usd", "output_usd", "cache_write_5m_usd",
              "cache_write_1h_usd", "cache_read_usd", "web_search_usd")


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _parse_ts(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        text = str(value)
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        parsed = datetime.fromisoformat(text)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)
    except Exception:
        return None


def _iso(value: Optional[datetime]) -> Optional[str]:
    return value.isoformat().replace("+00:00", "Z") if value else None


def _int(value) -> int:
    if value is None:
        return 0
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _float(value) -> float:
    """float() that cannot raise on transcript data.

    Anything that comes off a JSONL line is untyped; a bare float() on a
    cost-state field is one malformed record away from taking a whole report
    (or, in the watcher, the live snapshot) out permanently.
    """
    if value is None:
        return 0.0
    try:
        out = float(value)
    except (TypeError, ValueError):
        return 0.0
    return out if out == out and out not in (float("inf"), float("-inf")) else 0.0


def _line_type(raw: str) -> str:
    """Cheap type sniff so we can skip lines we never need without parsing.

    Three probes, cheapest first, because this runs on every line of every
    transcript and a full json.loads of a large tool_result is the one thing
    that would make loading a big session slow.
    """
    match = _TYPE_RE.search(raw, 0, 600)
    if match:
        return match.group(1)
    if _ROLE_ASSISTANT_RE.search(raw, 0, 900):
        return "assistant"
    match = _TYPE_RE.search(raw)
    return match.group(1) if match else ""


_COMMAND_RE = re.compile(
    r"<command-name>(?P<name>[^<]*)</command-name>.*?"
    r"(?:<command-args>(?P<args>[^<]*)</command-args>)?", re.S)


def _text_preview(value: Any, limit: int = 220) -> str:
    if isinstance(value, str):
        text = value
    elif isinstance(value, list):
        parts = []
        for block in value:
            if isinstance(block, dict) and block.get("type") == "text":
                parts.append(str(block.get("text") or ""))
            elif isinstance(block, str):
                parts.append(block)
        text = "\n".join(parts)
    else:
        text = ""
    text = _WS_RE.sub(" ", text).strip()
    if text.startswith("<command-name>"):
        # A slash command expands to XML; the name plus args is the readable part.
        match = _COMMAND_RE.match(text)
        if match:
            text = ("/" + (match.group("name") or "").strip().lstrip("/")
                    + " " + (match.group("args") or "").strip()).strip()
    return text[:limit] + ("..." if len(text) > limit else "")


def _mcp_server(tool_name: str) -> Optional[str]:
    if tool_name and tool_name.startswith("mcp__"):
        parts = tool_name.split("__")
        if len(parts) >= 2:
            return parts[1]
    return None


# ---------------------------------------------------------------------------
# records
# ---------------------------------------------------------------------------


# Resolution of the cumulative-spend series carried in data.json. 2,000 points
# is finer than the chart can draw and costs tens of KB even on a heavy session,
# a fraction of a percent of that session's data.json.
_COST_SERIES_POINTS = 2000
# How many of the priciest requests to carry for the report's raw table.
# report.MAX_HTML_CALL_ROWS renders 300; the margin lets the renderer
# filter (errors, one origin) without running out of rows.
TOP_CALL_ROWS = 400


@dataclass
class ApiCall:
    """One billed API request."""

    request_id: str
    uuid: Optional[str]
    ts: Optional[datetime]
    model: str
    tier: str
    effort: Optional[str]
    speed: str
    service_tier: Optional[str]
    origin: str  # 'main' | 'subagent' | 'workflow'
    agent_id: Optional[str] = None
    agent_type: Optional[str] = None
    agent_description: Optional[str] = None
    spawn_depth: Optional[int] = None
    attribution_skill: Optional[str] = None
    attribution_plugin: Optional[str] = None
    attribution_mcp_server: Optional[str] = None
    prompt_id: Optional[str] = None
    turn_index: Optional[int] = None
    input_tokens: int = 0
    output_tokens: int = 0
    thinking_tokens: int = 0
    cache_write_5m: int = 0
    cache_write_1h: int = 0
    cache_read: int = 0
    web_search_requests: int = 0
    web_fetch_requests: int = 0
    context_tokens: int = 0
    cost: Dict[str, Any] = field(default_factory=dict)
    tools: List[str] = field(default_factory=list)
    stop_reason: Optional[str] = None
    is_error: bool = False
    error_status: Optional[Any] = None
    aborted: bool = False
    unpriced: bool = False
    workflow_id: Optional[str] = None
    workflow_label: Optional[str] = None

    @property
    def total_usd(self) -> float:
        return float(self.cost.get("total_usd", 0.0) or 0.0)

    @property
    def total_tokens(self) -> int:
        return (self.input_tokens + self.output_tokens + self.cache_write_5m
                + self.cache_write_1h + self.cache_read)

    def to_dict(self) -> Dict[str, Any]:
        row = asdict(self)
        row["ts"] = _iso(self.ts)
        row["total_usd"] = round(self.total_usd, 6)
        row["total_tokens"] = self.total_tokens
        return row


@dataclass
class ToolCall:
    name: str
    tool_use_id: Optional[str]
    ts: Optional[datetime]
    origin: str
    agent_id: Optional[str] = None
    duration_ms: Optional[int] = None
    is_error: bool = False
    input_bytes: int = 0
    result_bytes: int = 0
    server: Optional[str] = None
    request_id: Optional[str] = None
    prompt_id: Optional[str] = None
    turn_index: Optional[int] = None
    target: Optional[str] = None  # file path / command fingerprint, for re-read detection
    # result_bytes is len(the whole JSONL line), which for a tool result counts
    # the payload roughly twice (Claude Code writes it under BOTH
    # message.content[].content and toolUseResult). That is fine as a relative
    # "which tool is fat" signal, which is all by_tool uses it for, but it is
    # the wrong input to a dollar figure. content_bytes is the exact length of
    # the text the model actually received, measured only for the read tools,
    # where it is the thing being paid for.
    content_bytes: int = 0
    span_lo: Optional[int] = None   # Read offset (1-based), when the call gave one
    span_hi: Optional[int] = None   # last line requested, when offset+limit gave one

    def to_dict(self) -> Dict[str, Any]:
        row = asdict(self)
        row["ts"] = _iso(self.ts)
        return row


# ---------------------------------------------------------------------------
# re-read ledger
# ---------------------------------------------------------------------------

# Only Read is counted as a "read". Grep/Glob return matches, not a file, and
# counting them as re-reads of a path would double-book the same bytes.
READ_TOOLS = frozenset({"Read"})
# A write to a path makes every earlier copy of it stale, which is what turns a
# later re-read from waste into work.
MUTATE_TOOLS = frozenset({"Edit", "Write", "MultiEdit", "NotebookEdit"})

# Why a read of an already-read path happened. Exactly one applies, and the
# order below is the precedence: a window that never held the file cannot be
# faulted for reading it, whatever else is also true.
#
#   first         the session's first read of this path -- not a repeat at all
#   subagent      a different context window (an agent's own window, or the main
#                 window reading what until now only an agent had read)
#   post_compact  this window held it, and a compaction dropped it
#   new_range     resident, but this call asked for lines the window has not
#                 seen (a Read with an offset past what was read before)
#   changed       still resident over this range, but the file was written since
#                 it was read, so the bytes genuinely differ
#   avoidable     still resident, unchanged: the model already had these exact
#                 bytes in this exact window and paid to carry them again
REREAD_REASONS = ("first", "subagent", "post_compact", "new_range", "changed",
                  "avoidable")
LEGITIMATE_REREADS = ("subagent", "post_compact", "new_range", "changed")

# Dollars per 1,000 tokens placed into a context. Carrying tokens forward costs
# hundreds of times what it costs to read them once, because every later request
# re-sends the whole prefix. It is a RATE -- list-price arithmetic, never a
# measurement of anybody's spend -- and a CALIBRATION rather than a measurement
# of this session, which is why every row also carries `carry_usd`, computed
# from this session's own request stream. Override with
# insights.carry_usd_per_1k in config.json.
CARRY_USD_PER_1K = 0.126


def _read_span(tool_input: Any) -> Tuple[Optional[int], Optional[int]]:
    """(first line, last line) a Read asked for, or (None, None) for the lot."""
    if not isinstance(tool_input, dict):
        return (None, None)
    offset = tool_input.get("offset")
    limit = tool_input.get("limit")
    try:
        lo = int(offset) if offset is not None else None
    except (TypeError, ValueError):
        lo = None
    try:
        count = int(limit) if limit is not None else None
    except (TypeError, ValueError):
        count = None
    if lo is None and count is None:
        return (None, None)
    lo = max(1, lo or 1)
    return (lo, (lo + count - 1) if count else None)


def _result_content_bytes(obj: dict, tool_use_id: str) -> int:
    """Length of the text a tool_result actually put into the context."""
    message = obj.get("message")
    if not isinstance(message, dict):
        return 0
    content = message.get("content")
    if not isinstance(content, list):
        return 0
    total = 0
    for block in content:
        if not isinstance(block, dict) or block.get("type") != "tool_result":
            continue
        if block.get("tool_use_id") != tool_use_id:
            continue
        payload = block.get("content")
        if isinstance(payload, str):
            total += len(payload)
        elif isinstance(payload, list):
            for part in payload:
                if isinstance(part, dict) and isinstance(part.get("text"), str):
                    total += len(part["text"])
    return total


@dataclass
class _Turn:
    index: int
    prompt_id: Optional[str]
    uuid: Optional[str]
    ts: Optional[datetime]
    preview: str


# ---------------------------------------------------------------------------
# per-request accumulation
# ---------------------------------------------------------------------------


class _Request:
    """Accumulates the several JSONL lines that make up one API request."""

    __slots__ = ("obj", "usage", "best_output", "tool_blocks", "seen_tools", "ts",
                 "is_error", "aborted", "error_status", "source", "lines")

    def __init__(self, obj: dict, usage: dict, source: str):
        self.obj = obj
        self.usage = usage
        self.best_output = _int(usage.get("output_tokens"))
        self.tool_blocks: List[dict] = []
        self.seen_tools: set = set()
        self.ts = _parse_ts(obj.get("timestamp"))
        self.is_error = bool(obj.get("isApiErrorMessage") or obj.get("apiErrorStatus")
                             or obj.get("error"))
        self.aborted = bool(obj.get("isAbortedMidStream") or obj.get("truncatedAfterOutput"))
        self.error_status = obj.get("apiErrorStatus")
        self.source = source
        self.lines = 1

    def absorb(self, obj: dict, usage: dict) -> None:
        self.lines += 1
        output = _int(usage.get("output_tokens"))
        # Sidechain lines are mid-stream snapshots; the largest is the closest
        # the file gets to the true final usage.
        if output > self.best_output:
            self.best_output = output
            self.usage = usage
            self.obj = obj
        ts = _parse_ts(obj.get("timestamp"))
        if ts and (self.ts is None or ts < self.ts):
            self.ts = ts
        self.is_error = self.is_error or bool(obj.get("isApiErrorMessage")
                                              or obj.get("apiErrorStatus") or obj.get("error"))
        self.aborted = self.aborted or bool(obj.get("isAbortedMidStream")
                                            or obj.get("truncatedAfterOutput"))
        self.error_status = self.error_status or obj.get("apiErrorStatus")

    def add_blocks(self, content: Any) -> None:
        if not isinstance(content, list):
            return
        for block in content:
            if not isinstance(block, dict) or block.get("type") != "tool_use":
                continue
            key = block.get("id") or (block.get("name"), len(self.tool_blocks))
            if key in self.seen_tools:
                continue
            self.seen_tools.add(key)
            self.tool_blocks.append(block)


# ---------------------------------------------------------------------------
# the ledger
# ---------------------------------------------------------------------------


class SessionLedger:
    """Everything we know about one session's token spend."""

    def __init__(self, transcript_path: Path):
        self.transcript_path = str(transcript_path)
        self.session_id: str = Path(transcript_path).stem
        self.project: str = paths.project_of(transcript_path)
        self.cwd: Optional[str] = None
        self.git_branch: Optional[str] = None
        self.cc_version: Optional[str] = None
        self.slug: Optional[str] = None
        self.title: Optional[str] = None
        self.last_prompt: Optional[str] = None
        self.started_at: Optional[datetime] = None
        self.last_activity: Optional[datetime] = None
        self.calls: List[ApiCall] = []
        self.tools: List[ToolCall] = []
        self.reported: Optional[dict] = None
        self.cost_states: List[dict] = []
        # Parallel to cost_states: the newest main-loop request timestamp seen
        # before each checkpoint line, i.e. how far that checkpoint is billed.
        self.cost_state_marks: List[Optional[datetime]] = []
        self.turns: List[_Turn] = []
        self.agents: Dict[str, dict] = {}
        self.workflows: List[dict] = []
        self.compactions: List[dict] = []
        # Transcript-native compaction instants (a compact_boundary system line
        # or an isCompactSummary user line). self.compactions above comes from
        # the PreCompact hook and therefore only exists for sessions that ran
        # with the hook installed; these are in every transcript ever written,
        # and the re-read ledger needs them to know when a window was emptied.
        self.compaction_marks: List[datetime] = []
        self.parse_errors: int = 0
        self.files_read: int = 0
        self.bytes_read: int = 0
        self.load_seconds: float = 0.0
        self._config = paths.load_config()

    # -- basics ------------------------------------------------------------

    @property
    def _account(self) -> Dict[str, Any]:
        """Which account paid, as {label, source}. Resolved once per ledger.

        infer=False: this runs inside `oe report`/`oe status`, and the org-quota
        hint costs a full-file scan. A hint already cached by `oe account list`
        is still honoured, so the report agrees with the listing.
        """
        cached = getattr(self, "_account_cache", None)
        if cached is None:
            try:
                cached = accounts.resolve(self.session_id, Path(self.transcript_path),
                                          started_at=_iso(self.started_at))
            except Exception:
                cached = {"label": accounts.LABEL_UNKNOWN, "source": "unknown"}
            self._account_cache = cached
        return cached

    @property
    def wall_seconds(self) -> float:
        if self.started_at and self.last_activity:
            return max(0.0, (self.last_activity - self.started_at).total_seconds())
        return 0.0

    @property
    def primary_model(self) -> str:
        best, best_cost = "", -1.0
        for model, row in self.by_model.items():
            if row["cost_usd"] > best_cost:
                best, best_cost = model, row["cost_usd"]
        return best or (self.calls[-1].model if self.calls else "")

    # -- aggregates --------------------------------------------------------

    @property
    def totals(self) -> Dict[str, Any]:
        agg = {
            "calls": 0,
            "requests_main": 0,
            "requests_subagent": 0,
            "requests_workflow": 0,
            "input_tokens": 0,
            "output_tokens": 0,
            "thinking_tokens": 0,
            "cache_write_5m_tokens": 0,
            "cache_write_1h_tokens": 0,
            "cache_write_tokens": 0,
            "cache_read_tokens": 0,
            "web_search_requests": 0,
            "web_fetch_requests": 0,
            "total_tokens": 0,
            "billable_prompt_tokens": 0,
            "input_usd": 0.0,
            "output_usd": 0.0,
            "cache_write_5m_usd": 0.0,
            "cache_write_1h_usd": 0.0,
            "cache_read_usd": 0.0,
            "web_search_usd": 0.0,
            "cost_usd": 0.0,
            "errors": 0,
            "aborted": 0,
            "unpriced_calls": 0,
            "tool_calls": 0,
        }
        for call in self.calls:
            agg["calls"] += 1
            agg["requests_" + ("workflow" if call.origin == "workflow"
                               else "subagent" if call.origin == "subagent" else "main")] += 1
            agg["input_tokens"] += call.input_tokens
            agg["output_tokens"] += call.output_tokens
            agg["thinking_tokens"] += call.thinking_tokens
            agg["cache_write_5m_tokens"] += call.cache_write_5m
            agg["cache_write_1h_tokens"] += call.cache_write_1h
            agg["cache_read_tokens"] += call.cache_read
            agg["web_search_requests"] += call.web_search_requests
            agg["web_fetch_requests"] += call.web_fetch_requests
            for key in ("input_usd", "output_usd", "cache_write_5m_usd",
                        "cache_write_1h_usd", "cache_read_usd", "web_search_usd"):
                agg[key] += float(call.cost.get(key, 0.0) or 0.0)
            agg["cost_usd"] += call.total_usd
            agg["errors"] += 1 if call.is_error else 0
            agg["aborted"] += 1 if call.aborted else 0
            agg["unpriced_calls"] += 1 if call.unpriced else 0
        agg["cache_write_tokens"] = agg["cache_write_5m_tokens"] + agg["cache_write_1h_tokens"]
        agg["total_tokens"] = (agg["input_tokens"] + agg["output_tokens"]
                               + agg["cache_write_tokens"] + agg["cache_read_tokens"])
        agg["billable_prompt_tokens"] = (agg["input_tokens"] + agg["cache_write_tokens"]
                                         + agg["cache_read_tokens"])
        agg["tool_calls"] = len(self.tools)
        agg["wall_seconds"] = self.wall_seconds
        agg["cost_usd_per_hour"] = (agg["cost_usd"] / (self.wall_seconds / 3600.0)
                                    if self.wall_seconds > 60 else 0.0)
        reported = self.reported_cost_usd
        # cost-state is Claude Code's own billing record, so where a checkpoint
        # covers a request its dollars win. But a checkpoint only ever covers
        # its OWN run: resume a session and Claude Code restarts the
        # accumulator, leaving every earlier request in the same file with no
        # reported number at all. Handing `reported` straight to the headline
        # then reports a fraction of a session as if it were the whole thing,
        # because nearly every request in it can predate the only checkpoint on
        # disk. The authoritative figure is therefore the reported dollars for
        # the covered window PLUS our measured cost for everything outside it.
        coverage = self._coverage()
        agg["cost_usd_reported"] = reported
        agg["cost_usd_uncovered"] = round(coverage["uncovered_usd"], 6)
        agg["uncovered_calls"] = coverage["uncovered_calls"]
        agg["cost_usd_authoritative"] = (agg["cost_usd"] if reported is None
                                         else reported + coverage["uncovered_usd"])
        # True only when every request in the file sits inside a checkpoint, so
        # a surface can say "Claude Code's own number" without lying.
        agg["cost_fully_reported"] = reported is not None and not coverage["uncovered_calls"]
        return agg

    @property
    def runs(self) -> List[Dict[str, Any]]:
        """cost-state is per RUN, not per file.

        Resuming a session keeps writing to the same transcript but restarts the
        cost accumulator under a new startTime, so a file can hold several
        independent cost-state series. Reconciling the whole file against only
        the last one compares a full transcript to a partial bill -- which is
        how a 20x "drift" appears out of nowhere. Group by startTime and keep the
        latest checkpoint of each run.
        """
        marks = self.cost_state_marks
        by_start: Dict[int, dict] = {}
        by_start_mark: Dict[int, Any] = {}
        for index, state in enumerate(self.cost_states):
            start = _int(state.get("startTime"))
            previous = by_start.get(start)
            if previous is None or _int(state.get("totalDuration")) >= _int(
                    previous.get("totalDuration")):
                by_start[start] = state
                by_start_mark[start] = marks[index] if index < len(marks) else None
        out = []
        for start in sorted(by_start):
            state = by_start[start]
            out.append({
                "start_time": start,
                "started_at": _iso(datetime.fromtimestamp(start / 1000.0, tz=timezone.utc))
                if start else None,
                # How far past start_time this run's newest checkpoint accounts
                # for. _coverage needs it: a checkpoint is a snapshot, so the
                # covered window has a right edge as well as a left one.
                "total_duration_ms": _int(state.get("totalDuration")),
                # How far this run is actually billed: the last main-loop
                # request written above the checkpoint. NOT start_time +
                # totalDuration -- that field is accumulated active time and
                # lands hours short of the run's real end on any session with
                # idle gaps.
                "covered_through": by_start_mark.get(start),
                "reported_usd": _float(state.get("totalCostUSD")),
                "state": state,
            })
        return out

    @property
    def reported_cost_usd(self) -> Optional[float]:
        """Lifetime cost of this transcript: the sum over every run it contains."""
        runs = self.runs
        if not runs:
            return None
        return sum(run["reported_usd"] for run in runs)

    def _coverage(self) -> Dict[str, Any]:
        """Split our per-call cost into the part some checkpoint accounts for
        and the part that predates every checkpoint in the file.

        Deliberately free of any reference to .totals or .reconciliation: both
        of those call this, and a property cycle here is a stack overflow on
        every report build.
        """
        runs = self.runs
        first_start = min((r["start_time"] for r in runs if r["start_time"]), default=0)
        window_start = (datetime.fromtimestamp(first_start / 1000.0, tz=timezone.utc)
                        - _RUN_START_GRACE) if first_start else None
        # A checkpoint is a snapshot: it bounds the window on the RIGHT as well,
        # which is what makes a LIVE session's post-checkpoint requests show up
        # instead of being silently billed at the last checkpoint's figure.
        #
        # The edge is the last main-loop request written ABOVE the newest
        # checkpoint -- NOT start_time + totalDuration. totalDuration is
        # accumulated ACTIVE time, so on a session with idle gaps it lands well
        # short of the transcript's real end and declares everything after it
        # uncovered. In fact the final checkpoint tends to be the very last line
        # of the file, so those requests are already inside its own figure, and
        # pricing them again reads the row far above Claude Code's own total
        # while calling itself "mixed".
        #
        # A transcript that carries a cost-state has no assistant line after its
        # last checkpoint, which is what makes the right-hand bound safe.
        ends = [r["covered_through"] for r in runs if r.get("covered_through")]
        # No grace: the mark IS a request timestamp from this file (see
        # _RIGHT_EDGE_EPS). With +120s here, `oe status` read 4% under the true
        # figure on a 4-requests-then-checkpoint-then-6-more transcript, and the
        # cheap path read 2% under it -- two surfaces, three answers.
        window_end = max(ends) if ends else None
        # ...and no right edge AT ALL when the newest checkpoint is the last
        # thing in the main transcript. The mark is a MAIN-loop timestamp, but
        # subagents flush their own files afterwards, so sidechain requests are
        # routinely stamped after it, and every one of them is already inside the
        # checkpoint that was written below them (its cost-state is line 130 of
        # 131, the last assistant line is 117). Bounding there added 32% on top
        # of Claude Code's own figure -- a 32% over-count of real money.
        # When main-loop work CONTINUES past the checkpoint the mark is real,
        # and that is the live session this whole edge exists for.
        if window_end is not None:
            main_last = max((c.ts for c in self.calls
                             if c.origin == "main" and c.ts), default=None)
            if main_last is not None and main_last <= window_end:
                window_end = None
        # A right edge only says anything when the MAIN loop actually continued
        # past the newest checkpoint. When it did not -- the checkpoint is the
        # last thing in the file, which is the case in all 12 checkpointed
        # transcripts here -- that checkpoint bills the whole tree, including
        # the subagent requests that keep landing after the final main-loop
        # message. A transcript can end with a run of subagent requests landing
        # minutes past its last main request; with the edge left in place they
        # were priced a second time on top of what Claude Code had
        # already billed: the row landed 32% over that figure and the cheap path
        # 35% over -- two surfaces, two wrong answers, neither of them the bill.
        if window_end is not None and not any(
                call.origin == "main" and call.ts and call.ts > window_end
                for call in self.calls):
            window_end = None
        if window_start is not None and window_end is not None and window_end <= window_start:
            window_end = None       # nothing usable to bound the right side
        covered = uncovered = 0.0
        covered_calls = uncovered_calls = 0
        # Split the uncovered part by WHICH edge it fell off: a resumed-away
        # accumulator and a run that stopped checkpointing are different facts
        # and the report has to name the right one.
        before_usd = after_usd = 0.0
        before_calls = after_calls = 0
        for call in self.calls:
            early = bool(window_start and call.ts and call.ts < window_start)
            late = bool(window_end and call.ts and call.ts > window_end)
            if early or late:
                uncovered += call.total_usd
                uncovered_calls += 1
                if early:
                    before_usd += call.total_usd
                    before_calls += 1
                else:
                    after_usd += call.total_usd
                    after_calls += 1
            else:
                covered += call.total_usd
                covered_calls += 1
        return {
            "window_start": window_start,
            "window_end": window_end,
            "covered_usd": covered,
            "uncovered_usd": uncovered,
            "covered_calls": covered_calls,
            "uncovered_calls": uncovered_calls,
            "before_usd": before_usd,
            "before_calls": before_calls,
            "after_usd": after_usd,
            "after_calls": after_calls,
        }

    @property
    def by_model(self) -> Dict[str, Dict[str, Any]]:
        out: Dict[str, Dict[str, Any]] = {}
        for call in self.calls:
            row = out.setdefault(call.model, {
                "model": call.model,
                "display_name": pricing.display_name(call.model),
                "tier": call.tier,
                "calls": 0, "input_tokens": 0, "output_tokens": 0,
                "thinking_tokens": 0, "cache_write_tokens": 0,
                "cache_write_5m_tokens": 0, "cache_write_1h_tokens": 0,
                "cache_read_tokens": 0, "total_tokens": 0, "cost_usd": 0.0,
                "web_search_requests": 0,
                "context_window": pricing.context_window(call.model),
                **{key: 0.0 for key in _COST_KEYS},
            })
            row["calls"] += 1
            row["input_tokens"] += call.input_tokens
            row["output_tokens"] += call.output_tokens
            row["thinking_tokens"] += call.thinking_tokens
            row["cache_write_5m_tokens"] += call.cache_write_5m
            row["cache_write_1h_tokens"] += call.cache_write_1h
            row["cache_write_tokens"] += call.cache_write_5m + call.cache_write_1h
            row["cache_read_tokens"] += call.cache_read
            row["web_search_requests"] += call.web_search_requests
            row["total_tokens"] += call.total_tokens
            row["cost_usd"] += call.total_usd
            # Per-kind USD travels with every breakdown row so the report can
            # show tokens x rate = dollars for each line it prints, rather than
            # asking the reader to trust an opaque total.
            for key in _COST_KEYS:
                row[key] += float(call.cost.get(key, 0.0) or 0.0)
        return out

    @property
    def by_origin(self) -> Dict[str, Dict[str, Any]]:
        out: Dict[str, Dict[str, Any]] = {}
        for call in self.calls:
            if call.origin == "main":
                key = "main"
            else:
                key = f"{call.origin}:{call.agent_type or 'unknown'}"
            row = out.setdefault(key, {
                "origin": key, "calls": 0, "agents": set(),
                "input_tokens": 0, "output_tokens": 0, "thinking_tokens": 0,
                "cache_write_tokens": 0, "cache_write_5m_tokens": 0,
                "cache_write_1h_tokens": 0,
                "cache_read_tokens": 0, "total_tokens": 0, "cost_usd": 0.0,
                "models": set(),
                **{key: 0.0 for key in _COST_KEYS},
            })
            row["calls"] += 1
            if call.agent_id:
                row["agents"].add(call.agent_id)
            row["models"].add(call.model)
            row["input_tokens"] += call.input_tokens
            row["output_tokens"] += call.output_tokens
            row["thinking_tokens"] += call.thinking_tokens
            row["cache_write_5m_tokens"] += call.cache_write_5m
            row["cache_write_1h_tokens"] += call.cache_write_1h
            row["cache_write_tokens"] += call.cache_write_5m + call.cache_write_1h
            row["cache_read_tokens"] += call.cache_read
            row["total_tokens"] += call.total_tokens
            row["cost_usd"] += call.total_usd
            for key in _COST_KEYS:
                row[key] += float(call.cost.get(key, 0.0) or 0.0)
        for row in out.values():
            row["agent_count"] = len(row["agents"])
            # The full agent-id list is unbounded (one session held 198) and no
            # consumer needs it, so keep the count and drop the roster.
            row["agents"] = sorted(row["agents"])[:200]
            row["models"] = sorted(row["models"])
        return out

    @property
    def by_tool(self) -> Dict[str, Dict[str, Any]]:
        out: Dict[str, Dict[str, Any]] = {}
        for tool in self.tools:
            row = out.setdefault(tool.name, {
                "name": tool.name, "server": tool.server, "count": 0,
                "total_duration_ms": 0, "timed_calls": 0, "errors": 0,
                "est_result_bytes": 0, "max_result_bytes": 0, "input_bytes": 0,
            })
            row["count"] += 1
            if tool.duration_ms is not None:
                row["total_duration_ms"] += int(tool.duration_ms)
                row["timed_calls"] += 1
            row["errors"] += 1 if tool.is_error else 0
            row["est_result_bytes"] += tool.result_bytes
            row["max_result_bytes"] = max(row["max_result_bytes"], tool.result_bytes)
            row["input_bytes"] += tool.input_bytes
        for row in out.values():
            row["avg_result_bytes"] = int(row["est_result_bytes"] / row["count"]) if row["count"] else 0
            row["avg_duration_ms"] = (int(row["total_duration_ms"] / row["timed_calls"])
                                      if row["timed_calls"] else None)
        return out

    @property
    def by_turn(self) -> List[Dict[str, Any]]:
        rows: List[Dict[str, Any]] = []
        index_of = {turn.index: position for position, turn in enumerate(self.turns)}
        for turn in self.turns:
            rows.append({
                "prompt_id": turn.prompt_id,
                "index": turn.index,
                "first_ts": _iso(turn.ts),
                "prompt_preview": turn.preview,
                "calls": 0, "tokens": 0, "input_tokens": 0, "output_tokens": 0,
                "cache_read_tokens": 0, "cache_write_tokens": 0,
                "cost": 0.0, "tools": 0, "subagent_calls": 0, "duration_s": 0.0,
                "context_end_tokens": 0,
                # Per-kind USD travels with every other breakdown row (by_model,
                # by_origin); by_turn is the one that never got it, which is why
                # the console could show WHAT a turn cost but not WHICH KIND of
                # token it went on. main_cache_read_usd is separate because a
                # turn's blended cache_read_usd includes every agent window
                # spawned inside it -- a fan-out turn would otherwise read as
                # the user's own window growing.
                **{key: 0.0 for key in _COST_KEYS},
                "main_cache_read_usd": 0.0,
            })
        orphan = {
            "prompt_id": None, "index": -1, "first_ts": None,
            "prompt_preview": "(before the first recorded prompt)",
            "calls": 0, "tokens": 0, "input_tokens": 0, "output_tokens": 0,
            "cache_read_tokens": 0, "cache_write_tokens": 0,
            "cost": 0.0, "tools": 0, "subagent_calls": 0, "duration_s": 0.0,
            "context_end_tokens": 0,
            **{key: 0.0 for key in _COST_KEYS},
            "main_cache_read_usd": 0.0,
        }
        for call in self.calls:
            position = index_of.get(call.turn_index)
            row = rows[position] if position is not None else orphan
            row["calls"] += 1
            row["tokens"] += call.total_tokens
            row["input_tokens"] += call.input_tokens
            row["output_tokens"] += call.output_tokens
            row["cache_read_tokens"] += call.cache_read
            row["cache_write_tokens"] += call.cache_write_5m + call.cache_write_1h
            row["cost"] += call.total_usd
            row["tools"] += len(call.tools)
            for key in _COST_KEYS:
                row[key] += float(call.cost.get(key, 0.0) or 0.0)
            if call.origin != "main":
                row["subagent_calls"] += 1
            else:
                row["main_cache_read_usd"] += float(
                    call.cost.get("cache_read_usd", 0.0) or 0.0)
                # Still guarded: a main call that carries no context figure must
                # not overwrite the one the turn already has.
                if call.context_tokens:
                    row["context_end_tokens"] = call.context_tokens
        for position, turn in enumerate(self.turns):
            start = turn.ts
            end = (self.turns[position + 1].ts if position + 1 < len(self.turns)
                   else self.last_activity)
            if start and end:
                rows[position]["duration_s"] = max(0.0, (end - start).total_seconds())
        if orphan["calls"]:
            rows.insert(0, orphan)
        return rows

    @property
    def context_series(self) -> List[Dict[str, Any]]:
        series: List[Dict[str, Any]] = []
        for call in self.calls:
            if call.origin != "main" or not call.context_tokens:
                continue
            window = pricing.context_window(call.model) or pricing.DEFAULT_CONTEXT_WINDOW
            series.append({
                "ts": _iso(call.ts),
                "context_tokens": call.context_tokens,
                "max_tokens": window,
                "pct": round(100.0 * call.context_tokens / window, 2) if window else 0.0,
                "turn_index": call.turn_index,
            })
        return series

    @property
    def cost_series(self) -> List[List[float]]:
        """Cumulative spend against wall clock, over EVERY request.

        [epoch_seconds, cumulative_usd] pairs. This exists because to_dict()
        caps its embedded `calls` list: a chart drawn from that capped list ends
        partway up the bill of any session with more requests than the cap, on a
        time axis that stops before the session did.
        The series is thinned to at most _COST_SERIES_POINTS by keeping the last
        point of each horizontal bucket, which always includes the final point,
        so the endpoint of the drawn line is the session total.
        """
        points: List[List[float]] = []
        running = 0.0
        for call in self.calls:
            if call.ts is None:
                continue
            running += call.total_usd
            points.append([call.ts.timestamp(), round(running, 6)])
        if len(points) <= _COST_SERIES_POINTS:
            return points
        first, last = points[0][0], points[-1][0]
        span = (last - first) or 1.0
        buckets: Dict[int, List[float]] = {}
        for point in points:
            index = int((point[0] - first) / span * (_COST_SERIES_POINTS - 1))
            buckets[index] = point
        return [buckets[index] for index in sorted(buckets)]

    @property
    def context_window_state(self) -> Dict[str, Any]:
        """Exactly how Claude Code's own meter computes it: the LAST main-loop
        assistant message's input + cache_creation + cache_read."""
        last = None
        for call in reversed(self.calls):
            if call.origin == "main" and call.context_tokens:
                last = call
                break
        if last is None:
            for call in reversed(self.calls):
                if call.context_tokens:
                    last = call
                    break
        if last is None:
            return {"used_tokens": 0, "max_tokens": pricing.DEFAULT_CONTEXT_WINDOW,
                    "pct": 0.0, "model": None, "ts": None}
        window = pricing.context_window(last.model) or pricing.DEFAULT_CONTEXT_WINDOW
        return {
            "used_tokens": last.context_tokens,
            "max_tokens": window,
            "pct": round(100.0 * last.context_tokens / window, 2) if window else 0.0,
            "model": last.model,
            "ts": _iso(last.ts),
        }

    @property
    def cache_efficiency(self) -> Dict[str, Any]:
        """hit_ratio is cache_read / all prompt tokens (read + write + fresh input):
        the share of everything fed to the model that arrived from cache."""
        read = write = fresh = 0
        saved = paid = 0.0
        for call in self.calls:
            read += call.cache_read
            write += call.cache_write_5m + call.cache_write_1h
            fresh += call.input_tokens
            saved += pricing.uncached_equivalent_usd(call.cache_read, call.model, call.speed)
            paid += float(call.cost.get("cache_write_5m_usd", 0.0) or 0.0)
            paid += float(call.cost.get("cache_write_1h_usd", 0.0) or 0.0)
        prompt_total = read + write + fresh
        read_cost = sum(float(c.cost.get("cache_read_usd", 0.0) or 0.0) for c in self.calls)
        return {
            "read_tokens": read,
            "write_tokens": write,
            "fresh_input_tokens": fresh,
            "hit_ratio": (read / prompt_total) if prompt_total else 0.0,
            "cost_saved_vs_uncached_usd": saved - read_cost,
            "cost_paid_on_writes_usd": paid,
            "cost_paid_on_reads_usd": read_cost,
            "net_usd": (saved - read_cost) - paid,
            "uncached_equivalent_usd": saved,
        }

    @property
    def reconciliation(self) -> Dict[str, Any]:
        """Our number vs Claude Code's own cost-state, with a diagnosis.

        Empirically: sessions with no subagents agree to ~1% (the residue is the
        Haiku title/summarizer requests, which are never written to a
        transcript). Sessions with subagents run 8-25% low because sidechain
        transcripts never persist final output_tokens. We report that rather than
        fudging it.
        """
        computed = round(sum(call.total_usd for call in self.calls), 6)
        if not self.reported:
            return {
                "computed_usd": computed,
                "computed_usd_covered": computed,
                "computed_usd_uncovered": 0.0,
                "uncovered_calls": 0,
                "runs": [],
                "reported_usd": None,
                "delta_usd": None,
                "delta_pct": None,
                "per_model": [],
                "per_kind": {},
                "origin_split": {},
                "status": "unavailable",
                "diagnosis": ["no cost-state checkpoint in this transcript"],
                "cost_scale": 1.0,
            }
        runs = self.runs
        reported = self.reported_cost_usd or 0.0

        # modelUsage is also per run, so sum the runs' tables before comparing.
        model_usage: Dict[str, Dict[str, Any]] = {}
        for run in runs:
            # A malformed cost-state row must not take reconciliation -- and so
            # to_dict(), and so the whole report -- down with it.
            run_usage = run["state"].get("modelUsage")
            if not isinstance(run_usage, dict):
                continue
            for raw_model, usage in run_usage.items():
                if not isinstance(usage, dict):
                    continue
                acc = model_usage.setdefault(str(raw_model), {})
                for key in ("inputTokens", "outputTokens", "cacheReadInputTokens",
                            "cacheCreationInputTokens", "webSearchRequests", "thinkingTokens"):
                    acc[key] = _int(acc.get(key)) + _int(usage.get(key))
                acc["costUSD"] = _float(acc.get("costUSD")) + _float(usage.get("costUSD"))

        # Only calls inside a run's window are covered by a checkpoint; anything
        # before the earliest run belongs to a resumed-away accumulator and must
        # be excluded from the comparison rather than counted as drift. The
        # startTime is recorded a beat before or after the first request it
        # covers, so a bare comparison would strand a call on clock skew --
        # _RUN_START_GRACE absorbs that; a genuine resume is hours away.
        coverage = self._coverage()
        window_start = coverage["window_start"]
        window_end = coverage.get("window_end")
        uncovered = coverage["uncovered_usd"]
        uncovered_calls = coverage["uncovered_calls"]
        covered = round(coverage["covered_usd"], 6)

        # Everything compared below is restricted to the covered window, so the
        # token tables are apples-to-apples with the checkpoints we sum. BOTH
        # edges matter: a run resumed after the last checkpoint contributes real
        # requests to the transcript and nothing to the reported total, and
        # leaving them in makes the comparison report a drift that is really
        # just requests the checkpoint never saw.
        covered_calls = [c for c in self.calls
                         if not (window_start and c.ts and c.ts < window_start)
                         and not (window_end and c.ts and c.ts > window_end)]
        by_norm: Dict[str, Dict[str, Any]] = {}
        computed_tokens = {"input": 0, "output": 0, "cache_read": 0, "cache_write": 0}
        for call in covered_calls:
            key = pricing.normalize_model(call.model)
            acc = by_norm.setdefault(key, {"calls": 0, "cost_usd": 0.0, "input_tokens": 0,
                                           "output_tokens": 0, "cache_read_tokens": 0,
                                           "cache_write_tokens": 0})
            acc["calls"] += 1
            acc["cost_usd"] += call.total_usd
            acc["input_tokens"] += call.input_tokens
            acc["output_tokens"] += call.output_tokens
            acc["cache_read_tokens"] += call.cache_read
            acc["cache_write_tokens"] += call.cache_write_5m + call.cache_write_1h
            acc["cache_write_1h_tokens"] = (acc.get("cache_write_1h_tokens", 0)
                                            + call.cache_write_1h)
            computed_tokens["input"] += call.input_tokens
            computed_tokens["output"] += call.output_tokens
            computed_tokens["cache_read"] += call.cache_read
            computed_tokens["cache_write"] += call.cache_write_5m + call.cache_write_1h

        per_model = []
        rep_tokens = {"input": 0, "output": 0, "cache_read": 0, "cache_write": 0}
        # What the tokens Claude Code billed but the transcript never recorded
        # actually COST, per kind. Without this the report can only say "output
        # is 90% covered", which does not tell anyone where the dollars went --
        # and it is what makes the "output-only" claim checkable rather than
        # asserted.
        missing_usd = {"input": 0.0, "output": 0.0, "cache_read": 0.0, "cache_write": 0.0}
        for raw_model, usage in model_usage.items():
            key = pricing.normalize_model(raw_model)
            ours = by_norm.get(key, {})
            rep_cost = float(usage.get("costUSD") or 0.0)
            our_cost = float(ours.get("cost_usd") or 0.0)
            rep_tokens["input"] += _int(usage.get("inputTokens"))
            rep_tokens["output"] += _int(usage.get("outputTokens"))
            rep_tokens["cache_read"] += _int(usage.get("cacheReadInputTokens"))
            rep_tokens["cache_write"] += _int(usage.get("cacheCreationInputTokens"))
            tier, _tname = pricing.tier_for(raw_model)
            if tier is not None:
                writes = _int(ours.get("cache_write_tokens"))
                # Price the missing writes at the 5m/1h blend this model
                # actually used in this session; 5m alone when we saw none.
                hour_share = (_int(ours.get("cache_write_1h_tokens")) / writes) if writes else 0.0
                write_rate = tier.cw_1h * hour_share + tier.cw_5m * (1.0 - hour_share)
                for kind, rate, rep_key, our_key in (
                        ("input", tier.input, "inputTokens", "input_tokens"),
                        ("output", tier.output, "outputTokens", "output_tokens"),
                        ("cache_read", tier.cache_read, "cacheReadInputTokens", "cache_read_tokens"),
                        ("cache_write", write_rate, "cacheCreationInputTokens",
                         "cache_write_tokens")):
                    gap = _int(usage.get(rep_key)) - _int(ours.get(our_key))
                    if gap > 0:
                        missing_usd[kind] += gap * rate / 1e6
            per_model.append({
                "model": raw_model,
                "reported_usd": round(rep_cost, 6),
                "computed_usd": round(our_cost, 6),
                "delta_usd": round(our_cost - rep_cost, 6),
                "reported_output_tokens": _int(usage.get("outputTokens")),
                "computed_output_tokens": _int(ours.get("output_tokens")),
                "reported_cache_read_tokens": _int(usage.get("cacheReadInputTokens")),
                "computed_cache_read_tokens": _int(ours.get("cache_read_tokens")),
                "in_transcript": key in by_norm,
            })
        for key, ours in by_norm.items():
            if not any(pricing.normalize_model(m["model"]) == key for m in per_model):
                per_model.append({
                    "model": key,
                    "reported_usd": None,
                    "computed_usd": round(float(ours["cost_usd"]), 6),
                    "delta_usd": None,
                    "reported_output_tokens": None,
                    "computed_output_tokens": _int(ours["output_tokens"]),
                    "reported_cache_read_tokens": None,
                    "computed_cache_read_tokens": _int(ours["cache_read_tokens"]),
                    "in_transcript": True,
                })

        totals = self.totals
        per_kind = {kind: {"computed": computed_tokens[kind], "reported": rep_tokens[kind]}
                    for kind in ("input", "output", "cache_read", "cache_write")}
        for kind, row in per_kind.items():
            row["delta"] = row["computed"] - row["reported"]
            row["coverage_pct"] = (round(100.0 * row["computed"] / row["reported"], 2)
                                   if row["reported"] else None)
            row["missing_usd"] = round(missing_usd[kind], 6)
        missing_total = sum(missing_usd.values())

        delta = covered - reported
        if reported:
            delta_pct = 100.0 * delta / reported
            status = "ok" if abs(delta_pct) <= 2.0 else "drift"
        elif covered == 0.0:
            # Nothing billed and nothing computed: agreement, not drift.
            delta_pct = 0.0
            status = "ok"
        else:
            delta_pct = None
            status = "drift"
        # A tight delta on a sliver of the file is not agreement. When most of
        # the transcript sits outside every checkpoint, the comparison covers
        # too little to certify anything, and calling that "ok" is how a
        # session gets reported at a twentieth of what it spent.
        uncovered_share = (uncovered / (covered + uncovered)) if (covered + uncovered) else 0.0
        if uncovered_calls and uncovered_share > 0.05:
            status = "partial"

        # Evidence for the diagnosis rather than an assertion: where the
        # transcript's output tokens actually live.
        origin_split = {"main": {"calls": 0, "output_tokens": 0, "cache_read_tokens": 0},
                        "sidechain": {"calls": 0, "output_tokens": 0, "cache_read_tokens": 0}}
        for call in covered_calls:
            bucket = origin_split["main" if call.origin == "main" else "sidechain"]
            bucket["calls"] += 1
            bucket["output_tokens"] += call.output_tokens
            bucket["cache_read_tokens"] += call.cache_read

        diagnosis: List[str] = []
        sidechain_calls = origin_split["sidechain"]["calls"]
        out_gap = per_kind["output"]["reported"] - per_kind["output"]["computed"]
        read_cov = per_kind["cache_read"]["coverage_pct"]
        if status == "drift":
            if sidechain_calls and out_gap > 0:
                # Rank the kinds by the dollars they are short, and SAY which
                # one dominates instead of asserting it. The output gap is often
                # a minority of the shortfall, with input and cache_read making
                # up the rest, so a hardcoded "output-only" is simply false
                # for that session.
                ranked = sorted(missing_usd.items(), key=lambda kv: -kv[1])
                lead_kind, lead_usd = ranked[0]
                share = (100.0 * lead_usd / missing_total) if missing_total else 0.0
                breakdown = ", ".join(f"{kind} ${value:,.2f}" for kind, value in ranked
                                      if value > 0.005)
                diagnosis.append(
                    f"${missing_total:,.2f} of tokens are billed by Claude Code but absent from "
                    f"disk ({breakdown}). {sidechain_calls} of {len(covered_calls)} requests ran "
                    "in sidechain (subagent) transcripts, which persist a mid-stream usage "
                    "snapshot and never write back the final message_delta usage. "
                    + (f"The shortfall is dominated by {lead_kind} ({share:.0f}% of it)."
                       if share >= 60 else
                       f"It is spread across kinds -- {lead_kind} is the largest at only "
                       f"{share:.0f}% -- so whole requests, not just their output counts, are "
                       "missing from disk.")
                    + " Unrecoverable from the transcript; cost-state is authoritative for the "
                      "session total and cost_scale re-expresses per-call attribution in those "
                      "dollars.")
            if read_cov is not None and read_cov < 99.5:
                diagnosis.append(
                    f"cache_read coverage {read_cov}% (${missing_usd['cache_read']:,.2f}): billed "
                    "requests that are never written to any transcript -- the Haiku title/summary "
                    "calls that appear in modelUsage, plus retried attempts.")
            if delta > 0:
                diagnosis.append(
                    "computed exceeds reported: the cost-state line is a checkpoint written "
                    "before the session ended, so later requests are ours alone.")
        elif status == "partial":
            diagnosis.append(
                f"PARTIAL: the checkpoints on disk account for only "
                f"{100.0 * (1.0 - uncovered_share):.1f}% of this transcript's spend, so the "
                f"{delta_pct:+.2f}% delta below certifies that sliver and nothing more. The "
                "headline cost is the reported dollars for the covered window plus our measured "
                f"${uncovered:,.2f} for the {uncovered_calls:,} requests outside it.")
        else:
            diagnosis.append("within 2 percent of Claude Code's own accounting")
        if totals["unpriced_calls"]:
            diagnosis.append(f"{totals['unpriced_calls']} calls used a model missing from the "
                             "pricing table and were counted as zero -- run `oe reprice`")

        if coverage["before_calls"]:
            diagnosis.append(
                f"{coverage['before_calls']} calls (${coverage['before_usd']:,.2f}) predate the "
                f"earliest cost-state checkpoint "
                f"({window_start.isoformat() if window_start else '?'}): this "
                "transcript was resumed and Claude Code restarted its accumulator, so those runs "
                "have no reported number to compare against. They are excluded from the delta and "
                "added to the headline at our measured price.")
        if coverage["after_calls"]:
            diagnosis.append(
                f"{coverage['after_calls']} calls (${coverage['after_usd']:,.2f}) come AFTER the "
                f"newest checkpoint's window "
                f"({window_end.isoformat() if window_end else '?'}): the session kept working and "
                "never wrote another cost-state line, so no reported dollar covers them. They are "
                "excluded from the delta and added to the headline at our measured price.")
        if len(runs) > 1:
            diagnosis.append(f"{len(runs)} separate runs share this transcript; reported_usd is "
                             "their sum.")

        return {
            "computed_usd": computed,
            "computed_usd_covered": covered,
            "computed_usd_uncovered": round(uncovered, 6),
            "uncovered_calls": uncovered_calls,
            "runs": [{"start_time": r["start_time"], "started_at": r["started_at"],
                      "reported_usd": round(r["reported_usd"], 6)} for r in runs],
            "reported_usd": round(reported, 6),
            "delta_usd": round(delta, 6),
            "delta_pct": round(delta_pct, 3) if delta_pct is not None else None,
            "per_model": sorted(per_model, key=lambda r: -(r["reported_usd"] or 0.0)),
            "per_kind": per_kind,
            "missing_usd": {kind: round(value, 6) for kind, value in missing_usd.items()},
            "missing_usd_total": round(missing_total, 6),
            "origin_split": origin_split,
            "status": status,
            "uncovered_share": round(uncovered_share, 6),
            "diagnosis": diagnosis,
            # Multiply a per-call cost by this to express it in the same dollars
            # as cost-state. Attribution only -- never presented as measured.
            # It applies to COVERED calls: an uncovered call has no reported
            # counterpart, so scaling it would invent dollars.
            "cost_scale": round(reported / covered, 6) if covered else 1.0,
            "reported_api_duration_ms": _int(self.reported.get("totalAPIDuration")),
            "reported_tool_duration_ms": _int(self.reported.get("totalToolDuration")),
            "reported_lines_added": _int(self.reported.get("totalLinesAdded")),
            "reported_lines_removed": _int(self.reported.get("totalLinesRemoved")),
        }

    # -- insights ----------------------------------------------------------

    @property
    def expensive_turns(self) -> List[Dict[str, Any]]:
        limit = int(self._config["insights"]["top_turns"])
        rows = [r for r in self.by_turn if r["calls"]]
        rows.sort(key=lambda r: -r["cost"])
        return rows[:limit]

    @property
    def expensive_agents(self) -> List[Dict[str, Any]]:
        by_agent: Dict[str, Dict[str, Any]] = {}
        for call in self.calls:
            if call.origin == "main" or not call.agent_id:
                continue
            row = by_agent.setdefault(call.agent_id, {
                "agent_id": call.agent_id,
                "agent_type": call.agent_type,
                "description": call.agent_description,
                "workflow_id": call.workflow_id,
                "spawn_depth": call.spawn_depth,
                "calls": 0, "tokens": 0, "cost_usd": 0.0, "output_tokens": 0,
                "cache_read_tokens": 0, "tools": 0,
            })
            row["calls"] += 1
            row["tokens"] += call.total_tokens
            row["output_tokens"] += call.output_tokens
            row["cache_read_tokens"] += call.cache_read
            row["cost_usd"] += call.total_usd
            row["tools"] += len(call.tools)
        return sorted(by_agent.values(), key=lambda r: -r["cost_usd"])

    @property
    def agent_type_costs(self) -> List[Dict[str, Any]]:
        by_type: Dict[str, Dict[str, Any]] = {}
        for row in self.expensive_agents:
            key = row["agent_type"] or "unknown"
            acc = by_type.setdefault(key, {"agent_type": key, "agents": 0, "calls": 0,
                                           "tokens": 0, "cost_usd": 0.0})
            acc["agents"] += 1
            acc["calls"] += row["calls"]
            acc["tokens"] += row["tokens"]
            acc["cost_usd"] += row["cost_usd"]
        for acc in by_type.values():
            acc["cost_per_agent_usd"] = acc["cost_usd"] / acc["agents"] if acc["agents"] else 0.0
        return sorted(by_type.values(), key=lambda r: -r["cost_usd"])

    @property
    def redundant_work(self) -> List[Dict[str, Any]]:
        """Same file read, or same shell command run, more than N times.

        Every repeat pays full cache-write + cache-read on the result it puts
        back into context, so this is the cheapest win in the whole report.
        """
        threshold = int(self._config["insights"]["reread_threshold"])
        buckets: Dict[Tuple[str, str], Dict[str, Any]] = {}
        for tool in self.tools:
            if not tool.target:
                continue
            key = (tool.name, tool.target)
            row = buckets.setdefault(key, {"tool": tool.name, "target": tool.target,
                                           "count": 0, "bytes": 0, "origins": set()})
            row["count"] += 1
            row["bytes"] += tool.result_bytes
            row["origins"].add(tool.origin if tool.origin == "main" else (tool.agent_id or tool.origin))
        rows = []
        for row in buckets.values():
            if row["count"] < threshold:
                continue
            row["distinct_callers"] = len(row["origins"])
            row.pop("origins")
            row["wasted_bytes"] = int(row["bytes"] * (row["count"] - 1) / row["count"])
            rows.append(row)
        return sorted(rows, key=lambda r: -r["wasted_bytes"])[:20]


    # -- re-read ledger ----------------------------------------------------

    def _carry_windows(self) -> Tuple[Dict[str, List[datetime]], List[datetime]]:
        """(context window -> its request timestamps, main-loop compaction marks).

        A tool result is written into ONE context window and then re-read by the
        requests that follow it IN THAT WINDOW -- not by the whole session. A
        subagent's window dies with the agent; the main window is cut by every
        compaction. Both bounds are load-bearing: without them a read inside a
        short-lived agent is priced as though every later main-loop request had
        carried it, which overstates it several times over.
        """
        windows: Dict[str, List[datetime]] = {}
        for call in self.calls:
            if call.ts is None:
                continue
            windows.setdefault(_window_of(call), []).append(call.ts)
        for stamps in windows.values():
            stamps.sort()
        return windows, sorted(self.compaction_marks)

    def _calibrated_rate(self) -> float:
        try:
            return float((self._config.get("insights") or {}).get(
                "carry_usd_per_1k", CARRY_USD_PER_1K))
        except (TypeError, ValueError):
            return CARRY_USD_PER_1K

    def reread_events(self) -> List[Dict[str, Any]]:
        """One row per Read call, classified and priced.

        One pass in timestamp order over ALL tool calls -- reads and writes
        interleaved, because a write is what makes a later read of the same path
        legitimate. Four pieces of state carry the classification: what the
        session has ever read, what each context window currently holds and over
        which line ranges, when each window last saw each path, and when each
        path was last written.
        """
        windows, marks = self._carry_windows()
        tier, _name = pricing.tier_for(self.primary_model)
        if tier is None:
            tier = pricing.TIERS["tier_5_25"]
        calibrated_rate = self._calibrated_rate()

        seen_session: set = set()
        seen_main: set = set()
        last_write: Dict[str, datetime] = {}
        held: Dict[Tuple[str, int], Dict[str, List[List[int]]]] = {}
        held_ts: Dict[Tuple[str, int], Dict[str, datetime]] = {}

        events: List[Dict[str, Any]] = []
        for tool in self.tools:
            path = tool.target
            if not path:
                continue
            if tool.name in MUTATE_TOOLS:
                if tool.ts is not None and not tool.is_error:
                    last_write[path] = tool.ts
                continue
            if tool.name not in READ_TOOLS or tool.is_error:
                continue

            window = _window_of(tool)
            stamp = tool.ts
            generation = (bisect_right(marks, stamp)
                          if (window == "main" and stamp is not None and marks) else 0)
            epoch = (window, generation)
            spans = held.setdefault(epoch, {})
            stamps_seen = held_ts.setdefault(epoch, {})
            lo = tool.span_lo or 1
            hi = (tool.span_hi if tool.span_hi is not None
                  else lo + DEFAULT_READ_LINES - 1)
            covered = spans.get(path)

            if path not in seen_session:
                reason = "first"
            elif covered is None:
                # This window has never held the file. Nothing about that is
                # recoverable by reading less: it is a different window, and it
                # genuinely does not have the bytes.
                reason = ("post_compact"
                          if (window == "main" and generation > 0 and path in seen_main)
                          else "subagent")
            elif not _span_contained(covered, lo, hi):
                reason = "new_range"
            elif (last_write.get(path) is not None
                  and last_write[path] > stamps_seen.get(path, _MIN_TS)):
                reason = "changed"
            else:
                reason = "avoidable"

            content = tool.content_bytes or tool.result_bytes
            tokens = content / 4.0
            carried = _requests_after(windows.get(window) or [], stamp,
                                      marks if window == "main" else None)
            events.append({
                "path": path,
                "ts": _iso(stamp),
                "window": window,
                "generation": generation,
                "turn_index": tool.turn_index,
                "origin": tool.origin,
                "reason": reason,
                "bytes": int(content),
                "tokens": tokens,
                "span_lo": tool.span_lo,
                "span_hi": tool.span_hi,
                "carry_requests": carried,
                "carry_usd": tokens * (tier.cw_5m + carried * tier.cache_read) / 1e6,
                "calibrated_usd": tokens * calibrated_rate / 1000.0,
            })

            seen_session.add(path)
            if window == "main":
                seen_main.add(path)
            spans[path] = _span_merge(covered or [], lo, hi)
            if stamp is not None:
                stamps_seen[path] = stamp
        return events

    def reread_analysis(self, limit: int = 40) -> Dict[str, Any]:
        """The re-read ledger: per file, per reason, priced two ways."""
        return summarise_rereads(self.reread_events(), limit=limit,
                                 calibrated_rate=self._calibrated_rate(), sessions=1)

    @property
    def rereads(self) -> Dict[str, Any]:
        try:
            limit = int((self._config.get("insights") or {}).get("top_rereads", 40))
        except (TypeError, ValueError):
            limit = 40
        return self.reread_analysis(limit=limit)

    @property
    def context_growth(self) -> Dict[str, Any]:
        """How fast the window fills, measured turn-end to turn-end.

        Sampling every call would count intra-turn oscillation (a tool result
        lands, the next request carries it) as growth; sampling turn ends and
        taking the MEDIAN positive step also survives a compaction, which drops
        context by hundreds of thousands of tokens in one step.
        """
        series = self.context_series
        if not series:
            return {"tokens_per_turn": 0.0, "turns_until_full": None, "current_tokens": 0,
                    "max_tokens": pricing.DEFAULT_CONTEXT_WINDOW, "headroom_tokens": 0,
                    "resets": 0, "major_resets": 0, "samples": 0,
                    "per_call_tokens": 0.0}
        current = series[-1]["context_tokens"]
        window = series[-1]["max_tokens"]
        headroom = max(0, window - current)

        turn_end: Dict[Any, int] = {}
        for row in series:
            turn_end[row["turn_index"]] = row["context_tokens"]
        ordered = [turn_end[key] for key in sorted(turn_end, key=lambda k: (k is None, k))]

        per_call_steps = [b["context_tokens"] - a["context_tokens"]
                          for a, b in zip(series, series[1:])
                          if b["context_tokens"] > a["context_tokens"]]
        per_call = (sum(per_call_steps) / len(per_call_steps)) if per_call_steps else 0.0

        steps = [b - a for a, b in zip(ordered, ordered[1:])]
        rises = sorted(step for step in steps if step > 0)
        resets = sum(1 for step in steps if step < 0)
        # `resets` counts EVERY backward step, and a window shrinks slightly for
        # reasons that are not a compaction. Dividing a session's re-read bill by
        # that count therefore divides by too much. `major_resets` counts only
        # the falls that actually emptied the window.
        #
        # _RESET_FRACTION is a separator, not a calibration. Real compactions and
        # ordinary shrinkage do not occupy the same range -- they sit either side
        # of a wide empty band, and every threshold across that band returns the
        # same count on the sessions this was checked against. It is here to name
        # the gap, not to tune a number, which is why nothing downstream exposes
        # it as a setting.
        major_resets = sum(1 for before, after in zip(ordered, ordered[1:])
                           if before > 0 and (after - before) / before < -_RESET_FRACTION)
        if rises:
            middle = len(rises) // 2
            per_turn = (rises[middle] if len(rises) % 2
                        else (rises[middle - 1] + rises[middle]) / 2.0)
        elif per_call_steps:
            # One turn only: its own total growth is the best estimate of what
            # the next turn like it would add.
            per_turn = float(sum(per_call_steps))
        else:
            per_turn = 0.0

        return {
            "tokens_per_turn": round(per_turn, 1),
            "major_resets": major_resets,
            "per_call_tokens": round(per_call, 1),
            "turns_until_full": (int(headroom / per_turn) if per_turn > 0 else None),
            "current_tokens": current,
            "max_tokens": window,
            "headroom_tokens": headroom,
            "resets": resets,
            "samples": len(series),
            "turns_sampled": len(ordered),
        }

    @property
    def waste(self) -> Dict[str, Any]:
        cost = 0.0
        tokens = 0
        calls = 0
        for call in self.calls:
            if call.is_error or call.aborted:
                calls += 1
                tokens += call.total_tokens
                cost += call.total_usd
        tool_errors = sum(1 for t in self.tools if t.is_error)
        return {
            "error_calls": calls,
            "error_tokens": tokens,
            "error_cost_usd": cost,
            "tool_errors": tool_errors,
            "tool_error_pct": (100.0 * tool_errors / len(self.tools)) if self.tools else 0.0,
        }

    @property
    def insights(self) -> List[str]:
        out: List[str] = []
        totals = self.totals
        cost = totals["cost_usd"]
        if not self.calls:
            return ["no API calls recorded in this transcript"]

        # First, because it invalidates every other number below it. An unknown
        # model is priced at zero, and the reconciliation only shouts about that
        # when a cost-state line exists to compare against, and many transcripts
        # do not have one -- the largest are often among them. Silence there
        # would hand the user an understated total with nothing to notice.
        if totals["unpriced_calls"]:
            models = sorted({c.model for c in self.calls if c.unpriced})
            out.append(
                f"UNPRICED: {totals['unpriced_calls']:,} of {totals['calls']:,} requests used a "
                f"model the pricing table does not know ({', '.join(models[:4])}"
                f"{'...' if len(models) > 4 else ''}) and were counted as $0.00, so every dollar "
                "figure in this report is a floor. Run `oe reprice` to re-derive the table from "
                "the installed Claude Code binary.")

        cache = self.cache_efficiency
        out.append(
            f"Cache hit ratio {cache['hit_ratio'] * 100:.1f}% "
            f"({cache['read_tokens']:,} read vs {cache['write_tokens']:,} written). "
            f"Caching saved ${cache['cost_saved_vs_uncached_usd']:,.2f} versus paying full input "
            f"price, and the writes cost ${cache['cost_paid_on_writes_usd']:,.2f} -- "
            f"net ${cache['net_usd']:,.2f}.")

        if cost > 0:
            read_share = 100.0 * totals["cache_read_usd"] / cost
            out.append(
                f"Cache reads are {read_share:.0f}% of spend (${totals['cache_read_usd']:,.2f} of "
                f"${cost:,.2f}). " + (
                    "That is the dominant term: every extra turn re-reads the whole context, so "
                    "shorter sessions and smaller contexts beat any other optimisation."
                    if read_share > 55 else
                    "Output tokens still dominate; trimming thinking effort will move the needle "
                    "more than shrinking context."))

        turns = self.expensive_turns
        if turns:
            top = turns[0]
            share = 100.0 * top["cost"] / cost if cost else 0.0
            # Identified by its index and its numbers, never by its text. A
            # truncated prompt is still the prompt, and this sentence is copied
            # verbatim into data.json, report.html and summary.md.
            out.append(
                f"Most expensive turn: #{top['index']} at ${top['cost']:,.2f} ({share:.0f}% of the "
                f"session) over {top['calls']} calls, {top['tools']} tool calls and "
                f"{top['tokens']:,} tokens.")
            if len(turns) > 1:
                head = sum(t["cost"] for t in turns[:3])
                out.append(f"Top 3 turns account for ${head:,.2f} "
                           f"({100.0 * head / cost if cost else 0:.0f}% of spend).")

        agent_types = self.agent_type_costs
        if agent_types:
            first = agent_types[0]
            out.append(
                f"Subagents cost ${sum(a['cost_usd'] for a in agent_types):,.2f} across "
                f"{sum(a['agents'] for a in agent_types)} agents; the priciest type is "
                f"'{first['agent_type']}' at ${first['cost_usd']:,.2f} "
                f"(${first['cost_per_agent_usd']:,.2f} per agent over {first['agents']} runs).")
            agent_share = 100.0 * sum(a["cost_usd"] for a in agent_types) / cost if cost else 0.0
            if agent_share > 50:
                out.append(f"{agent_share:.0f}% of spend happens inside subagents -- fan-out width "
                           "is the main cost lever in this session, not prompt wording.")

        tools = sorted(self.by_tool.values(), key=lambda r: -r["count"])
        if tools:
            first = tools[0]
            out.append(f"{totals['tool_calls']:,} tool calls; heaviest by count is "
                       f"{first['name']} ({first['count']:,}).")
            fattest = sorted(self.by_tool.values(), key=lambda r: -r["est_result_bytes"])[:3]
            if fattest and fattest[0]["est_result_bytes"] > 0:
                pieces = ", ".join(
                    f"{row['name']} {row['est_result_bytes'] / 1024:,.0f} KB "
                    f"(avg {row['avg_result_bytes'] / 1024:,.1f} KB)" for row in fattest)
                out.append("Largest tool results, which is what actually fills the context: "
                           + pieces + ".")

        growth = self.context_growth
        if growth.get("tokens_per_turn"):
            remaining = growth.get("turns_until_full")
            out.append(
                f"Context grows ~{growth['tokens_per_turn']:,.0f} tokens per turn; now at "
                f"{growth['current_tokens']:,} of {growth['max_tokens']:,} "
                f"({100.0 * growth['current_tokens'] / growth['max_tokens']:.0f}%)"
                + (f", about {remaining} more turns before the window fills."
                   if remaining is not None else "."))

        repeats = self.redundant_work
        if repeats:
            worst = repeats[0]
            # Composed from a shape, not from the value: shape_of() names the
            # KIND of target ("a .ts file", "a `git` command") and nothing that
            # could identify a repository, a ticket or a person. The row itself
            # is the first entry of the redundant-work table, which carries the
            # matching id.
            out.append(
                f"Redundant work: {len(repeats)} targets were re-fetched at or above the "
                f"{self._config['insights']['reread_threshold']}x threshold. Worst is "
                f"{worst['tool']} on {redact.shape_of(worst['tool'], worst['target'])} "
                f"x{worst['count']} (~{worst['wasted_bytes'] / 1024:,.0f} KB of avoidable "
                "context); it is the top row of the redundant-work table.")

        waste = self.waste
        if waste["error_calls"]:
            out.append(f"{waste['error_calls']} API calls errored or aborted mid-stream, burning "
                       f"{waste['error_tokens']:,} tokens (${waste['error_cost_usd']:,.2f}).")
        if waste["tool_errors"]:
            out.append(f"{waste['tool_errors']:,} tool calls failed "
                       f"({waste['tool_error_pct']:.1f}% of all tool calls); each failure still "
                       "pays to carry its error text in context for the rest of the session.")

        if totals["output_tokens"]:
            share = 100.0 * totals["thinking_tokens"] / totals["output_tokens"]
            out.append(f"Thinking is {share:.0f}% of output tokens "
                       f"({totals['thinking_tokens']:,} of {totals['output_tokens']:,}) -- "
                       f"${totals['output_usd'] * share / 100:,.2f} at output prices. Lower "
                       "effort on mechanical turns converts directly into savings."
                       if share > 25 else
                       f"Thinking is {share:.0f}% of output tokens.")

        budget = self._config.get("budget") or {}
        limit = float(budget.get("session_usd") or 0)
        authoritative = totals["cost_usd_authoritative"]
        if limit and authoritative >= limit * (float(budget.get("warn_pct") or 80) / 100.0):
            out.append(f"BUDGET: ${authoritative:,.2f} against a ${limit:,.2f} per-session budget "
                       f"({100.0 * authoritative / limit:.0f}%).")

        recon = self.reconciliation
        if recon["status"] == "drift":
            out.append(f"Reconciliation drift {recon['delta_pct']}%: computed "
                       f"${recon['computed_usd']:,.2f} vs Claude Code's ${recon['reported_usd']:,.2f}. "
                       + (recon["diagnosis"][0] if recon["diagnosis"] else ""))
        return out

    # -- serialisation -----------------------------------------------------

    def to_dict(self) -> Dict[str, Any]:
        totals = self.totals
        config_report = self._config.get("report") or {}
        max_calls = int(config_report.get("max_raw_calls") or 4000)
        include_calls = bool(config_report.get("include_raw_calls", True))
        calls = [c.to_dict() for c in self.calls[:max_calls]] if include_calls else []
        return {
            "schema_version": SCHEMA_VERSION,
            "generated_at": _iso(_now()),
            "session": {
                "session_id": self.session_id,
                "transcript_path": self.transcript_path,
                "project": self.project,
                "project_display": paths.project_display(self.project),
                "cwd": self.cwd,
                "git_branch": self.git_branch,
                "cc_version": self.cc_version,
                "slug": self.slug,
                "title": self.title,
                "last_prompt": self.last_prompt,
                "started_at": _iso(self.started_at),
                "last_activity": _iso(self.last_activity),
                "wall_seconds": self.wall_seconds,
                "primary_model": self.primary_model,
                # Label and source only; never the address or the uuid. This
                # payload becomes data.json and report.html.
                "account_label": self._account.get("label"),
                "account_source": self._account.get("source"),
                "turns": len(self.turns),
                "agents": len(self.agents),
                "workflows": len(self.workflows),
            },
            "totals": totals,
            "by_model": self.by_model,
            "by_origin": self.by_origin,
            "by_tool": self.by_tool,
            "by_turn": self.by_turn,
            "context_series": self.context_series,
            "context_window": self.context_window_state,
            "cache_efficiency": self.cache_efficiency,
            "reconciliation": self.reconciliation,
            "insights": self.insights,
            "expensive_turns": self.expensive_turns,
            "expensive_agents": self.expensive_agents[
                : int(self._config["insights"]["top_subagents"])],
            "agent_type_costs": self.agent_type_costs,
            "redundant_work": self.redundant_work,
            "rereads": self.rereads,
            "context_growth": self.context_growth,
            "waste": self.waste,
            "workflows": self.workflows,
            "compactions": self.compactions,
            "calls": calls,
            "calls_truncated": include_calls and len(self.calls) > max_calls,
            # `calls` above is the FIRST max_calls requests, so anything derived
            # from it silently drops the back half of a long session. These two
            # are derived from self.calls in full and are what the report renders:
            # the cumulative-spend chart, and the most-expensive-requests table
            # (which would otherwise rank inside the truncated slice and miss
            # most of the true top of a long session).
            "cost_series": self.cost_series,
            # Only when `calls` is short of the whole session: below the cap it
            # already contains every request, so ranking inside it is already
            # ranking across the session and duplicating those rows would just
            # inflate data.json (and could push a mid-size session past the
            # cache cut-off for no gain).
            "top_calls": ([c.to_dict() for c in sorted(
                self.calls, key=lambda c: -c.total_usd)[:TOP_CALL_ROWS]]
                if include_calls and len(self.calls) > max_calls else []),
            "tools": [t.to_dict() for t in self.tools[:max_calls]],
            # Same cap as `calls`, so it needs the same flag: without it a reader
            # cannot tell a 4,000-tool session from one truncated at 4,000.
            # by_tool stays complete, so the per-tool counts remain trustworthy.
            "tools_truncated": len(self.tools) > max_calls,
            "parse": {
                "files_read": self.files_read,
                "bytes_read": self.bytes_read,
                "bad_lines": self.parse_errors,
                "load_seconds": round(self.load_seconds, 3),
            },
        }


# ---------------------------------------------------------------------------
# loading
# ---------------------------------------------------------------------------



# Read truncates at 2,000 lines unless the call passes a limit, so a call with
# no offset/limit did NOT put the whole of a 5,000-line file into context. If
# that read were recorded as covering everything, a later `offset=2000` would
# be classified as an avoidable repeat and an enforcing guard would block the
# one read that was genuinely fetching new lines. Erring here always errs
# toward allowing.
DEFAULT_READ_LINES = 2000
_MIN_TS = datetime.min.replace(tzinfo=timezone.utc)


def _window_of(row: Any) -> str:
    """The context window a call or tool call lived in.

    The main loop is one window; every agent is its own. Keyed on agent_id
    rather than on origin, because two agents of the same type share an origin
    and emphatically do not share a context.
    """
    origin = getattr(row, "origin", "main")
    if origin == "main":
        return "main"
    return getattr(row, "agent_id", None) or origin


def _span_contained(spans: Sequence[Sequence[int]], lo: int, hi: int) -> bool:
    """Is [lo, hi] inside the union of `spans`? (spans are merged and sorted)"""
    for start, end in spans:
        if start <= lo and hi <= end:
            return True
    return False


def _span_merge(spans: Sequence[Sequence[int]], lo: int, hi: int) -> List[List[int]]:
    """Union of `spans` with [lo, hi], kept merged, disjoint and sorted.

    Same canonical-interval invariant as oe/store.py's ranges table, for the
    same reason: containment is then a single scan and can never be fooled by
    two adjacent fragments that together cover the query.
    """
    out: List[List[int]] = []
    placed = False
    for start, end in sorted(list(spans) + [[lo, hi]]):
        if out and start <= out[-1][1] + 1:
            out[-1][1] = max(out[-1][1], end)
        else:
            out.append([start, end])
        placed = True
    return out if placed else [[lo, hi]]


def _requests_after(stamps: Sequence[datetime], stamp: Optional[datetime],
                    marks: Optional[Sequence[datetime]]) -> int:
    """How many requests in this window still had to carry a result landed at `stamp`.

    Bounded on the right by the next compaction when the window is the main
    loop: after a compaction the bytes are gone and nobody pays for them again.
    """
    if stamp is None or not stamps:
        return 0
    start = bisect_right(stamps, stamp)
    end = len(stamps)
    if marks:
        cut = bisect_right(marks, stamp)
        if cut < len(marks):
            end = min(end, bisect_left(stamps, marks[cut]))
    return max(0, end - start)


def summarise_rereads(events: Sequence[Dict[str, Any]], *, limit: int = 40,
                      calibrated_rate: float = CARRY_USD_PER_1K,
                      sessions: int = 1) -> Dict[str, Any]:
    """Fold a list of reread_events() rows into the reported shape.

    Split out of the ledger so `oe rereads --all` can pour every session's
    events into one call and get a corpus table with exactly the same
    arithmetic as a single-session one -- there is no second implementation
    that could drift.
    """
    files: Dict[str, Dict[str, Any]] = {}
    by_reason: Dict[str, Dict[str, Any]] = {}
    totals = {"reads": 0, "bytes": 0, "tokens": 0.0, "carry_usd": 0.0,
              "calibrated_usd": 0.0, "carry_requests": 0}
    for row in events:
        path = row.get("path") or ""
        reason = row.get("reason") or "avoidable"
        nbytes = _int(row.get("bytes"))
        tokens = _float(row.get("tokens"))
        carry = _float(row.get("carry_usd"))
        calib = _float(row.get("calibrated_usd"))
        repeat = reason != "first"
        avoidable = reason == "avoidable"

        totals["reads"] += 1
        totals["bytes"] += nbytes
        totals["tokens"] += tokens
        totals["carry_usd"] += carry
        totals["calibrated_usd"] += calib
        totals["carry_requests"] += _int(row.get("carry_requests"))

        bucket = by_reason.setdefault(reason, {
            "reason": reason, "reads": 0, "bytes": 0, "tokens": 0.0,
            "carry_usd": 0.0, "calibrated_usd": 0.0})
        bucket["reads"] += 1
        bucket["bytes"] += nbytes
        bucket["tokens"] += tokens
        bucket["carry_usd"] += carry
        bucket["calibrated_usd"] += calib

        entry = files.get(path)
        if entry is None:
            entry = files[path] = {
                "path": path, "ext": _ext_of(path), "reads": 0, "bytes": 0,
                "tokens": 0.0, "carry_usd": 0.0, "calibrated_usd": 0.0,
                "first_reads": 0, "first_bytes": 0, "first_calibrated_usd": 0.0,
                "repeat_reads": 0, "repeat_bytes": 0,
                "repeat_carry_usd": 0.0, "repeat_calibrated_usd": 0.0,
                "avoidable_reads": 0, "avoidable_bytes": 0,
                "avoidable_carry_usd": 0.0, "avoidable_calibrated_usd": 0.0,
                "reasons": {}, "windows": set(), "first_ts": row.get("ts"),
                "last_ts": row.get("ts"),
            }
        entry["reads"] += 1
        entry["bytes"] += nbytes
        entry["tokens"] += tokens
        entry["carry_usd"] += carry
        entry["calibrated_usd"] += calib
        entry["reasons"][reason] = entry["reasons"].get(reason, 0) + 1
        entry["windows"].add(row.get("window") or "main")
        if row.get("ts"):
            entry["last_ts"] = row.get("ts")
            if not entry["first_ts"]:
                entry["first_ts"] = row.get("ts")
        if not repeat:
            entry["first_reads"] += 1
            entry["first_bytes"] += nbytes
            entry["first_calibrated_usd"] += calib
        if repeat:
            entry["repeat_reads"] += 1
            entry["repeat_bytes"] += nbytes
            entry["repeat_carry_usd"] += carry
            entry["repeat_calibrated_usd"] += calib
        if avoidable:
            entry["avoidable_reads"] += 1
            entry["avoidable_bytes"] += nbytes
            entry["avoidable_carry_usd"] += carry
            entry["avoidable_calibrated_usd"] += calib

    rows = []
    for entry in files.values():
        entry["windows"] = len(entry["windows"])
        rows.append(entry)
    rows.sort(key=lambda r: (-r["repeat_calibrated_usd"], -r["reads"], r["path"]))

    def _r(name: str, field: str) -> float:
        return _float((by_reason.get(name) or {}).get(field))

    repeat_reads = totals["reads"] - int(_r("first", "reads"))
    repeat_bytes = totals["bytes"] - int(_r("first", "bytes"))
    legit = [name for name in REREAD_REASONS if name not in ("first", "avoidable")]
    out = {
        "reads": totals["reads"],
        "files": len(files),
        "sessions": sessions,
        "bytes": totals["bytes"],
        "tokens": round(totals["tokens"], 1),
        "first_reads": int(_r("first", "reads")),
        "first_bytes": int(_r("first", "bytes")),
        "repeat_reads": repeat_reads,
        "repeat_bytes": repeat_bytes,
        "repeat_pct": (100.0 * repeat_bytes / totals["bytes"]) if totals["bytes"] else 0.0,
        "repeat_pct_calls": (100.0 * repeat_reads / totals["reads"]) if totals["reads"] else 0.0,
        "avoidable_reads": int(_r("avoidable", "reads")),
        "avoidable_bytes": int(_r("avoidable", "bytes")),
        "legitimate_reads": sum(int(_r(name, "reads")) for name in legit),
        "legitimate_bytes": sum(int(_r(name, "bytes")) for name in legit),
        "carry_usd": totals["carry_usd"],
        "repeat_carry_usd": totals["carry_usd"] - _r("first", "carry_usd"),
        "avoidable_carry_usd": _r("avoidable", "carry_usd"),
        "calibrated_usd": totals["calibrated_usd"],
        "repeat_calibrated_usd": totals["calibrated_usd"] - _r("first", "calibrated_usd"),
        "avoidable_calibrated_usd": _r("avoidable", "calibrated_usd"),
        "carry_requests_mean": (totals["carry_requests"] / totals["reads"]
                                if totals["reads"] else 0.0),
        "carry_rate_usd_per_1k_measured": (
            1000.0 * totals["carry_usd"] / totals["tokens"] if totals["tokens"] else 0.0),
        "carry_rate_usd_per_1k_calibrated": calibrated_rate,
        "by_reason": [dict(by_reason[name]) for name in REREAD_REASONS if name in by_reason],
        "files_ranked": rows if limit <= 0 else rows[:limit],
        "files_truncated": bool(limit > 0 and len(rows) > limit),
        # What an enforcing guard would have done with exactly these events.
        # Its whole job is to deny a read whose bytes are already in this
        # window, so it acts on 'avoidable' and -- because residency alone
        # cannot see a file change -- would also have denied 'changed'. That
        # second number is the false-block rate, and it is the only reason the
        # guard ships defaulted to warn.
        "guard": {
            "would_block": int(_r("avoidable", "reads")) + int(_r("changed", "reads")),
            "correct_blocks": int(_r("avoidable", "reads")),
            "false_blocks": int(_r("changed", "reads")),
            "false_block_pct": (
                100.0 * _r("changed", "reads")
                / max(1.0, _r("avoidable", "reads") + _r("changed", "reads"))),
            "allowed": (int(_r("first", "reads")) + int(_r("subagent", "reads"))
                        + int(_r("post_compact", "reads")) + int(_r("new_range", "reads"))),
            "saved_carry_usd": _r("avoidable", "carry_usd"),
            "saved_calibrated_usd": _r("avoidable", "calibrated_usd"),
            "saved_bytes": int(_r("avoidable", "bytes")),
        },
    }
    return out


def merge_rereads(parts: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
    """Combine per-session analyses. Kept separate from summarise_rereads
    because the two answer different questions: this one must NOT re-classify
    across sessions. A file read in two sessions was read into two different
    context windows, and the second one is not waste -- calling it waste is the
    single easiest way to make a corpus number look bigger than the truth."""
    merged: Dict[str, Dict[str, Any]] = {}
    out = {
        "reads": 0, "bytes": 0, "tokens": 0.0, "first_reads": 0, "first_bytes": 0,
        "repeat_reads": 0, "repeat_bytes": 0, "avoidable_reads": 0,
        "avoidable_bytes": 0, "legitimate_reads": 0, "legitimate_bytes": 0,
        "carry_usd": 0.0, "repeat_carry_usd": 0.0, "avoidable_carry_usd": 0.0,
        "calibrated_usd": 0.0, "repeat_calibrated_usd": 0.0,
        "avoidable_calibrated_usd": 0.0, "sessions": 0,
    }
    reasons: Dict[str, Dict[str, Any]] = {}
    guard = {"would_block": 0, "correct_blocks": 0, "false_blocks": 0, "allowed": 0,
             "saved_carry_usd": 0.0, "saved_calibrated_usd": 0.0, "saved_bytes": 0}
    carry_requests = 0.0
    rate = CARRY_USD_PER_1K
    for part in parts:
        if not part or not part.get("reads"):
            continue
        out["sessions"] += _int(part.get("sessions")) or 1
        for key in ("reads", "bytes", "first_reads", "first_bytes", "repeat_reads",
                    "repeat_bytes", "avoidable_reads", "avoidable_bytes",
                    "legitimate_reads", "legitimate_bytes"):
            out[key] += _int(part.get(key))
        for key in ("tokens", "carry_usd", "repeat_carry_usd", "avoidable_carry_usd",
                    "calibrated_usd", "repeat_calibrated_usd",
                    "avoidable_calibrated_usd"):
            out[key] += _float(part.get(key))
        carry_requests += _float(part.get("carry_requests_mean")) * _int(part.get("reads"))
        rate = _float(part.get("carry_rate_usd_per_1k_calibrated")) or rate
        for row in part.get("by_reason") or []:
            name = row.get("reason") or "avoidable"
            acc = reasons.setdefault(name, {"reason": name, "reads": 0, "bytes": 0,
                                            "tokens": 0.0, "carry_usd": 0.0,
                                            "calibrated_usd": 0.0})
            acc["reads"] += _int(row.get("reads"))
            acc["bytes"] += _int(row.get("bytes"))
            acc["tokens"] += _float(row.get("tokens"))
            acc["carry_usd"] += _float(row.get("carry_usd"))
            acc["calibrated_usd"] += _float(row.get("calibrated_usd"))
        part_guard = part.get("guard") or {}
        for key in guard:
            guard[key] += (_float(part_guard.get(key)) if "usd" in key
                           else _int(part_guard.get(key)))
        for row in part.get("files_ranked") or []:
            path = row.get("path") or ""
            entry = merged.get(path)
            if entry is None:
                entry = merged[path] = {"path": path, "ext": row.get("ext") or "",
                                        "reasons": {}, "windows": 0, "sessions": 0,
                                        "first_ts": row.get("first_ts"),
                                        "last_ts": row.get("last_ts")}
                for key in ("reads", "bytes", "first_reads", "first_bytes",
                            "repeat_reads", "repeat_bytes",
                            "avoidable_reads", "avoidable_bytes"):
                    entry[key] = 0
                for key in ("tokens", "carry_usd", "calibrated_usd",
                            "first_calibrated_usd",
                            "repeat_carry_usd", "repeat_calibrated_usd",
                            "avoidable_carry_usd", "avoidable_calibrated_usd"):
                    entry[key] = 0.0
            entry["sessions"] += 1
            entry["windows"] += _int(row.get("windows"))
            for key in ("reads", "bytes", "first_reads", "first_bytes",
                        "repeat_reads", "repeat_bytes",
                        "avoidable_reads", "avoidable_bytes"):
                entry[key] += _int(row.get(key))
            for key in ("tokens", "carry_usd", "calibrated_usd", "first_calibrated_usd",
                        "repeat_carry_usd", "repeat_calibrated_usd",
                        "avoidable_carry_usd", "avoidable_calibrated_usd"):
                entry[key] += _float(row.get(key))
            for name, count in (row.get("reasons") or {}).items():
                entry["reasons"][name] = entry["reasons"].get(name, 0) + _int(count)
            if row.get("last_ts") and (not entry["last_ts"]
                                       or row["last_ts"] > entry["last_ts"]):
                entry["last_ts"] = row["last_ts"]
            if row.get("first_ts") and (not entry["first_ts"]
                                        or row["first_ts"] < entry["first_ts"]):
                entry["first_ts"] = row["first_ts"]

    rows = sorted(merged.values(),
                  key=lambda r: (-r["repeat_calibrated_usd"], -r["reads"], r["path"]))
    out["files"] = len(merged)
    out["repeat_pct"] = (100.0 * out["repeat_bytes"] / out["bytes"]) if out["bytes"] else 0.0
    out["repeat_pct_calls"] = (100.0 * out["repeat_reads"] / out["reads"]) if out["reads"] else 0.0
    out["carry_requests_mean"] = carry_requests / out["reads"] if out["reads"] else 0.0
    out["carry_rate_usd_per_1k_measured"] = (
        1000.0 * out["carry_usd"] / out["tokens"] if out["tokens"] else 0.0)
    out["carry_rate_usd_per_1k_calibrated"] = rate
    out["by_reason"] = [dict(reasons[name]) for name in REREAD_REASONS if name in reasons]
    guard["false_block_pct"] = (100.0 * guard["false_blocks"]
                                / max(1, guard["correct_blocks"] + guard["false_blocks"]))
    out["guard"] = guard
    out["files_ranked"] = rows
    out["files_truncated"] = False
    # A path read in two sessions is a "first" twice above, which is correct
    # per-window and understates the corpus-wide repeat share. Both are stated
    # so neither can be quoted as the other.
    out["distinct_files"] = len(merged)
    out["corpus_repeat_reads"] = max(0, out["reads"] - len(merged))
    out["corpus_repeat_pct_calls"] = (
        100.0 * out["corpus_repeat_reads"] / out["reads"]) if out["reads"] else 0.0
    # Bytes for the same view. One first read per PATH survives, sized at that
    # path's mean first read -- exact per-event first-read bytes are not carried
    # through the per-file rows, and the mean is within a rounding error of it
    # because a first read of the same file is the same read.
    corpus_first_bytes = 0.0
    corpus_first_usd = 0.0
    for row in rows:
        firsts = max(1, _int(row.get("first_reads")))
        corpus_first_bytes += _float(row.get("first_bytes")) / firsts
        corpus_first_usd += _float(row.get("first_calibrated_usd")) / firsts
    out["corpus_repeat_bytes"] = int(max(0.0, out["bytes"] - corpus_first_bytes))
    out["corpus_repeat_pct"] = (100.0 * out["corpus_repeat_bytes"] / out["bytes"]
                                if out["bytes"] else 0.0)
    out["corpus_repeat_calibrated_usd"] = max(
        0.0, out["calibrated_usd"] - corpus_first_usd)
    return out


def _ext_of(path: str) -> str:
    suffix = Path(str(path)).suffix.lower()
    return suffix if 1 < len(suffix) <= 9 and suffix[1:].isalnum() else ""


def _target_of(tool_name: str, tool_input: Any) -> Optional[str]:
    """A stable fingerprint for 'the same work done again'."""
    if not isinstance(tool_input, dict):
        return None
    if tool_name in ("Read", "NotebookEdit", "Edit", "Write"):
        path = tool_input.get("file_path") or tool_input.get("notebook_path")
        return str(path) if path else None
    if tool_name == "Bash":
        command = tool_input.get("command")
        if not command:
            return None
        return _WS_RE.sub(" ", str(command)).strip()[:300]
    if tool_name in ("Grep", "Glob"):
        pattern = tool_input.get("pattern")
        where = tool_input.get("path") or ""
        return f"{pattern} @ {where}" if pattern else None
    if tool_name in ("WebFetch", "WebSearch"):
        return str(tool_input.get("url") or tool_input.get("query") or "") or None
    return None


class _Loader:
    def __init__(self, ledger: SessionLedger, include_subagents: bool):
        self.ledger = ledger
        self.include_subagents = include_subagents
        self.requests: Dict[str, _Request] = {}
        # tool_use ids belonging to a read tool. Populated as the assistant line
        # is parsed, which always precedes its result line in the same file, so
        # by the time the result arrives we know whether it is worth the extra
        # json.loads that measures its content exactly.
        self.read_ids: set = set()
        self.order: List[str] = []
        self.sources: Dict[str, dict] = {}   # request_id -> source context
        self.tool_results: Dict[str, dict] = {}
        self.file_prompt: Dict[str, Optional[str]] = {}
        # Newest main-transcript request timestamp parsed so far. Stamped onto
        # each cost-state line as its billed-through mark; see the cost-state
        # branch in _read_file.
        self._last_main_ts: Optional[datetime] = None

    # -- file walking ------------------------------------------------------

    def _read_file(self, path: Path, source: dict) -> None:
        try:
            size = path.stat().st_size
        except OSError:
            return
        self.ledger.files_read += 1
        self.ledger.bytes_read += size
        current_prompt: Optional[str] = None
        try:
            handle = open(path, "r", encoding="utf-8", errors="replace")
        except OSError:
            return
        with handle:
            for raw in handle:
                if len(raw) < 12:
                    continue
                # Two shapes, both cheap to reject: a `compact_boundary`
                # system line and the `isCompactSummary` user line that follows
                # it. The substring test costs one scan of a line we were about
                # to scan anyway; the regex only runs on the handful of lines
                # that contain the word at all.
                if source["origin"] == "main" and "ompact" in raw \
                        and _COMPACT_MARK_RE.search(raw):
                    obj = self._loads(raw)
                    stamp = _parse_ts((obj or {}).get("timestamp"))
                    if stamp is not None:
                        self.ledger.compaction_marks.append(stamp)
                    # The same line usually carries compactMetadata, with the
                    # preTokens/postTokens/trigger the compaction lever needs to
                    # price itself. Without this, `compactions` comes ONLY from
                    # the PreCompact hook journal -- which exists only once those
                    # hooks are installed -- so the lever sees stale journal rows
                    # instead of the session's real ceiling compactions, and
                    # prices them at zero.
                    meta = (obj or {}).get("compactMetadata")
                    if isinstance(meta, dict):
                        row = {"trigger": meta.get("trigger") or "auto",
                               "pre_tokens": meta.get("preTokens"),
                               "post_tokens": meta.get("postTokens"),
                               "preTokens": meta.get("preTokens"),
                               "postTokens": meta.get("postTokens"),
                               "cumulative_dropped_tokens":
                                   meta.get("cumulativeDroppedTokens"),
                               "source": "transcript"}
                        if stamp is not None:
                            row["ts"] = stamp.isoformat()
                        self.ledger.compactions.append(row)
                kind = _line_type(raw)
                if kind == "assistant":
                    obj = self._loads(raw)
                    if obj is not None:
                        self._on_assistant(obj, source, current_prompt)
                        if source["origin"] == "main":
                            stamp = _parse_ts(obj.get("timestamp"))
                            if stamp is not None and (self._last_main_ts is None
                                                      or stamp > self._last_main_ts):
                                self._last_main_ts = stamp
                elif kind == "user":
                    current_prompt = self._on_user(raw, source, current_prompt)
                elif kind == "cost-state":
                    obj = self._loads(raw)
                    if obj is not None and source["origin"] == "main":
                        self.ledger.reported = obj
                        self.ledger.cost_states.append(obj)
                        # A checkpoint is a snapshot of everything ABOVE it in
                        # the file, so the last main-loop request parsed before
                        # this line is exactly how far the run is billed. The
                        # line itself carries no timestamp, and totalDuration is
                        # accumulated ACTIVE time, not elapsed wall clock -- on
                        # a long transcript it can be a fraction of elapsed wall
                        # clock, so using it as a right edge declares
                        # already-billed requests "uncovered" and adds to Claude
                        # Code's own figure.
                        self.ledger.cost_state_marks.append(self._last_main_ts)
                elif kind in ("ai-title", "last-prompt", "system"):
                    obj = self._loads(raw)
                    if obj is None:
                        continue
                    if kind == "ai-title":
                        self.ledger.title = obj.get("aiTitle") or self.ledger.title
                    elif kind == "last-prompt":
                        self.ledger.last_prompt = obj.get("lastPrompt") or self.ledger.last_prompt

    def _loads(self, raw: str) -> Optional[dict]:
        try:
            obj = json.loads(raw)
        except Exception:
            # A transcript's final line can be half-written while the session
            # is live; skipping it is correct, crashing is not.
            self.ledger.parse_errors += 1
            return None
        return obj if isinstance(obj, dict) else None

    # -- line handlers -----------------------------------------------------

    def _on_assistant(self, obj: dict, source: dict, current_prompt: Optional[str]) -> None:
        # _line_type sniffs with regexes over a 600/900-byte prefix, so a user
        # line whose tool_result payload quotes `"role":"assistant"` early
        # enough can arrive here. The parsed object knows the truth for free;
        # without this check such a line becomes a phantom zero-cost request
        # keyed on its uuid, inflating the call count.
        kind = obj.get("type")
        if kind is not None and kind != "assistant":
            return
        # `or {}` only rescues None. A `message` or `usage` that is a string --
        # seen on client-synthesised error records, and reachable from any
        # hand-edited or torn line -- sails through it and then raises on .get,
        # which propagates all the way out of ledger.load().
        message = obj.get("message")
        if not isinstance(message, dict):
            message = {}
        usage = message.get("usage")
        if not isinstance(usage, dict):
            usage = {}
        request_id = obj.get("requestId") or f"uuid:{obj.get('uuid')}"
        record = self.requests.get(request_id)
        if record is None:
            record = _Request(obj, usage, source["origin"])
            self.requests[request_id] = record
            self.order.append(request_id)
            self.sources[request_id] = dict(source)
            self.sources[request_id]["prompt_id"] = obj.get("promptId") or current_prompt
        else:
            record.absorb(obj, usage)
        record.add_blocks(message.get("content"))
        content = message.get("content")
        if isinstance(content, list):
            for block in content:
                if isinstance(block, dict) and block.get("type") == "tool_use" \
                        and block.get("name") in READ_TOOLS and block.get("id"):
                    self.read_ids.add(block["id"])

        if source["origin"] == "main":
            self.ledger.cwd = obj.get("cwd") or self.ledger.cwd
            self.ledger.git_branch = obj.get("gitBranch") or self.ledger.git_branch
            self.ledger.cc_version = obj.get("version") or self.ledger.cc_version
            self.ledger.slug = obj.get("slug") or self.ledger.slug

    def _on_user(self, raw: str, source: dict, current_prompt: Optional[str]) -> Optional[str]:
        # Big user lines are tool results; we only need the id and the size, and
        # json.loads on a large payload is the hot spot we are avoiding.
        if len(raw) > _BIG_LINE and '"tool_result"' in raw:
            match = _TOOL_USE_ID_RE.search(raw)
            if match:
                tool_use_id = match.group(1)
                entry = {
                    "bytes": len(raw),
                    "is_error": bool(_IS_ERROR_RE.search(raw)),
                    "ts": None,
                }
                # Only for reads, and only a small share of all lines: the exact
                # length of the text that landed in the context. len(raw) is
                # about double it, so pricing re-reads off len(raw) would
                # overstate the bill by roughly 2x.
                if tool_use_id in self.read_ids:
                    obj = self._loads(raw)
                    if obj is not None:
                        entry["content_bytes"] = _result_content_bytes(obj, tool_use_id)
                        entry["ts"] = _parse_ts(obj.get("timestamp"))
                self.tool_results[tool_use_id] = entry
            prompt = _PROMPT_ID_RE.search(raw)
            return prompt.group(1) if prompt else current_prompt

        obj = self._loads(raw)
        if obj is None:
            return current_prompt
        prompt_id = obj.get("promptId") or current_prompt
        message = obj.get("message") or {}
        content = message.get("content")

        if isinstance(content, list):
            for block in content:
                if isinstance(block, dict) and block.get("type") == "tool_result":
                    tool_use_id = block.get("tool_use_id")
                    if tool_use_id:
                        payload = block.get("content")
                        entry = {
                            "bytes": len(raw),
                            "is_error": bool(block.get("is_error")),
                            "ts": _parse_ts(obj.get("timestamp")),
                        }
                        if tool_use_id in self.read_ids:
                            entry["content_bytes"] = _result_content_bytes(
                                obj, tool_use_id)
                        self.tool_results[tool_use_id] = entry
                        del payload
            has_tool_result = any(isinstance(b, dict) and b.get("type") == "tool_result"
                                  for b in content)
        else:
            has_tool_result = False

        is_prompt = (not has_tool_result and not obj.get("isMeta")
                     and not obj.get("isSidechain") and source["origin"] == "main"
                     and content is not None)
        if is_prompt:
            preview = _text_preview(content)
            # <local-command-stdout> is a slash command's own output echoed back,
            # not a new user turn; counting it splits one turn into two.
            if preview.startswith("<local-command-stdout>"):
                preview = ""
            if preview:
                self.ledger.turns.append(_Turn(
                    index=len(self.ledger.turns),
                    prompt_id=prompt_id,
                    uuid=obj.get("uuid"),
                    ts=_parse_ts(obj.get("timestamp")),
                    preview=preview,
                ))
        return prompt_id

    # -- assembly ----------------------------------------------------------

    def _agent_meta(self, path: Path) -> dict:
        meta_path = path.with_name(path.name.replace(".jsonl", ".meta.json"))
        try:
            data = json.loads(meta_path.read_text(encoding="utf-8"))
            return data if isinstance(data, dict) else {}
        except Exception:
            return {}

    def _collect_sources(self) -> List[Tuple[Path, dict]]:
        main = Path(self.ledger.transcript_path)
        out: List[Tuple[Path, dict]] = [(main, {"origin": "main", "agent_id": None,
                                                "agent_type": None, "description": None,
                                                "spawn_depth": 0, "workflow_id": None,
                                                "workflow_label": None})]
        if not self.include_subagents:
            return out
        dirs = paths.session_dirs(main)
        subagents = dirs.get("subagents")
        if not subagents:
            return out

        workflow_agents = self._load_workflows(dirs.get("workflows"))
        try:
            agent_files = sorted(subagents.rglob("agent-*.jsonl"))
        except Exception:
            agent_files = []
        for path in agent_files:
            agent_id = path.name[len("agent-"):-len(".jsonl")]
            meta = self._agent_meta(path)
            # Workflow agents sit under subagents/workflows/wf_<id>/ -- the extra
            # nesting is the thing that is easy to miss and costs 5x accuracy.
            workflow_id = None
            for part in path.parts:
                if part.startswith("wf_"):
                    workflow_id = part
                    break
            journal = workflow_agents.get(agent_id, {})
            source = {
                "origin": "workflow" if workflow_id else "subagent",
                "agent_id": agent_id,
                "agent_type": meta.get("agentType") or journal.get("agentType"),
                "description": meta.get("description") or journal.get("label"),
                "spawn_depth": meta.get("spawnDepth"),
                "tool_use_id": meta.get("toolUseId"),
                "workflow_id": workflow_id,
                "workflow_label": journal.get("label"),
            }
            self.ledger.agents[agent_id] = source
            out.append((path, source))
        return out

    def _load_workflows(self, workflows_dir: Optional[Path]) -> Dict[str, dict]:
        agents: Dict[str, dict] = {}
        if not workflows_dir:
            return agents
        try:
            journals = sorted(workflows_dir.glob("wf_*.json"))
        except Exception:
            return agents
        for journal_path in journals:
            try:
                data = json.loads(journal_path.read_text(encoding="utf-8", errors="replace"))
            except Exception:
                continue
            if not isinstance(data, dict):
                continue
            progress = data.get("workflowProgress") or []
            rows = [row for row in progress if isinstance(row, dict)
                    and row.get("type") == "workflow_agent"]
            for row in rows:
                agent_id = row.get("agentId")
                if agent_id:
                    agents[agent_id] = {
                        "label": row.get("label"),
                        "agentType": "workflow-subagent",
                        "phase": row.get("phaseTitle"),
                        "journal_tokens": _int(row.get("tokens")),
                        "journal_tool_calls": _int(row.get("toolCalls")),
                        "state": row.get("state"),
                        "duration_ms": _int(row.get("durationMs")),
                    }
            self.ledger.workflows.append({
                "workflow_id": journal_path.stem,
                "name": data.get("workflowName"),
                "status": data.get("status"),
                "agent_count": _int(data.get("agentCount")),
                "journal_total_tokens": _int(data.get("totalTokens")),
                "journal_tool_calls": _int(data.get("totalToolCalls")),
                "duration_ms": _int(data.get("durationMs")),
                "summary": data.get("summary"),
                "phases": [p.get("title") for p in (data.get("phases") or [])
                           if isinstance(p, dict)],
            })
        return agents

    def run(self) -> SessionLedger:
        started = time.time()
        for path, source in self._collect_sources():
            self._read_file(path, source)
        self._build_calls()
        self._build_tools()
        self._assign_turns()
        self._finalise()
        self.ledger.load_seconds = time.time() - started
        return self.ledger

    def _build_calls(self) -> None:
        rows: List[ApiCall] = []
        for request_id in self.order:
            record = self.requests[request_id]
            obj = record.obj
            # A transcript line is not a schema. Every one of these fields turns
            # up as the wrong type in a torn or client-synthesised record, and
            # each wrong type raises out of load() if it is not checked here: a
            # string `message` or `usage` -> AttributeError on .get, a dict
            # `speed` -> AttributeError on .lower() inside tier_for, a dict
            # `model` -> TypeError (unhashable) the moment by_model keys on it.
            # load() is called from hooks/session_end.py outside any local try,
            # so one bad line there silently costs the final report, the
            # dashboard refresh and the live-snapshot cleanup.
            message = obj.get("message")
            if not isinstance(message, dict):
                message = {}
            usage = record.usage
            if not isinstance(usage, dict):
                usage = {}
            model = message.get("model")
            model = model if isinstance(model, str) and model else "unknown"
            speed = usage.get("speed")
            speed = speed if isinstance(speed, str) and speed else "standard"
            source = self.sources.get(request_id, {})
            cost = pricing.price(usage, model, speed)
            five, hour = pricing.split_cache_creation(usage)
            details = usage.get("output_tokens_details")
            details = details if isinstance(details, dict) else {}
            server_tools = usage.get("server_tool_use")
            server_tools = server_tools if isinstance(server_tools, dict) else {}
            cache_creation_total = _int(usage.get("cache_creation_input_tokens")) or (five + hour)
            call = ApiCall(
                request_id=request_id,
                uuid=obj.get("uuid"),
                ts=record.ts,
                model=model,
                tier=cost["tier"],
                effort=obj.get("effort"),
                speed=speed,
                service_tier=usage.get("service_tier"),
                origin=source.get("origin", "main"),
                agent_id=source.get("agent_id") or obj.get("agentId"),
                agent_type=source.get("agent_type"),
                agent_description=source.get("description"),
                spawn_depth=source.get("spawn_depth"),
                attribution_skill=obj.get("attributionSkill"),
                attribution_plugin=obj.get("attributionPlugin"),
                attribution_mcp_server=obj.get("attributionMcpServer"),
                prompt_id=source.get("prompt_id"),
                input_tokens=_int(usage.get("input_tokens")),
                output_tokens=_int(usage.get("output_tokens")),
                thinking_tokens=_int(details.get("thinking_tokens") if isinstance(details, dict) else 0),
                cache_write_5m=five,
                cache_write_1h=hour,
                cache_read=_int(usage.get("cache_read_input_tokens")),
                web_search_requests=_int(server_tools.get("web_search_requests")),
                web_fetch_requests=_int(server_tools.get("web_fetch_requests")),
                context_tokens=(_int(usage.get("input_tokens")) + cache_creation_total
                                + _int(usage.get("cache_read_input_tokens"))),
                cost=cost,
                tools=[str(block.get("name")) for block in record.tool_blocks],
                stop_reason=message.get("stop_reason"),
                is_error=record.is_error,
                error_status=record.error_status,
                aborted=record.aborted,
                unpriced=bool(cost.get("unpriced")),
                workflow_id=source.get("workflow_id"),
                workflow_label=source.get("workflow_label"),
            )
            rows.append(call)
        rows.sort(key=lambda c: (c.ts or datetime.min.replace(tzinfo=timezone.utc)))
        self.ledger.calls = rows

    def _build_tools(self) -> None:
        tools: List[ToolCall] = []
        for request_id in self.order:
            record = self.requests[request_id]
            source = self.sources.get(request_id, {})
            for block in record.tool_blocks:
                name = str(block.get("name") or "unknown")
                tool_use_id = block.get("id")
                result = self.tool_results.get(tool_use_id or "", {})
                try:
                    input_bytes = len(json.dumps(block.get("input") or {}))
                except Exception:
                    input_bytes = 0
                span = (_read_span(block.get("input"))
                        if name in READ_TOOLS else (None, None))
                tools.append(ToolCall(
                    name=name,
                    tool_use_id=tool_use_id,
                    ts=record.ts,
                    origin=source.get("origin", "main"),
                    agent_id=source.get("agent_id"),
                    duration_ms=None,
                    is_error=bool(result.get("is_error")),
                    input_bytes=input_bytes,
                    result_bytes=_int(result.get("bytes")),
                    server=_mcp_server(name),
                    request_id=request_id,
                    prompt_id=source.get("prompt_id"),
                    target=_target_of(name, block.get("input")),
                    content_bytes=_int(result.get("content_bytes")),
                    span_lo=span[0],
                    span_hi=span[1],
                ))
        tools.sort(key=lambda t: (t.ts or datetime.min.replace(tzinfo=timezone.utc)))
        self.ledger.tools = tools

    def _assign_turns(self) -> None:
        turns = self.ledger.turns
        if not turns:
            return
        by_prompt = {turn.prompt_id: turn.index for turn in turns if turn.prompt_id}
        starts = [turn.ts or datetime.min.replace(tzinfo=timezone.utc) for turn in turns]
        for call in self.ledger.calls:
            index = by_prompt.get(call.prompt_id) if call.prompt_id else None
            if index is None and call.ts:
                position = bisect_right(starts, call.ts) - 1
                index = turns[position].index if position >= 0 else None
            call.turn_index = index
        turn_of_request = {c.request_id: c.turn_index for c in self.ledger.calls}
        for tool in self.ledger.tools:
            tool.turn_index = turn_of_request.get(tool.request_id)

    def _finalise(self) -> None:
        stamps = [c.ts for c in self.ledger.calls if c.ts]
        turn_stamps = [t.ts for t in self.ledger.turns if t.ts]
        if stamps or turn_stamps:
            self.ledger.started_at = min(stamps + turn_stamps)
            self.ledger.last_activity = max(stamps + turn_stamps)
        if self.ledger.reported:
            start_ms = _int(self.ledger.reported.get("startTime"))
            if start_ms:
                started = datetime.fromtimestamp(start_ms / 1000.0, tz=timezone.utc)
                if self.ledger.started_at is None or started < self.ledger.started_at:
                    self.ledger.started_at = started


def _apply_tool_events(ledger: SessionLedger, events_path: Path) -> None:
    """Fold in the PostToolUse hook's ndjson: it is the only source of per-tool
    wall-clock duration, which no transcript records."""
    try:
        raw_lines = events_path.read_text(encoding="utf-8", errors="replace").splitlines()
    except Exception:
        return
    events: Dict[str, dict] = {}
    for raw in raw_lines:
        raw = raw.strip()
        if not raw:
            continue
        try:
            event = json.loads(raw)
        except Exception:
            continue
        tool_use_id = event.get("tool_use_id")
        if tool_use_id:
            events[tool_use_id] = event
    if not events:
        return
    for tool in ledger.tools:
        event = events.get(tool.tool_use_id or "")
        if not event:
            continue
        if event.get("duration_ms") is not None:
            tool.duration_ms = _int(event.get("duration_ms"))
        if event.get("is_error"):
            tool.is_error = True
        if not tool.result_bytes:
            tool.result_bytes = _int(event.get("result_bytes"))


def _apply_compactions(ledger: SessionLedger) -> None:
    path = paths.compactions_path(ledger.session_id)
    rows: List[dict] = []
    try:
        raw_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except Exception:
        return
    for raw in raw_lines:
        raw = raw.strip()
        if not raw:
            continue
        try:
            row = json.loads(raw)
        except Exception:
            continue
        if isinstance(row, dict):
            rows.append(row)
    if not rows:
        return
    # The transcript is authoritative and is parsed first; the journal only adds
    # compactions the transcript did not record. Appending both double-counted
    # every compaction on any session that ran with the hooks installed.
    known = {_int(r.get("pre_tokens") or r.get("preTokens")) for r in ledger.compactions}
    known.discard(0)
    for row in rows:
        pre = _int(row.get("pre_tokens") or row.get("preTokens"))
        if pre and pre in known:
            continue
        ledger.compactions.append(row)


def load(transcript_path: str | os.PathLike, *, include_subagents: bool = True,
         tool_events_path: Optional[str | os.PathLike] = None) -> SessionLedger:
    """Build a full ledger for one session."""
    path = Path(transcript_path)
    ledger = SessionLedger(path)
    _Loader(ledger, include_subagents).run()
    events = Path(tool_events_path) if tool_events_path else paths.tool_events_path(ledger.session_id)
    if events and Path(events).exists():
        _apply_tool_events(ledger, Path(events))
    _apply_compactions(ledger)
    return ledger


def load_by_session_id(session_id: str, **kwargs) -> Optional[SessionLedger]:
    path = paths.find_transcript(session_id)
    if path is None:
        return None
    return load(path, **kwargs)


# ---------------------------------------------------------------------------
# incremental per-session cost cache
#
# WHY this exists at all: a cheap scan can only take a session's dollars from
# its cost-state lines, and Claude Code writes those as periodic CHECKPOINTS. A
# session that is running right now often has none yet, so `oe watch` and
# `oe sessions` would show $0.00 for exactly the session the user is watching,
# while `oe status` -- which parses the whole transcript -- shows the real
# figure. Same session, two numbers, and the wrong one on the live view.
#
# It has to be cheap: `oe watch` redraws every two seconds. So a session's cost
# is PARSED ONCE and then only extended by the bytes appended since, keyed on a
# fingerprint that covers the main transcript AND every subagent file, including
# the nested subagents/workflows/wf_*/agent-*.jsonl ones -- miss those and a
# session whose agents are still writing silently goes stale.
#
# Resuming from a byte offset is only sound because one requestId's several
# JSONL lines are contiguous within a file and never repeat in another file.
# The offset therefore rewinds to the START of the trailing request block, so
# everything below it is final and the block that is still being written is
# simply re-read next pass.
# ---------------------------------------------------------------------------

# Bump when the shape of a cached entry changes; a mismatch discards the entry.
# 3 adds the per-model split (`models`) that the live view's model line reads.
_COST_CACHE_VERSION = 8

# An idle stretch this long separates two runs of the same transcript. Every
# resume leaves one, and a landmark there records the exact prefix sum at the
# boundary, which is what the covered/uncovered split asks about.
_GAP_SECONDS = 600.0
# A landmark is dropped every this many requests as well, so the bracket around
# any threshold stays narrow and resolving it exactly costs a few kilobytes
# rather than a re-read of the whole file.
_LANDMARK_STRIDE = 64
_MAX_LANDMARKS = 4096

# Bytes of a file's head kept beside its offset. Transcripts are append-only,
# but a file that was REWRITTEN and happens to be larger passes every size
# check, and its new content would then be spliced onto the old file's totals.
_HEAD_SIG_BYTES = 256

# Bytes of not-yet-parsed transcript that ONE scan pass will read for sessions
# that are not currently active. A warm pass reads none of it; only a cold cache
# hits the cap, and the sessions it defers keep the number they already had and
# are picked up by the next pass. Live sessions are never deferred -- their
# number is the whole point of the view.
_COST_BYTES_PER_PASS = 32 * 1024 * 1024

# Byte-mode twins of the line sniffers above. The cost scan must track exact
# byte offsets to resume, so it iterates the file as bytes and decodes only the
# handful of lines it actually needs.
_B_TYPE_RE = re.compile(rb'"type"\s*:\s*"(' + "|".join(_TOP_TYPES).encode() + rb')"')
_B_ROLE_ASSISTANT_RE = re.compile(rb'"role"\s*:\s*"assistant"')
_B_REQUEST_ID_RE = re.compile(rb'"requestId"\s*:\s*"([^"]+)"')
_B_OUTPUT_TOKENS_RE = re.compile(rb'"output_tokens"\s*:\s*(\d+)')

# Local-date bucketing, memoised on a 15-minute grain: every real UTC offset is
# a multiple of 15 minutes, so a bucket never straddles a local midnight.
_LOCAL_DAY_CACHE: Dict[int, str] = {}


def _local_day(epoch: float) -> str:
    """The LOCAL calendar day an epoch second falls in.

    'Today' on the live view has to mean the user's today, not UTC's: at 21:00
    in a UTC-4 zone the two disagree, and the header would silently roll over
    three hours early.
    """
    bucket = int(epoch // 900)
    day = _LOCAL_DAY_CACHE.get(bucket)
    if day is None:
        try:
            day = datetime.fromtimestamp(bucket * 900.0).strftime("%Y-%m-%d")
        except (OverflowError, OSError, ValueError):
            day = "unknown"
        if len(_LOCAL_DAY_CACHE) > 8192:
            _LOCAL_DAY_CACHE.clear()
        _LOCAL_DAY_CACHE[bucket] = day
    return day


def _cost_cache_dir() -> Path:
    return paths.ensure_dir(paths.state_dir() / "cost-cache")


def _cost_cache_path(session_id: str) -> Path:
    return _cost_cache_dir() / f"{paths.safe_session_id(session_id)}.json"


def _new_file_state() -> Dict[str, Any]:
    """Per-file accumulator. Everything here is JSON-serialisable on purpose:
    it round-trips through the cache file between passes."""
    return {
        "size": 0,
        "offset": 0,          # start of the trailing (still-open) request block
        "usd": 0.0,           # committed dollars: requests entirely below offset
        "calls": 0,
        "tokens": 0,
        "unpriced": 0,
        "first_ts": None,
        "last_ts": None,
        "prev_ts": None,
        "gaps": [],           # [gap_end_epoch, cum_usd_before, cum_calls_before]
        "gaps_truncated": False,
        "days": {},           # local day -> computed usd
        # "<model>\t<speed>" -> [usd, calls, tokens]. The live view names the
        # model in use and prints ITS cost, which no aggregate total can answer:
        # a session that switched from Opus to Haiku, or one whose subagents run
        # a different model, has two bills inside one number.
        "models": {},
        "pending": None,      # the trailing request, re-read every pass
        # main-transcript only
        # str(startTime) -> [totalDuration, totalCostUSD, billed_through_epoch].
        # The third element is the newest request timestamp seen in this file
        # above the checkpoint, i.e. how far the run is actually billed.
        "runs": {},
        "title": None,
        "prompt": None,
        "slug": None,
        "context_tokens": 0,
        "context_model": None,
        "context_speed": None,   # usage.speed of the newest main-line request
        "context_effort": None,  # top-level `effort` of the newest main line
    }


def _price_usage(message: dict, usage: dict) -> Tuple[float, int, bool, str]:
    """(usd, tokens, unpriced, model) for one request's best usage snapshot.

    Deliberately the same three calls the full loader makes -- pricing.price,
    split_cache_creation and the same token sum -- so the cheap path and
    `oe status` cannot drift apart on arithmetic.
    """
    model = message.get("model")
    model = model if isinstance(model, str) and model else "unknown"
    speed = usage.get("speed")
    speed = speed if isinstance(speed, str) and speed else "standard"
    cost = pricing.price(usage, model, speed)
    five, hour = pricing.split_cache_creation(usage)
    tokens = (_int(usage.get("input_tokens")) + _int(usage.get("output_tokens"))
              + five + hour + _int(usage.get("cache_read_input_tokens")))
    return float(cost.get("total_usd") or 0.0), tokens, bool(cost.get("unpriced")), model


def _scan_cost_file(path: Path, state: Dict[str, Any], size: int,
                    is_main: bool) -> Dict[str, Any]:
    """Fold the bytes appended to `path` since the last pass into `state`.

    Returns the updated state. Never raises: a torn line, a vanished file or a
    truncated transcript degrades to "what we had", because this runs inside a
    two-second redraw loop where an exception is a blank screen.
    """
    start = _int(state.get("offset"))
    if size < _int(state.get("size")) or start > size:
        # Truncated or replaced underneath us -- every offset we hold is
        # meaningless, so re-read from the top rather than splice new bytes onto
        # a total that describes a file that no longer exists.
        state = _new_file_state()
        start = 0
    try:
        handle = open(path, "rb")
    except OSError:
        return state
    with handle:
        try:
            head = handle.read(_HEAD_SIG_BYTES).hex()
        except OSError:
            return state
        # Growing is not the same as appending. A transcript rewritten in place
        # with MORE bytes passes every size check and then splices the new
        # content onto totals that describe the old, so anchor the offset to the
        # bytes it was measured against.
        if start and state.get("head") and state.get("head") != head:
            state = _new_file_state()
            start = 0
        state["head"] = head
        state["size"] = size
        if start >= size:
            return state
        return _scan_cost_lines(handle, state, start, is_main)


def _scan_cost_lines(handle, state: Dict[str, Any], start: int,
                     is_main: bool) -> Dict[str, Any]:
    """The line loop of _scan_cost_file, split out so the integrity checks above
    it can reset the state before any accumulator is read."""
    usd = _float(state.get("usd"))
    calls = _int(state.get("calls"))
    tokens = _int(state.get("tokens"))
    unpriced = _int(state.get("unpriced"))
    first_ts = state.get("first_ts")
    last_ts = state.get("last_ts")
    prev_ts = state.get("prev_ts")
    gaps: List[list] = list(state.get("gaps") or [])
    gaps_truncated = bool(state.get("gaps_truncated"))
    days: Dict[str, float] = dict(state.get("days") or {})
    models: Dict[str, list] = {key: list(value) for key, value
                               in (state.get("models") or {}).items()
                               if isinstance(value, list) and len(value) >= 3}
    runs: Dict[str, list] = dict(state.get("runs") or {})

    # The trailing request block is re-read from `offset` every pass, so the
    # stored copy is rebuilt rather than trusted.
    cur_rid: Optional[str] = None
    cur_best = -1
    cur_usd = 0.0
    cur_tokens = 0
    cur_unpriced = False
    cur_model: Optional[str] = None
    cur_speed: Optional[str] = None
    cur_ts: Optional[float] = None
    cur_off = start

    def commit() -> None:
        nonlocal usd, calls, tokens, unpriced, first_ts, last_ts, prev_ts, gaps_truncated
        if cur_ts is not None:
            if first_ts is None:
                first_ts = cur_ts
            gap = prev_ts is not None and (cur_ts - prev_ts) > _GAP_SECONDS
            if gap or calls % _LANDMARK_STRIDE == 0:
                # A prefix-sum sample: (when, dollars and calls BEFORE this
                # request, and the byte at which it starts). Resume boundaries
                # always get one; the periodic ones keep the bracket around any
                # later question narrow enough to resolve by re-reading a few KB.
                if len(gaps) < _MAX_LANDMARKS:
                    gaps.append([cur_ts, usd, calls, cur_off])
                else:
                    gaps_truncated = True
            prev_ts = cur_ts
            last_ts = cur_ts if last_ts is None else max(last_ts, cur_ts)
            day = _local_day(cur_ts)
            days[day] = days.get(day, 0.0) + cur_usd
        usd += cur_usd
        calls += 1
        tokens += cur_tokens
        if cur_unpriced:
            unpriced += 1
        key = f"{cur_model or 'unknown'}\t{cur_speed or 'standard'}"
        bucket = models.get(key)
        if bucket is None:
            models[key] = [cur_usd, 1, cur_tokens]
        else:
            bucket[0] += cur_usd
            bucket[1] += 1
            bucket[2] += cur_tokens

    pos = start
    try:
        handle.seek(start)
        for raw in handle:
            line_start = pos
            if not raw.endswith(b"\n"):
                # A half-written final line: leave it unconsumed so the next
                # pass sees it whole instead of billing a torn record.
                break
            pos += len(raw)
            if len(raw) < 12:
                continue
            match = _B_TYPE_RE.search(raw, 0, 600)
            if match:
                kind = match.group(1)
            elif _B_ROLE_ASSISTANT_RE.search(raw, 0, 900):
                kind = b"assistant"
            else:
                continue
            if kind == b"assistant":
                # The several lines of one request repeat the same usage (main
                # transcript) or a growing snapshot (sidechain), and only a
                # LARGER output snapshot can change anything. Reading the two
                # fields that decide that straight out of the bytes skips a
                # json.loads of a large thinking block on most assistant lines,
                # which is most of the cost of priming a big session.
                if cur_rid is not None:
                    same = _B_REQUEST_ID_RE.search(raw)
                    if same is not None and same.group(1).decode("utf-8", "replace") == cur_rid:
                        seen_output = _B_OUTPUT_TOKENS_RE.search(raw)
                        if seen_output is not None and int(seen_output.group(1)) <= cur_best:
                            continue
                try:
                    obj = json.loads(raw)
                except Exception:
                    continue
                if not isinstance(obj, dict):
                    continue
                # A user line quoting "role":"assistant" inside a tool_result
                # sniffs as assistant; the parsed object knows better.
                top = obj.get("type")
                if top is not None and top != "assistant":
                    continue
                message = obj.get("message")
                if not isinstance(message, dict):
                    message = {}
                usage = message.get("usage")
                if not isinstance(usage, dict):
                    usage = {}
                request_id = obj.get("requestId") or f"uuid:{obj.get('uuid')}"
                if request_id != cur_rid:
                    if cur_rid is not None:
                        commit()
                    cur_rid = request_id
                    cur_best = -1
                    cur_usd = 0.0
                    cur_tokens = 0
                    cur_unpriced = False
                    cur_model = None
                    cur_speed = None
                    cur_off = line_start
                    stamp = _parse_ts(obj.get("timestamp"))
                    cur_ts = stamp.timestamp() if stamp else None
                output = _int(usage.get("output_tokens"))
                if output > cur_best:
                    # Sidechain lines carry a GROWING mid-stream snapshot and
                    # the final one is never written back, so the largest is
                    # the closest this file gets to the truth.
                    cur_best = output
                    cur_usd, cur_tokens, cur_unpriced, cur_model = _price_usage(
                        message, usage)
                    # `speed` decides the tier (fast Opus is 30/150, not 5/25),
                    # so the model bucket has to be keyed by it too or a fast
                    # burst is averaged into the standard row and disappears.
                    speed = usage.get("speed")
                    cur_speed = speed if isinstance(speed, str) and speed else "standard"
                if is_main and not obj.get("isSidechain"):
                    state["slug"] = obj.get("slug") or state.get("slug")
                    if usage:
                        # Exactly context_window_state's formula, including
                        # its fallback for a missing flat cache_creation.
                        creation = _int(usage.get("cache_creation_input_tokens"))
                        if not creation:
                            five, hour = pricing.split_cache_creation(usage)
                            creation = five + hour
                        state["context_tokens"] = (
                            _int(usage.get("input_tokens")) + creation
                            + _int(usage.get("cache_read_input_tokens")))
                        state["context_model"] = cur_model or state.get("context_model")
                        state["context_speed"] = cur_speed or state.get("context_speed")
                    # `effort` is a TOP-LEVEL field on the assistant record, not
                    # part of usage, and it is what the user actually chose.
                    effort = obj.get("effort")
                    if isinstance(effort, str) and effort:
                        state["context_effort"] = effort
            elif not is_main:
                continue
            elif kind == b"cost-state":
                try:
                    cost_state = json.loads(raw)
                except Exception:
                    continue
                if not isinstance(cost_state, dict):
                    continue
                # Per RUN, not per file: a resume restarts the accumulator
                # under a new startTime, so keep each run's latest checkpoint
                # and sum them. Same rule as SessionLedger.runs.
                key = str(_int(cost_state.get("startTime")))
                previous = runs.get(key)
                duration = _int(cost_state.get("totalDuration"))
                if previous is None or duration >= _int(previous[0]):
                    # Third element: how far this checkpoint is billed. A
                    # checkpoint accounts for everything written above it, so
                    # that is the newest request timestamp parsed so far in
                    # this file -- `cur_ts` while a request block is still
                    # open, otherwise the last one committed.
                    runs[key] = [duration, _float(cost_state.get("totalCostUSD")),
                                 cur_ts if cur_ts is not None else last_ts]
            elif kind == b"ai-title":
                try:
                    state["title"] = (json.loads(raw) or {}).get("aiTitle") or state.get("title")
                except Exception:
                    pass
            elif kind == b"last-prompt":
                try:
                    state["prompt"] = ((json.loads(raw) or {}).get("lastPrompt")
                                       or state.get("prompt"))
                except Exception:
                    pass
    except OSError:
        pass

    state["usd"] = usd
    state["calls"] = calls
    state["tokens"] = tokens
    state["unpriced"] = unpriced
    state["first_ts"] = first_ts
    state["last_ts"] = last_ts
    state["prev_ts"] = prev_ts
    state["gaps"] = gaps
    state["gaps_truncated"] = gaps_truncated or bool(state.get("gaps_truncated"))
    state["days"] = days
    state["models"] = models
    state["runs"] = runs
    if cur_rid is not None:
        # Everything below cur_off is final; the open block is re-read next pass.
        state["offset"] = cur_off
        state["pending"] = {"usd": cur_usd, "tokens": cur_tokens, "ts": cur_ts,
                            "unpriced": cur_unpriced, "model": cur_model,
                            "speed": cur_speed}
    else:
        state["offset"] = pos
        state["pending"] = None
    return state


def _uncovered_of_file(path: Path, state: Dict[str, Any],
                       threshold: float) -> Tuple[float, int]:
    """(usd, calls) of this file's requests that predate `threshold`, exactly.

    This is the "resumed session" split: a transcript can hold several runs, and
    only the runs Claude Code checkpointed have a reported number, so everything
    older has to be added at OUR measured price. Getting it wrong is not
    cosmetic: when the earliest checkpoint starts hours into the file, a
    landmark-only estimate lands well under the real figure.

    Landmarks bracket the threshold; the residue between the last landmark below
    it and the threshold itself is resolved by re-reading those few kilobytes.
    The answer is memoised against the threshold that produced it, because the
    earliest run start of a transcript never moves.
    """
    pending = state.get("pending") or {}
    # last_ts only advances when a request block is COMMITTED, and the trailing
    # block of a live transcript is never committed -- it is re-read every pass.
    # Leaving it out of this bound is not cosmetic: it is the newest request in
    # the file, so on a session that has checkpointed and kept working the
    # "everything is below the threshold" shortcut fires, the request in flight
    # is filed as covered, and the headline sticks at the stale checkpoint. Made
    # visible by a 4-requests / checkpoint / 1-request transcript whose live
    # path read 1% under what the full pass billed -- the request in flight.
    last_ts = state.get("last_ts")
    pending_ts = pending.get("ts")
    if pending_ts is not None:
        last_ts = pending_ts if last_ts is None else max(last_ts, pending_ts)
    if last_ts is None:
        return 0.0, 0
    total_usd = _float(state.get("usd")) + _float(pending.get("usd"))
    total_calls = _int(state.get("calls")) + (1 if state.get("pending") else 0)
    if last_ts < threshold:
        return total_usd, total_calls
    first_ts = state.get("first_ts")
    if first_ts is None:
        first_ts = pending_ts
    if first_ts is not None and first_ts >= threshold:
        return 0.0, 0

    # Keyed by threshold: this is now asked TWO questions per pass (the left and
    # the right edge of the checkpoint window), and a single-slot memo would
    # thrash between them and re-read the file on every redraw.
    memo = state.get("uncovered")
    if isinstance(memo, list) and len(memo) == 3 and memo[0] == threshold:
        memo = {repr(threshold): [memo[1], memo[2]]}   # migrate the v3 shape
        state["uncovered"] = memo
    if not isinstance(memo, dict):
        memo = {}
    hit = memo.get(repr(threshold))
    if isinstance(hit, list) and len(hit) == 2:
        return _float(hit[0]), _int(hit[1])

    base_usd, base_calls, base_offset = 0.0, 0, 0
    for landmark in state.get("gaps") or []:
        try:
            stamp, cum_usd, cum_calls, offset = (landmark[0], landmark[1],
                                                 landmark[2], landmark[3])
        except (IndexError, TypeError):
            continue
        if stamp is not None and stamp < threshold:
            base_usd, base_calls, base_offset = _float(cum_usd), _int(cum_calls), _int(offset)
        else:
            break
    extra_usd, extra_calls = _sum_requests_before(path, base_offset, threshold)
    result = (base_usd + extra_usd, base_calls + extra_calls)
    if len(memo) > 8:
        memo.clear()
    memo[repr(threshold)] = [result[0], result[1]]
    state["uncovered"] = memo
    return result


def _sum_requests_before(path: Path, start: int,
                         threshold: float) -> Tuple[float, int]:
    """Cost of the requests from byte `start` up to the first one at or after
    `threshold`. Requests are chronological within a file, so the first request
    that reaches the threshold ends the walk."""
    usd = 0.0
    calls = 0
    cur_rid: Optional[str] = None
    cur_best = -1
    cur_usd = 0.0
    cur_ts: Optional[float] = None
    try:
        handle = open(path, "rb")
    except OSError:
        return 0.0, 0
    with handle:
        try:
            handle.seek(start)
            for raw in handle:
                if len(raw) < 12 or not raw.endswith(b"\n"):
                    continue
                match = _B_TYPE_RE.search(raw, 0, 600)
                if match:
                    if match.group(1) != b"assistant":
                        continue
                elif not _B_ROLE_ASSISTANT_RE.search(raw, 0, 900):
                    continue
                try:
                    obj = json.loads(raw)
                except Exception:
                    continue
                if not isinstance(obj, dict):
                    continue
                top = obj.get("type")
                if top is not None and top != "assistant":
                    continue
                message = obj.get("message")
                if not isinstance(message, dict):
                    message = {}
                usage = message.get("usage")
                if not isinstance(usage, dict):
                    usage = {}
                request_id = obj.get("requestId") or f"uuid:{obj.get('uuid')}"
                if request_id != cur_rid:
                    if cur_rid is not None:
                        usd += cur_usd
                        calls += 1
                    stamp = _parse_ts(obj.get("timestamp"))
                    cur_ts = stamp.timestamp() if stamp else None
                    if cur_ts is not None and cur_ts >= threshold:
                        return usd, calls
                    cur_rid = request_id
                    cur_best = -1
                    cur_usd = 0.0
                output = _int(usage.get("output_tokens"))
                if output > cur_best:
                    cur_best = output
                    cur_usd = _price_usage(message, usage)[0]
        except OSError:
            pass
    if cur_rid is not None:
        usd += cur_usd
        calls += 1
    return usd, calls


def _settle(rows: List[Dict[str, Any]], field: str, target: float) -> None:
    """Push the rounding residue onto the largest row so the parts sum to the
    whole exactly. No-op when there are no rows to carry it."""
    if not rows:
        return
    residue = round(target - sum(_float(row.get(field)) for row in rows), 6)
    if residue:
        rows[0][field] = round(_float(rows[0].get(field)) + residue, 6)


def _settle_map(values: Dict[str, float], target: float) -> None:
    """_settle for a {key: usd} mapping; the residue lands on the largest key."""
    if not values:
        return
    residue = round(target - sum(_float(v) for v in values.values()), 6)
    if residue:
        key = max(values, key=lambda k: _float(values[k]))
        values[key] = round(_float(values[key]) + residue, 6)


def _derive_cost(states: List[Tuple[Path, Dict[str, Any]]],
                 main: Dict[str, Any]) -> Dict[str, Any]:
    """Turn per-file accumulators into the row's cost block.

    The headline is Claude Code's own dollars wherever a checkpoint accounts for
    them and ours everywhere else, and it says which -- never silently mixed.
    """
    computed = 0.0
    calls = 0
    tokens = 0
    unpriced = 0
    days: Dict[str, float] = {}
    models: Dict[str, List[float]] = {}
    first_ts: Optional[float] = None
    last_ts: Optional[float] = None

    def _fold_model(key: str, usd: float, count: int, token_count: int) -> None:
        bucket = models.get(key)
        if bucket is None:
            models[key] = [usd, float(count), float(token_count)]
        else:
            bucket[0] += usd
            bucket[1] += count
            bucket[2] += token_count

    for _path, state in states:
        pending = state.get("pending") or {}
        computed += _float(state.get("usd")) + _float(pending.get("usd"))
        calls += _int(state.get("calls")) + (1 if state.get("pending") else 0)
        tokens += _int(state.get("tokens")) + _int(pending.get("tokens"))
        unpriced += _int(state.get("unpriced")) + (1 if pending.get("unpriced") else 0)
        for day, value in (state.get("days") or {}).items():
            days[day] = days.get(day, 0.0) + _float(value)
        for key, value in (state.get("models") or {}).items():
            if isinstance(value, list) and len(value) >= 3:
                _fold_model(key, _float(value[0]), _int(value[1]), _int(value[2]))
        if state.get("pending"):
            # The still-open trailing block is counted in the totals above, so it
            # has to be counted here too or the model rows quietly sum to less
            # than the headline on every actively-writing session.
            _fold_model(f"{pending.get('model') or 'unknown'}\t"
                        f"{pending.get('speed') or 'standard'}",
                        _float(pending.get("usd")), 1, _int(pending.get("tokens")))
        if pending.get("ts") is not None:
            day = _local_day(_float(pending.get("ts")))
            days[day] = days.get(day, 0.0) + _float(pending.get("usd"))
        start = state.get("first_ts")
        if start is not None:
            first_ts = start if first_ts is None else min(first_ts, start)
        end = state.get("last_ts")
        if end is not None:
            last_ts = end if last_ts is None else max(last_ts, end)

    runs = main.get("runs") or {}
    reported: Optional[float] = None
    window_start: Optional[float] = None
    window_end: Optional[float] = None
    if runs:
        reported = sum(_float(row[1]) for row in runs.values() if isinstance(row, list))
        starts = [int(key) for key in runs if key.isdigit() and int(key) > 0]
        if starts:
            window_start = min(starts) / 1000.0 - _RUN_START_GRACE.total_seconds()
            # A checkpoint is a SNAPSHOT, so it bounds the covered window on the
            # RIGHT as well -- that is what makes a live session's requests since
            # the last checkpoint visible instead of being billed at a stale
            # figure. The edge is each run's billed-through mark: the newest
            # request written ABOVE its newest checkpoint.
            #
            # NOT start_time + totalDuration. totalDuration is accumulated
            # ACTIVE time, not elapsed wall clock, so on any session with idle
            # gaps that edge lands early, declares already-billed requests
            # uncovered, and prices them a second time on top of the reported
            # total.
            ends = [row[2] for row in runs.values()
                    if isinstance(row, list) and len(row) > 2 and row[2]]
            # +EPS, not +grace: _uncovered_of_file counts requests STRICTLY
            # before the threshold, so the epsilon keeps the marked request on
            # the covered side while everything after it is uncovered. This is
            # the same edge _coverage() applies, which is what keeps `oe watch`
            # and `oe status` on the same number.
            end = max(ends) + _RIGHT_EDGE_EPS if ends else None
            # No mark means nothing to bound the right side with (an entry from
            # an older cache, or a checkpoint with no request above it). Leave
            # the window open rather than guess: an open right edge can only
            # under-report a resumed-away tail, while a guessed one double-counts
            # money Claude Code has already billed.
            # Same rule as _coverage(): a checkpoint with no main-loop request
            # after it in the file was written last and covers the whole tree,
            # sidechain flushes included.
            if end is not None and ends:
                main_last = main.get("last_ts")
                main_pending_ts = (main.get("pending") or {}).get("ts")
                if main_pending_ts is not None:
                    main_last = (main_pending_ts if main_last is None
                                 else max(main_last, main_pending_ts))
                if main_last is not None and main_last <= max(ends):
                    end = None
            if end is not None and end > window_start:
                window_end = end

    uncovered_usd = 0.0
    uncovered_calls = 0
    if reported is not None and window_start is not None:
        for path, state in states:
            part_usd, part_calls = _uncovered_of_file(path, state, window_start)
            uncovered_usd += part_usd
            uncovered_calls += part_calls
            if window_end is not None:
                # Requests after the window: everything in the file minus the
                # part that precedes the right edge. Same landmark machinery, so
                # this stays a few-KB re-read rather than a second full parse.
                total_usd = (_float(state.get("usd"))
                             + _float((state.get("pending") or {}).get("usd")))
                total_calls = _int(state.get("calls")) + (1 if state.get("pending") else 0)
                before_usd, before_calls = _uncovered_of_file(path, state, window_end)
                uncovered_usd += max(0.0, total_usd - before_usd)
                uncovered_calls += max(0, total_calls - before_calls)

    if reported is None:
        # No checkpoint anywhere in the file. Our measured number is all there
        # is, and it is a floor: sidechain transcripts never persist the final
        # message_delta usage, so subagent-heavy sessions land 8-25% under
        # Claude Code's own figure. Say estimate, never a bare zero.
        total = computed
        source = "computed"
        # ...except when there is nothing to estimate. A transcript with zero
        # requests cost exactly zero, and marking that "~$0.00" would claim a
        # floor on a number that has no error bar at all.
        estimate = calls > 0
    elif uncovered_calls:
        total = reported + uncovered_usd
        source = "mixed"
        estimate = True
    else:
        total = reported
        source = "reported"
        estimate = False

    # A run can start before its first billed request (and a resumed transcript's
    # earliest run is older than any call still in the file), so the session
    # began at whichever came first -- the same rule _finalise() applies.
    started = first_ts
    if runs:
        earliest = min((int(key) / 1000.0 for key in runs if key.lstrip("-").isdigit()
                        and int(key) > 0), default=None)
        if earliest is not None:
            started = earliest if started is None else min(started, earliest)

    # Per-day attribution is measured in OUR dollars; rescale it so the days sum
    # to the headline instead of quietly disagreeing with it.
    scale = (total / computed) if computed > 0 else 1.0
    headline = round(total, 6)
    by_day = {day: round(value * scale, 6) for day, value in sorted(days.items())}
    # Same rescale for the model split, and for the same reason: the parts are
    # measured, the headline may be billed, and a live view that shows both must
    # not let them contradict each other by 8-25%.
    by_model = []
    for key, value in models.items():
        model, _, speed = key.partition("\t")
        by_model.append({
            "model": model,
            "speed": speed or "standard",
            "cost_usd": round(value[0] * scale, 6),
            "calls": int(value[1]),
            "tokens": int(value[2]),
        })
    by_model.sort(key=lambda row: (-row["cost_usd"], row["model"]))
    # Rounding each part to six places leaves a residue of up to a few
    # micro-dollars against the headline. It is invisible at two decimals, but
    # the UI prints the parts directly under the whole and a reader is entitled
    # to add them up, so the residue goes on the largest row rather than being
    # left to contradict the total.
    _settle(by_model, "cost_usd", headline)
    _settle_map(by_day, headline)

    return {
        "cost_usd": headline,
        "cost_source": source,
        "cost_is_estimate": estimate,
        "cost_known": True,
        "cost_computed_usd": round(computed, 6),
        "cost_reported_usd": round(reported, 6) if reported is not None else None,
        "cost_uncovered_usd": round(uncovered_usd, 6),
        "uncovered_calls": uncovered_calls,
        "runs": len(runs),
        "cost_by_day": by_day,
        "cost_by_model": by_model,
        "calls": calls,
        "calls_partial": False,
        "total_tokens": tokens,
        "unpriced_calls": unpriced,
        "first_ts": first_ts,
        "last_ts": last_ts,
        "context_tokens": _int(main.get("context_tokens")),
        "model": main.get("context_model"),
        "speed": main.get("context_speed"),
        "effort": main.get("context_effort"),
        "title": main.get("title") or (str(main.get("prompt"))[:120]
                                       if main.get("prompt") else None),
        "slug": main.get("slug"),
        "started_at": _iso(datetime.fromtimestamp(started, tz=timezone.utc))
        if started else None,
    }


def _session_files(transcript: Path) -> List[Tuple[str, Path, int, int]]:
    """(key, path, size, mtime_ns) for the main transcript and every agent file.

    The nested subagents/workflows/wf_*/agent-*.jsonl files are included because
    they usually hold MOST of a session's spend -- one session here has 11 agent
    files at the documented path and 227 nested ones -- and because a session
    whose agents are still writing must invalidate on their bytes, not just on
    the main transcript's.
    """
    out: List[Tuple[str, Path, int, int]] = []
    try:
        stat = transcript.stat()
        out.append(("main", transcript, stat.st_size, stat.st_mtime_ns))
    except OSError:
        return out
    subagents = paths.session_dirs(transcript).get("subagents")
    if not subagents:
        return out
    try:
        agent_files = sorted(subagents.rglob("agent-*.jsonl"))
    except Exception:
        return out
    for path in agent_files:
        try:
            stat = path.stat()
        except OSError:
            continue
        out.append((str(path), path, stat.st_size, stat.st_mtime_ns))
    return out


def _tz_key() -> str:
    """Identity of the local timezone, for the cost cache.

    `cost_by_day` is bucketed in LOCAL time and then cached, so a cache primed
    under one zone answers a different question than the one the reader is
    asking: prime it under TZ=Etc/GMT-14, read it back under a western zone, and
    the live session's dollars sit in a bucket labelled tomorrow, so
    `spend_today` reports nothing while a session is actively spending. That is
    the header defect this cache key exists to prevent.

    A DST transition does NOT belong in this key: _local_day resolves each epoch
    against the offset in force AT that epoch, so a bucket computed in August is
    still right in December. Only changing the zone itself invalidates them.
    """
    return f"{time.timezone}/{time.altzone}/{'|'.join(time.tzname)}"


def _read_cost_cache(session_id: str) -> Optional[Dict[str, Any]]:
    try:
        payload = json.loads(_cost_cache_path(session_id).read_text(encoding="utf-8"))
    except Exception:
        return None
    if not isinstance(payload, dict):
        return None
    if payload.get("version") != _COST_CACHE_VERSION:
        return None
    if payload.get("pricing_version") != pricing.PRICING_SOURCE_VERSION:
        # Re-priced table: every cached dollar was computed with the old rates.
        return None
    if payload.get("tz") != _tz_key():
        return None
    return payload


def _write_cost_cache(session_id: str, payload: Dict[str, Any]) -> None:
    try:
        paths.atomic_write(_cost_cache_path(session_id),
                           json.dumps(payload, separators=(",", ":")))
    except Exception:
        pass  # a cache that cannot be written must not break the scan


def session_cost(transcript: Path, *, budget: Optional[List[int]] = None,
                 active: bool = False) -> Optional[Dict[str, Any]]:
    """A trustworthy cost block for one session, computed once and then extended.

    `budget` is [bytes remaining, bytes already read] for the current scan pass,
    mutated in place, so one pass cannot spend unbounded time priming a cold
    cache. Active sessions ignore it: their number is the reason the view
    exists.

    A block with `deferred` set carries no cost: the session has never been
    costed and this pass had no budget left for it, so the caller falls back to
    whatever the old cheap path can say and the next pass fills it in.
    """
    session_id = transcript.stem
    files = _session_files(transcript)
    if not files:
        return None
    fingerprint = [[key, size, mtime] for key, _path, size, mtime in files]
    # The newest write ANYWHERE in the session, agent files included. The main
    # transcript alone is a poor liveness signal: while a subagent runs, only
    # its own file grows, and a session in the middle of a long fan-out looks
    # dead for as long as the fan-out lasts.
    last_mtime = max((mtime for _k, _p, _s, mtime in files), default=0) / 1e9

    cached = _read_cost_cache(session_id)
    if cached and cached.get("fingerprint") == fingerprint:
        block = cached.get("cost")
        if isinstance(block, dict):
            block = dict(block)
            block["cost_cached"] = True
            block["last_mtime"] = last_mtime
            return block

    states: Dict[str, Dict[str, Any]] = {}
    if cached and isinstance(cached.get("files"), dict):
        states = cached["files"]

    pending_bytes = 0
    for key, _path, size, _mtime in files:
        state = states.get(key) or {}
        offset = _int(state.get("offset"))
        pending_bytes += max(0, size - offset) if size >= _int(state.get("size")) else size
    # Defer when this session does not fit what is LEFT of the pass -- unless the
    # pass has not read anything yet, in which case it goes ahead however big it
    # is. Comparing size against the remaining budget alone starves any session
    # larger than the whole budget forever; ignoring the remainder instead lets
    # one pass overshoot by a whole transcript on top of a full budget, which is
    # a visibly slow redraw.
    if not active and budget is not None and pending_bytes:
        spent = budget[1] if len(budget) > 1 else 0
        if pending_bytes > budget[0] and spent > 0:
            if cached and isinstance(cached.get("cost"), dict):
                block = dict(cached["cost"])
                block["cost_cached"] = True
                block["cost_stale"] = True
                block["last_mtime"] = last_mtime
                return block
            # Nothing to serve, but the caller still needs the session-wide
            # mtime: it is what tells a report cache whether a subagent has
            # written since, and what decides whether this session is live.
            return {"deferred": True, "last_mtime": last_mtime}
    if budget is not None:
        budget[0] -= pending_bytes
        if len(budget) > 1:
            budget[1] += pending_bytes

    ordered: List[Tuple[Path, Dict[str, Any]]] = []
    main_state: Optional[Dict[str, Any]] = None
    for key, path, size, _mtime in files:
        state = states.get(key)
        if not isinstance(state, dict):
            state = _new_file_state()
        else:
            base = _new_file_state()
            base.update(state)
            state = base
        state = _scan_cost_file(path, state, size, key == "main")
        states[key] = state
        ordered.append((path, state))
        if key == "main":
            main_state = state
    # A file that disappeared (an agent dir pruned) must leave the cache too, or
    # its dollars outlive the transcript they came from.
    live_keys = {key for key, _p, _s, _m in files}
    states = {key: value for key, value in states.items() if key in live_keys}

    block = _derive_cost(ordered, main_state or _new_file_state())
    _write_cost_cache(session_id, {
        "version": _COST_CACHE_VERSION,
        "pricing_version": pricing.PRICING_SOURCE_VERSION,
        "tz": _tz_key(),
        "session_id": session_id,
        "transcript_path": str(transcript),
        "fingerprint": fingerprint,
        "files": states,
        "cost": block,
        "updated_at": _iso(_now()),
    })
    result = dict(block)
    result["cost_cached"] = False
    result["last_mtime"] = last_mtime
    return result


# ---------------------------------------------------------------------------
# cheap cross-session scan
# ---------------------------------------------------------------------------


def _tail(path: Path, size: int) -> List[str]:
    """Last complete lines of a file without reading the whole thing."""
    try:
        total = path.stat().st_size
        with open(path, "rb") as handle:
            if total > size:
                handle.seek(total - size)
                chunk = handle.read()
                newline = chunk.find(b"\n")
                chunk = chunk[newline + 1:] if newline >= 0 else chunk
            else:
                chunk = handle.read()
    except OSError:
        return []
    return chunk.decode("utf-8", errors="replace").splitlines()


def _head_timestamp(path: Path, size: int) -> Optional[datetime]:
    try:
        with open(path, "rb") as handle:
            chunk = handle.read(size)
    except OSError:
        return None
    match = _TS_RE.search(chunk.decode("utf-8", errors="replace"))
    return _parse_ts(match.group(1)) if match else None


# data.json for a heavy session runs to several MB. scan_sessions() visits
# every transcript on the machine, so parsing those would make the dashboard
# cost more than the reports it links to; past this size we tail instead.
_MAX_CACHE_BYTES = 4 * 1024 * 1024


def _row_from_cost(transcript: Path, cost: Dict[str, Any]) -> Dict[str, Any]:
    """A scan row whose dollars come from the incremental cost cache.

    This is the path every session takes now. The three fields a consumer must
    read before printing a number are cost_source, cost_is_estimate and
    uncovered_calls: 'reported' is Claude Code's own accounting and exact,
    'mixed' is that plus our measured price for the runs it never checkpointed,
    and 'computed' is ours alone -- a FLOOR, because sidechain transcripts never
    persist the final message_delta usage.
    """
    model = cost.get("model")
    return {
        "session_id": transcript.stem,
        "project": paths.project_of(transcript),
        "slug": cost.get("slug"),
        "title": cost.get("title"),
        "transcript_path": str(transcript),
        "context_tokens": _int(cost.get("context_tokens")),
        "max_tokens": pricing.context_window(model),
        "cost_usd": _float(cost.get("cost_usd")),
        "cost_known": True,
        "cost_partial": False,
        "cost_source": cost.get("cost_source"),
        "cost_is_estimate": bool(cost.get("cost_is_estimate")),
        "cost_computed_usd": _float(cost.get("cost_computed_usd")),
        "cost_reported_usd": cost.get("cost_reported_usd"),
        "cost_uncovered_usd": _float(cost.get("cost_uncovered_usd")),
        "uncovered_calls": _int(cost.get("uncovered_calls")),
        "cost_runs": _int(cost.get("runs")),
        "cost_by_day": cost.get("cost_by_day") or {},
        "cost_by_model": cost.get("cost_by_model") or [],
        "cost_cached": bool(cost.get("cost_cached")),
        "cost_stale": bool(cost.get("cost_stale")),
        "unpriced_calls": _int(cost.get("unpriced_calls")),
        "total_tokens": _int(cost.get("total_tokens")),
        "model": model,
        "speed": cost.get("speed"),
        "effort": cost.get("effort"),
        "calls": _int(cost.get("calls")),
        "calls_partial": False,
        "started_at": cost.get("started_at"),
        "source": "cost-cache",
    }


def _row_from_live(transcript: Path, newer_than: float = 0.0) -> Optional[Dict[str, Any]]:
    """Prefer the watcher's live snapshot: kilobytes, and never stale.

    It is written after every tick, so for any session with a watcher it is
    both cheaper to read than data.json and more current than the tail scan.

    Only reached when the cost cache could not answer, which is why its cost is
    still read here -- but the caller marks it as unverified, because a snapshot
    written by a watcher that has since died is exactly the stale number this
    module now exists to stop showing.
    """
    live_path = paths.live_snapshot_path(transcript.stem)
    try:
        # `newer_than` is the newest write anywhere in the session, agent files
        # included. Comparing against the main transcript alone calls a snapshot
        # fresh while a subagent is still appending millions of tokens under it.
        if live_path.stat().st_mtime < max(transcript.stat().st_mtime, newer_than):
            return None
        payload = json.loads(live_path.read_text(encoding="utf-8"))
    except Exception:
        return None
    if not isinstance(payload, dict) or not payload.get("session_id"):
        return None
    totals = payload.get("totals") or {}
    session = payload.get("session") or {}
    # Two writers publish this file: watcher.live_payload() (flat
    # context_used_tokens/context_max_tokens) and statusline.snapshot_payload()
    # (nested context_window{used_tokens,max_tokens}), which is the shape the
    # module contract names. Read both, or a snapshot from the documented writer
    # renders as 0% context -- the one number this row exists to show.
    window = payload.get("context_window")
    if not isinstance(window, dict):
        window = payload.get("context") if isinstance(payload.get("context"), dict) else {}
    return {
        "session_id": payload.get("session_id"),
        "project": paths.project_of(transcript),
        "slug": session.get("slug"),
        "title": session.get("title") or session.get("last_prompt"),
        "transcript_path": str(transcript),
        "context_tokens": _int(payload.get("context_used_tokens")
                               or window.get("used_tokens")),
        "max_tokens": (_int(payload.get("context_max_tokens"))
                       or _int(window.get("max_tokens"))
                       or pricing.DEFAULT_CONTEXT_WINDOW),
        "cost_usd": float(totals.get("cost_usd_authoritative")
                          or payload.get("cost_usd") or 0.0),
        "total_tokens": _int(totals.get("total_tokens") or payload.get("total_tokens")),
        "model": payload.get("model"),
        "calls": _int(totals.get("calls") or payload.get("calls")),
        "started_at": session.get("started_at"),
        "cost_known": True,
        "source": "live",
    }


def _row_from_row_file(transcript: Path, newer_than: float = 0.0) -> Optional[Dict[str, Any]]:
    """The kilobyte-sized row.json that write_report() leaves next to data.json.

    data.json for a heavy session runs to several MB, past the _MAX_CACHE_BYTES
    cut-off, so without this the cache path falls through to the tail scan -- and
    a transcript with no cost-state line then reports $0.00 despite having a full
    report sitting beside it. row.json exists so the scan never has to choose
    parsing megabytes and lying.
    """
    row_path = (paths.reports_root() / "sessions"
                / paths.report_dir_name(transcript.stem) / "row.json")
    try:
        stat = row_path.stat()
        if stat.st_mtime < max(transcript.stat().st_mtime, newer_than):
            return None
        payload = json.loads(row_path.read_text(encoding="utf-8"))
    except Exception:
        return None
    if not isinstance(payload, dict) or payload.get("schema_version") != SCHEMA_VERSION:
        return None
    row = dict(payload)
    row.pop("schema_version", None)
    # row.json is an artifact and speaks in pseudonyms; a scan row is LOCAL and
    # speaks in real ids, so the identifying half is put back here -- from the
    # transcript filename we are already holding, and from the local session
    # map. Neither reads anything back out of the reports tree.
    row.pop("session", None)
    row["project"] = paths.project_of(transcript)
    row["transcript_path"] = str(transcript)
    row.setdefault("session_id", transcript.stem)
    local = redact.local_session_info(row["session_id"])
    if local.get("title") and not row.get("title"):
        row["title"] = local["title"]
    row.setdefault("max_tokens", pricing.DEFAULT_CONTEXT_WINDOW)
    row["cost_known"] = True
    row["source"] = "report"
    return row


def _row_from_cache(transcript: Path, newer_than: float = 0.0) -> Optional[Dict[str, Any]]:
    """Reuse a report we already built when it is newer than the transcript."""
    row = _row_from_row_file(transcript, newer_than)
    if row is not None:
        return row
    data_path = (paths.reports_root() / "sessions"
                 / paths.report_dir_name(transcript.stem) / "data.json")
    try:
        stat = data_path.stat()
        if (stat.st_mtime < max(transcript.stat().st_mtime, newer_than)
                or stat.st_size > _MAX_CACHE_BYTES):
            return None
        payload = json.loads(data_path.read_text(encoding="utf-8"))
    except Exception:
        return None
    if not isinstance(payload, dict) or payload.get("schema_version") != SCHEMA_VERSION:
        return None
    session = payload.get("session") or {}
    totals = payload.get("totals") or {}
    window = payload.get("context_window") or {}
    # Same rule as _row_from_row_file: data.json no longer carries an id, a slug
    # or a title, so the local half comes from the filename and the local map.
    local = redact.local_session_info(transcript.stem)
    return {
        "session_id": transcript.stem,
        "project": paths.project_of(transcript),
        "slug": None,
        "title": local.get("title"),
        "transcript_path": str(transcript),
        "context_tokens": _int(window.get("used_tokens")),
        "max_tokens": _int(window.get("max_tokens")) or pricing.DEFAULT_CONTEXT_WINDOW,
        "cost_usd": float(totals.get("cost_usd_authoritative") or 0.0),
        "total_tokens": _int(totals.get("total_tokens")),
        "model": session.get("primary_model"),
        "calls": _int(totals.get("calls")),
        "started_at": session.get("started_at"),
        "cost_known": True,
        "source": "report",
    }


def scan_sessions(active_within_seconds: Optional[int] = None, *,
                  cost_budget_bytes: Optional[int] = None) -> List[Dict[str, Any]]:
    """Lightweight row per session across every project, with a real cost.

    Cost comes from the incremental cache: a session is parsed once and then
    only extended by the bytes appended since, so a warm pass reads no transcript
    bytes at all and `oe watch` can redraw every two seconds. The cheap tail
    scan survives only as the fallback for a session this pass had no budget to
    prime, and it no longer decides anybody's dollars.

    `cost_budget_bytes` caps how much previously-unparsed transcript ONE pass
    will read for sessions that are not currently active. Active sessions are
    never deferred.
    """
    config = paths.load_config()
    scan_config = config.get("scan") or {}
    tail_bytes = int(scan_config.get("tail_bytes") or 262144)
    head_bytes = int(scan_config.get("head_bytes") or 65536)
    max_sessions = int(scan_config.get("max_sessions") or 500)
    if cost_budget_bytes is None:
        cost_budget_bytes = int(scan_config.get("cost_bytes_per_pass")
                                or _COST_BYTES_PER_PASS)
    # [bytes left in this pass, bytes already read by it]
    budget = [int(cost_budget_bytes), 0]
    now = time.time()
    if active_within_seconds is None:
        active_within_seconds = int(scan_config.get("active_within_seconds") or 900)

    # Liveness is not a file property. A transcript's mtime says when it was
    # last written, not whether Claude Code is still open on it: a probe file
    # dropped into ~/.claude/projects reads as "1 open" and lands in the
    # "in flight" total for a full 15 minutes with no process behind it, and a
    # session whose user is thinking drops out of the live pane the moment it
    # goes quiet. The process table is the ground truth -- a running `claude`
    # PID whose /proc/<pid>/cwd maps to a project slug -- and it is cheap.
    # None means the machine will not answer (no /proc, hardened container), and
    # then mtime alone is all there is.
    live_slugs: Optional[Dict[str, Dict[str, Any]]] = None
    if (scan_config.get("liveness_from_processes", True)):
        try:
            from . import watcher as _watcher      # local: watcher imports us
        except ImportError:                        # pragma: no cover
            try:
                from oe import watcher as _watcher  # type: ignore
            except Exception:
                _watcher = None                     # type: ignore
        except Exception:                           # pragma: no cover
            _watcher = None                         # type: ignore
        try:
            live_slugs = _watcher.live_project_slugs() if _watcher else None
        except Exception:
            live_slugs = None

    def _live(slug: Optional[str], mtime: float, mtime_says: bool) -> bool:
        if live_slugs is None:
            return mtime_says
        proc = live_slugs.get(str(slug or ""))
        if proc is None:
            # No Claude Code process is open in this project. Whatever touched
            # the file, it was not a running session.
            return False
        # A transcript written since the oldest claude in this slug started was
        # written BY one of them, so it stays open while they do -- that is what
        # keeps a thinking session in the live pane past the idle window.
        return mtime_says or mtime >= float(proc.get("since") or 0.0)

    # Newest first, so the byte budget is spent on the sessions a reader is
    # actually looking at and max_sessions truncates the oldest, not an
    # arbitrary directory order.
    candidates: List[Tuple[Path, Any]] = []
    for transcript in paths.iter_transcripts():
        try:
            stat = transcript.stat()
        except OSError:
            continue
        if stat.st_size < 2:
            continue
        candidates.append((transcript, stat))
    candidates.sort(key=lambda item: -item[1].st_mtime)

    rows: List[Dict[str, Any]] = []
    for transcript, stat in candidates[:max_sessions]:
        slug = transcript.parent.name
        is_active = _live(slug, stat.st_mtime,
                          (now - stat.st_mtime) <= active_within_seconds)
        try:
            cost = session_cost(transcript, budget=budget, active=is_active)
        except Exception:
            # A cost cache that blows up must cost this session its dollars, not
            # the whole listing.
            cost = None
        # Liveness on the session, not on one file of it: a fan-out writes only
        # agent transcripts for minutes at a time, and judging by the main
        # transcript alone drops the running session out of "in flight" -- and
        # out of the live pane -- for exactly as long as it stays busy.
        mtime = max(stat.st_mtime, _float((cost or {}).get("last_mtime")))
        is_active = _live(slug, mtime, (now - mtime) <= active_within_seconds)
        row = (_row_from_cost(transcript, cost)
               if cost and not cost.get("deferred") else None)
        if row is None:
            row = (_row_from_live(transcript, mtime) or _row_from_cache(transcript, mtime)
                   or _scan_one(transcript, tail_bytes, head_bytes))
            if row is None:
                continue
            # Nothing below this line was verified against the transcript this
            # pass, so it is an estimate whatever its origin claims.
            row["cost_source"] = None
            row["cost_is_estimate"] = True
            row["cost_pending"] = True
        row["mtime"] = mtime
        row["transcript_mtime"] = stat.st_mtime
        row["last_active"] = datetime.fromtimestamp(mtime, tz=timezone.utc).isoformat().replace("+00:00", "Z")
        row["local_day"] = _local_day(mtime)
        row["size_bytes"] = stat.st_size
        row["is_active"] = is_active
        window = row.get("max_tokens") or pricing.DEFAULT_CONTEXT_WINDOW
        row["max_tokens"] = window
        row["context_pct"] = round(100.0 * (row.get("context_tokens") or 0) / window, 2) if window else 0.0
        rows.append(row)
    rows.sort(key=lambda r: (not r["is_active"], -r["mtime"]))
    # Which account paid for each of these. Label + provenance only -- the email
    # and the accountUuid stay in accounts' own state file, because these rows
    # are serialised verbatim into sessions.json, which is an artifact.
    # infer=False: the org-quota hint needs a full-file scan and this is the hot
    # path; `oe account list` is where that cost is paid.
    try:
        accounts.annotate_rows(rows, infer=False)
    except Exception:
        pass
    return rows


def spend_today(rows: Iterable[Dict[str, Any]]) -> float:
    """Dollars spent TODAY in local time, attributed to the day they were spent.

    Not the same question as "sessions touched today": resuming a month-old
    session for one turn moves its whole lifetime cost into today's bucket if
    you group by last-activity, which is how the live header came to bill a
    month of spend against two hours of work. Rows carry a per-day split for exactly
    this; a row without one (an un-costed fallback) falls back to the old
    all-or-nothing rule so it is not silently dropped.
    """
    today = _local_day(time.time())
    total = 0.0
    for row in rows:
        by_day = row.get("cost_by_day")
        if isinstance(by_day, dict) and by_day:
            total += _float(by_day.get(today))
        elif row.get("cost_known", True) and row.get("local_day") == today:
            total += _float(row.get("cost_usd"))
    return total


def spend_in_flight(rows: Iterable[Dict[str, Any]]) -> float:
    """Current cost of every session that is still running.

    Every row carries a real number, so a live session is never skipped for want
    of a cost-state checkpoint: "$0.00 in flight" while the session in the pane
    above is spending real money is the failure this path exists to prevent.
    """
    return sum(_float(row.get("cost_usd")) for row in rows if row.get("is_active"))


def _scan_one(transcript: Path, tail_bytes: int, head_bytes: int) -> Optional[Dict[str, Any]]:
    lines = _tail(transcript, tail_bytes)
    cost_state: Optional[dict] = None
    cost_states: List[dict] = []
    last_usage: Optional[dict] = None
    last_model: Optional[str] = None
    title: Optional[str] = None
    prompt: Optional[str] = None
    slug: Optional[str] = None
    request_ids: set = set()

    for raw in lines:
        if len(raw) < 12:
            continue
        kind = _line_type(raw)
        if kind == "assistant":
            try:
                obj = json.loads(raw)
            except Exception:
                continue
            message = obj.get("message") or {}
            usage = message.get("usage")
            if isinstance(usage, dict) and not obj.get("isSidechain"):
                last_usage = usage
                last_model = message.get("model")
                slug = obj.get("slug") or slug
            rid = obj.get("requestId")
            if rid:
                request_ids.add(rid)
        elif kind == "cost-state":
            try:
                state = json.loads(raw)
            except Exception:
                continue
            if isinstance(state, dict):
                cost_state = state
                cost_states.append(state)
        elif kind == "ai-title":
            try:
                title = (json.loads(raw) or {}).get("aiTitle") or title
            except Exception:
                pass
        elif kind == "last-prompt":
            try:
                prompt = (json.loads(raw) or {}).get("lastPrompt") or prompt
            except Exception:
                pass

    if cost_state is None and last_usage is None and not lines:
        return None

    context_tokens = 0
    if last_usage:
        context_tokens = (_int(last_usage.get("input_tokens"))
                          + _int(last_usage.get("cache_creation_input_tokens"))
                          + _int(last_usage.get("cache_read_input_tokens")))

    model = last_model
    calls = len(request_ids)
    cost = 0.0
    started_at = None
    if cost_state:
        # cost-state is per RUN, not per file: resuming a session restarts the
        # accumulator under a new startTime. Taking only the last checkpoint
        # bills a whole transcript at its final run -- one session here reads
        # 4.6% of its true cost that way. Group by startTime, keep each
        # run's latest checkpoint, sum. Same rule as SessionLedger.runs, so the
        # dashboard and the report agree on one number.
        by_start: Dict[int, dict] = {}
        for state in cost_states:
            start = _int(state.get("startTime"))
            previous = by_start.get(start)
            if previous is None or _int(state.get("totalDuration")) >= _int(
                    previous.get("totalDuration")):
                by_start[start] = state
        cost = sum(_float(s.get("totalCostUSD")) for s in by_start.values())
        start_ms = min((s for s in by_start if s), default=0)
        if start_ms:
            started_at = datetime.fromtimestamp(start_ms / 1000.0, tz=timezone.utc)
        if not model:
            usage_by_model = cost_state.get("modelUsage") or {}
            if usage_by_model:
                model = max(usage_by_model.items(),
                            key=lambda kv: float((kv[1] or {}).get("costUSD") or 0))[0]
    head_ts = _head_timestamp(transcript, head_bytes)
    if started_at is None:
        started_at = head_ts

    # Summing the runs is only right when we SAW every run. Two things break
    # that from a tail scan, and both under-report by an order of magnitude:
    # an earlier run's checkpoint can sit outside the scanned tail, and a
    # resumed session can have no checkpoint for its earlier run at all -- its
    # only checkpoint starting hours into the file, leaving most of the spend
    # outside it. Both show up the same way: the earliest checkpoint we found
    # starts well after the transcript's first line. Report that as unknown
    # rather than as a confident wrong number; `oe backfill` / the full ledger
    # then supplies the real figure.
    cost_partial = False
    if cost_state is not None and head_ts is not None and started_at is not None:
        cost_partial = (started_at - head_ts) > _RUN_START_GRACE

    return {
        "session_id": transcript.stem,
        "project": paths.project_of(transcript),
        "slug": slug,
        "title": title or (prompt[:120] if prompt else None),
        "transcript_path": str(transcript),
        "context_tokens": context_tokens,
        "max_tokens": pricing.context_window(model),
        "cost_usd": cost,
        "model": model,
        "calls": calls,
        "calls_partial": True,
        # No cost-state line in the tail means the session's dollars are simply
        # not known from a cheap scan -- older Claude Code builds never wrote
        # one at all. Rendering that as $0.00 silently under-reports the
        # all-time rollup, which a few large sessions dominate; callers must
        # show it as unknown and `oe backfill` turns it into a real number.
        "cost_known": cost_state is not None and not cost_partial,
        "cost_partial": cost_partial,
        "started_at": _iso(started_at),
        "source": "tail",
    }


def daily_rollup(rows: Iterable[Dict[str, Any]]) -> Dict[str, Any]:
    """Spend grouped by day / project / model, for the cross-session dashboard.

    by_day is LOCAL time and attributes each request to the day it was actually
    billed, not to the day its session was last touched: one turn on a month-old
    session would otherwise shove that session's whole lifetime cost into today.
    """
    by_day: Dict[str, float] = {}
    by_project: Dict[str, float] = {}
    by_model: Dict[str, float] = {}
    total = 0.0
    for row in rows:
        cost = float(row.get("cost_usd") or 0.0)
        total += cost
        split = row.get("cost_by_day")
        if isinstance(split, dict) and split:
            for day, value in split.items():
                by_day[str(day)] = by_day.get(str(day), 0.0) + _float(value)
        else:
            # No per-day split (an un-costed fallback row): the old all-or-
            # nothing rule, on the local day the transcript was last written.
            day = (row.get("local_day")
                   or str(row.get("last_active") or row.get("started_at") or "")[:10]
                   or "unknown")
            by_day[day] = by_day.get(day, 0.0) + cost
        project = row.get("project") or "unknown"
        by_project[project] = by_project.get(project, 0.0) + cost
        model = pricing.normalize_model(row.get("model")) or "unknown"
        by_model[model] = by_model.get(model, 0.0) + cost
    return {
        "total_usd": total,
        "by_day": dict(sorted(by_day.items())),
        "by_project": dict(sorted(by_project.items(), key=lambda kv: -kv[1])),
        "by_model": dict(sorted(by_model.items(), key=lambda kv: -kv[1])),
    }


__all__ = [
    "ApiCall", "ToolCall", "SessionLedger",
    "load", "load_by_session_id", "scan_sessions", "daily_rollup",
    "session_cost", "spend_today", "spend_in_flight",
    # the re-read ledger
    "summarise_rereads", "merge_rereads", "REREAD_REASONS", "LEGITIMATE_REREADS",
    "READ_TOOLS", "MUTATE_TOOLS", "CARRY_USD_PER_1K", "DEFAULT_READ_LINES",
]
