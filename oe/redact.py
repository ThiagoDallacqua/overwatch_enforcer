"""The one place that decides what a shareable artifact is allowed to contain.

WHY this module exists
----------------------
The reports under <reports_root> are meant to be sent to other people: the
question they answer is "what did this session cost and where did the tokens
go", and none of that needs to say who ran it, on which machine, in which
repository, or what was typed into the prompt. Everything that leaves this
process as a FILE therefore goes through here first.

Two design decisions are load-bearing and deliberate:

1.  ALLOWLIST, NOT DENYLIST. Every artifact is rebuilt field by field from an
    explicit schema below (`_SESSION_FIELDS`, `_CALL_FIELDS`, ...). A denylist
    leaks whatever field the upstream ledger grows next month; an allowlist
    simply drops it. The cost is that a genuinely new, genuinely useful field
    has to be added here on purpose -- which is the point.

2.  ORDINAL PSEUDONYMS, NOT HASHES. `session_01`, `turn_07`, `call_0413` are
    assigned by first-seen order. A hash of a real uuid is still a stable
    fingerprint OF that uuid: it survives rainbow-tabling and it lets anyone
    holding the original confirm a match. An ordinal cannot be inverted by
    anyone who does not already hold the local map, which never leaves
    state_dir().

The local/shareable line
------------------------
Terminal output is local and ephemeral, so `oe sessions` / `oe watch` keep
showing real titles and paths. Files are shareable, so they carry pseudonyms.
`state_dir()/session-map.json` bridges the two and is the ONLY file that holds
both halves; it lives outside the artifact tree and `audit()` fails if a copy
is ever found inside it.
"""

from __future__ import annotations

import contextlib
import getpass
import hashlib
import json
import os
import re
import socket
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from . import paths

__all__ = [
    "REDACTION_VERSION", "RedactionError", "Finding", "Redactor",
    "audit", "audit_file", "blocking", "ensure_redacted", "redact_payload",
    "redact_scan_row", "redact_scan_rows", "redact_row_json", "redact_call",
    "redact_rereads", "target_label", "shape_of", "map_path",
    "record_local", "whois",
    "reverse_lookup", "local_session_info", "session_pseudonym",
    "project_pseudonym",
    # CLI redaction policy
    "scrub", "cli_redaction_enabled", "set_cli_redaction", "redaction_reason",
    "install_cli_redaction", "ENV_REDACT", "write_verbatim", "merge_map_files",
]

REDACTION_VERSION = 1

# The note copied into every data.json so a reader knows what they are holding.
REDACTION_NOTE = (
    "Identifiers are per-report ordinal pseudonyms; prompt text, file paths, "
    "titles, branches, hostnames and account data are not collected."
)


class RedactionError(RuntimeError):
    """Raised instead of writing an artifact that failed its own audit."""


# ---------------------------------------------------------------------------
# audit -- the safety net behind the allowlist
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Finding:
    """One suspected leak.

    `sample` is the raw matched text. It is fine in terminal output (local,
    ephemeral, and the user is the data subject) but must never be written into
    an artifact or a log that ships, so RedactionError quotes only kind+offset.
    """

    kind: str
    severity: str  # 'block' (refuse the write) | 'review' (report, do not block)
    offset: int
    sample: str
    where: str = ""

    def describe(self) -> str:
        return f"{self.kind}@{self.offset}"


_UUID_RE = re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", re.I)
# A generic issue key: JIRA, Linear, GitHub and every other tracker share this
# shape. Case-insensitive because branch names carry the lowercase form
# ('feature/abc-913-...'), which is the same identifier and the same leak.
_TICKET_RE = re.compile(r"\b[A-Z][A-Z0-9]{1,9}-\d{1,6}\b", re.I)
_BLOCK_PATTERNS: Tuple[Tuple[str, "re.Pattern[str]"], ...] = (
    ("email", re.compile(r"[\w.+-]+@[\w-]+\.[\w.]{2,}")),
    ("home", re.compile(r"/(?:home|Users)/\w+")),
    ("uuid", _UUID_RE),
    ("branch", re.compile(r"\b(feature|fix|chore|main|hotfix|release|bugfix)/[\w.-]+", re.I)),
    # Bounded so a version string like 1.2.3 cannot match and a viewBox cannot
    # either; four dotted 1-3 digit groups not glued to another digit or dot.
    ("ipv4", re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")),
)


def _identity_values() -> List[str]:
    """Account identifiers belonging to THIS machine, read at audit time.

    Read from ~/.claude.json and the process environment so the scanner knows
    the actual emails/uuids to look for rather than only their shape. Nothing
    here is ever written anywhere: the values are used as needles and dropped.
    """
    values: List[str] = []

    def add(value: Any) -> None:
        text = str(value or "").strip()
        # Two characters would match everything; ids are long by construction.
        if len(text) >= 6:
            values.append(text)

    try:
        raw = json.loads((paths.CLAUDE_HOME.parent / ".claude.json").read_text(
            encoding="utf-8", errors="replace"))
    except Exception:
        raw = {}
    if isinstance(raw, dict):
        add(raw.get("machineID"))
        add(raw.get("userID"))
        account = raw.get("oauthAccount") or raw.get("account") or {}
        if isinstance(account, dict):
            for key in ("emailAddress", "email", "accountUuid", "organizationUuid",
                        "organizationName", "displayName"):
                add(account.get(key))
    # The username and hostname sources are filtered through the same
    # generic-name list the write gate uses: `docker`, `runner`, `builder` and
    # friends are what the machine is CALLED, not who it belongs to, and as
    # needles they match the tool's own output rather than a leak.
    for key in ("USER", "LOGNAME", "USERNAME"):
        value = os.environ.get(key)
        if str(value or "").strip().lower() not in _GENERIC_USERNAMES:
            add(value)
    try:
        host = socket.gethostname()
        if str(host or "").strip().lower() not in _GENERIC_USERNAMES:
            add(host)
    except Exception:
        pass
    # Deduplicate but keep the longest first, so a nested match reports the
    # most specific needle.
    return sorted({v for v in values}, key=len, reverse=True)


# Usernames too generic to substitute blind, and too generic to BE identity.
# Two separate jobs, one list. (a) The CLI scrubber must not rewrite 'user' or
# 'root' as a bare substring or it mangles ordinary English and every other path
# on screen. (b) The write gate must not BLOCK on them either: on a machine
# whose account is one of these -- every Docker container, most CI images,
# `sudo -i`, a great many devcontainers -- a bare-substring needle matches the
# tool's own generated HTML (`:root{` in its stylesheet, `device-width` in its
# viewport meta, `-apple-system` in its font stack, its own chart label "Cost
# per user turn", its own prose "a verbose test log"), so every report is
# refused for a leak that does not exist. Dropping these needles costs no
# privacy: an account named `root` or `test` identifies nobody.
_GENERIC_USERNAMES = frozenset({
    "user", "users", "root", "admin", "administrator", "home", "claude",
    "runner", "ubuntu", "ec2-user", "node", "app", "test", "guest", "me",
    "dev", "www", "www-data", "ci", "build", "builder", "ops", "docker",
    "vagrant", "service", "nobody", "jenkins", "deploy", "circleci", "worker",
    "container", "devcontainer", "vscode", "codespace", "default",
})

# WHY a length threshold exists at all.
#
# A username is evidence of identity only when it appears where a username
# belongs. A long, unusual name ('<name>s-laptop', '<name>1') is its own
# evidence wherever it lands, because nothing else in a report spells it. A
# SHORT name is not: 'max', 'git', 'main', 'code', 'data' and 'mark' are
# ordinary words of English and of source code before they are anybody's
# account, so their bare presence in a line says nothing about who ran it.
#
# So the rule is split by that difference rather than by a list of names,
# which cannot be enumerated:
#
#   * at or above _SUFFIXABLE_NEEDLE characters -- match at a left identifier
#     boundary, right-hand side free, exactly as before.
#   * below it -- match ONLY in a context that MAKES the token an identity: a
#     home directory (/home/<n>, /Users/<n>, the flattened -home-<n>- project
#     slug), a tilde home (~<n>), or the local part of an address (<n>@host).
#     A bare 'max' in 'max(1, lo - 1)' is not one of those and never was.
#
# The list of generic account names below is a convenience -- it keeps 'root'
# and 'user' from being scanned for at all -- not the thing holding the class
# closed. Ordinary names such as max, mark, git, main, code and data are exactly
# what a list cannot enumerate, because the space it has to cover is "words
# people are called".
_SUFFIXABLE_NEEDLE = 5

# Shorter than this and there is no spelling of the name left to anchor on.
_MIN_NEEDLE = 2

# Text that, sitting IMMEDIATELY before a short needle, makes the needle a
# username rather than a word. Lowercase; compared against the lowered text.
# '-home-' / 'home-' cover the flattened project-slug spelling Claude Code
# uses for its transcript directories ('-home-<name>-<repo>'), which is the
# single most common way this tool has ever seen an account name reach an
# artifact.
_IDENTITY_PREFIXES: Tuple[str, ...] = (
    "/home/", "/users/", "\\home\\", "\\users\\",
    "home/", "users/", "home-", "users-", "~",
)


def _is_word_char(ch: str) -> bool:
    """Underscore counts.

    Without it the needle 'max' matched inside 'max_tokens' and
    'MAX_SLICE_LINES' -- an identifier is one word to a reader and must be one
    word here, or every snake_case name in the tool's own output is a leak.
    """
    return ch.isalnum() or ch == "_"


def _identity_context(text: str, lowered: str, start: int, end: int) -> bool:
    """True when text[start:end] sits where only a username can sit."""
    head = lowered[:start]
    if any(head.endswith(prefix) for prefix in _IDENTITY_PREFIXES):
        # /home/maxwell is not user 'max': the name must end where the needle
        # ends.
        return end >= len(text) or not _is_word_char(text[end])
    # '<n>@host' -- an address or an ssh/scp target. The left side must still
    # be a boundary so 'formax@x' does not read as user 'max'.
    if end < len(text) and text[end] == "@":
        return start == 0 or not _is_word_char(text[start - 1])
    return False


def _needle_offsets(text: str, lowered: str, needle: str) -> List[int]:
    """Offsets where `needle` occurs AS a username.

    Bare `str.find` is what made a three-letter account name match ordinary
    English everywhere; an identifier boundary alone was not enough either,
    because 'origin/main' and 'def main():' clear a boundary check while
    telling a reader nothing about who is at the keyboard. See the note above
    _SUFFIXABLE_NEEDLE for why the two lengths are treated differently.
    """
    out: List[int] = []
    if not needle:
        return out
    span = len(needle)
    long_enough = span >= _SUFFIXABLE_NEEDLE
    start = lowered.find(needle)
    while start != -1:
        end = start + span
        if long_enough:
            # Left boundary required, right side free: '<name>s-laptop' and
            # '<name>1' leak the same name.
            if start == 0 or not _is_word_char(text[start - 1]):
                out.append(start)
        elif _identity_context(text, lowered, start, end):
            out.append(start)
        start = lowered.find(needle, start + 1)
    return out


class _NeedleRule:
    """A scrub rule shaped like a compiled regex, backed by _needle_offsets.

    `_scrub_rules()` returns (pattern, replacement) pairs and applies them with
    `pattern.sub(replacement, text)`; this exposes that one method so the
    username rule can reuse the gate's definition of a username instead of
    re-stating it as a regex that would then drift from it.
    """

    __slots__ = ("needle",)

    def __init__(self, needle: str) -> None:
        self.needle = needle.lower()

    def sub(self, repl: Any, text: str) -> str:
        offsets = _needle_offsets(text, text.lower(), self.needle)
        if not offsets:
            return text
        span = len(self.needle)
        out: List[str] = []
        cursor = 0
        for start in offsets:
            if start < cursor:      # overlapping match: the first one wins
                continue
            out.append(text[cursor:start])
            out.append(repl if isinstance(repl, str) else repl(text[start:start + span]))
            cursor = start + span
        out.append(text[cursor:])
        return "".join(out)


def _user_needles() -> List[str]:
    """Every spelling of the local username, as boundary-matched needles.

    Two filters, both load-bearing:

    * generic account names are dropped entirely (_GENERIC_USERNAMES). They
      identify nobody, and as needles they match the tool's own hardcoded
      output, which would make `redact.guard()` refuse every report on any
      machine whose account is `root`, `user`, `dev`, `app` or `test`.
    * what survives is matched by _needle_offsets(), not by `str.find`, so a
      short name is only a match where a username can actually sit.

    _MIN_NEEDLE is two rather than three because the second filter carries the
    weight: a two-character name can only match '/home/<n>/', '~<n>' or
    '<n>@host', and on a machine whose account is `pi` those are exactly the
    three places the name leaks.

    USERNAME is read as well as USER/LOGNAME: it is the spelling Windows and
    some CI images set, and without it one source of the name goes unscanned.
    """
    needles = set()
    for value in (getpass.getuser() if hasattr(getpass, "getuser") else None,
                  os.environ.get("USER"), os.environ.get("LOGNAME"),
                  os.environ.get("USERNAME")):
        try:
            text = str(value or "").strip()
        except Exception:
            continue
        if len(text) >= _MIN_NEEDLE and text.lower() not in _GENERIC_USERNAMES:
            needles.add(text.lower())
    try:
        home = Path.home().name
        if len(home) >= _MIN_NEEDLE and home.lower() not in _GENERIC_USERNAMES:
            needles.add(home.lower())
    except Exception:
        pass
    return sorted(needles)


# A ticket-shaped match sitting immediately behind one of these is part of a
# MODEL ID, not an issue key. A SHAPE rule on purpose: deriving the exemption
# from the pricing catalog instead ties it to a frozen literal pinned to one
# Claude Code build, so the first model shipped after that build is
# ticket-shaped, unknown, and therefore BLOCKING -- which makes redact.guard()
# refuse the write and takes `oe report`, `oe dashboard` and the `oe backfill`
# dashboard down with an unhandled RedactionError. The safety property a
# membership rule would defend is kept either way: a bare 'ABC-913' has no
# model prefix in front of it and still blocks.
# Deliberately only the two spellings this tool can ever emit -- `claude-...`
# and the Bedrock/Vertex `...anthropic.claude-...` -- rather than a vendor list.
# A wider list would have to exempt a match that IS its own prefix ('gpt-5'),
# and that turns any tracker whose project key happens to be GPT into a bypass.
# Every model id in a Claude Code transcript is one of these two shapes.
_MODEL_ID_PREFIXES: Tuple[str, ...] = ("claude-", "anthropic.")


def _model_prefixed(text: str, start: int) -> bool:
    """True when the match at `start` is the tail of a model id."""
    head = text[:start].lower()
    return any(head.endswith(prefix) for prefix in _MODEL_ID_PREFIXES)


def _safe_ticket_shapes() -> frozenset:
    """Ticket-SHAPED strings that are not tickets and are emitted on purpose.

    The HTML charset declaration ('utf-8') matches the generic issue-key
    pattern, and so does every model id in the catalog we happen to know about
    ('claude-opus-5' contains 'opus-5'). Model ids are handled by the SHAPE rule
    above -- _model_prefixed() -- which covers ids this build has never heard
    of; the catalog entries below are kept only as a belt-and-braces second
    source for ids whose prefix spelling changes.
    """
    safe = {"utf-8"}
    try:
        from . import pricing
        names: List[str] = list(getattr(pricing, "MODEL_TIERS", {}) or {})
        names += list(getattr(pricing, "TIERS", {}) or {})
        for name in names:
            for match in _TICKET_RE.finditer(str(name)):
                safe.add(match.group(0).lower())
    except Exception:
        pass
    return frozenset(safe)


def audit(text_or_obj: Any, *, where: str = "") -> List[Finding]:
    """Scan a string (or any JSON-serialisable object) for personal data.

    An object is serialised with json.dumps before scanning, so reported
    offsets are into that serialisation rather than into the file that will be
    written. That is close enough to locate the field and avoids re-rendering.
    """
    if isinstance(text_or_obj, (bytes, bytearray)):
        text = bytes(text_or_obj).decode("utf-8", errors="replace")
    elif isinstance(text_or_obj, str):
        text = text_or_obj
    else:
        try:
            text = json.dumps(text_or_obj, ensure_ascii=False, default=str)
        except Exception:
            text = str(text_or_obj)

    findings: List[Finding] = []
    for kind, pattern in _BLOCK_PATTERNS:
        for match in pattern.finditer(text):
            findings.append(Finding(kind, "block", match.start(), match.group(0), where))

    lowered = text.lower()
    for needle in _user_needles():
        for start in _needle_offsets(text, lowered, needle):
            findings.append(Finding("user", "block", start, text[start:start + len(needle)], where))

    for needle in _identity_values():
        start = lowered.find(needle.lower())
        while start != -1:
            findings.append(Finding("identity", "block", start,
                                    text[start:start + len(needle)], where))
            start = lowered.find(needle.lower(), start + 1)

    safe = _safe_ticket_shapes()
    for match in _TICKET_RE.finditer(text):
        value = match.group(0)
        start = match.start()
        # ONLY two things are downgraded: an exact value from the pricing
        # catalog ('opus-5' inside claude-opus-5) plus 'utf-8', and a CSS custom
        # property, which is the '--' double hyphen.
        #
        # A looser rule -- "preceded by any single '-'" -- is a bypass, not a
        # heuristic: 'fix-abc-913-verifier', which is the shape of a branch
        # name, a directory name or a subagent name, would be downgraded to
        # 'review' and sail through write_report() into calls.csv, data.json,
        # report.html and summary.md.
        css_property = start > 1 and text[start - 1] == "-" and text[start - 2] == "-"
        model_id = _model_prefixed(text, start)
        severity = ("review" if (css_property or model_id or value.lower() in safe)
                    else "block")
        findings.append(Finding("ticket", severity, start, value, where))

    findings.sort(key=lambda f: (f.offset, f.kind))
    return findings


def audit_file(path: str | os.PathLike) -> List[Finding]:
    """audit() over a file already on disk, plus the location rule.

    A session map inside the reports tree would pair every pseudonym with its
    real session id, defeating the whole scheme, so its presence there is
    itself a finding.
    """
    target = Path(path)
    where = str(target)
    # The rolling backup is the same oracle under a different name, so the rule
    # is on the prefix rather than the exact filename.
    if target.name == "session-map.json" or target.name.startswith("session-map."):
        # The map pairs every pseudonym with its real session id and title, so
        # a copy anywhere a reader could pick it up alongside a report defeats
        # the entire scheme. Its ONE legitimate home is state_dir(), which is
        # runtime state rather than an artifact and is never shared or purged.
        try:
            root = paths.reports_root().resolve()
            resolved = target.resolve()
            inside = resolved.is_relative_to(root)
            sanctioned = resolved.parent == paths.state_dir().resolve()
        except Exception:
            inside, sanctioned = False, False
        if inside and not sanctioned:
            return [Finding("map-in-reports", "block", 0, target.name, where)]
    try:
        text = target.read_text(encoding="utf-8", errors="replace")
    except Exception as exc:
        return [Finding("unreadable", "review", 0, str(exc), where)]
    return audit(text, where=where)


def blocking(findings: Iterable[Finding]) -> List[Finding]:
    """The subset that must stop a write. 'review' findings are reported only."""
    return [f for f in findings if f.severity == "block"]


def guard(text: str, where: str) -> str:
    """Return `text` unchanged, or raise rather than let a leak be written."""
    bad = blocking(audit(text, where=where))
    if bad:
        kinds: Dict[str, int] = {}
        for finding in bad:
            kinds[finding.kind] = kinds.get(finding.kind, 0) + 1
        summary = ", ".join(f"{k} x{v}" for k, v in sorted(kinds.items()))
        # Deliberately quotes offsets, never the matched text: this message ends
        # up in watcher logs and on stderr.
        # The remedy deliberately does NOT say "run oe audit": nothing was
        # written, so a scan of what is on disk finds nothing and tells the
        # reader their install is healthy. The kinds above are the detail.
        raise RedactionError(
            f"refusing to write {where}: audit found {len(bad)} item(s) ({summary}); "
            f"first at offset {bad[0].offset}. Nothing was written; the kinds listed "
            f"are what matched.")
    return text


# ---------------------------------------------------------------------------
# the local-only pseudonym map
# ---------------------------------------------------------------------------


_MAP_SCHEMA = 1
_map_cache: Dict[str, Any] = {}
_map_cache_key: Optional[Tuple[str, float, int]] = None


def map_path() -> Path:
    """state_dir()/session-map.json -- runtime state, never an artifact."""
    return paths.state_dir() / "session-map.json"


def _blank_map() -> Dict[str, Any]:
    return {"schema": _MAP_SCHEMA, "sessions": {}, "projects": {}}


def _load_map() -> Dict[str, Any]:
    """Read the map, memoised on (path, mtime, size). Never raises."""
    global _map_cache, _map_cache_key
    path = map_path()
    try:
        stat = path.stat()
        key = (str(path), stat.st_mtime, stat.st_size)
    except Exception:
        _map_cache_key = None
        return _blank_map()
    if key == _map_cache_key and _map_cache:
        return _map_cache
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return _blank_map()
    if not isinstance(data, dict):
        return _blank_map()
    data.setdefault("schema", _MAP_SCHEMA)
    data.setdefault("sessions", {})
    data.setdefault("projects", {})
    _map_cache, _map_cache_key = data, key
    return data


@contextlib.contextmanager
def _map_lock():
    """Exclusive, blocking flock over session-map.json, or a no-op fallback.

    The same idiom oe.accounts._state_lock() uses, for the same reason and
    against the same file shape: a read-modify-write of one small JSON document
    from several processes at once. It is NOT decoration here. _allocate() used
    to do _load_map() -> mint -> _save_map() unguarded, and _save_map() replaces
    the whole file, so at the concurrency this tool configures for itself
    (one watcher process per live session, plus `oe report` / `oe backfill`
    targeting a session a watcher is already rebuilding) several processes read
    the same map, each minted the SAME ordinal, and the last writer's file was
    the only one that survived. Two real sessions then published their
    artifacts into the same sessions/session_NN/ directory, the second
    overwriting the first, and `oe whois session_NN` returned one confident
    wrong answer -- with exit 0 and a path printed, so nothing looked wrong.

    Blocking rather than non-blocking: every holder does one small read, one
    dict update and one atomic_write. Failure to lock is never fatal; an
    unlockable filesystem degrades to the previous (racy) behaviour rather than
    losing the pseudonym entirely.
    """
    handle = None
    try:
        lock_path = map_path().with_suffix(".lock")
        paths.ensure_dir(lock_path.parent)
        handle = open(lock_path, "a+")
        import fcntl
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
    except Exception:
        if handle is not None:
            try:
                handle.close()
            except Exception:
                pass
            handle = None
    try:
        yield
    finally:
        if handle is not None:
            try:
                import fcntl
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
            except Exception:
                pass
            try:
                handle.close()
            except Exception:
                pass


def _read_map_uncached(path: Optional[Path] = None) -> Dict[str, Any]:
    """The map as it is ON DISK right now, bypassing the mtime memo."""
    target = Path(path) if path is not None else map_path()
    try:
        data = json.loads(target.read_text(encoding="utf-8"))
    except Exception:
        return _blank_map()
    if not isinstance(data, dict):
        return _blank_map()
    data.setdefault("schema", _MAP_SCHEMA)
    if not isinstance(data.get("sessions"), dict):
        data["sessions"] = {}
    if not isinstance(data.get("projects"), dict):
        data["projects"] = {}
    return data


def _merge_map(base: Dict[str, Any], incoming: Dict[str, Any]) -> Dict[str, Any]:
    """Union two maps key by key. `base` wins; nothing is ever dropped.

    The map is an append-only allocation ledger: an entry that exists is the
    only record of what a published `session_07` directory refers to, so a
    merge may add and may fill blanks, and may never delete or re-point a key.
    A pseudonym already taken by a different key is re-minted rather than
    duplicated, because two keys sharing one pseudonym is exactly the collision
    this merge exists to prevent.
    """
    out: Dict[str, Any] = {"schema": base.get("schema", _MAP_SCHEMA)}
    for kind in ("sessions", "projects"):
        merged: Dict[str, Any] = {}
        for entry_key, entry in (base.get(kind) or {}).items():
            merged[entry_key] = dict(entry) if isinstance(entry, dict) else entry
        taken = {str((e or {}).get("pseudonym")) for e in merged.values()
                 if isinstance(e, dict)}
        prefix = "session" if kind == "sessions" else "project"
        for entry_key, entry in (incoming.get(kind) or {}).items():
            if not isinstance(entry, dict):
                continue
            existing = merged.get(entry_key)
            if isinstance(existing, dict):
                for field, value in entry.items():
                    if field != "pseudonym" and value is not None \
                            and existing.get(field) in (None, ""):
                        existing[field] = value
                continue
            entry = dict(entry)
            if str(entry.get("pseudonym") or "") in taken or not entry.get("pseudonym"):
                entry["pseudonym"] = _next_ordinal(merged, prefix)
            merged[entry_key] = entry
            taken.add(str(entry["pseudonym"]))
        out[kind] = merged
    for field, value in base.items():
        if field not in out:
            out[field] = value
    return out


def _save_map(data: Dict[str, Any]) -> None:
    """Merge `data` over what is on disk and replace the file atomically.

    Merge, not replace. atomic_write() writes the WHOLE document, so a caller
    holding a slightly stale copy would silently drop every entry another
    process had added since it read. Callers that hold _map_lock() cannot
    race, but _save_map is reachable without it, and re-reading here costs one
    small read and makes the operation safe from either side.
    """
    global _map_cache_key
    try:
        merged = _merge_map(data, _read_map_uncached())
    except Exception:
        merged = data
    try:
        target = map_path()
        # One rolling backup. Losing this file makes every pseudonym in every
        # published report permanently unresolvable, so the previous good copy
        # is worth one extra write. Rolling rather than timestamped: an
        # unbounded set of copies of the de-pseudonymisation oracle is its own
        # problem.
        try:
            if target.exists():
                paths.atomic_write(target.with_suffix(".json.bak"),
                                   target.read_text(encoding="utf-8"))
        except Exception:
            pass
        paths.atomic_write(target, json.dumps(merged, indent=2, sort_keys=True) + "\n")
    except Exception:
        return
    _map_cache_key = None  # force the next read to see what we just wrote


def merge_map_files(destination: Path, legacy: Path) -> bool:
    """Fold a stray session-map.json into the sanctioned one. Never deletes.

    Used by oe.paths when it finds a pre-relocation `.state/` inside the reports
    tree. The generic newest-wins file move that handles every other state file
    is WRONG for this one: it is not a cache, it is the only record of which
    real session each published `session_NN` directory belongs to, and letting
    a one-entry legacy copy replace a five-entry current one made four
    pseudonyms permanently unresolvable and pointed the fifth at a stranger.
    """
    try:
        base = _read_map_uncached(destination)
        incoming = _read_map_uncached(legacy)
        merged = _merge_map(base, incoming)
        paths.atomic_write(Path(destination),
                           json.dumps(merged, indent=2, sort_keys=True) + "\n")
    except Exception:
        return False
    global _map_cache_key
    _map_cache_key = None
    return True


# Pseudonyms are joined with '_' rather than '-'. The separator is not
# cosmetic: a hyphenated "session" + "-01" is an exact match for the generic
# issue-key pattern this module scans for (\b[A-Z][A-Z0-9]{1,9}-\d{1,6}\b), so
# hyphenated pseudonyms would put tens of thousands of self-inflicted hits into
# every audit and drown a real ticket id in them. 'session_01' reads the same
# and collides with nothing.
PSEUDONYM_SEP = "_"


def _next_ordinal(bucket: Dict[str, Any], prefix: str) -> str:
    """1 + the highest ordinal already issued, so a lost update cannot reuse one."""
    highest = 0
    for entry in bucket.values():
        name = (entry or {}).get("pseudonym") if isinstance(entry, dict) else None
        try:
            highest = max(highest, int(str(name).rsplit(PSEUDONYM_SEP, 1)[-1]))
        except Exception:
            continue
    return f"{prefix}{PSEUDONYM_SEP}{highest + 1:02d}"


def _allocate(kind: str, key: str, extra: Optional[Dict[str, Any]] = None) -> str:
    """Look up or mint a persistent pseudonym for a session or a project.

    Serialised on an exclusive flock over a sibling lock file, and the memo is
    dropped INSIDE the lock, so the whole read-modify-write is atomic against
    other processes: two watchers rebuilding at once cannot mint the same
    ordinal for different sessions. Where flock is unavailable the write still
    MERGES rather than replaces, so the worst a lost race can do is give one of
    the two keys a fresh ordinal; it cannot drop the other process's entry,
    which is what would make a pseudonym unresolvable.
    """
    global _map_cache_key
    with _map_lock():
        # Inside the lock, and only inside it: a memo read before the lock was
        # acquired describes the map as it was before the previous holder wrote,
        # and minting from that is the collision the lock exists to stop.
        _map_cache_key = None
        data = _load_map()
        bucket = data.get(kind) or {}
        entry = bucket.get(key)
        if isinstance(entry, dict) and entry.get("pseudonym"):
            if extra:
                missing = {k: v for k, v in extra.items()
                           if v is not None and entry.get(k) != v}
                if missing:
                    entry.update(missing)
                    data[kind] = bucket
                    _save_map(data)
            return str(entry["pseudonym"])
        prefix = "session" if kind == "sessions" else "project"
        name = _next_ordinal(bucket, prefix)
        bucket[key] = dict(extra or {})
        bucket[key]["pseudonym"] = name
        data[kind] = bucket
        _save_map(data)
        # Read back through the file, not the memo: _save_map merges, so if the
        # lock could not be taken on this filesystem and another writer landed
        # first, the merge has already settled which ordinal this key owns.
        settled = (_read_map_uncached().get(kind) or {}).get(key) or {}
        return str(settled.get("pseudonym") or name)


# A value that is already a pseudonym. Redaction runs at several boundaries and
# some of them see rows another one has already been through; without this a
# pseudonym would be pseudonymised again and one project would end up with two
# names in the same rollup.
_PSEUDONYM_RE = re.compile(r"^(session|project)" + PSEUDONYM_SEP + r"\d+$")


def session_pseudonym(session_id: Any, **extra: Any) -> str:
    """'session_01' for a real session id. Stable for the life of the map."""
    key = str(session_id or "").strip()
    if not key:
        return "session" + PSEUDONYM_SEP + "00"
    if _PSEUDONYM_RE.match(key):
        return key
    return _allocate("sessions", key, {k: v for k, v in extra.items() if v is not None})


def project_pseudonym(slug: Any) -> str:
    """'project_01' for a project slug, stable across every artifact.

    Persistent rather than per-report because the dashboard rolls spend up by
    project: if each report invented its own numbering the rollup could not be
    joined back to the per-session pages.
    """
    key = str(slug or "").strip()
    if not key:
        return "project" + PSEUDONYM_SEP + "00"
    if _PSEUDONYM_RE.match(key):
        return key
    display = ""
    try:
        display = paths.project_display(key) or ""
    except Exception:
        display = ""
    return _allocate("projects", key, {"display": display} if display else None)


def record_local(session_id: Any, *, title: Any = None, project: Any = None,
                 project_display: Any = None, transcript_path: Any = None,
                 started_at: Any = None) -> str:
    """Note the identifying detail for one session in the LOCAL map only.

    This is what makes `oe whois session_07` able to answer; none of it is ever
    written into an artifact.
    """
    return session_pseudonym(
        session_id,
        title=(str(title) if title else None),
        project=(str(project) if project else None),
        project_display=(str(project_display) if project_display else None),
        transcript_path=(str(transcript_path) if transcript_path else None),
        started_at=(str(started_at) if started_at else None),
    )


def whois(pseudonym: str) -> Optional[Dict[str, Any]]:
    """Real identity behind 'session_07' / 'project_02'. Local lookup only."""
    wanted = str(pseudonym or "").strip().lower()
    if not wanted:
        return None
    data = _load_map()
    for kind in ("sessions", "projects"):
        for key, entry in (data.get(kind) or {}).items():
            if isinstance(entry, dict) and str(entry.get("pseudonym", "")).lower() == wanted:
                out = dict(entry)
                out["kind"] = kind[:-1]
                out["key"] = key
                return out
    return None


def reverse_lookup(session_id: str) -> Optional[Dict[str, Any]]:
    """The pseudonym a real session id was given, if it has one."""
    key = str(session_id or "").strip()
    if not key:
        return None
    sessions = _load_map().get("sessions") or {}
    entry = sessions.get(key)
    if not isinstance(entry, dict):
        # Accept a unique prefix, the way every other oe command does.
        matches = [(k, v) for k, v in sessions.items()
                   if isinstance(v, dict) and k.startswith(key)]
        if len(matches) != 1:
            return None
        key, entry = matches[0]
    out = dict(entry)
    out["kind"] = "session"
    out["key"] = key
    return out


def local_session_info(session_id: str) -> Dict[str, Any]:
    """Whatever the local map knows about a session ({} when it knows nothing).

    Used by the terminal surfaces to put a human title back on a row whose
    cached artifact no longer carries one.
    """
    entry = (_load_map().get("sessions") or {}).get(str(session_id or ""))
    return dict(entry) if isinstance(entry, dict) else {}


# ---------------------------------------------------------------------------
# shape-preserving tokens for tool targets
# ---------------------------------------------------------------------------

# Binaries common enough that naming them says something about the workload and
# nothing about the person. Anything else collapses to 'other'.
_ARGV0_ALLOWED = frozenset({
    "git", "python3", "node", "npm", "pnpm", "ls", "cat", "grep", "find", "curl",
    "docker", "make", "sed", "awk", "jq", "dotnet", "java", "go", "cargo", "rg",
})
_FILE_TOOLS = frozenset({"Read", "Write", "Edit", "NotebookEdit", "MultiEdit"})
_SEARCH_TOOLS = frozenset({"Grep", "Glob"})
_WEB_TOOLS = frozenset({"WebFetch", "WebSearch"})
_EXT_RE = re.compile(r"^\.[A-Za-z0-9]{1,8}$")
_SPLIT_RE = re.compile(r"&&|\|\||;|\|")


def _argv0(command: str) -> str:
    """The binary a shell command runs, restricted to the allowlist.

    Real commands are routinely prefixed ('cd <dir> && git status'), and
    labelling all of those 'other' would empty the column of its meaning, so
    one hop past the first shell separator is tried before giving up. Only two
    tokens are ever considered, and neither is emitted unless allowlisted.
    """
    text = str(command or "").strip()
    if not text:
        return "other"
    segments = [seg.strip() for seg in _SPLIT_RE.split(text) if seg.strip()]
    for segment in segments[:2]:
        head = segment.split()[0] if segment.split() else ""
        head = head.rsplit("/", 1)[-1]
        if head in _ARGV0_ALLOWED:
            return head
    return "other"


def shape_of(tool: Any, target: Any) -> str:
    """A STATELESS description of what a target was, with no id and no value.

    ledger.py composes its prose with this so an insight sentence never has to
    be regex-scrubbed after the fact.
    """
    kind, detail = _classify(tool, target)
    if kind == "file":
        return f"a {detail} file" if detail else "a file"
    if kind == "command":
        return f"a `{detail}` command" if detail != "other" else "a shell command"
    if kind == "search":
        return "a code search"
    if kind == "web":
        return "a web fetch"
    return "a target"


def _classify(tool: Any, target: Any) -> Tuple[str, str]:
    """(kind, detail) for a target, deciding on the TOOL first.

    The tool name is authoritative and safe; the value is only consulted when
    the tool is unknown, and then only for its leading '/'.
    """
    name = str(tool or "")
    text = str(target or "")
    if name in _FILE_TOOLS:
        return "file", _ext_of(text)
    if name == "Bash":
        return "command", _argv0(text)
    if name in _SEARCH_TOOLS:
        return "search", ""
    if name in _WEB_TOOLS:
        return "web", ""
    if text.startswith("/") or text.startswith("./"):
        return "file", _ext_of(text)
    return "other", ""


def _ext_of(path: str) -> str:
    """A file extension, or '' when it is not obviously one.

    Bounded to short alphanumerics so a dotted filename fragment (which could
    carry a ticket id or a username) can never ride out as an 'extension'.
    """
    suffix = Path(str(path)).suffix.lower()
    return suffix if _EXT_RE.match(suffix) else ""


def _depth_of(path: str) -> int:
    return len([part for part in str(path).split("/") if part and part != "."])


def target_label(token: Any) -> str:
    """A one-line rendering of a shape token, for tables and prose."""
    if not isinstance(token, dict):
        return "-"
    kind = token.get("kind")
    ident = token.get("id") or ""
    if kind == "file":
        ext = token.get("ext") or "no ext"
        return f"{ext} file, depth {token.get('depth')} ({ident})"
    if kind == "command":
        return f"{token.get('argv0')} command ({ident})"
    if kind in ("search", "web", "other"):
        return f"{kind} ({ident})"
    return str(ident or "-")


# ---------------------------------------------------------------------------
# the redactor
# ---------------------------------------------------------------------------


class Redactor:
    """Per-report pseudonym allocator.

    Turn/call/agent/workflow/tool/target ordinals are scoped to ONE report:
    they only have to make the joins inside that document work ("this call
    belongs to that turn", "this file was read nine times"), and keeping them
    local means nothing about them is comparable across reports either.
    Session and project ordinals are persistent, because the dashboard has to
    join across sessions.
    """

    def __init__(self) -> None:
        self._turns: Dict[str, str] = {}
        self._calls: Dict[str, str] = {}
        self._agents: Dict[str, str] = {}
        self._workflows: Dict[str, str] = {}
        self._tool_uses: Dict[str, str] = {}
        self._targets: Dict[str, Dict[str, Any]] = {}
        self._target_counts: Dict[str, int] = {}

    # -- identifier pseudonyms ---------------------------------------------

    def _ordinal(self, store: Dict[str, str], raw: Any, prefix: str, width: int) -> Optional[str]:
        key = str(raw or "").strip()
        if not key:
            return None
        existing = store.get(key)
        if existing:
            return existing
        name = f"{prefix}{PSEUDONYM_SEP}{len(store) + 1:0{width}d}"
        store[key] = name
        return name

    def turn(self, prompt_id: Any) -> Optional[str]:
        return self._ordinal(self._turns, prompt_id, "turn", 2)

    def call(self, call_id: Any) -> Optional[str]:
        return self._ordinal(self._calls, call_id, "call", 4)

    def agent(self, agent_id: Any) -> Optional[str]:
        return self._ordinal(self._agents, agent_id, "agent", 2)

    def workflow(self, workflow_id: Any) -> Optional[str]:
        return self._ordinal(self._workflows, workflow_id, "workflow", 2)

    def tool_use(self, tool_use_id: Any) -> Optional[str]:
        return self._ordinal(self._tool_uses, tool_use_id, "tooluse", 4)

    def session(self, session_id: Any, **extra: Any) -> str:
        return session_pseudonym(session_id, **extra)

    def project(self, slug: Any) -> str:
        return project_pseudonym(slug)

    # -- targets ------------------------------------------------------------

    def target(self, tool: Any, value: Any) -> Optional[Dict[str, Any]]:
        """Shape token for a file path or shell command.

        Keyed on the raw value so the SAME target always gets the same id --
        that identity is the entire content of the redundant-work section, and
        it survives without the value ever being emitted.
        """
        raw = str(value or "")
        if not raw:
            return None
        cached = self._targets.get(raw)
        if cached is not None:
            return dict(cached)
        kind, detail = _classify(tool, raw)
        prefix = {"file": "path", "command": "cmd", "search": "search",
                  "web": "web"}.get(kind, "target")
        index = self._target_counts.get(prefix, 0) + 1
        self._target_counts[prefix] = index
        token: Dict[str, Any] = {"kind": kind, "id": f"{prefix}{PSEUDONYM_SEP}{index:02d}"}
        if kind == "file":
            token["ext"] = detail
            token["depth"] = _depth_of(raw)
        elif kind == "command":
            token["argv0"] = detail
        self._targets[raw] = token
        return dict(token)

    def counts(self) -> Dict[str, int]:
        return {
            "turns": len(self._turns),
            "calls": len(self._calls),
            "agents": len(self._agents),
            "workflows": len(self._workflows),
            "targets": len(self._targets),
        }


# ---------------------------------------------------------------------------
# the artifact schemas -- THE allowlist
# ---------------------------------------------------------------------------

# Copied through untouched. These carry NO nested dict a future field could hide
# in: two ints, two scalars, and a list of [epoch, usd] pairs.
#
# Everything else is projected field by field below. Naming a whole BLOCK here
# is a denylist wearing an allowlist's clothes: the block is copied by
# reference, so a key the ledger grows inside it ships on the next rebuild.
# `by_origin[...]["agents"]` is the concrete case -- it carries raw agent ids,
# which are literally the `agent-<id>.jsonl` filenames on disk.
_PASSTHROUGH_KEYS: Tuple[str, ...] = (
    "schema_version", "generated_at", "calls_truncated", "tools_truncated",
    "cost_series",
)

# -- the aggregate blocks, projected --------------------------------------
# Each list below is the union of that block's keys across the transcript
# shapes this tool parses, so nothing analytic is lost; anything the ledger
# adds later is dropped until it is added here on purpose.

_TOTALS_FIELDS: Tuple[str, ...] = (
    "calls", "requests_main", "requests_subagent", "requests_workflow",
    "input_tokens", "output_tokens", "thinking_tokens", "cache_write_5m_tokens",
    "cache_write_1h_tokens", "cache_write_tokens", "cache_read_tokens",
    "web_search_requests", "web_fetch_requests", "total_tokens",
    "billable_prompt_tokens", "input_usd", "output_usd", "cache_write_5m_usd",
    "cache_write_1h_usd", "cache_read_usd", "web_search_usd", "cost_usd",
    "errors", "aborted", "unpriced_calls", "tool_calls", "wall_seconds",
    "cost_usd_per_hour", "cost_usd_reported", "cost_usd_authoritative",
    "cost_usd_uncovered", "uncovered_calls", "cost_fully_reported",
)

_PARSE_FIELDS: Tuple[str, ...] = (
    "files_read", "bytes_read", "bad_lines", "load_seconds",
)

_WASTE_FIELDS: Tuple[str, ...] = (
    "error_calls", "error_tokens", "error_cost_usd", "tool_errors",
    "tool_error_pct",
)

_GROWTH_FIELDS: Tuple[str, ...] = (
    "tokens_per_turn", "per_call_tokens", "turns_until_full", "current_tokens",
    "max_tokens", "headroom_tokens", "resets", "major_resets", "samples",
    "turns_sampled",
)

_CACHE_FIELDS: Tuple[str, ...] = (
    "read_tokens", "write_tokens", "fresh_input_tokens", "hit_ratio",
    "cost_saved_vs_uncached_usd", "cost_paid_on_writes_usd",
    "cost_paid_on_reads_usd", "net_usd", "uncached_equivalent_usd",
)

_WINDOW_FIELDS: Tuple[str, ...] = (
    "ts", "model", "used_tokens", "max_tokens", "pct",
)

_SERIES_FIELDS: Tuple[str, ...] = (
    "ts", "context_tokens", "max_tokens", "pct", "turn_index",
)

_BY_MODEL_FIELDS: Tuple[str, ...] = (
    "model", "display_name", "tier", "context_window", "calls", "input_tokens",
    "output_tokens", "thinking_tokens", "cache_write_5m_tokens",
    "cache_write_1h_tokens", "cache_write_tokens", "cache_read_tokens",
    "web_search_requests", "total_tokens", "cost_usd", "input_usd",
    "output_usd", "cache_write_5m_usd", "cache_write_1h_usd", "cache_read_usd",
    "web_search_usd",
)

# `agents` is NOT here. It was a roster of raw agent ids -- high-entropy, stable,
# and the exact filename of a transcript on disk -- sitting next to the
# pseudonymised `expensive_agents` rows. `agent_count` is the number the report
# actually renders, and it is kept.
_BY_ORIGIN_FIELDS: Tuple[str, ...] = (
    "origin", "calls", "agent_count", "models", "input_tokens", "output_tokens",
    "thinking_tokens", "cache_write_5m_tokens", "cache_write_1h_tokens",
    "cache_write_tokens", "cache_read_tokens", "total_tokens", "cost_usd",
    "input_usd", "output_usd", "cache_write_5m_usd", "cache_write_1h_usd",
    "cache_read_usd", "web_search_usd",
)

_BY_TOOL_FIELDS: Tuple[str, ...] = (
    "name", "server", "count", "total_duration_ms", "timed_calls", "errors",
    "est_result_bytes", "max_result_bytes", "input_bytes", "avg_result_bytes",
    "avg_duration_ms",
)

_AGENT_TYPE_COST_FIELDS: Tuple[str, ...] = (
    "agent_type", "agents", "calls", "tokens", "cost_usd", "cost_per_agent_usd",
)

# reconciliation is dollars, counts and prose composed clean at source in
# ledger.py. Projected at its top level so a new sibling key cannot ride along;
# `diagnosis` stays because it is the explanation of the number.
_RECON_FIELDS: Tuple[str, ...] = (
    "computed_usd", "computed_usd_covered", "computed_usd_uncovered",
    "uncovered_calls", "runs", "reported_usd", "delta_usd", "delta_pct",
    "per_model", "per_kind", "missing_usd", "missing_usd_total", "origin_split",
    "status", "uncovered_share", "diagnosis", "cost_scale",
    "reported_api_duration_ms", "reported_tool_duration_ms",
    "reported_lines_added", "reported_lines_removed",
)

# session: everything identifying is dropped. cc_version stays -- it is API
# metadata and says nothing about the machine or the person.
_SESSION_FIELDS: Tuple[str, ...] = (
    "cc_version", "started_at", "last_activity", "wall_seconds",
    "primary_model", "turns", "agents", "workflows",
    # A label ('personal'/'work'/'unknown') and the name of the path that
    # produced it. oe/accounts.py keeps the email and the accountUuid in its
    # own state file and never puts either on a payload; account_evidence is a
    # generated sentence that can name an organisation, so it is NOT listed.
    "account_label", "account_source",
)

# by_turn / expensive_turns: prompt_preview is REMOVED, not truncated -- 60
# characters of a prompt is still the prompt. The turn keeps its index, so
# every join and every chart still works.
_TURN_FIELDS: Tuple[str, ...] = (
    "index", "first_ts", "calls", "tokens", "input_tokens", "output_tokens",
    "cache_read_tokens", "cache_write_tokens", "cost", "tools",
    "subagent_calls", "duration_s", "context_end_tokens",
    # Per-kind dollars, spelled out rather than imported, to match
    # _BY_MODEL_FIELDS and _BY_ORIGIN_FIELDS. All floats: no identifier shape
    # can hide in them. prompt_preview stays out, as above.
    "input_usd", "output_usd", "cache_write_5m_usd", "cache_write_1h_usd",
    "cache_read_usd", "web_search_usd", "main_cache_read_usd",
)

_AGENT_FIELDS: Tuple[str, ...] = (
    "agent_type", "spawn_depth", "calls", "tokens", "cost_usd", "output_tokens",
    "cache_read_tokens", "tools",
)

# name / summary / phases are all user-authored prose and all carry ticket ids.
_WORKFLOW_FIELDS: Tuple[str, ...] = (
    "status", "agent_count", "journal_total_tokens", "journal_tool_calls",
    "duration_ms",
)

_CALL_FIELDS: Tuple[str, ...] = (
    "ts", "model", "tier", "speed", "effort", "service_tier", "origin",
    "agent_type", "spawn_depth", "attribution_skill", "attribution_plugin",
    "attribution_mcp_server", "turn_index", "input_tokens", "output_tokens",
    "thinking_tokens", "cache_write_5m", "cache_write_1h", "cache_read",
    "web_search_requests", "web_fetch_requests", "context_tokens", "cost",
    "tools", "stop_reason", "is_error", "aborted", "unpriced", "total_usd",
    "total_tokens",
)

_TOOL_FIELDS: Tuple[str, ...] = (
    "name", "ts", "origin", "duration_ms", "is_error", "input_bytes",
    "result_bytes", "server", "turn_index",
)

_REDUNDANT_FIELDS: Tuple[str, ...] = (
    "tool", "count", "bytes", "distinct_callers", "wasted_bytes",
)

# The re-read ledger. Every figure is a count, a byte total or a dollar amount;
# the only field that could name anything is `path`, which redact_payload()
# replaces with the same shape token the redundant-work table uses -- so the
# per-file ranking survives the projection and the file names do not.
_REREAD_TOTALS_FIELDS: Tuple[str, ...] = (
    "reads", "files", "sessions", "bytes", "tokens", "first_reads", "first_bytes",
    "repeat_reads", "repeat_bytes", "repeat_pct", "repeat_pct_calls",
    "avoidable_reads", "avoidable_bytes", "legitimate_reads", "legitimate_bytes",
    "carry_usd", "repeat_carry_usd", "avoidable_carry_usd", "calibrated_usd",
    "repeat_calibrated_usd", "avoidable_calibrated_usd", "carry_requests_mean",
    "carry_rate_usd_per_1k_measured", "carry_rate_usd_per_1k_calibrated",
    "files_truncated", "distinct_files", "corpus_repeat_reads",
    "corpus_repeat_pct_calls", "corpus_repeat_bytes", "corpus_repeat_pct",
    "corpus_repeat_calibrated_usd",
)

_REREAD_FILE_FIELDS: Tuple[str, ...] = (
    "ext", "reads", "bytes", "tokens", "windows", "sessions",
    "first_reads", "first_bytes", "first_calibrated_usd",
    "repeat_reads", "repeat_bytes", "repeat_carry_usd", "repeat_calibrated_usd",
    "avoidable_reads", "avoidable_bytes", "avoidable_carry_usd",
    "avoidable_calibrated_usd", "carry_usd", "calibrated_usd", "reasons",
)

_REREAD_REASON_FIELDS: Tuple[str, ...] = (
    "reason", "reads", "bytes", "tokens", "carry_usd", "calibrated_usd",
)

_REREAD_GUARD_FIELDS: Tuple[str, ...] = (
    "would_block", "correct_blocks", "false_blocks", "false_block_pct",
    "allowed", "saved_carry_usd", "saved_calibrated_usd", "saved_bytes",
)

_COMPACTION_FIELDS: Tuple[str, ...] = (
    "ts", "iso", "event", "trigger", "has_custom_instructions", "model",
    "context_tokens", "max_tokens", "pct", "source", "transcript_bytes",
    # Token counts of the window either side of a compaction. Same class as
    # context_tokens/max_tokens above -- pure integers, no path, no identifier.
    # Their absence made the compaction lever structurally blind: it prices
    # itself on preTokens, and redaction removed them before it could look.
    "pre_tokens", "post_tokens", "preTokens", "postTokens",
    "cumulative_dropped_tokens",
)

# One scan row on the dashboard. Titles, paths and slugs are gone; the numbers,
# the timestamps and the cost provenance flags all stay.
_SCAN_ROW_FIELDS: Tuple[str, ...] = (
    "context_tokens", "max_tokens", "cost_usd", "cost_known", "cost_partial",
    "cost_source", "cost_is_estimate", "cost_computed_usd", "cost_reported_usd",
    "cost_uncovered_usd", "uncovered_calls", "cost_runs", "cost_by_day",
    "cost_by_model", "cost_cached", "cost_stale", "unpriced_calls",
    "total_tokens", "model", "speed", "effort", "calls", "calls_partial",
    "started_at", "source", "mtime", "transcript_mtime", "last_active",
    "local_day", "size_bytes", "is_active", "context_pct",
    "account_label", "account_source",
)


def _pick(row: Any, fields: Sequence[str]) -> Dict[str, Any]:
    """Build a new dict from an explicit field list. Absent fields stay absent."""
    if not isinstance(row, dict):
        return {}
    return {name: row[name] for name in fields if name in row}


def _error_status(value: Any) -> Any:
    """Keep an HTTP status, drop an error body.

    apiErrorStatus is usually an int, but Claude Code sometimes puts a message
    there and a provider message can quote the request -- so anything that is
    not a small integer becomes a bare 'error'.
    """
    if value is None or value is False:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return "error"


def redact_call(call: Dict[str, Any], red: Redactor) -> Dict[str, Any]:
    """One API request row, allowlisted and pseudonymised."""
    out = _pick(call, _CALL_FIELDS)
    # Keyed on request_id FIRST: that is the field a ToolCall carries, so it is
    # the only key on which the tools table and the calls table still join. The
    # transcript line uuid is the fallback for a call that has no request id.
    out["call"] = red.call(call.get("request_id") or call.get("uuid"))
    out["turn"] = red.turn(call.get("prompt_id"))
    out["agent"] = red.agent(call.get("agent_id"))
    out["workflow"] = red.workflow(call.get("workflow_id"))
    out["error_status"] = _error_status(call.get("error_status"))
    return out


def _redact_tool(tool: Dict[str, Any], red: Redactor) -> Dict[str, Any]:
    out = _pick(tool, _TOOL_FIELDS)
    out["tooluse"] = red.tool_use(tool.get("tool_use_id"))
    out["call"] = red.call(tool.get("request_id"))
    out["turn"] = red.turn(tool.get("prompt_id"))
    out["agent"] = red.agent(tool.get("agent_id"))
    out["target"] = red.target(tool.get("name"), tool.get("target"))
    return out


def redact_rereads(block: Any, red: Redactor) -> Dict[str, Any]:
    """The re-read ledger, projected. Paths become shape tokens.

    The token comes from the SAME Redactor as the redundant-work table, and
    Redactor.target() is memoised on the raw value, so path_07 in this section
    is path_07 in that one and the two tables still join.
    """
    if not isinstance(block, dict):
        return {}
    out = _pick(block, _REREAD_TOTALS_FIELDS)
    out["files_ranked"] = [
        dict(_pick(row, _REREAD_FILE_FIELDS), target=red.target("Read", row.get("path")))
        for row in (block.get("files_ranked") or []) if isinstance(row, dict)]
    out["by_reason"] = [_pick(row, _REREAD_REASON_FIELDS)
                        for row in (block.get("by_reason") or []) if isinstance(row, dict)]
    out["guard"] = _pick(block.get("guard"), _REREAD_GUARD_FIELDS)
    return out


def ensure_redacted(payload: Dict[str, Any]) -> Dict[str, Any]:
    """redact_payload() unless the payload already carries a redaction stamp.

    Makes the renderers safe to call directly with either shape, and makes
    redaction idempotent so a re-render cannot renumber anything.
    """
    if isinstance(payload, dict) and isinstance(payload.get("redaction"), dict):
        return payload
    return redact_payload(payload)


def redact_payload(payload: Dict[str, Any],
                   red: Optional[Redactor] = None) -> Dict[str, Any]:
    """data.json, rebuilt field by field from the schemas above.

    Everything not named in a schema is dropped, including anything the ledger
    grows later. That is the safety property; a missing new field shows up as
    an absent column, never as a leak.
    """
    src = payload or {}
    red = red or Redactor()
    session = src.get("session") or {}
    # Note the real identity locally BEFORE dropping it, so `oe whois` works.
    pseudonym = record_local(
        session.get("session_id"),
        title=session.get("title") or session.get("last_prompt"),
        project=session.get("project"),
        project_display=session.get("project_display"),
        transcript_path=session.get("transcript_path"),
        started_at=session.get("started_at"),
    )

    out: Dict[str, Any] = {name: src[name] for name in _PASSTHROUGH_KEYS if name in src}

    # The aggregate blocks, projected field by field rather than copied whole.
    for name, fields in (("totals", _TOTALS_FIELDS), ("parse", _PARSE_FIELDS),
                         ("waste", _WASTE_FIELDS), ("context_growth", _GROWTH_FIELDS),
                         ("cache_efficiency", _CACHE_FIELDS),
                         ("context_window", _WINDOW_FIELDS),
                         ("reconciliation", _RECON_FIELDS)):
        if name in src:
            out[name] = _pick(src.get(name), fields)
    for name, fields in (("by_model", _BY_MODEL_FIELDS), ("by_origin", _BY_ORIGIN_FIELDS),
                         ("by_tool", _BY_TOOL_FIELDS)):
        if name in src:
            block = src.get(name) or {}
            out[name] = {key: _pick(row, fields) for key, row in block.items()
                         if isinstance(row, dict)} if isinstance(block, dict) else {}
    if "agent_type_costs" in src:
        out["agent_type_costs"] = [_pick(row, _AGENT_TYPE_COST_FIELDS)
                                   for row in (src.get("agent_type_costs") or [])
                                   if isinstance(row, dict)]
    if "context_series" in src:
        out["context_series"] = [_pick(row, _SERIES_FIELDS)
                                 for row in (src.get("context_series") or [])
                                 if isinstance(row, dict)]

    out["session"] = dict(_pick(session, _SESSION_FIELDS),
                          id=pseudonym,
                          project=project_pseudonym(session.get("project")))

    out["by_turn"] = [dict(_pick(row, _TURN_FIELDS), turn=red.turn(row.get("prompt_id")))
                      for row in (src.get("by_turn") or []) if isinstance(row, dict)]
    out["expensive_turns"] = [
        dict(_pick(row, _TURN_FIELDS), turn=red.turn(row.get("prompt_id")))
        for row in (src.get("expensive_turns") or []) if isinstance(row, dict)]

    out["expensive_agents"] = [
        dict(_pick(row, _AGENT_FIELDS),
             agent=red.agent(row.get("agent_id")),
             workflow=red.workflow(row.get("workflow_id")))
        for row in (src.get("expensive_agents") or []) if isinstance(row, dict)]

    out["workflows"] = [
        dict(_pick(row, _WORKFLOW_FIELDS), workflow=red.workflow(row.get("workflow_id")))
        for row in (src.get("workflows") or []) if isinstance(row, dict)]

    out["redundant_work"] = [
        dict(_pick(row, _REDUNDANT_FIELDS),
             target=red.target(row.get("tool"), row.get("target")))
        for row in (src.get("redundant_work") or []) if isinstance(row, dict)]

    if "rereads" in src:
        out["rereads"] = redact_rereads(src.get("rereads"), red)

    out["compactions"] = [
        dict(_pick(row, _COMPACTION_FIELDS),
             turn=red.turn(row.get("prompt_id")), agent=red.agent(row.get("agent_id")))
        for row in (src.get("compactions") or []) if isinstance(row, dict)]

    out["calls"] = [redact_call(row, red) for row in (src.get("calls") or [])
                    if isinstance(row, dict)]
    out["top_calls"] = [redact_call(row, red) for row in (src.get("top_calls") or [])
                        if isinstance(row, dict)]
    out["tools"] = [_redact_tool(row, red) for row in (src.get("tools") or [])
                    if isinstance(row, dict)]

    # THE ONE UNPROJECTED SURFACE. insights is free prose, so there is no field
    # list that could filter it -- it is composed clean at source in ledger.py
    # (every sentence there interpolates numbers, tool names and
    # redact.shape_of() targets, never a path, a title or a prompt) and copied,
    # never regex-scrubbed. audit() is therefore the ONLY control on this list:
    # a new insight sentence that interpolates a raw value ships unless the
    # audit happens to recognise its shape. Any new sentence in
    # SessionLedger.insights() has to be written with that in mind.
    out["insights"] = [str(line) for line in (src.get("insights") or [])]

    out["redaction"] = {
        "version": REDACTION_VERSION,
        "policy": "allowlist",
        "note": REDACTION_NOTE,
        "pseudonyms": red.counts(),
    }
    return out


def redact_row_json(payload: Dict[str, Any]) -> Dict[str, Any]:
    """row.json: the few fields the session scan reads back, all of them safe.

    session_id/slug/title are gone. The scan puts the session id back from the
    transcript filename it is already holding, and the terminal puts the title
    back from the local map, so nothing downstream loses anything.
    """
    session = payload.get("session") or {}
    totals = payload.get("totals") or {}
    window = payload.get("context_window") or {}

    def _int(value: Any) -> int:
        try:
            return int(value or 0)
        except (TypeError, ValueError):
            return 0

    return {
        "schema_version": payload.get("schema_version"),
        "session": session.get("id"),
        "project": session.get("project"),
        "context_tokens": _int(window.get("used_tokens")),
        "max_tokens": _int(window.get("max_tokens")),
        "cost_usd": float(totals.get("cost_usd_authoritative") or 0.0),
        "total_tokens": _int(totals.get("total_tokens")),
        "model": session.get("primary_model"),
        "calls": _int(totals.get("calls")),
        "started_at": session.get("started_at"),
    }


def redact_scan_row(row: Dict[str, Any]) -> Dict[str, Any]:
    """One row of sessions.json / one row of the dashboard table."""
    if not isinstance(row, dict):
        return {}
    out = _pick(row, _SCAN_ROW_FIELDS)
    out["session"] = session_pseudonym(
        row.get("session_id"),
        title=row.get("title"),
        project=row.get("project"),
        transcript_path=row.get("transcript_path"),
    ) if row.get("session_id") else None
    out["project"] = project_pseudonym(row.get("project")) if row.get("project") else None
    return out


def redact_scan_rows(rows: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return [redact_scan_row(row) for row in (rows or [])]


def redact_rollup(rollup: Dict[str, Any]) -> Dict[str, Any]:
    """daily_rollup() with its by_project keys replaced by project pseudonyms."""
    if not isinstance(rollup, dict):
        return {}
    out = dict(rollup)
    by_project = rollup.get("by_project") or {}
    if isinstance(by_project, dict):
        merged: Dict[str, float] = {}
        for slug, value in by_project.items():
            name = project_pseudonym(slug)
            merged[name] = merged.get(name, 0.0) + float(value or 0.0)
        out["by_project"] = merged
    return out


# ---------------------------------------------------------------------------
# CLI REDACTION -- one policy, applied to every byte the CLI emits
#
# The reports have been allowlist-built and audited for a while; the TERMINAL
# was the hole. `oe status`, `oe sessions`, `oe doctor` and a traceback all
# print absolute home paths, project names, session uuids and branch names --
# and terminal output is precisely what gets screenshotted into a ticket and
# pasted into a chat. So the rule is about DESTINATION, not about the command:
#
#     stdout IS a tty   -> the operator is reading it themselves; show detail.
#     stdout is NOT a tty -> it is being piped, redirected, captured by CI or
#                            copied into a bug report; REDACT.
#
# It is enforced by wrapping sys.stdout/sys.stderr rather than by editing every
# print(), because a policy that every print() in the codebase has to remember
# is a policy that leaks the first time somebody adds a line. sys.excepthook is
# wrapped for the same reason: a traceback quoting an absolute home path is a
# leak that no print() audit would ever have covered.
# ---------------------------------------------------------------------------

ENV_REDACT = "OE_REDACT"
CONFIG_KEY_REDACT = "redact_cli"  # auto | always | never

_TRUE = {"1", "true", "yes", "on", "always", "redact"}
_FALSE = {"0", "false", "no", "off", "never", "raw"}

# Set by the --redact / --no-redact flags. None = no explicit choice.
_cli_override: Optional[bool] = None


def set_cli_redaction(value: Optional[bool]) -> None:
    """Called once by the CLI for --redact / --no-redact. None restores policy."""
    global _cli_override
    _cli_override = value


def _config_policy() -> str:
    try:
        value = str(paths.load_config().get(CONFIG_KEY_REDACT) or "auto").strip().lower()
    except Exception:
        return "auto"
    return value if value in ("auto", "always", "never") else "auto"


def cli_redaction_enabled(stream: Any = None) -> bool:
    """Should output to `stream` be redacted? Precedence, highest first:

      1. --redact / --no-redact on the command line
      2. OE_REDACT in the environment
      3. redact_cli in config.json (auto | always | never)
      4. auto: redact whenever the stream is not a terminal

    Never raises. A stream that cannot answer isatty() is treated as NOT a
    terminal, which is the safe direction: it redacts.
    """
    if _cli_override is not None:
        return _cli_override
    env = str(os.environ.get(ENV_REDACT) or "").strip().lower()
    if env in _TRUE:
        return True
    if env in _FALSE:
        return False
    # Any other OE_REDACT value (including "auto") defers to config.json.
    policy = _config_policy()
    if policy == "always":
        return True
    if policy == "never":
        return False
    stream = stream if stream is not None else sys.stdout
    try:
        return not bool(stream.isatty())
    except Exception:
        return True


def redaction_reason(stream: Any = None) -> str:
    """One line explaining the decision, for `oe doctor` and the header note."""
    if _cli_override is not None:
        return "--redact" if _cli_override else "--no-redact"
    env = str(os.environ.get(ENV_REDACT) or "").strip().lower()
    if env in _TRUE or env in _FALSE:
        return f"{ENV_REDACT}={env}"
    policy = _config_policy()
    if policy in ("always", "never"):
        return f"config.json {CONFIG_KEY_REDACT}={policy}"
    stream = stream if stream is not None else sys.stdout
    try:
        tty = bool(stream.isatty())
    except Exception:
        tty = False
    return "stdout is a terminal" if tty else "stdout is not a terminal"


# A project needle shorter than this is not evidence of anything and is far
# too likely to appear inside an unrelated word.
_MIN_PROJECT_NEEDLE = 6

# Path segments that are structure, not identity. Substituting these would
# rewrite half of every path on screen and tell a reader nothing.
_GENERIC_PATH_SEGMENTS = frozenset({
    "home", "users", "user", "tmp", "var", "opt", "src", "srv", "mnt",
    "documents", "desktop", "downloads", "projects", "project", "repos",
    "code", "workspace", "work", "dev", "git", "github", "source",
    "library", "application support", ".claude", "claude",
})

_SCRUB_CACHE: Dict[str, Any] = {"key": None, "rules": None}


def _hash_token(kind: str, value: str) -> str:
    """A short, stable, non-invertible stand-in for an identifier we have no
    pseudonym for. Stable so the same id reads as the same thing twice in one
    screenshot; truncated so it carries no recoverable content."""
    digest = hashlib.blake2b(value.encode("utf-8", "replace"), digest_size=4).hexdigest()
    return f"<{kind}-{digest}>"


def _account_token(address: str) -> str:
    """An email becomes its ACCOUNT LABEL and nothing else -- 'primary',
    'work', whatever this machine calls it. The label is the useful part
    (which account was this?); the address is the part that identifies a human.
    """
    try:
        from . import accounts  # lazy: accounts imports this module
        label = accounts.label_for_email(address)
    except Exception:
        label = ""
    label = str(label or "").strip() or "unknown"
    return f"<account:{label}>"


def _scrub_rules() -> List[Tuple[Any, Any]]:
    """(pattern, replacement) pairs, longest-literal first. Rebuilt when the
    environment that feeds them changes."""
    try:
        key = "|".join([
            str(Path.home()), str(os.environ.get("USER") or ""),
            str(os.environ.get(ENV_REDACT) or ""),
        ])
    except Exception:
        key = ""
    if _SCRUB_CACHE.get("key") == key and _SCRUB_CACHE.get("rules") is not None:
        return _SCRUB_CACHE["rules"]

    rules: List[Tuple[Any, Any]] = []

    # 1. Project slugs AND the paths they came from -> the pseudonym the reports
    #    already use, so a redacted terminal line and a report page name the same
    #    project. FIRST, before home and username: those rewrite the middle of
    #    '-home-<name>-<repo>' and of '/home/<name>/<repo>', and the exact-match
    #    lookup would then miss. The repo name is the giveaway here -- it names
    #    the employer.
    #
    #    Two guards, both load-bearing: a needle must be at least
    #    _MIN_PROJECT_NEEDLE characters (the map can hold junk like 'v' and
    #    '/dev' from a rehearsal, and substituting those turned
    #    'overwatch-enforcer' into 'oproject_08erwatch-enforcer'), and it must
    #    not itself be a pseudonym (a map that ever pseudonymised a pseudonym
    #    would otherwise rewrite the output of an earlier pass). Longest first,
    #    so '/a/b/c' wins over '/a/b'.
    projects_seen = 0
    try:
        needles: List[Tuple[str, str]] = []
        for slug, entry in (_load_map().get("projects") or {}).items():
            projects_seen += 1
            name = (entry or {}).get("pseudonym") if isinstance(entry, dict) else None
            if not slug or not name:
                continue
            display = (entry or {}).get("display") if isinstance(entry, dict) else None
            candidates = [str(slug), str(display or "")]
            # Plus the LAST path segment of the project directory -- the
            # repository name. A table cell is clipped before it is printed
            # ('…ome/<user>/<repo>'), so by the time the text reaches the
            # stream the full path is gone and the repo name is all that is
            # left of it -- and the repo name is the word in that line that
            # names the employer. Last segment only: an intermediate one is
            # usually the home directory, and mapping a USERNAME to a project
            # pseudonym would be both wrong and confusing.
            segment = str(display or "").strip("/").rsplit("/", 1)[-1]
            if (segment.lower() not in _GENERIC_PATH_SEGMENTS
                    and segment.lower() not in set(_user_needles())):
                candidates.append(segment)
            for candidate in candidates:
                if (len(candidate) >= _MIN_PROJECT_NEEDLE
                        and not _PSEUDONYM_RE.match(candidate.lstrip("/-"))):
                    needles.append((candidate, str(name)))
        for needle, name in sorted(set(needles), key=lambda kv: -len(kv[0])):
            rules.append((re.compile(r"(?<![A-Za-z0-9])" + re.escape(needle)
                                     + r"(?![A-Za-z0-9])"), name))
    except Exception:
        pass

    # 2. This machine's own home directory.
    try:
        home = str(Path.home()).rstrip("/")
        if len(home) > 3:
            rules.append((re.compile(re.escape(home) + r"(?=/|\b)"), "~"))
    except Exception:
        pass

    # 3. Anybody ELSE's home directory, including the /Users form macOS uses.
    rules.append((re.compile(r"/(home|Users)/[A-Za-z0-9._-]+"), r"/\1/<user>"))

    # 4. The username as a bare token, wherever it appears ('<name>-laptop').
    #
    #    Matched by the SAME rule the write gate uses (_needle_offsets), not by
    #    a bare substring. Two reasons, and the second is the important one:
    #    a substring rewrite turned 'max_tokens' into '<user>_tokens' and
    #    'origin/main' into 'origin/<user>' on any machine whose account is a
    #    short common word; and if the scrubber and the gate disagreed about
    #    what counts as the username, a line could pass one and be rewritten by
    #    the other, which is how you get two different answers to "is this
    #    redacted?" in the same process.
    for needle in _user_needles():
        if needle not in _GENERIC_USERNAMES:
            rules.append((_NeedleRule(needle), "<user>"))

    # 5. The hostname -- it names the machine and often the person.
    try:
        host = socket.gethostname()
        if len(host) >= 4:
            rules.append((re.compile(re.escape(host), re.I), "<host>"))
            short = host.split(".")[0]
            if len(short) >= 4 and short != host:
                rules.append((re.compile(re.escape(short), re.I), "<host>"))
    except Exception:
        pass

    # 6. Emails -> the account LABEL.
    rules.append((re.compile(r"[\w.+-]+@[\w-]+\.[\w.]{2,}"),
                  lambda m: _account_token(m.group(0))))

    # 7. UUIDs -> the session pseudonym when we know it, a stable hash when not.
    #    Lookup only: printing a line must never MINT a pseudonym, or the map
    #    would grow an entry for every uuid that ever crossed the terminal.
    def _uuid_repl(match: "re.Match") -> str:
        raw = match.group(0)
        try:
            entry = (_load_map().get("sessions") or {}).get(raw)
            name = (entry or {}).get("pseudonym") if isinstance(entry, dict) else None
            if name:
                return str(name)
        except Exception:
            pass
        return _hash_token("id", raw)

    rules.append((_UUID_RE, _uuid_repl))

    # 8. Branch names and ticket ids: both name the work, which names the
    #    employer and often the customer.
    rules.append((re.compile(r"\b(feature|fix|chore|hotfix|release|bugfix)/[\w.:/-]+", re.I),
                  "<branch>"))

    def _ticket_repl(match: "re.Match") -> str:
        value = match.group(0)
        # Same shape rule the write gate uses: a model id is not an issue key,
        # including one this build's pricing catalog has never heard of. Without
        # this an unknown model printed as 'claude-<ticket>', so the one warning
        # that fires about it could not name the model it was warning about.
        if _model_prefixed(match.string, match.start()):
            return value
        return value if value.lower() in _safe_ticket_shapes() else "<ticket>"

    rules.append((_TICKET_RE, _ticket_repl))
    rules.append((re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])"), "<ip>"))

    # Do NOT cache a ruleset built without the project map.
    #
    # The project rule is the one that turns the repository name -- the word
    # that names the employer -- into project_NN, and it is the ONLY rule that
    # needs a file. If session-map.json is momentarily unreadable (a concurrent
    # write, a permission blip, a state dir not yet created) the block above
    # silently produces no needles, and caching that answer would leak the repo
    # name for the rest of the process even after the file came back. With the
    # map unreadable, `oe audit` prints '~/<repo>/.claude/reports/usage' where it
    # should print 'project_01/.claude/reports/usage'. Costs one rebuild per call
    # in the degraded case and nothing at all in the normal one.
    if projects_seen or not map_path().exists():
        _SCRUB_CACHE["key"] = key
        _SCRUB_CACHE["rules"] = rules
    return rules


def scrub(text: str) -> str:
    """Apply the CLI redaction policy to one piece of text. Never raises:
    failing to scrub must degrade to printing nothing sensitive, so on error we
    return a placeholder rather than the raw text."""
    if not text:
        return text
    try:
        out = str(text)
        for pattern, repl in _scrub_rules():
            out = pattern.sub(repl, out)
        return out
    except Exception:
        return "<redaction failed; output suppressed>"


class _ScrubbedStream:
    """A text stream that applies scrub() to whole lines on the way out.

    Line-buffered on purpose: an identifier written across two write() calls
    (print() emits the text and the newline separately) would not match any
    pattern if each fragment were scrubbed alone. Everything up to the last
    newline is scrubbed and forwarded; the tail waits for its newline or for an
    explicit flush().
    """

    def __init__(self, wrapped: Any) -> None:
        self._wrapped = wrapped
        self._buffer = ""

    def write(self, text: Any) -> int:
        text = "" if text is None else str(text)
        if not text:
            return 0
        self._buffer += text
        if "\n" in self._buffer:
            head, _, tail = self._buffer.rpartition("\n")
            self._buffer = tail
            self._wrapped.write(scrub(head + "\n"))
        return len(text)

    def flush(self) -> None:
        if self._buffer:
            pending, self._buffer = self._buffer, ""
            self._wrapped.write(scrub(pending))
        try:
            self._wrapped.flush()
        except Exception:
            pass

    def isatty(self) -> bool:
        try:
            return bool(self._wrapped.isatty())
        except Exception:
            return False

    def fileno(self) -> int:
        return self._wrapped.fileno()

    def raw(self) -> Any:
        """The unwrapped stream underneath, after draining the line buffer.

        Draining first is what keeps order: this class buffers up to the last
        newline, so writing past it while a partial line is still held would put
        the two pieces on the wire in the wrong order.
        """
        self.flush()
        return self._wrapped

    def __getattr__(self, name: str) -> Any:
        return getattr(self._wrapped, name)


def write_verbatim(text: str, stream: Any = None) -> None:
    """Write `text` to a stream WITHOUT the CLI scrubber, in order.

    There is exactly one thing this is for: the file CONTENT that `oe find`,
    `oe slice` and `oe deps` print. Those commands exist to be a cheaper
    substitute for reading a file, and docs/privacy.md promises in bold that
    the contents come back verbatim, piped or not. The stream scrubber does not
    know a printed line of Python from a printed path, so with stdout not a
    terminal -- which is every caller running these through a shell -- it would
    rewrite the source on the way out: `r"^[a-z0-9-]+$"` comes back as
    `r"^[a-<ticket>-]+$"`, `AES-256-GCM` as `<ticket>-GCM`, and three distinct
    dict keys collapse onto one. Handing somebody altered source that they are
    about to edit is a worse outcome than any of the leaks the scrubber exists
    to stop, and the content is the user's own file, which they can already read.

    Everything AROUND the content -- the header line, the paths, the ratio
    footer -- still goes through the scrubber. Only the body bypasses it.
    """
    target = stream if stream is not None else sys.stdout
    seen = 0
    while isinstance(target, _ScrubbedStream) and seen < 8:
        target = target.raw()
        seen += 1
    try:
        target.write(text)
    except Exception:
        pass


def install_cli_redaction(force: Optional[bool] = None) -> bool:
    """Wrap stdout/stderr (and sys.excepthook) if the policy says to redact.

    Returns whether redaction is now active. Idempotent -- calling it twice does
    not stack two wrappers.
    """
    if force is not None:
        set_cli_redaction(force)
    active = cli_redaction_enabled(sys.stdout)
    if not active:
        return False
    if not isinstance(sys.stdout, _ScrubbedStream):
        sys.stdout = _ScrubbedStream(sys.stdout)
    if not isinstance(sys.stderr, _ScrubbedStream):
        sys.stderr = _ScrubbedStream(sys.stderr)

    previous = sys.excepthook

    def hook(exc_type, exc, tb):
        # A traceback is the single richest leak in the tool: every frame quotes
        # an absolute path, and the message often quotes the file that failed.
        try:
            import traceback
            text = "".join(traceback.format_exception(exc_type, exc, tb))
            sys.stderr.write(scrub(text))
            sys.stderr.flush()
        except Exception:
            previous(exc_type, exc, tb)

    if getattr(sys.excepthook, "_oe_scrubbed", False) is not True:
        hook._oe_scrubbed = True  # type: ignore[attr-defined]
        sys.excepthook = hook
    return True
