"""Filesystem layout resolution for Overwatch Enforcer.

Everything else in the package asks this module where things live, so that the
install root, the reports root and the transcript layout are stated exactly
once. Nothing here may raise: the statusline and the PostToolUse hook call into
it on every invocation and a traceback there would surface inside the user's
session.
"""

from __future__ import annotations

import functools
import itertools
import json
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

# Disambiguates two atomic_write() calls from the same process (the watcher
# writes five files per rebuild); the pid disambiguates across processes.
_TMP_SEQ = itertools.count()

# --------------------------------------------------------------------------
# Where we are, and where Claude Code is. Both DERIVED, never literal.
#
# A hardcoded install root is the single thing that makes a tool unshareable:
# it is correct on exactly one machine and silently wrong on every other. This
# module resolves both roots from facts available at import time, so the same
# checkout works for another person, under another username, on macOS or Linux,
# checked out anywhere.
# --------------------------------------------------------------------------

ENV_INSTALL_ROOT = "OE_INSTALL_ROOT"
ENV_CLAUDE_HOME = "CLAUDE_CONFIG_DIR"  # Claude Code's own override (verified in 2.1.265)


def _resolve_install_root() -> Path:
    """The directory holding this package -- i.e. the checkout we are running from.

    `Path(__file__).resolve().parents[1]` is the answer in every normal case, and
    resolve() means a symlinked bin/oe still lands on the real tree. The env
    override exists for the one case __file__ cannot answer: a hook spawned with
    a copied-out script.
    """
    override = os.environ.get(ENV_INSTALL_ROOT)
    if override:
        try:
            return Path(override).expanduser().resolve()
        except Exception:
            pass
    try:
        return Path(__file__).resolve().parents[1]
    except Exception:  # pragma: no cover - __file__ always exists for a module
        return Path.cwd()


def _resolve_claude_home() -> Path:
    """~/.claude, honouring Claude Code's own CLAUDE_CONFIG_DIR.

    Home comes from Path.home(), which reads $HOME first and falls back to the
    password database -- so a test harness can point the whole tool at a
    throwaway HOME with one environment variable, and a machine whose user is
    not the one who packaged the tree works without an edit.
    """
    override = os.environ.get(ENV_CLAUDE_HOME)
    if override:
        try:
            return Path(override).expanduser()
        except Exception:
            pass
    try:
        return Path.home() / ".claude"
    except Exception:  # pragma: no cover - no HOME and no passwd entry
        return Path(os.path.expanduser("~")) / ".claude"


INSTALL_ROOT = _resolve_install_root()
CLAUDE_HOME = _resolve_claude_home()
PROJECTS_ROOT = CLAUDE_HOME / "projects"
# Portable default: beside Claude Code's own config, NOT inside somebody's
# work checkout. A per-machine choice belongs in config.json, not in code.
DEFAULT_REPORTS = CLAUDE_HOME / "reports" / "usage"
# Machine-local and OPTIONAL: the repository tracks config.example.json and not
# this file, because it holds one machine's reports_root -- tracking it would
# publish a local path and make `git pull` abort on a dirty tree. A clone that
# never creates one is fully supported; load_config() below simply returns
# DEFAULT_CONFIG.
CONFIG_PATH = INSTALL_ROOT / "config.json"

# Runtime state lives beside the CODE, never under reports_root(). The reports
# root is the directory the user hands to somebody else; state_dir() holds the
# file that undoes every pseudonym in it (session-map.json), the account address
# and a cost cache full of absolute paths and session titles. While the two were
# nested, `tar -czf report.tgz .` of the reports folder shipped the key along
# with the lock -- roughly a quarter of that archive was state, session-map.json
# included. Separating the trees is what makes that impossible rather than
# merely documented; the same tar now contains no state files at all.
STATE_ROOT = INSTALL_ROOT / "state"
LEGACY_STATE_DIRNAME = ".state"

# Every path helper below derives from reports_root(), so this one environment
# variable is the only handle a caller needs to relocate the entire runtime
# tree. The watcher exports it into the daemon it spawns when start() is given
# an explicit reports_root, and the test harness uses it to run against a
# throwaway directory without touching the user's real reports. It deliberately
# does NOT move state_dir() any more: a relocated reports tree is usually one
# somebody is about to share, which is the last place state belongs. Use
# ENV_STATE_DIR to isolate state as well.
ENV_REPORTS_ROOT = "OE_REPORTS_ROOT"
ENV_STATE_DIR = "OE_STATE_DIR"

DEFAULT_CONFIG: Dict[str, Any] = {
    "reports_root": str(DEFAULT_REPORTS),
    "refresh_seconds": 5,
    "idle_exit_seconds": 1800,
    "currency": "USD",
    "budget": {"session_usd": 25.0, "daily_usd": 150.0, "warn_pct": 80},
    "scan": {
        "active_within_seconds": 900,
        "tail_bytes": 262144,
        "head_bytes": 65536,
        "max_sessions": 500,
    },
    "insights": {
        "top_turns": 8,
        "top_tools": 12,
        "top_subagents": 8,
        "reread_threshold": 3,
        "large_result_bytes": 40000,
    },
    "report": {"include_raw_calls": True, "max_raw_calls": 4000},
    # Account labelling is SELF-CONFIGURING: the first account this tool ever
    # sees becomes "primary", every later one "secondary", and the map lives in
    # state/accounts.json where it can be renamed. There is deliberately no
    # address here -- a literal email in a shipped config is somebody else's
    # identity baked into your machine. See oe/accounts.py.
    "accounts": {},
    # CLI redaction policy. "auto" = redact whenever stdout is not a TTY,
    # because output that leaves the terminal is output that gets shared.
    "redact_cli": "auto",  # auto | always | never
}


def _deep_merge(base: Dict[str, Any], over: Dict[str, Any]) -> Dict[str, Any]:
    out = dict(base)
    for key, value in (over or {}).items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = _deep_merge(out[key], value)
        else:
            out[key] = value
    return out


def load_config() -> Dict[str, Any]:
    """Config with defaults filled in. Never raises -- a corrupt config.json
    must degrade to defaults rather than break the user's status line."""
    try:
        raw = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
        if not isinstance(raw, dict):
            raw = {}
    except Exception:
        raw = {}
    return _deep_merge(DEFAULT_CONFIG, raw)


_REPORTS_FALLBACK: Dict[str, Any] = {"checked": None, "usable": True}


def _usable_root(root: Path) -> bool:
    """Can we actually write reports here? Memoised per process, per path.

    This exists because config.json travels with the checkout. A reports_root
    that names somebody else's machine ('~/work/.claude/reports' under a home
    that is not yours, '/home/someone/...' on a Mac where /home is autofs) is not a
    misconfiguration the user made -- it is one they INHERITED -- and silently
    writing nothing, or throwing out of the status line, is the worst possible
    answer. Falling back to the portable default is the right one.
    """
    key = str(root)
    if _REPORTS_FALLBACK.get("checked") == key:
        return bool(_REPORTS_FALLBACK.get("usable"))
    usable = True
    try:
        if root.is_dir():
            usable = os.access(str(root), os.W_OK)
        else:
            root.mkdir(parents=True, exist_ok=True)
            usable = os.access(str(root), os.W_OK)
    except Exception:
        usable = False
    _REPORTS_FALLBACK["checked"] = key
    _REPORTS_FALLBACK["usable"] = usable
    return usable


def reports_root() -> Path:
    override = os.environ.get(ENV_REPORTS_ROOT)
    if override:
        try:
            return Path(override).expanduser()
        except Exception:
            pass
    cfg = load_config()
    try:
        root = Path(str(cfg.get("reports_root") or DEFAULT_REPORTS)).expanduser()
    except Exception:
        return DEFAULT_REPORTS
    if root != DEFAULT_REPORTS and not _usable_root(root):
        return DEFAULT_REPORTS
    return root


def set_reports_root(root: str | os.PathLike | None) -> None:
    """Point this process (and anything it spawns) at a different reports tree."""
    if root is None:
        os.environ.pop(ENV_REPORTS_ROOT, None)
    else:
        os.environ[ENV_REPORTS_ROOT] = str(root)


def ensure_dir(path: Path) -> Path:
    try:
        path.mkdir(parents=True, exist_ok=True)
    except Exception:
        pass
    return path


def safe_session_id(session_id: Any) -> str:
    """A session id reduced to one harmless path component.

    Every path helper below interpolates this into a filename. Claude Code only
    ever hands us a UUID, but a session id that carried a '/' or a '..' would
    make `reports_root() / "sessions" / sid` escape the reports root -- and
    ensure_dir(parents=True) would happily create the directories on the way out
    -- so the containment guarantee cannot rest on the caller. An absolute id is
    worse still: `Path('/x/.state') / '/etc/y'` IS '/etc/y'.
    """
    text = str(session_id or "").strip()
    if not text:
        return "unknown"
    text = text.replace("\\", "/").replace("\x00", "")
    text = text.replace("/", "_")
    if text in (".", "..") or set(text) <= {"."}:
        return "unknown"
    return text[:128] or "unknown"


def report_dir_name(session_id: str) -> str:
    """The directory a session's artifacts live in: its PSEUDONYM, not its id.

    The name of a directory is as shareable as the files in it -- the dashboard
    links to it and the user zips it up -- so `sessions/session_07/` is what
    goes on disk. `oe whois session_07` maps it back locally. The import is
    deferred because oe.redact imports this module; a failure falls back to the
    session id so a report is still written somewhere sane.
    """
    try:
        from . import redact
        name = redact.session_pseudonym(session_id)
        if name:
            return safe_session_id(name)
    except Exception:
        pass
    return safe_session_id(session_id)


def session_report_dir(session_id: str) -> Path:
    return ensure_dir(reports_root() / "sessions" / report_dir_name(session_id))


_state_migrated = False
# What was found in <reports_root>/.state the first time state_dir() resolved,
# and what happened to it. `oe audit` cannot see this any other way: it resolves
# state_dir() (which migrates) before it looks for stray private files, so by
# the time it looks the directory it was meant to fail on is gone.
_legacy_state_seen: List[Dict[str, str]] = []


def legacy_state_report() -> List[Dict[str, str]]:
    """One entry per file found in a legacy <reports_root>/.state, with its fate.

    Each entry is {"name": <relative path>, "fate": moved|merged|kept|failed}.
    Empty when there was nothing to migrate, which is the normal case.
    """
    return [dict(row) for row in _legacy_state_seen]


def _migrate_legacy_state(target: Path) -> None:
    """Move a pre-relocation ``<reports_root>/.state`` into `target`. Once, best effort.

    State used to live inside the reports tree, so an existing install has a
    populated ``.state/`` sitting in the directory the user shares. Leaving it
    there would keep the leak alive for exactly the machines that already have
    it, so the first process to resolve state_dir() carries it across.

    When both locations hold the same file the newer one wins and the other is
    deleted: a daemon started before the relocation keeps writing to the old path
    until it restarts, so BOTH copies can be real, and leaving either behind
    leaves an identifying file inside the tree the user shares. Unlinking a file
    such a daemon still has open is safe on POSIX -- it goes on writing to the
    unlinked inode and the name is gone from the shared directory, which is the
    whole point. Anything it genuinely cannot move stays put and visible to
    `oe audit`, which fails on whatever is left.

    TWO EXCEPTIONS, both below and both load-bearing:

    * session-map.json is merged, never replaced, and its legacy copy is set
      aside rather than unlinked. Newest-wins is right for a cache and
      catastrophic for an append-only ledger.
    * a reports root supplied through OE_REPORTS_ROOT is not migrated at all.
      That variable names somebody else's tree far more often than a legacy
      install of our own.

    Everything this function touched is recorded in legacy_state_report(), so a
    caller can say what it did instead of discovering the directory is gone.
    """
    global _state_migrated
    if _state_migrated:
        return
    _state_migrated = True
    try:
        legacy = reports_root() / LEGACY_STATE_DIRNAME
        if not legacy.is_dir() or legacy.resolve() == target.resolve():
            return
        # A reports root named by the environment is somebody ELSE'S tree far
        # more often than it is a legacy install of our own: it is what a
        # colleague hands you and what every harness points at. Absorbing that
        # tree's .state/ ingested their session titles and customer paths into
        # this machine's map and deleted the directory out of the tree they
        # gave you -- while `oe audit` on it said "the whole directory is
        # shareable". A foreign tree is read, never absorbed; leaving the
        # directory in place is also what lets `oe audit` fail on it, which is
        # what docs/privacy.md says happens.
        if os.environ.get(ENV_REPORTS_ROOT):
            for source in sorted(legacy.rglob("*")):
                if source.is_file():
                    _legacy_state_seen.append(
                        {"name": str(source.relative_to(legacy)), "fate": "kept"})
            return
        import shutil  # lazy: only an install that still has a legacy dir pays for it

        for source in sorted(legacy.rglob("*")):
            if not source.is_file():
                continue
            relative = str(source.relative_to(legacy))
            destination = target / source.relative_to(legacy)
            ensure_dir(destination.parent)
            # session-map.json is exempt from newest-wins, and the exemption is
            # the whole point. Every other file here is a cache or a pidfile
            # where the newer copy is simply the better one. This one is an
            # APPEND-ONLY allocation ledger: it is the only record of which real
            # session each published sessions/session_NN/ directory belongs to,
            # so "newer wins, delete the other" turned a one-entry legacy copy
            # into the whole map and made every other pseudonym on the machine
            # permanently unresolvable -- silently, during a read-only command.
            # Merge instead, keep the sanctioned side on any collision, and put
            # the legacy copy aside rather than unlinking it.
            if source.name.startswith("session-map."):
                try:
                    from . import redact as _redact
                    merged = _redact.merge_map_files(destination, source)
                except Exception:
                    merged = False
                if merged:
                    try:
                        shutil.move(str(source),
                                    str(target / ("legacy-" + source.name)))
                    except Exception:
                        pass
                    _legacy_state_seen.append({"name": relative, "fate": "merged"})
                else:
                    _legacy_state_seen.append({"name": relative, "fate": "failed"})
                continue
            try:
                if destination.exists():
                    if source.stat().st_mtime <= destination.stat().st_mtime:
                        source.unlink()
                        _legacy_state_seen.append({"name": relative, "fate": "moved"})
                        continue
                    destination.unlink()
                shutil.move(str(source), str(destination))  # handles a cross-device move
                _legacy_state_seen.append({"name": relative, "fate": "moved"})
            except Exception:
                _legacy_state_seen.append({"name": relative, "fate": "failed"})
                continue
        for stale in sorted(legacy.rglob("*"), reverse=True):
            if stale.is_dir():
                try:
                    stale.rmdir()  # empty ones only; rmdir refuses the rest
                except OSError:
                    pass
        try:
            legacy.rmdir()
        except OSError:
            pass
    except Exception:
        pass


def state_dir() -> Path:
    """Runtime scratch: pidfiles, live snapshots, hook ndjson, watcher logs.

    OUTSIDE reports_root() by construction -- see STATE_ROOT. This directory is
    the de-pseudonymisation oracle for the reports (session-map.json alone pairs
    every `session_07` with a real uuid, title and transcript path), so it must
    not be reachable by an archive of the shareable tree.

    OE_STATE_DIR is the one override; a harness that points OE_REPORTS_ROOT at a
    throwaway tree should set it too if it wants isolated state.
    """
    override = os.environ.get(ENV_STATE_DIR)
    if override:
        try:
            return ensure_dir(Path(override).expanduser())
        except Exception:
            pass
    target = ensure_dir(STATE_ROOT)
    _migrate_legacy_state(target)
    return target


def slug_for_cwd(cwd: str) -> str:
    """Claude Code's project-directory naming: the absolute cwd with every
    path separator replaced by a dash."""
    return str(cwd).replace("/", "-")


def session_dirs(transcript_path: str | os.PathLike) -> Dict[str, Optional[Path]]:
    """Resolve the sidecar directories that belong to a transcript.

    The sibling directory is the transcript path minus the .jsonl suffix. It is
    optional: short sessions that never spawned an agent have none.
    """
    main = Path(transcript_path)
    sidecar = main.with_suffix("") if main.suffix == ".jsonl" else Path(str(main) + "_dir")
    result: Dict[str, Optional[Path]] = {
        "main": main,
        "sidecar": sidecar if sidecar.is_dir() else None,
        "subagents": None,
        "workflows": None,
        "tool_results": None,
    }
    if result["sidecar"] is not None:
        for key, name in (
            ("subagents", "subagents"),
            ("workflows", "workflows"),
            ("tool_results", "tool-results"),
        ):
            candidate = sidecar / name
            if candidate.is_dir():
                result[key] = candidate
    return result


def iter_transcripts():
    """Every top-level session transcript across all projects.

    Only files directly under ~/.claude/projects/<slug>/ are sessions; agent
    transcripts live one level deeper and are reached through session_dirs().
    """
    try:
        projects = sorted(p for p in PROJECTS_ROOT.iterdir() if p.is_dir())
    except Exception:
        return
    for project in projects:
        try:
            entries = sorted(project.glob("*.jsonl"))
        except Exception:
            continue
        for entry in entries:
            # Windows/WSL drops ':Zone.Identifier' companions next to downloads.
            if ":" in entry.name or not entry.is_file():
                continue
            yield entry


def find_transcript(session_id: str) -> Optional[Path]:
    """Locate a session transcript by id across every project directory."""
    if not session_id:
        return None
    # A '/' here would let the id address a file outside ~/.claude/projects,
    # which the watcher would then happily tail.
    name = f"{safe_session_id(session_id)}.jsonl"
    try:
        for project in PROJECTS_ROOT.iterdir():
            candidate = project / name
            if candidate.is_file():
                return candidate
    except Exception:
        return None
    return None


def project_of(transcript_path: str | os.PathLike) -> str:
    """The project slug directory a transcript belongs to (e.g. -home-u-myrepo)."""
    try:
        return Path(transcript_path).parent.name
    except Exception:
        return ""


@functools.lru_cache(maxsize=512)
def project_display(slug: str) -> str:
    """Turn a project slug back into the path it came from.

    Claude Code builds the slug by replacing every '/' in the cwd with '-', which
    is lossy: a directory whose own name contains a hyphen is indistinguishable
    from a path separator. Replacing every '-' with '/' therefore invents
    directories that do not exist: a slug like '-home-u-work-Api-Core-Service'
    expands to '/home/u/work/Api/Core/Service', and '-home-u-orchard-table-planner'
    to '/home/u/orchard/table/planner'. A wrong path is worse than a truncated
    one: it is the thing the reader would cd into.

    The ambiguity is resolvable because the directory usually still exists, so
    walk the tokens left to right and at each step take the LONGEST run of them
    that names a real directory. Bounded work: O(tokens^2) isdir() calls on a
    slug of a handful of tokens, memoised per process, and it degrades to the
    expansion the moment the tree is gone (a deleted project, another machine's
    reports), so nothing regresses.
    """
    if not slug:
        return ""
    naive = "/" + slug.lstrip("-").replace("-", "/")
    tokens = [t for t in slug.lstrip("-").split("-")]
    if not tokens:
        return naive
    try:
        parts: list = []
        index = 0
        while index < len(tokens):
            best = 1
            for take in range(len(tokens) - index, 0, -1):
                candidate = "/" + "/".join(parts + ["-".join(tokens[index:index + take])])
                if os.path.isdir(candidate):
                    best = take
                    break
            parts.append("-".join(tokens[index:index + best]))
            index += best
        resolved = "/" + "/".join(parts)
        # Only trust a resolution that actually landed on a directory; a
        # half-matched guess is no better evidence than the naive expansion.
        return resolved if os.path.isdir(resolved) else naive
    except Exception:
        return naive


def live_snapshot_path(session_id: str) -> Path:
    return state_dir() / f"{safe_session_id(session_id)}.live.json"


def tool_events_path(session_id: str) -> Path:
    return state_dir() / f"{safe_session_id(session_id)}.tools.ndjson"


def compactions_path(session_id: str) -> Path:
    return state_dir() / f"{safe_session_id(session_id)}.compactions.ndjson"


def watcher_pidfile(session_id: str) -> Path:
    return state_dir() / f"{safe_session_id(session_id)}.watcher.pid"


def watcher_log(session_id: str) -> Path:
    return state_dir() / f"watcher-{safe_session_id(session_id)}.log"


def atomic_write(path: Path, text: str, encoding: str = "utf-8") -> Path:
    """Write via a sibling temp file + os.replace so a reader (the dashboard,
    the statusline) never observes a half-written file.

    The temp name carries the writer's pid and a counter because the writers are
    NOT serialised: every live session runs its own watcher and each of them
    refreshes the shared <reports>/index.html and sessions.json, and `oe report`
    / `oe backfill` can target a session a watcher is already rebuilding. With a
    single fixed '<name>.tmp' two writers open the same file, interleave their
    bytes into it, and the loser of the rename gets FileNotFoundError out of
    os.replace. A per-writer temp makes the rename the only shared step, which
    is where the atomicity was supposed to come from.
    """
    ensure_dir(path.parent)
    tmp = path.with_name("%s.%d.%d.tmp" % (path.name, os.getpid(), next(_TMP_SEQ)))
    try:
        with open(tmp, "w", encoding=encoding, newline="\n") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)  # never leave a stray temp behind on failure
        except OSError:
            pass
        raise
    return path
