"""The dependency-tree checklist: everything that must be true before we write.

This is the artifact a co-worker screenshots when the install did not go the way
they expected, so it is built to be read rather than parsed: five groups, one
row per fact, the value we FOUND next to the value we REQUIRE, and -- on a
failure -- one line saying what to do about it. No prose, no spinner, no
progress bar; a person scanning the left margin for a red marker should find
every problem in one pass.

Two severities, and the difference is the whole contract:

    FAIL  the install cannot work. Nothing is written, the exit code is 1.
    warn  the install works but something is worth knowing.

`oe doctor --install` prints exactly this, writes nothing at all, and exits
non-zero when any row failed -- so it can be run before cloning anything into a
settings file, and in CI.
"""

from __future__ import annotations

import json
import os
import platform
import re
import shlex
import shutil
import subprocess
import sys
import sqlite3
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

MIN_PYTHON = (3, 10)
MIN_FREE_BYTES = 64 * 1024 * 1024  # the context store and a year of reports
SUPPORTED_PLATFORMS = ("linux", "darwin")

OK = "ok"
FAIL = "FAIL"
WARN = "warn"

# Every module the package must be able to import, and every hook script the
# settings file will point at. Stated here rather than discovered, so that a
# half-copied checkout FAILS instead of silently installing fewer hooks.
MODULES: Tuple[str, ...] = (
    "paths", "pricing", "ledger", "report", "statusline", "watcher", "dashboard",
    "redact", "accounts", "store", "retrieval", "shrink", "autostart",
    "checklist",
)

HOOK_SCRIPTS: Tuple[str, ...] = (
    "session_start.py", "user_prompt_submit.py", "session_end.py",
)

# The hook events we register. Verified against the Claude Code binary at check
# time rather than trusted -- an event this version does not know is an entry
# that will sit in settings.json forever doing nothing.
HOOK_EVENTS: Tuple[str, ...] = (
    "SessionStart", "UserPromptSubmit", "SessionEnd",
)


@dataclass
class Row:
    group: str
    name: str
    status: str          # OK | FAIL | WARN
    found: str
    requires: str
    remedy: str = ""

    @property
    def failed(self) -> bool:
        return self.status == FAIL


@dataclass
class Report:
    rows: List[Row] = field(default_factory=list)
    facts: Dict[str, Any] = field(default_factory=dict)

    def add(self, group: str, name: str, ok: Any, found: Any, requires: str,
            remedy: str = "", warn_only: bool = False) -> Row:
        status = OK if ok else (WARN if warn_only else FAIL)
        row = Row(group, name, status, str(found), requires, remedy if not ok else "")
        self.rows.append(row)
        return row

    @property
    def failures(self) -> List[Row]:
        return [r for r in self.rows if r.status == FAIL]

    @property
    def warnings(self) -> List[Row]:
        return [r for r in self.rows if r.status == WARN]

    @property
    def ok(self) -> bool:
        return not self.failures


# ---------------------------------------------------------------------------
# probes
# ---------------------------------------------------------------------------


def _human_bytes(count: float) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if count < 1024 or unit == "TB":
            return f"{count:,.0f} {unit}" if unit == "B" else f"{count:,.1f} {unit}"
        count /= 1024.0
    return f"{count:.1f} TB"


def _sqlite_capability(conn: sqlite3.Connection, sql: str) -> Tuple[bool, str]:
    """Actually CREATE the thing. compile_options is not proof: a build can name
    an option the module then fails to use, and a virtual table that cannot be
    created is the failure the user would hit at runtime anyway."""
    try:
        conn.execute(sql)
        return True, "usable"
    except Exception as exc:
        return False, f"{type(exc).__name__}: {exc}"


def check_runtime(report: Report) -> None:
    version = ".".join(str(p) for p in sys.version_info[:3])
    report.add("Runtime", "python version", sys.version_info[:2] >= MIN_PYTHON,
               version, ">= %d.%d" % MIN_PYTHON,
               "install python3.10+ and re-run with it: python3.11 install.py")
    report.add("Runtime", "interpreter", bool(sys.executable),
               sys.executable or "(unknown)", "an absolute path",
               "run the installer with a real interpreter, not an embedded one")
    system = sys.platform
    report.add("Runtime", "platform", system in SUPPORTED_PLATFORMS,
               f"{system} ({platform.machine()})", " | ".join(SUPPORTED_PLATFORMS),
               "macOS and Linux are supported; this platform is not")
    shell = os.path.basename(os.environ.get("SHELL") or "") or "(unset)"
    report.add("Runtime", "login shell", True, shell, "bash | zsh (informational)",
               "", warn_only=True)
    report.facts["python"] = version
    report.facts["platform"] = system
    report.facts["shell"] = shell


def check_database(report: Report) -> None:
    report.add("Database", "sqlite version", sqlite3.sqlite_version_info >= (3, 9, 0),
               sqlite3.sqlite_version, ">= 3.9.0",
               "your python is linked against an sqlite too old for FTS5")
    try:
        conn = sqlite3.connect(":memory:")
    except Exception as exc:
        report.add("Database", "sqlite connect", False, f"{type(exc).__name__}", "works",
                   "python's sqlite3 module cannot open a database")
        return
    with conn:
        for name, sql, remedy in (
            ("FTS5", "CREATE VIRTUAL TABLE t USING fts5(body)",
             "rebuild python/sqlite with -DSQLITE_ENABLE_FTS5 (bm25 retrieval needs it)"),
            ("RTREE", "CREATE VIRTUAL TABLE r USING rtree(id, lo, hi)",
             "rebuild python/sqlite with -DSQLITE_ENABLE_RTREE (line-range residency "
             "needs it)"),
        ):
            ok, detail = _sqlite_capability(conn, sql)
            report.add("Database", name.lower(), ok, detail, "usable", remedy)
        try:
            conn.execute("SELECT json_extract('{\"a\":1}', '$.a')").fetchone()
            ok, detail = True, "usable"
        except Exception as exc:
            ok, detail = False, f"{type(exc).__name__}"
        report.add("Database", "json1", ok, detail, "usable",
                   "rebuild python/sqlite with JSON1 (it is default since 3.38)")
    conn.close()


def _claude_binary() -> Optional[Path]:
    """The Claude Code executable, however it was installed.

    PATH first (npm global, homebrew, a shim), then the native installer's
    versioned directories on both platforms. Absence is a real finding, not
    something to paper over: hooks written for a Claude Code that is not there
    will never run.
    """
    found = shutil.which("claude")
    if found:
        try:
            return Path(found).resolve()
        except Exception:
            return Path(found)
    home = Path.home()
    roots = [
        Path(os.environ.get("XDG_DATA_HOME") or (home / ".local" / "share")) / "claude",
        home / "Library" / "Application Support" / "claude",
        home / ".claude",
    ]
    for root in roots:
        versions = root / "versions"
        try:
            if versions.is_dir():
                entries = sorted((p for p in versions.iterdir() if p.is_file()),
                                 key=lambda p: p.stat().st_mtime, reverse=True)
                if entries:
                    return entries[0]
        except Exception:
            continue
    return None


def _binary_events(binary: Path, wanted: Sequence[str]) -> Dict[str, bool]:
    """Which of `wanted` appear as quoted strings in the Claude Code binary.

    One streaming pass with an overlap, because the binary runs to hundreds of
    megabytes and reading it once per event would be nine passes over the whole
    of it. The overlap is what stops a name that straddles a chunk boundary from
    being missed.
    """
    needles = {name: ('"%s"' % name).encode() for name in wanted}
    found = {name: False for name in wanted}
    longest = max((len(v) for v in needles.values()), default=32)
    try:
        with open(binary, "rb") as handle:
            carry = b""
            while True:
                chunk = handle.read(8 * 1024 * 1024)
                if not chunk:
                    break
                window = carry + chunk
                for name, needle in needles.items():
                    if not found[name] and needle in window:
                        found[name] = True
                if all(found.values()):
                    break
                carry = window[-longest:]
    except Exception:
        return {name: False for name in wanted}
    return found


def check_claude(report: Report, *, probe_binary: bool = True,
                 allow_missing: bool = False) -> None:
    binary = _claude_binary()
    report.facts["claude_binary"] = str(binary or "")
    report.add("Claude Code", "installed", binary is not None,
               str(binary) if binary else "not found on PATH or in the version dirs",
               "the claude executable",
               "install Claude Code first (https://claude.com/claude-code), or pass "
               "--allow-missing-claude to wire hooks for a later install",
               warn_only=allow_missing)
    if binary is None:
        for event in HOOK_EVENTS:
            report.add("Claude Code", f"hook {event}", False, "unverifiable",
                       "supported by the binary",
                       "cannot verify without Claude Code installed", warn_only=True)
        return

    version = ""
    try:
        result = subprocess.run([str(binary), "--version"], capture_output=True,
                                text=True, timeout=25)
        version = (result.stdout or result.stderr or "").strip().splitlines()[0][:60]
    except Exception:
        version = binary.name if binary.name[:1].isdigit() else ""
    report.add("Claude Code", "version", bool(version), version or "(could not ask)",
               "any", "", warn_only=True)
    report.facts["claude_version"] = version

    if not probe_binary:
        report.add("Claude Code", "hook events", True, "skipped (--no-binary-probe)",
                   f"{len(HOOK_EVENTS)} events", "", warn_only=True)
        return
    events = _binary_events(binary, HOOK_EVENTS)
    for event, present in events.items():
        report.add("Claude Code", f"hook {event}", present,
                   "supported" if present else "not found in the binary",
                   "named in the binary",
                   f"this Claude Code does not know {event}; the entry would be inert",
                   warn_only=True)
    report.facts["events_supported"] = sum(1 for v in events.values() if v)


# `<anything>/hooks/<one of ours>.py` or `<anything>/oe/statusline.py`. The
# directory name has to match too, so somebody else's hooks/stop.py in a flat
# directory is not mistaken for ours.
_OUR_SCRIPTS = frozenset(HOOK_SCRIPTS) | {"statusline.py"}


def _entry_root(command: Any) -> Optional[Path]:
    """The checkout an entry runs out of, if the entry has our shape. Else None."""
    if not isinstance(command, str):
        return None
    try:
        parts = shlex.split(command)
    except Exception:
        return None
    for part in parts:
        if not part.endswith(".py"):
            continue
        path = Path(part)
        if path.name not in _OUR_SCRIPTS:
            continue
        if path.parent.name != ("oe" if path.name == "statusline.py" else "hooks"):
            continue
        return path.parent.parent
    return None


def check_wiring(report: Report, root: Path, settings_path: Path) -> None:
    """WHICH checkout the settings file's entries point at.

    The row a git clone needs and a tarball never did. Cloning to a new
    directory -- the ordinary way to reinstall or to update a checkout that was
    moved -- leaves the previous entries behind aimed at scripts that are gone,
    and from the outside that settings file looks exactly like a working
    install. `install.py --yes` repairs it in one pass; the only thing missing
    is anything that says so.

    Never a hard failure. Not being wired at all is the supported zero-config
    state (`oe watch` reads transcripts Claude Code already writes), and a
    second live copy is somebody's deliberate choice rather than a broken
    machine.
    """
    try:
        data = json.loads(settings_path.read_text(encoding="utf-8"))
    except Exception:
        data = None
    if not isinstance(data, dict):
        report.add("Claude Code", "hooks wired", True, "no readable settings file yet",
                   "this checkout, or nothing", "")
        return

    commands: List[Any] = []
    hooks = data.get("hooks")
    if isinstance(hooks, dict):
        for groups in hooks.values():
            for group in groups if isinstance(groups, list) else []:
                if isinstance(group, dict):
                    for entry in group.get("hooks") or []:
                        if isinstance(entry, dict):
                            commands.append(entry.get("command"))
    status = data.get("statusLine")
    statusline_command = status.get("command") if isinstance(status, dict) else None

    def here(command: Any) -> Optional[bool]:
        """True ours-and-here, False ours-elsewhere, None not ours."""
        entry_root = _entry_root(command)
        if entry_root is None:
            return None
        try:
            return entry_root.resolve() == root.resolve()
        except Exception:
            return str(entry_root) == str(root)

    mine = sum(1 for command in commands if here(command) is True)
    statusline = here(statusline_command) is True
    others: Dict[str, int] = {}
    for command in commands + [statusline_command]:
        if here(command) is False:
            others[str(_entry_root(command))] = 1 + others.get(
                str(_entry_root(command)), 0)

    if others:
        stray = sum(others.values())
        who = sorted(others)[0] + ("" if len(others) == 1 else f" (+{len(others) - 1} more)")
        gone = not (Path(sorted(others)[0]) / "hooks").is_dir()
        report.add("Claude Code", "hooks wired", False,
                   f"{stray} entr{'y' if stray == 1 else 'ies'} point at {who}"
                   + (" -- that tree is gone" if gone else " -- a second live copy")
                   + (f", {mine} at this one" if mine else ""),
                   "this checkout, or nothing",
                   "re-run install.py --yes from here: the merge re-points our "
                   "entries and drops the ones a previous location left behind",
                   warn_only=True)
        return
    if not mine and not statusline:
        report.add("Claude Code", "hooks wired", True, "not wired (optional)",
                   "this checkout, or nothing", "")
        return
    expected = len(HOOK_EVENTS)
    report.add("Claude Code", "hooks wired", mine >= expected,
               f"{mine}/{expected} hook entries -> this checkout"
               + (" + statusLine" if statusline else ""),
               f"{expected}, or none",
               "re-run install.py --yes: the merge adds the events this "
               "settings file is missing", warn_only=True)


def check_package(report: Report, root: Path) -> None:
    package = root / "oe"
    report.add("Package", "package dir", package.is_dir(), str(package),
               "<install dir>/oe exists",
               "point --dir at the directory that CONTAINS oe/, hooks/ and bin/")
    if not package.is_dir():
        return

    # Import in a CHILD process: importing 16 modules into the installer would
    # bind this process to whichever tree it found first, and the whole point of
    # --dir is that the tree under test may not be the one we are running from.
    code = (
        "import sys, json;"
        "sys.path.insert(0, %r);"
        "bad = {};"
        "\nfor name in %r:\n"
        "    try:\n"
        "        __import__('oe.' + name)\n"
        "    except Exception as exc:\n"
        "        bad[name] = type(exc).__name__ + ': ' + str(exc)[:120]\n"
        "print(json.dumps(bad))"
    ) % (str(root), list(MODULES))
    try:
        # -B: no __pycache__. This probe is the one thing `--check` runs that
        # could touch the tree, and a checklist advertised as writing nothing
        # must not leave bytecode in somebody's fresh clone.
        result = subprocess.run([sys.executable, "-B", "-c", code],
                                capture_output=True, text=True, timeout=180)
        broken = json.loads((result.stdout or "{}").strip().splitlines()[-1])
    except Exception as exc:
        broken = {"<probe>": f"{type(exc).__name__}: {exc}"}
    report.add("Package", "modules import", not broken,
               f"{len(MODULES) - len(broken)}/{len(MODULES)} import"
               + ("" if not broken else "  " + ", ".join(sorted(broken))),
               f"{len(MODULES)}/{len(MODULES)}",
               "a module failed to import; the install would be half-alive")

    missing: List[str] = []
    unreadable: List[str] = []
    for script in HOOK_SCRIPTS:
        path = root / "hooks" / script
        if not path.is_file():
            missing.append(script)
        elif not os.access(str(path), os.R_OK):
            unreadable.append(script)
    report.add("Package", "hook scripts", not missing and not unreadable,
               f"{len(HOOK_SCRIPTS) - len(missing) - len(unreadable)}/"
               f"{len(HOOK_SCRIPTS)} present and readable"
               + ("  missing: " + ", ".join(missing) if missing else "")
               + ("  unreadable: " + ", ".join(unreadable) if unreadable else ""),
               f"{len(HOOK_SCRIPTS)} readable files",
               "re-clone or re-copy the tree; hooks/ is incomplete")

    binary = root / "bin" / "oe"
    report.add("Package", "bin/oe", binary.is_file() and os.access(str(binary), os.X_OK),
               str(binary) if binary.is_file() else "missing",
               "present and executable", f"chmod +x {binary}")
    check_carried_state(report, root)
    statusline = package / "statusline.py"
    report.add("Package", "statusline", statusline.is_file(), str(statusline),
               "oe/statusline.py exists", "the status line entry would be inert",
               warn_only=True)


def _home() -> Path:
    try:
        return Path.home()
    except Exception:
        return Path(os.path.expanduser("~"))


def check_carried_state(report: Report, root: Path) -> None:
    """Is state/ somebody else's?

    state/ is the runtime tree: the account map (a real email address), the
    session map that undoes every pseudonym in the reports, a cost cache full
    of absolute paths and session titles, and a context database built from
    whatever source tree this machine works in. None of it is code and none
    of it means anything on another machine -- but a tree handed over as a
    directory copy or a zip carries all of it, and the new user's first
    `oe account` then shows a stranger's address as a known account.

    A warning, not a failure: it is a privacy and confusion problem, not a
    reason the install cannot work, and the remedy is one command.
    """
    state = root / "state"
    if not state.is_dir():
        report.add("Package", "carried state", True, "no state/ directory (clean tree)",
                   "empty or yours", "")
        return
    mine = str(_home())
    pattern = re.compile(r"/(?:home|Users)/[A-Za-z0-9._-]{1,64}")
    others: Dict[str, int] = {}
    looked: List[Path] = []
    for name in ("accounts.json", "session-map.json", "prefix-baseline.json"):
        candidate = state / name
        if candidate.is_file():
            looked.append(candidate)
    try:
        looked.extend(sorted(state.glob("*.live.json"))[:5])
    except Exception:
        pass
    for candidate in looked:
        try:
            text = candidate.read_text(encoding="utf-8", errors="replace")[:262144]
        except Exception:
            continue
        for hit in pattern.findall(text):
            if hit == mine or mine.startswith(hit + "/") or hit.startswith(mine):
                continue
            others[hit] = others.get(hit, 0) + 1
    total = 0
    try:
        for path in state.rglob("*"):
            if path.is_file():
                total += path.stat().st_size
    except Exception:
        pass
    if others:
        who = ", ".join(sorted(others)[:3])
        report.add("Package", "carried state", False,
                   f"state/ holds {_human_bytes(total)} belonging to {who}",
                   "empty or yours",
                   f"this tree was copied WITH its runtime state (account map, "
                   f"session map, context db). Delete it before first use: "
                   f"rm -rf {state}", warn_only=True)
        return
    report.add("Package", "carried state", True,
               ("empty" if total == 0 else f"{_human_bytes(total)}, this machine's"),
               "empty or yours", "")


def check_filesystem(report: Report, root: Path, settings_path: Path,
                     reports_root: Optional[Path] = None) -> None:
    claude_home = settings_path.parent
    exists = claude_home.is_dir()
    creatable = exists
    if not exists:
        parent = claude_home.parent
        creatable = parent.is_dir() and os.access(str(parent), os.W_OK)
    report.add("Filesystem", "claude home", exists or creatable,
               f"{claude_home}" + ("" if exists else "  (absent, "
                                   + ("creatable" if creatable else "NOT creatable") + ")"),
               "exists or can be created",
               f"mkdir -p {claude_home}")

    if settings_path.exists():
        readable = os.access(str(settings_path), os.R_OK)
        report.add("Filesystem", "settings readable", readable, str(settings_path),
                   "readable", f"chmod +r {settings_path}")
        valid = False
        detail = "unreadable"
        if readable:
            try:
                data = json.loads(settings_path.read_text(encoding="utf-8"))
                valid = isinstance(data, dict)
                detail = ("valid JSON object, %d top-level keys" % len(data)) if valid \
                    else "valid JSON but not an object"
            except json.JSONDecodeError as exc:
                detail = f"INVALID JSON: line {exc.lineno} col {exc.colno}: {exc.msg}"
            except Exception as exc:
                detail = f"{type(exc).__name__}: {exc}"
        report.add("Filesystem", "settings valid", valid, detail, "a JSON object",
                   f"fix or move {settings_path} -- we will not rewrite a file we "
                   "cannot parse, because we could not prove we preserved it")
        writable = os.access(str(settings_path), os.W_OK)
        report.add("Filesystem", "settings writable", writable,
                   "writable" if writable else "READ-ONLY", "writable",
                   f"chmod u+w {settings_path}  (or install to a different --scope)")
    else:
        parent_ok = claude_home.is_dir() and os.access(str(claude_home), os.W_OK)
        report.add("Filesystem", "settings file", True,
                   f"{settings_path} does not exist yet -- it will be created",
                   "absent or valid", "", warn_only=True)
        report.add("Filesystem", "settings writable", parent_ok or not claude_home.is_dir(),
                   "parent writable" if parent_ok else "parent NOT writable",
                   "we can create the file", f"chmod u+w {claude_home}")

    backup_dir = settings_path.parent
    backup_ok = (not backup_dir.is_dir()) or os.access(str(backup_dir), os.W_OK)
    report.add("Filesystem", "backup writable", backup_ok,
               f"{backup_dir}", "we can write settings.json.bak-N beside it",
               f"chmod u+w {backup_dir} -- a write without a backup is refused")

    if reports_root is not None:
        # Creatability is tested by walking UP to the nearest directory that
        # exists and asking whether we could write in it -- never by creating
        # anything. A checklist that fails must leave the machine exactly as it
        # found it, and mkdir(parents=True) on a reports_root inherited from
        # somebody else's config.json would scatter empty directories through a
        # stranger's home before the run had even been approved.
        ok = True
        detail = str(reports_root)
        if reports_root.is_dir():
            ok = os.access(str(reports_root), os.W_OK)
            if not ok:
                detail += "  (exists, not writable)"
        else:
            probe = reports_root
            while not probe.exists() and probe != probe.parent:
                probe = probe.parent
            ok = probe.is_dir() and os.access(str(probe), os.W_OK)
            detail += "  (absent; " + ("creatable" if ok else f"NOT creatable under {probe}") + ")"
        report.add("Filesystem", "reports root", ok, detail, "creatable and writable",
                   "set reports_root in config.json to a writable directory")

    try:
        probe = root if root.is_dir() else root.parent
        usage = shutil.disk_usage(str(probe))
        enough = usage.free >= MIN_FREE_BYTES
        report.add("Filesystem", "free disk", enough, _human_bytes(usage.free),
                   ">= " + _human_bytes(MIN_FREE_BYTES),
                   "free some space; the context store grows with your transcripts")
    except Exception as exc:
        report.add("Filesystem", "free disk", True, f"unknown ({type(exc).__name__})",
                   ">= " + _human_bytes(MIN_FREE_BYTES), "", warn_only=True)


def check_interpreter(report: Report, command: str) -> None:
    """Run the interpreter we are about to BAKE INTO settings.json and ask it
    what it is. The point of the whole exercise is that the string written to
    the hook must work when Claude Code spawns it -- and the only way to know
    that is to spawn it."""
    probe = (
        "import sys, sqlite3, json;"
        "c = sqlite3.connect(':memory:');"
        "caps = {};"
        "\nfor n, s in (('fts5','CREATE VIRTUAL TABLE t USING fts5(b)'),"
        "('rtree','CREATE VIRTUAL TABLE r USING rtree(i,a,b)')):\n"
        "    try:\n"
        "        c.execute(s); caps[n] = True\n"
        "    except Exception:\n"
        "        caps[n] = False\n"
        "print(json.dumps({'v': list(sys.version_info[:3]),"
        "'exe': sys.executable, 'sqlite': sqlite3.sqlite_version, 'caps': caps}))"
    )
    argv = command.split() if " " in command else [command]
    try:
        result = subprocess.run(argv + ["-c", probe], capture_output=True, text=True,
                                timeout=60)
        payload = json.loads((result.stdout or "").strip().splitlines()[-1])
    except Exception as exc:
        report.add("Interpreter", "executes", False, f"{type(exc).__name__}: {exc}",
                   f"`{command} -c ...` runs",
                   f"{command} is not runnable; pass --interpreter python3 or a real path")
        return
    version = tuple(payload.get("v") or [0, 0, 0])
    report.add("Interpreter", "command", True, command, "runs", "")
    report.add("Interpreter", "version", tuple(version[:2]) >= MIN_PYTHON,
               ".".join(str(p) for p in version), ">= %d.%d" % MIN_PYTHON,
               f"{command} is python {'.'.join(str(p) for p in version)}; "
               "pass --interpreter with a newer one")
    caps = payload.get("caps") or {}
    report.add("Interpreter", "sqlite", True, payload.get("sqlite") or "?", "any", "")
    for name in ("fts5", "rtree"):
        report.add("Interpreter", name, bool(caps.get(name)),
                   "usable" if caps.get(name) else "MISSING", "usable",
                   f"the interpreter that will run the hooks ({command}) has no "
                   f"{name}; pick another with --interpreter")
    report.facts["interpreter_version"] = ".".join(str(p) for p in version)


# ---------------------------------------------------------------------------
# rendering
# ---------------------------------------------------------------------------


def _colour(text: str, code: str, enabled: bool) -> str:
    return f"\x1b[{code}m{text}\x1b[0m" if enabled and code else text


MARKERS = {OK: ("[ok]  ", "32"), FAIL: ("[FAIL]", "31;1"), WARN: ("[warn]", "33")}


def render(report: Report, *, colour: Optional[bool] = None,
           width: Optional[int] = None) -> str:
    """The checklist, aligned. Deterministic: no timing, no spinner, no paths
    that differ per run, so two people can diff two screenshots."""
    if colour is None:
        colour = sys.stdout.isatty() and not os.environ.get("NO_COLOR")
    if width is None:
        try:
            width = max(72, min(120, shutil.get_terminal_size((100, 24)).columns))
        except Exception:
            width = 100
    name_width = max((len(r.name) for r in report.rows), default=10)
    name_width = min(max(name_width, 14), 26)
    lines: List[str] = []
    lines.append("")
    lines.append("  DEPENDENCY CHECKLIST")
    lines.append("  " + "=" * (width - 4))
    last_group = None
    for row in report.rows:
        if row.group != last_group:
            lines.append("")
            lines.append("  " + _colour(row.group.upper(), "1", colour))
            last_group = row.group
        marker, code = MARKERS[row.status]
        found = row.found
        budget = width - (6 + name_width + 8)
        requires = row.requires
        head = (f"  {_colour(marker, code, colour)}  {row.name:<{name_width}}  "
                f"{found}")
        if requires:
            pad = max(1, budget - len(found))
            head += " " * pad + _colour("need: " + requires, "2", colour)
        lines.append(head)
        if row.remedy:
            lines.append("        " + " " * name_width + _colour("-> " + row.remedy,
                                                                 "33", colour))
    lines.append("")
    lines.append("  " + "-" * (width - 4))
    fails, warns = len(report.failures), len(report.warnings)
    total = len(report.rows)
    if fails:
        verdict = _colour(
            f"  NOT READY -- {fails} hard failure(s), {warns} warning(s), "
            f"{total - fails - warns}/{total} checks passed. Nothing was written.",
            "31;1", colour)
    elif warns:
        verdict = _colour(
            f"  READY -- {total - warns}/{total} checks passed, {warns} warning(s).",
            "33", colour)
    else:
        verdict = _colour(f"  READY -- all {total} checks passed.", "32;1", colour)
    lines.append(verdict)
    lines.append("")
    return "\n".join(lines)


def build(root: Path, settings_path: Path, interpreter: Optional[str] = None, *,
          probe_binary: bool = True, allow_missing_claude: bool = False,
          reports_root: Optional[Path] = None) -> Report:
    """Run every probe, in the order a reader wants them."""
    report = Report()
    check_runtime(report)
    check_database(report)
    check_claude(report, probe_binary=probe_binary, allow_missing=allow_missing_claude)
    check_wiring(report, root, settings_path)
    check_package(report, root)
    check_filesystem(report, root, settings_path, reports_root)
    if interpreter:
        check_interpreter(report, interpreter)
    return report
