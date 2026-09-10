#!/usr/bin/env python3
"""Install Overwatch Enforcer into a Claude Code settings file -- and nothing else.

This installer is meant to be handed to somebody else, so it is built around
four rules:

1. NOTHING IS WRITTEN UNTIL EVERYTHING IS CHECKED. The dependency checklist runs
   first, prints itself, and any hard failure ends the run with exit 1 having
   touched no file. `--check` (and `oe doctor --install`) is that checklist on
   its own, for someone who has not installed anything yet.

2. A settings file is a live, hand-maintained config -- permissions, model,
   plugins, TUI preferences. Losing or reordering any of it is a real outage.
   So the merge may only ADD to "hooks" and "statusLine", and it proves it:
   every other top-level key is compared serialized, byte for byte, and the key
   ORDER is compared as a list, before AND after the write. A mismatch aborts.

3. Two independent axes, never conflated:
       INSTALL DIRECTORY -- where this package lives.
       SETTINGS SCOPE    -- which settings file gets the hooks.
   Both are prompted, both are validated, and the COMBINATION is validated:
   the loudest warning in this file is about writing hooks into a settings file
   that gets committed to git, because a teammate who clones it gets hooks
   pointing at a path that does not exist on their machine, and then every
   single tool call fails for them.

4. The default is a dry run. --yes is the authorisation to write.

Recovery: the previous file is copied to settings.json.bak-<n> before the write,
the new file lands via a temp file + os.replace so an interrupted write cannot
truncate the original, and the result is read back and re-verified. If that
verification fails, the backup is restored automatically. --uninstall removes
exactly our entries and, when the result is semantically the file we first saw,
restores the ORIGINAL BYTES from the baseline taken at install time -- and
removes the `oe` symlink, but only when that symlink is one WE made (a symlink
that resolves back into the install directory; never a regular file).

Every one of those touches is also written to ONE install manifest under state/
(oe/manifest.py): path, what we did to it, the checksum before, the checksum of
what we wrote, the backup, the settings scope. The manifest is what makes an
uninstall exact rather than heuristic -- and, just as importantly, what stops it
being reckless. Uninstall NEVER restores a pre-install backup by default: a
settings.json that has collected six months of MCP servers and other tools'
hooks since the install would be silently destroyed by it. It compares the file
against the checksum we wrote, restores verbatim only when they MATCH (nobody
touched it, so the restore is a provable undo), and otherwise removes only our
own entries and says out loud that the file changed and where the backup sits.
--restore-backup is the explicit opt-in for someone who really does want the
pre-install file back, and it prints what it would overwrite first.

PATH: --path-doctor diagnoses why `oe` is not found and writes nothing;
--path-fix (with --yes) adds a delimited, idempotent PATH block to the right rc
file for this shell and platform, through oe.autostart's backup + `shell -n`
gates. Both are reachable by full path, which is the state somebody is in when
they need them.
"""

from __future__ import annotations

import argparse
import copy
import difflib
import json
import os
import shutil
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

# The install root is the directory this file lives in. Never a literal: a
# hardcoded path is correct on exactly one machine, and this installer exists
# to be run on other people's.
HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

# This process runs once and then exits, so its own bytecode cache buys nobody
# anything -- and the tree it imports from is a git checkout, where a dry run
# that leaves __pycache__ behind is a dry run that wrote something. The hooks
# still cache normally; this flag is set here and nowhere else.
sys.dont_write_bytecode = True

try:
    from oe import checklist as checklist_mod  # noqa: E402
    from oe import manifest as manifest_mod  # noqa: E402
except ModuleNotFoundError as _exc:  # pragma: no cover -- the oe/ package is gone
    # The one failure this file must not answer with a bare traceback.
    #
    # `python3 install.py --check` is the second thing a user reaches for when
    # Claude Code stops starting, and if the oe/ package is missing it dies
    # here naming a Python module and nothing else -- not what broke, and not
    # bin/oe-repair, which sits one directory away, imports nothing from oe/
    # precisely so that it survives this, and is the only thing that can put
    # settings.json back. bin/oe answers the same failure the same way; a
    # rescue tool nobody can find has not rescued anyone.
    _repair = HERE / "bin" / "oe-repair"
    print(f"install.py: the oe/ package is missing or unimportable under "
          f"{HERE} ({_exc.__class__.__name__}: {_exc}).", file=sys.stderr)
    print("    This installer cannot run until it is restored -- re-clone or "
          "re-download the checkout.", file=sys.stderr)
    if _repair.exists():
        print("", file=sys.stderr)
        print("    If Claude Code itself is failing on a hook, repair its "
              "settings.json first.", file=sys.stderr)
        print("    That tool is standalone and needs none of this package:",
              file=sys.stderr)
        print(f"      python3 {_repair}", file=sys.stderr)
    raise SystemExit(2)

MANAGED_KEYS = ("hooks", "statusLine")

# Set by main() on every run so a caller (bin/oe) can tell "nothing to do" apart
# from "here is a diff, re-run with --yes".
LAST_RUN_NOOP = False

# The worst exit code returned by an extra-scope pass of an uninstall that had
# more than one settings file to clean. Reset by main(), raised by _run().
EXTRA_SCOPE_EXIT = 0

# event -> (script, timeout seconds). PostToolUse is the hot path and gets a
# tight timeout so a wedged hook can never stall a tool call for long;
# SessionEnd does the full synchronous rebuild and gets room to finish.
# v1.0.0 registers three hooks. The six that are gone all served the read guard
# or the compaction advisor, and both were cut -- see docs for what v1.0.0 is.
#
# ORDER MATTERS WHEN REMOVING ONE. A PreToolUse hook runs before EVERY tool
# call, so deleting its file while a settings.json still names it breaks every
# tool in every live session on this machine, with an error that points at the
# hook rather than at whoever removed it. Unregister first (this list, then
# `--yes`), confirm no settings file still references the script, and only then
# delete anything.
HOOK_PLAN: List[Tuple[str, str, int]] = [
    ("SessionStart", "session_start.py", 15),
    # The budget injector. Once per prompt, not per tool call, so it can afford
    # to open the context store; still bounded, because a stalled hook here
    # delays the user's own turn.
    ("UserPromptSubmit", "user_prompt_submit.py", 10),
    # The full synchronous report rebuild, so it gets room to finish.
    ("SessionEnd", "session_end.py", 180),
]

#: Events this tool registered in an EARLIER version and no longer wants. An
#: install has to actively take these out: settings.json is the user's file and
#: nothing else will ever remove a stale entry pointing at a script we deleted.
RETIRED_EVENTS: Tuple[str, ...] = (
    "PreToolUse", "PostToolUse", "PostToolUseFailure",
    "Stop", "PreCompact", "PostCompact",
)

STATUSLINE_ENTRY = {
    "type": "command",
    "command": None,  # filled in with the resolved interpreter
    "refreshInterval": 5,
    "padding": 0,
}

# Directories nobody means to install a personal tool into. Refused outright
# rather than warned about: every one of these either needs root, is managed by
# a package manager, or is wiped by the next `npm install`.
FORBIDDEN_PREFIXES = (
    "/usr", "/bin", "/sbin", "/lib", "/lib64", "/etc", "/boot", "/proc", "/sys",
    "/dev", "/System", "/Library", "/Applications", "/private/var/db",
)
FORBIDDEN_NAMES = ("node_modules", ".git", "__pycache__", "site-packages", "dist-packages")


# ---------------------------------------------------------------------------
# small helpers
# ---------------------------------------------------------------------------


def colour_enabled(stream=None) -> bool:
    stream = stream or sys.stdout
    try:
        return bool(stream.isatty()) and not os.environ.get("NO_COLOR")
    except Exception:
        return False


def c(text: str, code: str) -> str:
    return f"\x1b[{code}m{text}\x1b[0m" if colour_enabled() and code else text


def _emit(stream, text: str) -> None:
    """print() that cannot become the failure.

    On a full disk the write we are REPORTING is not the only one that fails:
    print() and flush() fail too, and an OSError raised out of fail() replaces
    a clean "write failed, rolled back" message with a traceback and skips the
    rollback entirely. The reporting path must survive the condition it exists
    to report.
    """
    try:
        print(text, file=stream)
        stream.flush()
    except Exception:
        pass


def say(text: str = "") -> None:
    _emit(sys.stdout, text)


def warn(text: str) -> None:
    # Flush stdout first. When output is piped, stdout is block-buffered and
    # stderr is not, so without this every warning surfaces at the TOP of the
    # captured log, detached from the line it belongs to -- which is exactly the
    # log somebody pastes into a bug report.
    try:
        sys.stdout.flush()
    except Exception:
        pass
    _emit(sys.stderr, c("  ! " + text, "33"))


def fail(text: str) -> None:
    try:
        sys.stdout.flush()
    except Exception:
        pass
    _emit(sys.stderr, c("  x " + text, "31;1"))


def stdin_is_interactive() -> bool:
    """Can we ask a question and expect a person to answer it?

    Both ends must be a terminal. A piped stdin (`echo | install.py`), a closed
    stdin (CI, a systemd unit, a hook) and a redirected stdout all mean nobody
    is there -- and input() on a closed stdin raises EOFError while input() on a
    pipe silently consumes somebody's data. Neither is acceptable in an
    installer, so this is checked BEFORE any prompt rather than caught after.
    """
    try:
        return bool(sys.stdin and sys.stdin.isatty() and sys.stdout.isatty())
    except Exception:
        return False


def ask(question: str, default: str, interactive: bool) -> str:
    """One prompt. Returns `default` on empty input, EOF, interrupt, or when
    there is no terminal -- it must never hang and never raise."""
    prompt = f"  {question}\n  [{default}]: "
    if not interactive:
        say(f"  {question}")
        say(f"  -> {default}   " + c("(no terminal; using the default)", "2"))
        return default
    try:
        answer = input(prompt).strip()
    except (EOFError, KeyboardInterrupt):
        say("")
        return default
    return answer or default


def ask_choice(question: str, options: Sequence[str], default: str,
               interactive: bool) -> str:
    joined = "/".join(options)
    while True:
        answer = ask(f"{question} ({joined})", default, interactive).strip().lower()
        if answer in options:
            return answer
        if not interactive:
            return default
        warn(f"pick one of: {joined}")


# ---------------------------------------------------------------------------
# install directory
# ---------------------------------------------------------------------------


def normalise_dir(raw: str) -> Path:
    """Expand ~ and $VARS, resolve to an absolute path. Never raises."""
    text = os.path.expandvars(str(raw or "").strip())
    try:
        return Path(text).expanduser().resolve()
    except Exception:
        return Path(os.path.abspath(os.path.expanduser(text or ".")))


def validate_dir(path: Path) -> List[str]:
    """Reasons this is not a sane install directory. Empty list = fine."""
    problems: List[str] = []
    text = str(path)
    if path == Path(path.anchor):
        problems.append("that is the filesystem root")
    for prefix in FORBIDDEN_PREFIXES:
        if text == prefix or text.startswith(prefix + "/"):
            problems.append(f"{prefix} is a system directory")
            break
    for part in path.parts:
        if part in FORBIDDEN_NAMES:
            problems.append(f"the path goes through {part}/, which is not yours to keep")
            break
    if path.exists() and not path.is_dir():
        problems.append("that path exists and is not a directory")
    probe = path if path.is_dir() else path.parent
    while not probe.exists() and probe != probe.parent:
        probe = probe.parent
    if not os.access(str(probe), os.W_OK):
        problems.append(f"not writable: {probe}")
    return problems


def looks_installed(path: Path) -> bool:
    """Is this already an Overwatch Enforcer tree?"""
    return (path / "oe" / "paths.py").is_file() and (path / "hooks").is_dir()


def choose_install_dir(explicit: Optional[str], interactive: bool) -> Path:
    """Resolve the install directory, prompting when we can.

    Prefilled with the directory this installer is running from, because "install
    where I cloned it" is what almost everybody means, and a default you can
    accept with Return is the difference between a prompt and an obstacle.
    """
    default = HERE
    if explicit:
        chosen = normalise_dir(explicit)
    elif not interactive:
        chosen = default
        say(f"  install directory: {chosen}   " + c("(default; no terminal to ask)", "2"))
    else:
        while True:
            answer = ask("Install directory (where this package lives)",
                         str(default), interactive)
            chosen = normalise_dir(answer)
            problems = validate_dir(chosen)
            if not problems:
                break
            for problem in problems:
                warn(problem)
    problems = validate_dir(chosen)
    if problems:
        for problem in problems:
            fail(problem)
        raise SystemExit(2)
    return chosen


# ---------------------------------------------------------------------------
# settings scopes
# ---------------------------------------------------------------------------


def claude_home() -> Path:
    override = os.environ.get("CLAUDE_CONFIG_DIR")
    if override:
        return Path(override).expanduser()
    return Path.home() / ".claude"


def project_roots(start: Optional[Path] = None) -> List[Path]:
    """Every ancestor of the cwd that carries a .claude/ directory.

    Walked upward rather than assumed, because Claude Code merges a settings
    file from the project you are IN, and a monorepo can have several.
    ~/.claude is skipped: it is the user scope, not a project.

    BOTH ~/.claude and the CLAUDE_CONFIG_DIR override are skipped, and that is
    not belt-and-braces. claude_home() returns the override when one is set, so
    testing claude_home() alone stopped skipping the real ~/.claude the moment
    somebody relocated their config: $HOME was then admitted as a "project",
    the installer recommended a project-LOCAL scope for it -- which Claude Code
    loads only for sessions started under $HOME, not the every-session coverage
    the user was promised -- and justified it with a sentence about teammates
    cloning the repo that was false in every clause. A candidate is not a
    project root if its marker is either directory.
    """
    try:
        here = (start or Path.cwd()).resolve()
    except Exception:
        return []
    not_a_project = set()
    for marker_dir in (claude_home(), Path.home() / ".claude"):
        try:
            not_a_project.add(marker_dir.resolve() if marker_dir.exists()
                              else marker_dir)
        except Exception:
            not_a_project.add(marker_dir)
    found: List[Path] = []
    for candidate in (here, *here.parents):
        marker = candidate / ".claude"
        try:
            if not marker.is_dir():
                continue
            if marker.resolve() in not_a_project:
                continue
        except Exception:
            continue
        found.append(candidate)
    return found


def scope_table(explicit_settings: Optional[str] = None) -> List[Dict[str, Any]]:
    """Every settings file that applies here, with what is already in it.

    The three writable scopes are the ones Claude Code names in its own binary:
    user (~/.claude/settings.json), project (<project>/.claude/settings.json)
    and local (<project>/.claude/settings.local.json). managedSettings and
    policySettings also exist and are deliberately absent from this table --
    they belong to an administrator and this installer must never write them.
    """
    rows: List[Dict[str, Any]] = []

    def describe(scope: str, path: Path, note: str, committed: Optional[bool]) -> None:
        row: Dict[str, Any] = {
            "scope": scope, "path": path, "note": note, "committed": committed,
            "exists": False, "size": 0, "valid": None, "hooks": 0,
            "statusline": None, "ours": 0,
        }
        try:
            if path.exists():
                row["exists"] = True
                row["size"] = path.stat().st_size
                data = json.loads(path.read_text(encoding="utf-8"))
                row["valid"] = isinstance(data, dict)
                if isinstance(data, dict):
                    hooks = data.get("hooks")
                    if isinstance(hooks, dict):
                        row["hooks"] = len(hooks)
                    status = data.get("statusLine")
                    if isinstance(status, dict):
                        row["statusline"] = str(status.get("command") or "")[:70]
                    row["ours"] = count_ours(data)
        except json.JSONDecodeError as exc:
            row["valid"] = False
            row["error"] = f"line {exc.lineno}: {exc.msg}"
        except Exception as exc:
            row["valid"] = False
            row["error"] = f"{type(exc).__name__}: {exc}"
        rows.append(row)

    if explicit_settings:
        describe("--settings", Path(explicit_settings).expanduser(),
                 "named on the command line", None)
        return rows

    describe("user", claude_home() / "settings.json",
             "every session on this machine, every project", False)
    for root in project_roots()[:2]:
        describe("project", root / ".claude" / "settings.json",
                 f"sessions under {root}", True)
        describe("local", root / ".claude" / "settings.local.json",
                 f"sessions under {root}, this machine only", False)
    return rows


def recommend_scope(rows: List[Dict[str, Any]], install_dir: Path
                    ) -> Tuple[str, str]:
    """(scope, reason). Stated out loud, because a default nobody can explain is
    a default nobody should accept."""
    have = {row["scope"] for row in rows}
    inside_project = any(row["scope"] == "project"
                         and _is_within(install_dir, row["path"].parent.parent)
                         for row in rows)
    if "user" in have and not inside_project:
        return "user", ("the package lives outside any project, so a per-project "
                        "settings file could not reach your other sessions; the user "
                        "scope covers every project on this machine and is not "
                        "committed to git")
    if inside_project and "local" in have:
        return "local", ("the package lives inside this project, so the hooks are "
                         "only meaningful here -- and settings.local.json is "
                         "gitignored, so a teammate who clones the repo does not "
                         "inherit paths that do not exist on their machine")
    if "user" in have:
        return "user", "it is the only scope that reaches every session on this machine"
    return rows[0]["scope"], "it is the only settings file available here"


def _is_within(child: Path, parent: Path) -> bool:
    try:
        child.resolve().relative_to(parent.resolve())
        return True
    except Exception:
        return False


def render_scopes(rows: List[Dict[str, Any]], recommended: str, reason: str) -> None:
    say()
    say("  SETTINGS SCOPES DETECTED")
    say("  " + "=" * 76)
    for row in rows:
        star = c(" <- recommended", "32;1") if row["scope"] == recommended else ""
        state = "absent"
        if row["exists"]:
            if row["valid"] is False:
                state = c("INVALID JSON: " + str(row.get("error", "")), "31;1")
            else:
                bits = [f"{row['size']:,}B"]
                if row["hooks"]:
                    bits.append(f"{row['hooks']} hook event(s)")
                if row["statusline"]:
                    bits.append("has statusLine")
                if row["ours"]:
                    bits.append(c(f"{row['ours']} of ours", "36"))
                state = ", ".join(bits)
        say(f"  {row['scope']:<10} {str(row['path'])}")
        say(f"  {'':<10} {state}{star}")
        say(f"  {'':<10} " + c(row["note"], "2"))
        if row["committed"]:
            say(f"  {'':<10} " + c("USUALLY COMMITTED TO GIT -- see the warning below",
                                   "33"))
        say()
    say("  " + c("recommended: ", "1") + recommended)
    say("  " + c("because " + reason, "2"))


COMMITTED_HOOKS_WARNING = """
  ------------------------------------------------------------------------
  WARNING -- writing hooks into a COMMITTED settings file

  <project>/.claude/settings.json is normally tracked by git. Hooks in it
  carry an ABSOLUTE path to this install directory. A teammate who clones
  the repo gets those hooks but not this directory, so the command fails --
  and a PreToolUse hook that fails is not a warning in a log, it is on the
  path of EVERY TOOL CALL they make.

  Prefer one of:
    --scope local   .claude/settings.local.json  (gitignored; same reach)
    --scope user    ~/.claude/settings.json      (all projects, this machine)

  If you really do want the whole team on it, every one of them must clone
  the package to the same absolute path, or you must commit the package
  inside the repo and install with --interpreter python3 so the command
  carries no machine-specific interpreter either.
  ------------------------------------------------------------------------
"""


# ---------------------------------------------------------------------------
# interpreter resolution
# ---------------------------------------------------------------------------


def resolve_interpreter(mode: str, install_dir: Path,
                        committed_scope: bool) -> Tuple[str, str]:
    """(command word, why).

    THE DEFAULT FOR SHARING IS THE ABSOLUTE PATH OF THE INTERPRETER RUNNING THIS
    INSTALLER, and that is a deliberate choice rather than an oversight:

      * settings.json is per-machine. Each person runs this installer on their
        own machine, so an absolute path is not "somebody else's path", it is
        theirs -- and it is unambiguous, which `python3` is not on a machine
        with pyenv, asdf, conda and Homebrew all claiming the name.
      * `python3` costs a PATH lookup and, through a pyenv/asdf shim, tens of
        milliseconds of shell per spawn. A hook that runs before every tool
        call turns that into minutes of latency per session.

    The exception is a COMMITTED settings file, where the absolute path is
    exactly the wrong thing because it will be read on a machine that is not
    this one. There the default flips to `python3` and says so.

    Whatever is chosen is then EXECUTED and interrogated before it is written --
    see checklist.check_interpreter.
    """
    if mode and mode not in ("auto", "python3", "resolved"):
        return mode, "given with --interpreter"
    if mode == "python3" or (mode in ("", "auto", None) and committed_scope):
        found = shutil.which("python3") or "python3"
        why = ("portable: the settings file is committed, so the command must not "
               "name a path that only exists here") if committed_scope else \
              "forced with --interpreter python3"
        return "python3", why
    executable = sys.executable or ""
    if executable and os.path.exists(executable):
        if "/shims/" in executable:
            return executable, ("resolved from the running interpreter; NOTE this is a "
                                "version-manager shim and adds shell start-up to every hook call")
        return executable, "resolved from the interpreter running install.py"
    found = shutil.which("python3") or "python3"
    return found, "resolved from PATH (this installer has no sys.executable)"


# ---------------------------------------------------------------------------
# merge
# ---------------------------------------------------------------------------


def _q(text: Any) -> str:
    """Shell-quote a path, but only when it needs it.

    Claude Code runs a hook entry as a shell command string, so an install
    directory containing a space -- '~/Library/Application Support/...' is the
    normal case on macOS, and 'My Projects' is common enough anywhere -- would
    be split into two arguments and the hook would die with "No such file or
    directory" on every single tool call. shlex.quote() leaves an ordinary path
    completely untouched, so the common case is unchanged and unquoted.
    """
    import shlex
    return shlex.quote(str(text))


def hook_command(interpreter: str, script: str, install_dir: Path) -> str:
    return f"{_q(interpreter)} {_q(install_dir / 'hooks' / script)}"


def statusline_command(interpreter: str, install_dir: Path) -> str:
    return f"{_q(interpreter)} {_q(install_dir / 'oe' / 'statusline.py')}"


def is_ours(command: Any, install_dir: Path) -> bool:
    """Our entries are exactly those that run something from the install root.

    Path text, not a marker key: settings.json may only gain keys Claude Code
    understands, so the command string has to carry the identity.
    """
    return isinstance(command, str) and str(install_dir) in command


# Every script this installer ever points a settings entry at. A command that
# names one of these, in a directory of the right shape, is ours whatever root
# it was installed from -- which is the only way to recognise the entries a
# PREVIOUS location left behind.
OUR_SCRIPTS = {script for _, script, _ in HOOK_PLAN} | {"statusline.py"}


def our_script_path(command: Any) -> Optional[Path]:
    """The script an entry runs, if the entry has our shape. Else None.

    Shape, not root: `<anything>/hooks/session_start.py` or
    `<anything>/oe/statusline.py`. Deliberately narrow -- the directory name
    has to match too, so somebody else's `hooks/stop.py` in a flat directory is
    not mistaken for ours.
    """
    if not isinstance(command, str):
        return None
    import shlex
    try:
        parts = shlex.split(command)
    except Exception:
        return None
    for part in parts:
        if not part.endswith(".py"):
            continue
        path = Path(part)
        if path.name not in OUR_SCRIPTS:
            continue
        parent = path.parent.name
        if path.name == "statusline.py" and parent != "oe":
            continue
        if path.name != "statusline.py" and parent != "hooks":
            continue
        return path
    return None


def stale_entry(command: Any, install_dir: Path) -> Optional[Path]:
    """An entry of ours from a DIFFERENT root whose script is gone.

    This is the relocated-checkout case, and it is the worst state this
    installer can leave somebody in: clone to ~/Downloads, install, move the
    tree, re-run install.py -- and because `is_ours` matches only the CURRENT
    root, the old entries survive the merge. The settings file then carries two
    entries per event, one of which runs a script that does not exist, on every
    single tool call. Both halves of the test matter: a different root is not
    enough (a second live install is a different problem, and gets a warning),
    and a missing script is not enough (that is a broken CURRENT install, which
    the merge repairs by rewriting the path).
    """
    script = our_script_path(command)
    if script is None:
        return None
    if is_ours(command, install_dir):
        return None
    try:
        if script.exists():
            return None
    except Exception:
        return None
    return script


def sweep_stale(settings: Dict[str, Any], install_dir: Path) -> List[str]:
    """Drop every dead entry of ours left by a previous install location."""
    changes: List[str] = []
    live_elsewhere: List[str] = []

    def dead(entry: Any, event: str = "") -> bool:
        if not isinstance(entry, dict):
            return False
        command = entry.get("command")
        if stale_entry(command, install_dir) is not None:
            return True
        # An event this tool used to register and no longer does. The script it
        # names may still exist right here, so `stale_entry` -- which only knows
        # about a PREVIOUS install path -- will never catch it. Nothing else
        # will either: settings.json belongs to the user and no other process
        # prunes our leftovers. Left in place it is worse than untidy, because
        # the next release deletes the script and the entry then breaks every
        # tool call in every session on this machine.
        if event in RETIRED_EVENTS and is_ours(command, install_dir):
            return True
        if our_script_path(command) is not None and not is_ours(command, install_dir):
            live_elsewhere.append(str(command))
        return False

    hooks = settings.get("hooks")
    if isinstance(hooks, dict):
        for event in list(hooks.keys()):
            groups = hooks.get(event)
            if not isinstance(groups, list):
                continue
            for group in list(groups):
                if not isinstance(group, dict):
                    continue
                entries = group.get("hooks")
                if not isinstance(entries, list):
                    continue
                keep = [e for e in entries if not dead(e, event)]
                if len(keep) != len(entries):
                    why = ("no longer part of this tool"
                           if event in RETIRED_EVENTS
                           else "left by a previous install path")
                    changes.append(f"drop {len(entries) - len(keep)} dead entry(s) "
                                   f"from {event} ({why})")
                    group["hooks"] = keep
                if not group.get("hooks") and set(group.keys()) <= {"hooks", "matcher"}:
                    groups.remove(group)
            if not groups:
                hooks.pop(event)
    status = settings.get("statusLine")
    if isinstance(status, dict) and stale_entry(status.get("command"),
                                                install_dir) is not None:
        settings.pop("statusLine")
        changes.append("drop the dead statusLine left by a previous install path")
    elif isinstance(status, dict) and our_script_path(status.get("command")) is not None \
            and not is_ours(status.get("command"), install_dir):
        live_elsewhere.append(str(status.get("command")))

    others = list(dict.fromkeys(live_elsewhere))
    if others:
        # One warning, not one per entry: nine identical paragraphs is a wall
        # somebody scrolls past, and the fact is a single fact.
        warn(f"this settings file also points at ANOTHER live copy of this tool "
             f"({len(others)} entr{'y' if len(others) == 1 else 'ies'}); both "
             "copies will fire on every event. Uninstall the other one, or run "
             "--uninstall from its directory:")
        roots = dict.fromkeys(
            str(our_script_path(cmd).parent.parent) for cmd in others
            if our_script_path(cmd) is not None)
        for root in roots:
            warn("    " + root)
    return changes


def count_ours(settings: Dict[str, Any], install_dir: Optional[Path] = None) -> int:
    """How many of OUR entries a settings document already holds.

    With no install_dir, recognise any command that has our SHAPE, wherever it
    lives -- that is what lets scope detection report "3 of ours" for an install
    somewhere else. Matching on the directory name would not: the git
    repository is `overwatch_enforcer` and the historical install directory is
    `overwatch-enforcer`, so a clone under either spelling (or any other name a
    user picks) has to count.
    """
    total = 0

    def mine(command: Any) -> bool:
        if not isinstance(command, str):
            return False
        if install_dir is not None:
            return str(install_dir) in command
        return (our_script_path(command) is not None
                or "overwatch-enforcer" in command or "overwatch_enforcer" in command
                or "usage-meter" in command)

    hooks = settings.get("hooks")
    if isinstance(hooks, dict):
        for groups in hooks.values():
            if not isinstance(groups, list):
                continue
            for group in groups:
                if not isinstance(group, dict):
                    continue
                for entry in group.get("hooks") or []:
                    if isinstance(entry, dict) and mine(entry.get("command")):
                        total += 1
    status = settings.get("statusLine")
    if isinstance(status, dict) and mine(status.get("command")):
        total += 1
    return total


def merge_hooks(settings: Dict[str, Any], interpreter: str,
                install_dir: Path) -> List[str]:
    """Add/refresh our hook entries in place. Returns a list of change notes."""
    changes: List[str] = []
    hooks = settings.get("hooks")
    if hooks is None:
        hooks = {}
        settings["hooks"] = hooks
        changes.append("create key: hooks")
    if not isinstance(hooks, dict):
        raise SystemExit(f"settings 'hooks' is a {type(hooks).__name__}, expected an "
                         "object; refusing to touch it")

    for event, script, timeout in HOOK_PLAN:
        command = hook_command(interpreter, script, install_dir)
        desired = {"type": "command", "command": command, "timeout": timeout}

        groups = hooks.get(event)
        if groups is None:
            groups = []
            hooks[event] = groups
            changes.append(f"create event: hooks.{event}")
        if not isinstance(groups, list):
            raise SystemExit(f"settings hooks.{event} is not a list; refusing to touch it")

        # Look for an entry of ours in ANY group first: an earlier install (or a
        # hand edit) may have put it in a matcher'd group, and adding a second
        # copy in the unmatched group would double-fire the hook.
        existing = None
        for group in groups:
            if not isinstance(group, dict):
                continue
            for entry in group.get("hooks") or []:
                if isinstance(entry, dict) and is_ours(entry.get("command"), install_dir) \
                        and script in str(entry.get("command")):
                    existing = entry
                    break
            if existing is not None:
                break

        if existing is None:
            # A group with no matcher applies to every tool, which is what we
            # want for PostToolUse; for non-tool events a matcher is meaningless.
            target = None
            for group in groups:
                if isinstance(group, dict) and not group.get("matcher"):
                    target = group
                    break
            if target is None:
                target = {"hooks": []}
                groups.append(target)
                changes.append(f"add group: hooks.{event}[matcher omitted]")
            entries = target.setdefault("hooks", [])
            if not isinstance(entries, list):
                raise SystemExit(f"settings hooks.{event}[].hooks is not a list; refusing")
            entries.append(desired)
            changes.append(f"add hook: {event} -> hooks/{script} (timeout {timeout}s)")
        else:
            for key, value in desired.items():
                if existing.get(key) != value:
                    changes.append(f"update hook: {event}.{key}: "
                                   f"{existing.get(key)!r} -> {value!r}")
                    existing[key] = value
    return changes


def merge_statusline(settings: Dict[str, Any], interpreter: str, install_dir: Path,
                     force: bool, settings_path: Path,
                     pending: Optional[Dict[str, Any]] = None) -> List[str]:
    """Add/refresh our statusLine. `pending` collects the displaced entry so the
    CALLER can park it after --yes: a dry run that stashed a file would be a
    write, and this installer's whole contract is that a dry run writes nothing.
    """
    changes: List[str] = []
    command = statusline_command(interpreter, install_dir)
    desired = dict(STATUSLINE_ENTRY, command=command)
    displaced_path = displaced_statusline_path(install_dir, settings_path)

    current = settings.get("statusLine")
    if current is None:
        settings["statusLine"] = desired
        return ["add statusLine: " + command]
    if not isinstance(current, dict):
        raise SystemExit("settings 'statusLine' is not an object; refusing to touch it")
    if not is_ours(current.get("command"), install_dir) and not force:
        warn("statusLine already points at something else and was left alone:")
        warn("    " + str(current.get("command")))
        warn("  re-run with --force-statusline to replace it "
             "(the old one is stashed and restored on --uninstall).")
        return []
    if not is_ours(current.get("command"), install_dir):
        if pending is not None:
            pending["path"] = displaced_path
            pending["value"] = copy.deepcopy(current)
        changes.append(f"stash displaced statusLine -> {displaced_path}")
    # Merge INTO the existing object: keys we do not own (hideVimModeIndicator,
    # anything a future version adds) survive.
    for key, value in desired.items():
        if current.get(key) != value:
            changes.append(f"update statusLine.{key}: {current.get(key)!r} -> {value!r}")
            current[key] = value
    return changes


def remove_ours(settings: Dict[str, Any], install_dir: Path,
                only: str = "all", settings_path: Optional[Path] = None,
                consumed: Optional[List[Path]] = None) -> List[str]:
    """Uninstall: drop exactly the entries whose command lives in the install root.

    `consumed` collects stash files that were used, so the caller can delete
    them AFTER the write lands -- a stash restored twice is a status line
    resurrected into a file that never had one.
    """
    changes: List[str] = []
    displaced_path = displaced_statusline_path(install_dir, settings_path) \
        if settings_path is not None else None
    hooks = settings.get("hooks") if only in ("all", "hooks") else None
    if isinstance(hooks, dict):
        for event in list(hooks.keys()):
            groups = hooks.get(event)
            if not isinstance(groups, list):
                continue
            for group in list(groups):
                if not isinstance(group, dict):
                    continue
                entries = group.get("hooks")
                if not isinstance(entries, list):
                    continue
                keep = [e for e in entries
                        if not (isinstance(e, dict)
                                and is_ours(e.get("command"), install_dir))]
                if len(keep) != len(entries):
                    changes.append(f"remove {len(entries) - len(keep)} hook(s) from {event}")
                    group["hooks"] = keep
                if not group.get("hooks") and set(group.keys()) <= {"hooks", "matcher"}:
                    groups.remove(group)
                    changes.append(f"remove empty group from {event}")
            if not groups:
                hooks.pop(event)
                changes.append(f"remove empty event: hooks.{event}")
        if not hooks:
            settings.pop("hooks")
            changes.append("remove now-empty key: hooks")

    status_line = settings.get("statusLine") if only in ("all", "statusline") else None
    if isinstance(status_line, dict) and is_ours(status_line.get("command"), install_dir):
        restored = None
        try:
            if displaced_path is not None and displaced_path.exists():
                candidate = json.loads(displaced_path.read_text(encoding="utf-8"))
                if isinstance(candidate, dict):
                    restored = candidate
        except Exception:
            restored = None
        if restored is not None:
            settings["statusLine"] = restored
            if consumed is not None and displaced_path is not None:
                consumed.append(displaced_path)
            changes.append(f"restore the statusLine we displaced: {restored.get('command')}")
        else:
            settings.pop("statusLine")
            changes.append("remove statusLine")
    elif status_line is not None:
        changes.append("statusLine left alone (not ours)")
    return changes


def install_state(settings: Dict[str, Any], install_dir: Path) -> Dict[str, Any]:
    """What is already there: complete, partial, or nothing.

    Partial is the interesting one. It means a previous run was interrupted, or
    somebody hand-edited a couple of entries out -- and the repair is the same
    merge, so this exists to SAY so rather than to change what happens.
    """
    present: List[str] = []
    for event, script, _ in HOOK_PLAN:
        groups = (settings.get("hooks") or {}).get(event) if isinstance(
            settings.get("hooks"), dict) else None
        hit = False
        if isinstance(groups, list):
            for group in groups:
                if not isinstance(group, dict):
                    continue
                for entry in group.get("hooks") or []:
                    if isinstance(entry, dict) \
                            and is_ours(entry.get("command"), install_dir) \
                            and script in str(entry.get("command")):
                        hit = True
        if hit:
            present.append(event)
    status = settings.get("statusLine")
    has_status = isinstance(status, dict) and is_ours(status.get("command"), install_dir)
    total = len(HOOK_PLAN)
    if not present and not has_status:
        state = "absent"
    elif len(present) == total:
        state = "complete"
    else:
        state = "partial"
    return {"state": state, "hooks_present": len(present), "hooks_expected": total,
            "statusline": has_status,
            "missing": [e for e, _, _ in HOOK_PLAN if e not in present]}


# ---------------------------------------------------------------------------
# safety net
# ---------------------------------------------------------------------------


def verify_untouched(before: Dict[str, Any], after: Dict[str, Any]) -> List[str]:
    """Every top-level key except ours must be identical, in the same order."""
    problems: List[str] = []
    before_keys = [k for k in before if k not in MANAGED_KEYS]
    after_keys = [k for k in after if k not in MANAGED_KEYS]
    if before_keys != after_keys:
        missing = set(before_keys) - set(after_keys)
        added = set(after_keys) - set(before_keys)
        if missing:
            problems.append(f"KEYS LOST: {sorted(missing)}")
        if added:
            problems.append(f"unexpected new keys: {sorted(added)}")
        if not missing and not added:
            problems.append(f"key ORDER changed: {before_keys} -> {after_keys}")
    for key in before_keys:
        if key in after_keys and json.dumps(before[key], sort_keys=True) != \
                json.dumps(after[key], sort_keys=True):
            problems.append(f"key modified: {key}")
    return problems


def next_backup(path: Path) -> Path:
    counter = 1
    while True:
        candidate = path.with_name(path.name + f".bak-{counter}")
        if not candidate.exists():
            return candidate
        counter += 1


def _settings_key(settings_path: Path) -> str:
    """A short, stable id for ONE settings file.

    Everything we park on disk about a settings file has to be keyed by which
    file it came from. It is the same reasoning in both places: a machine has a
    user scope, a project scope and however many --settings copies somebody
    rehearsed on, and a per-install-dir filename cannot tell them apart.
    """
    import hashlib
    return hashlib.blake2b(str(settings_path).encode("utf-8"),
                           digest_size=6).hexdigest()


def displaced_statusline_path(install_dir: Path, settings_path: Path) -> Path:
    """Where the statusLine we displaced in THIS settings file is parked.

    Keyed by the settings path, and this is not hypothetical tidiness: while it
    was one shared `replaced-statusline.json` at the install root, a
    --force-statusline against one file and an --uninstall against another
    restored the FIRST file's status line into the SECOND -- writing a command
    that pointed at a program the second machine did not have, into a file that
    never had a statusLine at all. It also broke the byte-identical restore,
    because the "restored" document no longer matched the baseline.
    """
    return install_dir / "state" / \
        f"replaced-statusline.{_settings_key(settings_path)}.json"


def baseline_path(install_dir: Path, settings_path: Path) -> Path:
    """Where the ORIGINAL bytes of a settings file are kept.

    Keyed by the settings path so rehearsing on a copy cannot overwrite the
    baseline of the real one. This is what makes `--uninstall` byte-identical
    rather than merely equivalent: our merge re-renders the document with
    json.dumps(indent=2), so a file that was formatted any other way would come
    back semantically equal but textually different, and "I restored your file"
    would be a claim nobody could check with md5.
    """
    return install_dir / "state" / \
        f"settings-baseline.{_settings_key(settings_path)}.json"


def render(settings: Dict[str, Any]) -> str:
    return json.dumps(settings, indent=2, ensure_ascii=False) + "\n"


def diff(before_text: str, after_text: str, path: Path) -> str:
    return "".join(difflib.unified_diff(
        before_text.splitlines(keepends=True), after_text.splitlines(keepends=True),
        fromfile=f"a/{path.name}", tofile=f"b/{path.name}", n=3))


def colourise(text: str) -> str:
    if not colour_enabled():
        return text
    out = []
    for line in text.splitlines(keepends=True):
        if line.startswith("+") and not line.startswith("+++"):
            out.append("\x1b[32m" + line + "\x1b[0m")
        elif line.startswith("-") and not line.startswith("---"):
            out.append("\x1b[31m" + line + "\x1b[0m")
        elif line.startswith("@@"):
            out.append("\x1b[36m" + line + "\x1b[0m")
        else:
            out.append(line)
    return "".join(out)


def read_exact(path: Path) -> str:
    """The file's text with its line endings INTACT.

    Path.read_text() applies universal newlines, so a settings.json written
    with CRLF comes back as LF -- and then the baseline we record is already
    normalised, the "your formatting will change" warning cannot see the
    difference, and --uninstall restores a file that is semantically right and
    byte-wrong. On a WSL or Windows-edited machine that is the common case, not
    the exotic one.
    """
    return path.read_bytes().decode("utf-8")


def atomic_replace(path: Path, text: str) -> None:
    tmp = path.with_name(path.name + f".oe-tmp.{os.getpid()}")
    try:
        # newline="" -- write the string exactly as given. Our own render() only
        # ever produces \n; a restored baseline may legitimately carry \r\n and
        # must come back the way it went in.
        with open(tmp, "w", encoding="utf-8", newline="") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        if path.exists():
            try:
                os.chmod(tmp, path.stat().st_mode & 0o7777)
            except Exception:
                pass
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


# ---------------------------------------------------------------------------
# the PATH link:  <a writable bin dir on PATH>/oe  ->  <install dir>/bin/oe
# ---------------------------------------------------------------------------
#
# Wiring the hooks makes the tool RUN; it does not make the tool REACHABLE.
# Without this, every co-worker's first `oe doctor` is a "command not found"
# and the documented next step in this installer's own closing line is a
# 40-character absolute path. So the link is part of the install, on the same
# terms as everything else here:
#
#   * NOTHING is created without --yes. A dry run prints the plan.
#   * We only ever create a SYMLINK, and we only ever remove a symlink that
#     resolves back into the install directory. A regular file called `oe` that
#     belongs to somebody else is never touched, in either direction.
#   * When there is nowhere to link, that is not a failure -- the install is
#     complete and working. We print the exact export line and the exact rc
#     file for THIS shell on THIS platform, and carry on.

DEFAULT_BIN_NAME = "oe"
LINK_STATE_NAME = "bin-link.json"


def _home() -> Path:
    try:
        return Path.home()
    except Exception:  # no HOME and no passwd entry
        return Path(os.path.expanduser("~"))


def _shell_bits() -> Tuple[str, List[Path]]:
    """(login shell name, rc files it would source, best first).

    Delegates to oe.autostart, which already gets the awkward part right: bash
    on macOS reads ~/.bash_profile (every Terminal window is a login shell) and
    bash on Linux reads ~/.bashrc, and zsh honours $ZDOTDIR. Duplicating that
    here would be a second copy to keep correct. Falls back to a local
    equivalent if the module cannot be imported, because a PATH hint must not
    be the thing that breaks an install.
    """
    try:
        from oe import autostart as autostart_mod
        shell = autostart_mod.detect_shell()
        return shell, list(autostart_mod.rc_candidates(shell))
    except Exception:
        pass
    name = os.path.basename(str(os.environ.get("SHELL") or "")).lstrip("-")
    if not name:
        name = "zsh" if sys.platform == "darwin" else "bash"
    home = _home()
    if name == "zsh":
        zdotdir = os.environ.get("ZDOTDIR")
        base = Path(zdotdir).expanduser() if zdotdir else home
        return name, [base / ".zshrc"]
    if name == "bash":
        return name, ([home / ".bash_profile", home / ".bashrc"]
                      if sys.platform == "darwin"
                      else [home / ".bashrc", home / ".bash_profile"])
    if name in ("sh", "dash", "ksh"):
        return name, [home / ".profile"]
    return name, [home / (".%src" % name)]


def _rc_target(shell: str, rcs: List[Path]) -> Path:
    """The rc file to name in the hint.

    Normally the first that EXISTS, because that is the file the user already
    keeps their shell config in. macOS + bash is the exception and it has to be
    hard-coded: every Terminal window there is a LOGIN shell, so ~/.bash_profile
    runs and ~/.bashrc is not read AT ALL unless .bash_profile sources it. On a
    Mac where only ~/.bashrc exists, "first that exists" would hand the user a
    line that silently never runs -- so bash on darwin always gets the file the
    login shell actually reads.
    """
    if shell == "fish":
        # oe.autostart only knows the shells its block is valid in, so its
        # generic fallback spells ~/.fishrc -- a file fish has never read.
        return _home() / ".config" / "fish" / "config.fish"
    if not rcs:
        return _home() / ".profile"
    if sys.platform == "darwin" and shell == "bash":
        return rcs[0]
    for rc in rcs:
        try:
            if rc.exists():
                return rc
        except Exception:
            continue
    return rcs[0]


def export_line(directory: Path, shell: str) -> str:
    """The one line to add to an rc file. Shell-specific because it has to be
    PASTEABLE -- a bash export in a fish config is a syntax error, not a hint."""
    text = str(directory)
    home = str(_home())
    if text == home or text.startswith(home + os.sep):
        text = "$HOME" + text[len(home):]
    if shell == "fish":
        return f'fish_add_path {_q(str(directory))}'
    if shell in ("csh", "tcsh"):
        return f'set path = ({text} $path)'
    return f'export PATH="{text}:$PATH"'


def _path_dirs() -> List[str]:
    """$PATH, split, with the empty entries (which mean "the cwd") dropped."""
    raw = os.environ.get("PATH") or ""
    out: List[str] = []
    for chunk in raw.split(os.pathsep):
        if not chunk:
            continue
        try:
            out.append(os.path.normpath(os.path.expanduser(chunk)))
        except Exception:
            continue
    return out


def _on_path(directory: Path) -> bool:
    try:
        want = os.path.normpath(str(directory))
    except Exception:
        return False
    if want in _path_dirs():
        return True
    # A PATH entry may be a symlink to the same directory (~/bin -> ~/.local/bin
    # is a common tidy-up). Compare what they resolve to, not what they spell.
    try:
        real = os.path.realpath(want)
    except Exception:
        return False
    for entry in _path_dirs():
        try:
            if os.path.realpath(entry) == real:
                return True
        except Exception:
            continue
    return False


def link_candidates() -> List[Path]:
    """Where a personal `oe` may go, best first.

    Only inside HOME. A tool installed for one user must not land in
    /usr/local/bin, where it needs root, outlives the user's account and
    collides with a package manager -- and where a test running with HOME
    pointed at a scratch directory would still hit the real machine. --link-dir
    is the way to say you meant somewhere else.
    """
    home = _home()
    out: List[Path] = []
    seen = set()
    # $XDG_BIN_HOME is ambient and unvalidated -- it comes from whatever
    # launched us. A relative value there ("bin", or the empty string with a
    # stray colon) would make `plan["link"]` a relative path, and the symlink
    # would land wherever the installer happened to be run FROM: reachable
    # today, gone tomorrow, and impossible for an uninstall to find. Absolute
    # or ignored.
    xdg_raw = os.environ.get("XDG_BIN_HOME") or ""
    xdg: Optional[Path] = None
    if xdg_raw.strip():
        try:
            probe = Path(os.path.expandvars(xdg_raw.strip())).expanduser()
            xdg = probe if probe.is_absolute() else None
        except Exception:
            xdg = None
    for candidate in ([xdg] if xdg is not None else []) + \
            [home / ".local" / "bin", home / "bin"]:
        try:
            key = os.path.normpath(str(candidate))
        except Exception:
            continue
        if key in seen:
            continue
        seen.add(key)
        out.append(candidate)
    return out


def _inside(child: Path, parent: Path) -> bool:
    # The scope test the merge already uses, under a name that reads correctly
    # here. One implementation, so "is this ours?" cannot answer two ways.
    return _is_within(child, parent)


def _writable_dir(directory: Path) -> bool:
    """Can we put a file in there, creating the directory if we must?"""
    try:
        if directory.is_dir():
            return os.access(str(directory), os.W_OK | os.X_OK)
        if directory.exists():
            return False          # exists and is not a directory
        probe = directory.parent
        while not probe.exists() and probe != probe.parent:
            probe = probe.parent
        return probe.is_dir() and os.access(str(probe), os.W_OK)
    except Exception:
        return False


def _points_into(link: Path, install_dir: Path) -> bool:
    """Is this a symlink of ours? Symlink AND resolving inside the install root.

    Both halves matter. Without is_symlink() an uninstall could delete a real
    binary; without the resolve() it could delete somebody else's `oe`.
    Deliberately tolerant of a BROKEN link (Path.resolve() is non-strict), so a
    relocated checkout still gets its dangling link cleaned up.
    """
    try:
        if not link.is_symlink():
            return False
        return _inside(link, install_dir) or _inside(
            Path(os.path.realpath(str(link))), install_dir)
    except Exception:
        return False


def _dead_link_of_ours(link: Path) -> Optional[str]:
    """The readlink() of a dangling symlink WE left at a previous location.

    stale_entry(), for the symlink instead of the settings entry, and it exists
    for the same reason: `git clone` into a new directory is the ordinary way
    to reinstall, and the link the last install made then points at a tree that
    is gone. Without this the link matches nothing, gets called somebody else's
    `oe`, and is left dangling -- so the user's `oe` command stays dead and the
    printed remedy is one that cannot fix it.

    Both halves matter. A link whose target still EXISTS is a second LIVE
    install and must stay a conflict; a target that is not `<something>/bin/oe`
    is not our layout and is none of our business.
    """
    try:
        if not link.is_symlink():
            return None
        dest = Path(os.path.realpath(str(link)))
        if dest.exists():
            return None
        if dest.name != DEFAULT_BIN_NAME or dest.parent.name != "bin":
            return None
        return os.readlink(str(link))
    except Exception:
        return None


def _ours_to_replace(link: Path, install_dir: Path) -> bool:
    """May we re-point or remove this link? Ours here, or ours and orphaned."""
    return _points_into(link, install_dir) or _dead_link_of_ours(link) is not None


def _describe(where: Path) -> str:
    try:
        if where.is_symlink():
            return f"symlink -> {os.readlink(str(where))}"
        if where.is_file():
            return "a regular file"
        if where.is_dir():
            return "a directory"
    except Exception:
        pass
    return "present"


def plan_bin_link(install_dir: Path, *, bin_name: str = DEFAULT_BIN_NAME,
                  explicit_dir: Optional[str] = None,
                  enabled: bool = True) -> Dict[str, Any]:
    """Decide what to do about `oe` on PATH. Reads only; writes nothing."""
    # The target is always bin/oe -- that is the only executable in the tree.
    # --bin-name renames the LINK, for a machine where something else already
    # owns `oe`; aiming the link at bin/<name> would just make it dangle.
    target = install_dir / "bin" / DEFAULT_BIN_NAME
    shell, rcs = _shell_bits()
    rc = _rc_target(shell, rcs)
    plan: Dict[str, Any] = {
        "action": "skip", "name": bin_name, "target": target, "link": None,
        "shell": shell, "rc": rc, "export": "", "note": "", "existing": None,
        "on_path": False,
        # A foreign command of the same name that our link will come in front
        # of. Only ever set when the user asked for that directory explicitly;
        # rendered as a warning, because shadowing somebody's binary silently is
        # the one thing this whole section exists to avoid.
        "shadows": None,
    }
    if not enabled:
        plan["note"] = "--no-link: leaving PATH alone"
        return plan
    if not target.is_file():
        plan["action"] = "unavailable"
        plan["note"] = f"{target} is not there, so there is nothing to link"
        return plan
    if not os.access(str(target), os.X_OK):
        plan["action"] = "unavailable"
        plan["note"] = f"{target} is not executable -- chmod +x it and re-run"
        return plan

    # 1. Is a command by that name already reachable? Ask PATH first, because
    #    that is what the user's shell will answer with.
    found = shutil.which(bin_name)
    hits: List[Path] = [Path(found)] if found else []
    for candidate in link_candidates():
        probe = candidate / bin_name
        try:
            if probe.exists() or probe.is_symlink():
                if not any(os.path.normpath(str(h)) == os.path.normpath(str(probe))
                           for h in hits):
                    hits.append(probe)
        except Exception:
            continue

    for hit in hits:
        if _points_into(hit, install_dir) or _inside(hit, install_dir):
            plan["action"] = "already"
            plan["link"] = hit
            plan["on_path"] = _on_path(hit.parent)
            same = False
            try:
                same = os.path.realpath(str(hit)) == os.path.realpath(str(target))
            except Exception:
                same = False
            if not same:
                # Ours, but aimed at a different file in the same tree (a rename,
                # or an older layout). Re-point it rather than leave it stale.
                plan["action"] = "relink"
                plan["existing"] = _describe(hit)
                # Name what it aims at NOW. _describe() renders "symlink ->
                # <target>", so pasting it after "points at" produced "points at
                # symlink -> ..." -- a sentence with no fact in it a reader can
                # act on.
                try:
                    aimed = os.readlink(str(hit))
                except OSError:
                    aimed = "something else in this tree"
                plan["note"] = f"{hit} is ours but aims at {aimed}, not {target}"
            elif not plan["on_path"]:
                plan["note"] = (f"{hit} exists but {hit.parent} is not on PATH")
                plan["export"] = export_line(hit.parent, shell)
            else:
                plan["note"] = f"{hit} already resolves to {target}"
            return plan

    for hit in hits:
        was = _dead_link_of_ours(hit)
        if was is None:
            continue
        plan["action"] = "relink"
        plan["link"] = hit
        plan["on_path"] = _on_path(hit.parent)
        plan["existing"] = _describe(hit)
        plan["note"] = (f"{hit} is a dead link left by a previous install "
                        f"({was}); re-pointing it at {target}")
        return plan

    # Nothing of ours anywhere. Anything left in `hits` belongs to somebody
    # else, and the two shapes of that are NOT the same problem:
    #
    #   * reachable on PATH -- taking the name would shadow a command the user
    #     already runs. Never done silently, in either direction.
    #   * a stray file in a candidate directory that is NOT on PATH -- shadows
    #     nothing and must not block the install. Reporting that as "`oe` is
    #     already on PATH and is not ours" would be simply false, and it would
    #     abort the link even though another candidate directory was free.
    foreign_on_path = [h for h in hits if _on_path(h.parent)]

    def occupied_by_stranger(directory: Path) -> bool:
        probe = directory / bin_name
        try:
            return probe.exists() or probe.is_symlink()
        except Exception:
            return True     # cannot tell -> treat as taken; never clobber

    def conflict(clash: Path, *, reachable: bool) -> Dict[str, Any]:
        where = ("is on your PATH" if reachable
                 else f"is in {clash.parent}, which is not on your PATH")
        plan["action"] = "conflict"
        plan["link"] = clash
        plan["existing"] = _describe(clash)
        plan["note"] = (f"{clash} {where} and is not ours ({_describe(clash)}); "
                        f"re-run with --bin-name <other> to install under a "
                        f"different name, or --link-dir to pick a directory that "
                        f"comes first on PATH")
        plan["export"] = export_line(target.parent, shell)
        return plan

    # 2. An explicit --link-dir is a decision the user has already made, so it is
    #    answered BEFORE the generic clash below. Answering it after would make
    #    the conflict branch's own advice -- "re-run with --link-dir" -- a
    #    suggestion this function then ignored on the next run.
    if explicit_dir:
        chosen = normalise_dir(explicit_dir)
        if not _writable_dir(chosen):
            plan["action"] = "manual"
            plan["note"] = f"--link-dir {chosen} is not writable"
            plan["export"] = export_line(target.parent, shell)
            return plan
        if occupied_by_stranger(chosen):
            return conflict(chosen / bin_name, reachable=_on_path(chosen))
        plan["link"] = chosen / bin_name
        plan["on_path"] = _on_path(chosen)
        plan["action"] = "link" if plan["on_path"] else "link+path"
        if not plan["on_path"]:
            plan["export"] = export_line(chosen, shell)
        if foreign_on_path:
            # Asked for explicitly, so it happens -- but it is said out loud.
            plan["shadows"] = str(foreign_on_path[0])
        if not _inside(chosen, _home()):
            plan["note"] = (f"{chosen} is outside {_home()}; it may need root and "
                            "it is shared with every account on this machine")
        return plan

    if foreign_on_path:
        return conflict(foreign_on_path[0], reachable=True)

    # 3. Pick a directory: one that is already on PATH beats one that is not,
    #    because the second needs the user to edit an rc file. Directories a
    #    stranger's file already occupies are skipped rather than fought over.
    usable = [d for d in link_candidates()
              if _writable_dir(d) and not occupied_by_stranger(d)]
    on_path = [d for d in usable if _on_path(d)]
    chosen_dir = on_path[0] if on_path else (usable[0] if usable else None)
    if chosen_dir is not None:
        plan["link"] = chosen_dir / bin_name
        plan["on_path"] = bool(on_path)
        plan["action"] = "link" if on_path else "link+path"
        if not on_path:
            plan["export"] = export_line(chosen_dir, shell)
        if not _inside(chosen_dir, _home()):
            # Only reachable via $XDG_BIN_HOME. The same warning --link-dir
            # gets, for the same reason: an ambient variable is not a smaller
            # decision than a flag just because nobody typed it today.
            plan["note"] = (f"{chosen_dir} is outside {_home()} ($XDG_BIN_HOME); "
                            "it may need root and it is shared with every account "
                            "on this machine")
        return plan

    if hits:
        # Every candidate is taken by somebody else's file and there is nowhere
        # left to route around to.
        return conflict(hits[0], reachable=_on_path(hits[0].parent))

    plan["action"] = "manual"
    plan["note"] = ("no writable bin directory in your home "
                    f"({', '.join(str(d) for d in link_candidates())})")
    plan["export"] = export_line(target.parent, shell)
    return plan


def offer_bin_link(plan: Dict[str, Any], interactive: bool) -> Dict[str, Any]:
    """Ask before putting a file in somebody's bin directory.

    Only where there is a decision to make -- a link we would CREATE. "already
    linked", "somebody else owns the name" and "nowhere to put it" have no
    question in them. Declining downgrades the plan to `manual`, which still
    prints the export line, so saying no leaves the user informed rather than
    stuck.
    """
    if not interactive or plan["action"] not in ("link", "link+path", "relink"):
        return plan
    link = plan["link"]
    answer = ask_choice(f"Put `{plan['name']}` on PATH?  {link} -> {plan['target']}",
                        ("yes", "no"), "yes", interactive)
    if answer == "yes":
        return plan
    plan["action"] = "manual"
    plan["note"] = "declined at the prompt"
    plan["export"] = export_line(plan["target"].parent, plan["shell"])
    return plan


def render_bin_link(plan: Dict[str, Any], *, will_write: bool) -> None:
    """Say what we are about to do, or what the user has to do instead."""
    action = plan["action"]
    say()
    say("  PATH")
    if action == "skip":
        say("    " + c(plan["note"] or "not linking", "2"))
        return
    if action == "unavailable":
        warn(plan["note"])
        return
    if action == "already":
        say("    " + c(f"ok: `{plan['name']}` already resolves to {plan['target']}",
                       "32"))
        if plan["export"]:
            say("    " + plan["note"])
            say("    add to " + str(plan["rc"]) + ":")
            say("      " + c(plan["export"], "1"))
        return
    if action == "relink":
        say(f"    {plan['link']} is ours but stale; it will be re-pointed at "
            f"{plan['target']}")
        if plan["note"]:
            say("    " + c(plan["note"], "2"))
        return
    if action == "conflict":
        warn(f"`{plan['name']}` is already on PATH and is not ours: {plan['link']}")
        warn("  left alone. " + str(plan["note"]))
        say("    or run it by its full path:")
        say("      " + c(str(plan["target"]), "1"))
        return
    if action == "manual":
        warn(plan["note"])
        say(f"    the install is complete and working; `{plan['name']}` just is not "
            "on PATH.")
        say(f"    add to {plan['rc']}  ({plan['shell']}):")
        say("      " + c(plan["export"], "1"))
        return
    verb = "link" if will_write else "would link"
    say(f"    {verb}  {plan['link']}  ->  {plan['target']}")
    if plan.get("shadows"):
        warn(f"this will come BEFORE {plan['shadows']} on your PATH and shadow it. "
             f"You asked for this directory explicitly; --bin-name <other> is the "
             f"way to keep both.")
    if plan.get("note") and action in ("link", "link+path"):
        say("    " + c(plan["note"], "33"))
    if action == "link+path":
        say("    " + c(f"{plan['link'].parent} is NOT on your PATH yet.", "33"))
        say(f"    add to {plan['rc']}  ({plan['shell']}):")
        say("      " + c(plan["export"], "1"))
        say("    " + c("then open a new terminal, or `source` that file.", "2"))
        say("    " + c(f"or let this installer do it: {HERE / 'install.py'} "
                       "--path-fix --yes", "2"))
    else:
        # The directory IS on PATH, so a new shell finds the command. The
        # CURRENT one may not: zsh builds its command hash table from the PATH
        # directories at startup and does not re-scan for a file that appeared
        # afterwards. That is a "command not found" seconds after a successful
        # install, and one word fixes it.
        say("    " + c("in this shell: `hash -r` (bash) / `rehash` (zsh); a new "
                       "terminal needs neither.", "2"))


def _recorded_links(install_dir: Path) -> List[Path]:
    """Every link we have a record of. Tolerates the older single-entry shape."""
    state = install_dir / "state" / LINK_STATE_NAME
    try:
        data = json.loads(state.read_text(encoding="utf-8"))
    except Exception:
        return []
    if isinstance(data, dict) and data.get("link"):
        data = {"links": [str(data["link"])]}
    if not isinstance(data, dict):
        return []
    out: List[Path] = []
    for entry in data.get("links") or []:
        if isinstance(entry, str) and entry:
            out.append(Path(entry))
    return out


def _record_link(install_dir: Path, link: Optional[Path],
                 removed: Optional[List[Path]] = None) -> None:
    """Remember what we made, so an uninstall can be exact even after PATH,
    $HOME or --bin-name has changed.

    A LIST, because there can legitimately be more than one: --bin-name and
    --link-dir both make a second link without invalidating the first, and a
    single-slot record would forget the earlier one -- which is exactly the
    link an uninstall would then leave behind. Best effort throughout: the
    removal path re-verifies every candidate anyway, so a missing, stale or
    unreadable record costs nothing.
    """
    state = install_dir / "state" / LINK_STATE_NAME
    known = _recorded_links(install_dir)
    if removed:
        gone = {os.path.normpath(str(p)) for p in removed}
        known = [p for p in known if os.path.normpath(str(p)) not in gone]
    if link is not None and not any(os.path.normpath(str(p)) == os.path.normpath(str(link))
                                    for p in known):
        known.append(link)
    try:
        state.parent.mkdir(parents=True, exist_ok=True)
        if not known:
            if state.exists():
                state.unlink()
            return
        state.write_text(json.dumps(
            {"links": [str(p) for p in known],
             "target": str(install_dir / "bin" / DEFAULT_BIN_NAME)},
            indent=2) + "\n", encoding="utf-8")
    except Exception:
        pass


def apply_bin_link(plan: Dict[str, Any], install_dir: Path,
                   man: Optional["manifest_mod.Manifest"] = None) -> bool:
    """Create (or re-point) the symlink. Returns True if `oe` is now reachable.

    Concurrency-safe by construction: symlink(2) is atomic and fails with EEXIST
    rather than clobbering, so two installers racing each other end with one
    link and no lost file -- the loser re-reads and finds its own answer there.
    """
    action = plan["action"]
    if action in ("skip", "unavailable", "conflict", "manual"):
        return action == "already"
    link: Optional[Path] = plan.get("link")
    if link is None:
        return False
    if action == "already":
        _record_link(install_dir, link)
        if man is not None:
            man.record(link, kind="symlink", action="linked", target=plan["target"])
        # Reachable only if the directory holding it is actually on PATH. A link
        # in a directory the shell never searches is not an installed command,
        # and telling the user to run `oe doctor` would be a lie they find out
        # about at the prompt.
        return bool(plan["on_path"])
    target = plan["target"]
    try:
        link.parent.mkdir(parents=True, exist_ok=True)
    except Exception as exc:
        warn(f"could not create {link.parent}: {exc}")
        return False
    try:
        if action == "relink":
            if not _ours_to_replace(link, install_dir):
                warn(f"{link} is no longer ours; left alone")
                return False
            tmp = link.with_name(link.name + f".oe-tmp.{os.getpid()}")
            try:
                os.symlink(str(target), str(tmp))
                os.replace(str(tmp), str(link))
            except BaseException:
                try:
                    os.unlink(str(tmp))
                except OSError:
                    pass
                raise
        else:
            try:
                os.symlink(str(target), str(link))
            except FileExistsError:
                # Somebody got there between the plan and the write. If it is
                # the same answer, that is a success, not a collision.
                if _points_into(link, install_dir):
                    say(f"  {link} was created concurrently and already points at us")
                else:
                    warn(f"{link} appeared while we were installing and is not "
                         f"ours ({_describe(link)}); left alone")
                    return False
    except Exception as exc:
        warn(f"could not link {link} -> {target}: {type(exc).__name__}: {exc}")
        return False

    # Prove it, rather than announce it: resolve the link and run it.
    try:
        resolved = os.path.realpath(str(link))
    except Exception:
        resolved = ""
    if resolved != os.path.realpath(str(target)):
        warn(f"{link} does not resolve to {target} ({resolved or 'unresolvable'})")
        return False
    _record_link(install_dir, link)
    if man is not None:
        # The manifest records the link too, so ONE file answers "what did this
        # install touch". bin-link.json stays: it is what remove_bin_link() has
        # always read, and an uninstall that depended on a file introduced later
        # would forget every link made before it.
        man.record(link, kind="symlink", action="linked", target=target)
    say(f"  linked      {link} -> {target}")
    if not plan["on_path"]:
        warn(f"{link.parent} is not on PATH yet -- add the line above to "
             f"{plan['rc']}, or run: {HERE / 'install.py'} --path-fix --yes")
        return False
    return True


def remove_bin_link(install_dir: Path, *, bin_name: str = DEFAULT_BIN_NAME,
                    apply: bool) -> List[str]:
    """Remove the symlinks we created, and only those.

    Every location is checked -- the recorded one, the candidates, and every
    directory on PATH -- because the link may have been made when HOME, PATH or
    the shell were different. Each is unlinked only if it is a SYMLINK that
    resolves back into this install directory, or a dangling one of our own
    shape -- otherwise uninstalling from a re-cloned tree leaves the previous
    clone's orphan behind for good, since the directory that could have claimed
    it no longer exists.
    """
    changes: List[str] = []
    seen = set()
    candidates: List[Path] = []

    def consider(path: Optional[Path]) -> None:
        if path is None:
            return
        try:
            key = os.path.normpath(str(path))
        except Exception:
            return
        if key in seen:
            return
        seen.add(key)
        candidates.append(path)

    state = install_dir / "state" / LINK_STATE_NAME
    for recorded in _recorded_links(install_dir):
        consider(recorded)
    for directory in link_candidates():
        consider(directory / bin_name)
    for entry in _path_dirs():
        consider(Path(entry) / bin_name)
    found = shutil.which(bin_name)
    consider(Path(found) if found else None)

    hit = False
    removed: List[Path] = []
    for link in candidates:
        if not _ours_to_replace(link, install_dir):
            continue
        hit = True
        changes.append(f"remove PATH link {link} -> {os.readlink(str(link))}")
        if apply:
            try:
                link.unlink()
                removed.append(link)
            except Exception as exc:
                warn(f"could not remove {link}: {type(exc).__name__}: {exc}")
                changes[-1] += "  (FAILED)"
    if apply and removed:
        _record_link(install_dir, None, removed=removed)
    if not hit:
        # Say nothing when there was nothing: an uninstall that reports removing
        # a link it did not create is a lie somebody will act on.
        try:
            if state.exists() and apply:
                state.unlink()
        except Exception:
            pass
    return changes


# ---------------------------------------------------------------------------
# the install manifest: what we touched, and what that licenses an uninstall
# to do about it
# ---------------------------------------------------------------------------
#
# oe/manifest.py holds the record itself and the reasoning behind it. What lives
# here is the POLICY, because the policy is this installer's, not the record's:
#
#   default            surgical removal. Only our own entries come out. The
#                      manifest makes that exact rather than heuristic.
#   file unchanged     the checksum still matches what we wrote, so nobody has
#                      touched it since. The pre-install bytes are then a
#                      provable undo and we restore them.
#   file edited        somebody added MCP servers, permissions, another tool's
#                      hooks. Surgical removal, their edits kept, and we say
#                      plainly that it changed and where the backup sits.
#   --restore-backup   the explicit opt-in for putting the pre-install file back
#                      anyway. It states what it is about to destroy first.
#
# A backup is not a safe thing to restore. That is the whole idea.


def render_uninstall_verdict(verdict: Dict[str, Any], settings_path: Path,
                             baseline: Path, man: "manifest_mod.Manifest") -> None:
    """Say what has happened to this file since the install, BEFORE we act.

    Printed on the dry run as well as the write, because the decision it
    describes -- restore verbatim, or remove surgically -- is the one thing a
    person would want to overrule, and they can only overrule it if they were
    told before it happened.
    """
    state = verdict.get("state")
    entry = verdict.get("entry") or {}
    backup = entry.get("backup")
    say()
    say("  SINCE THE INSTALL")
    if state == "unchanged":
        say("    " + c(f"{settings_path.name} is byte-for-byte what we wrote -- "
                       "nobody has edited it since.", "32"))
        say("    " + c("so taking our entries back out lands on the pre-install "
                       "file exactly, and restoring it is a provable undo, not a "
                       "guess.", "2"))
        return
    if state == "changed":
        warn(f"{settings_path.name} has been EDITED since we wrote it; its checksum "
             "no longer matches ours.")
        say("    removing only our own entries. Everything you added -- MCP "
            "servers, permissions, other tools' hooks -- is kept.")
        if baseline.exists():
            say(f"    the pre-install copy is at {baseline}")
        if backup:
            say(f"    the copy taken before our last write is at {backup}")
        say("    " + c("--restore-backup would write the pre-install file back and "
                       "DISCARD those edits. That is why it is not the default.",
                       "2"))
        return
    if state == "missing":
        say("    " + c("we have a record of writing this file, but it is not there "
                       "now. Nothing to take out of it.", "33"))
        return
    reason = {"absent": "no install manifest on this machine -- this install "
                        "predates it, or state/ was cleared",
              "unreadable": f"the manifest at {man.path} could not be read",
              }.get(man.status, "no manifest entry for this file")
    say("    " + c(f"{reason}.", "2"))
    say("    " + c("removing only the entries that are recognisably ours, and "
                   "claiming nothing about the rest of the file.", "2"))


def _pre_install_copy(install_dir: Path, settings_path: Path,
                      man: "manifest_mod.Manifest") -> Tuple[Optional[Path], str]:
    """(the file holding the pre-install bytes, what it is). (None, why) if none.

    The baseline first and the numbered .bak second, and the order is the whole
    point: the baseline is written ONCE, on the first install, so it is the file
    as it was before this tool ever saw it. A .bak-N is taken before every write,
    so on an upgraded install the newest one already contains our hooks --
    restoring it would reinstate the very entries the user is uninstalling while
    calling itself a clean undo.
    """
    baseline = baseline_path(install_dir, settings_path)
    if baseline.is_file():
        return baseline, "the byte-exact copy taken before the FIRST install"
    entry = man.entry(settings_path, "settings") or {}
    recorded = entry.get("backup")
    if recorded and Path(recorded).is_file():
        return (Path(recorded),
                "the copy taken before our most recent write (NOT necessarily "
                "before the first one)")
    return None, ("no pre-install copy of this file was kept -- it was installed "
                  "with --no-backup, or state/ has been cleared")


def restore_pre_install(install_dir: Path, settings_path: Path,
                        current_text: str, current: Dict[str, Any],
                        args, man: "manifest_mod.Manifest") -> int:
    """--restore-backup: put the PRE-INSTALL settings file back, verbatim.

    Deliberately opt-in, deliberately loud, and deliberately NOT what --uninstall
    does on its own. Between an install and an uninstall a settings file
    accumulates the user's real work; a verbatim restore silently deletes all of
    it, and the person running an uninstall is not expecting that. So this
    prints the keys it is about to lose BEFORE it does anything, and is still a
    dry run until --yes.

    The current file is backed up first. An "undo" that leaves the state it
    replaced unrecoverable is not an undo.
    """
    source, why = _pre_install_copy(install_dir, settings_path, man)
    verdict = man.verdict(settings_path, "settings")
    say()
    say(c("  RESTORE THE PRE-INSTALL FILE", "1"))
    say("  " + "=" * 76)
    if source is None:
        fail(why + ".")
        fail("There is nothing to restore. Plain --uninstall removes our entries "
             "and leaves the rest of your file alone, which is the safe undo.")
        return 2
    try:
        saved = read_exact(source)
        restored = json.loads(saved)
    except Exception as exc:
        fail(f"{source} is not readable as JSON ({type(exc).__name__}: {exc}); "
             "refusing to write it over a live settings file.")
        return 2
    if not isinstance(restored, dict):
        fail(f"{source} is not a JSON object; refusing to write it.")
        return 2

    say(f"    source        {source}")
    say(f"    which is      {why}")
    say(f"    target        {settings_path}")
    say(f"    verdict       " + {
        "unchanged": c("unedited since our write -- this restore is exact", "32"),
        "changed": c("EDITED since our write -- the edits below will be lost", "31;1"),
        "missing": c("the target is gone", "33"),
    }.get(verdict.get("state"), c("no install record; cannot say what changed", "33")))

    # Name the losses in the user's own vocabulary -- top-level keys -- before
    # showing a diff. A diff of a 400-line settings file scrolls past; "you will
    # lose mcpServers" does not.
    lost = [k for k in current if k not in restored]
    changed_keys = [k for k in current if k in restored
                    and json.dumps(current[k], sort_keys=True)
                    != json.dumps(restored[k], sort_keys=True)]
    gained = [k for k in restored if k not in current]
    say()
    if lost:
        warn("these top-level keys exist NOW and are not in the restore -- they "
             "will be LOST:")
        for key in lost:
            warn(f"    {key}")
    if changed_keys:
        warn("these keys exist in both and will be OVERWRITTEN with the older "
             "value:")
        for key in changed_keys:
            warn(f"    {key}")
    if gained:
        say("    these keys come back from the pre-install file: "
            + ", ".join(gained))
    if not (lost or changed_keys or gained):
        say("    " + c("no top-level key differs; only formatting or our own "
                       "entries change.", "32"))

    say()
    say(colourise(diff(current_text, saved, settings_path)) or "  (no textual change)")

    if not args.yes:
        say()
        say(c("  DRY RUN -- nothing written. Re-run with --yes to apply.", "1"))
        return 0

    backup = None
    if not args.no_backup and settings_path.is_file():
        # `is_file()` because the target may legitimately be GONE -- somebody
        # deleted settings.json and wants the pre-install one back. There is
        # then no current state to preserve, and next_backup() would copy from
        # a file that is not there.
        try:
            backup = next_backup(settings_path)
            shutil.copy2(str(settings_path), str(backup))
            if backup.read_bytes() != settings_path.read_bytes():
                fail(f"the backup at {backup} does not match the original; "
                     "refusing to write")
                return 3
            say(f"  backup      {backup}   (the file as it is RIGHT NOW)")
        except Exception as exc:
            fail(f"could not back up the current file ({type(exc).__name__}: {exc}); "
                 "refusing to overwrite it")
            return 3
    try:
        settings_path.parent.mkdir(parents=True, exist_ok=True)
        atomic_replace(settings_path, saved)
    except Exception as exc:
        fail(f"write failed: {type(exc).__name__}: {exc}")
        if backup is not None and backup.is_file():
            try:
                shutil.copy2(str(backup), str(settings_path))
                fail(f"restored {settings_path} from {backup}")
            except Exception as restore_exc:
                fail(f"COULD NOT RESTORE {settings_path}: {restore_exc}; your file "
                     f"is intact at {backup} -- copy it back by hand.")
        return 3

    # Prove it landed rather than announce it.
    try:
        landed = settings_path.read_bytes() == saved.encode("utf-8")
    except Exception:
        landed = False
    if not landed:
        fail(f"{settings_path} is not byte-identical to {source} after the write.")
        if backup is not None:
            fail(f"the file as it was is at {backup}.")
        return 3
    say(f"  wrote       {settings_path}")
    say(c("  verified: byte-identical to the pre-install copy.", "32;1"))

    # The pre-install copy has now been spent. The stash of a statusLine we
    # displaced is spent with it -- it is already inside the bytes we just wrote,
    # and leaving it would restore it a second time into whatever file is
    # uninstalled next.
    for path in (baseline_path(install_dir, settings_path),
                 displaced_statusline_path(install_dir, settings_path)):
        try:
            if path.is_file():
                path.unlink()
                say(f"  consumed    {path}")
        except Exception:
            pass
    man.forget(settings_path, "settings")

    if args.only == "all" and not args.no_link:
        rows = remove_bin_link(install_dir, bin_name=args.bin_name, apply=True)
        rows += drop_path_block(install_dir, man, apply=True)
        if rows:
            say()
            say("  PATH")
            for row in rows:
                say("    - " + row)
        _forget_dead_links(install_dir, man)
    man.save()
    say()
    say("  Start a new Claude Code session for the change to take effect.")
    return 0


def _forget_dead_links(install_dir: Path, man: "manifest_mod.Manifest") -> None:
    """Drop symlink rows for links that are no longer ours (or no longer there).

    Re-checked against the filesystem rather than assumed from what the removal
    reported: a link the removal could not delete must STAY in the manifest, or
    the next uninstall has no record of it at all.
    """
    for entry in list(man.of_kind("symlink")):
        path = Path(str(entry.get("path")))
        try:
            if not _points_into(path, install_dir):
                man.forget(path, "symlink")
        except Exception:
            continue


def _apply_and_record_reports_root(plan: Dict[str, Any],
                                   man: "manifest_mod.Manifest") -> bool:
    """apply_reports_root(), plus the manifest row for the file it wrote.

    config.json is machine-local and untracked, so it is easy to forget that the
    installer creates it. An uninstall that does not know it exists leaves a file
    behind, and the manifest is supposed to be the ONE answer to "what did this
    install touch".
    """
    path = plan.get("path")
    before = manifest_mod.digest(path) if path is not None else None
    wrote = apply_reports_root(plan)
    if wrote and path is not None:
        man.record(path, kind="config",
                   action="created" if before is None else "modified",
                   before=before, wrote=manifest_mod.digest(path))
    return wrote


# ---------------------------------------------------------------------------
# the PATH doctor:  why is `oe` not found, and the one command that fixes it
# ---------------------------------------------------------------------------
#
# This exists for a sequence that is entirely ordinary: install, open a fresh
# terminal, `oe: command not found`. The install was fine -- the link landed in a
# directory the shell does not search -- but the person at the prompt cannot
# tell that apart from a broken install, and the tool that could explain it is
# precisely the one they cannot run. Cloning to an arbitrary directory makes
# this MORE likely, not less.
#
# So the diagnosis lives here, in install.py, which is reachable by absolute
# path -- the one handle somebody still has when `oe` is not. It writes nothing
# by default. --path-fix authorises the repair and, like every other write in
# this file, is still a dry run until --yes.
#
# The rc mechanics are oe.autostart's, never a second copy. $ZDOTDIR, and bash
# on macOS being a login shell that reads .bash_profile and never .bashrc, are
# two facts a hand-rolled snippet gets wrong for somebody -- and the somebody it
# is wrong for is the person who is already stuck.

PATH_BEGIN_MARKER = "# >>> claude overwatch-enforcer PATH >>>"
PATH_END_MARKER = "# <<< claude overwatch-enforcer PATH <<<"


def path_block_text(directory: Path) -> str:
    """The delimited block that puts one directory on PATH, idempotently.

    A bare `export PATH="$DIR:$PATH"` is the line everybody writes and it is
    wrong here: an rc file gets sourced more than once (a `source ~/.zshrc`, a
    login shell that also reads the interactive rc, a tmux pane), and each pass
    prepends the directory again until $PATH is a page long. The `case` guard
    makes re-sourcing a no-op, which is the same property the delimited block
    gives the FILE.

    Every other detail earns its place:

      * `case ... esac` rather than `[[ ]]`, and no `local`: this same text goes
        into .zshrc, .bashrc and .profile, so it may only use POSIX sh.
      * `${PATH-}` so an rc running under `set -u` does not abort.
      * the pattern is QUOTED ("$__oe_bin"), so a directory containing a glob
        character is matched literally instead of being expanded.
      * the directory goes through shlex.quote, because
        '~/Library/Application Support/...' on macOS is an ordinary path with a
        space in it, and unquoted it would be two words and a syntax error in
        the file every terminal sources.
      * a variable, then `unset`: it keeps the quoting in ONE place and leaves
        nothing behind in the user's shell.
    """
    import shlex
    quoted = shlex.quote(str(directory))
    return (
        f"{PATH_BEGIN_MARKER}\n"
        "# Puts the Overwatch Enforcer command on PATH. Idempotent: sourcing\n"
        "# this file again cannot add a second copy of the directory.\n"
        f"__oe_bin={quoted}\n"
        'case ":${PATH-}:" in\n'
        '  *":$__oe_bin:"*) ;;\n'
        '  *) PATH="$__oe_bin:${PATH-}" ; export PATH ;;\n'
        "esac\n"
        "unset __oe_bin\n"
        f"{PATH_END_MARKER}\n"
    )


def _our_link(install_dir: Path, bin_name: str,
              man: Optional["manifest_mod.Manifest"] = None) -> Optional[Path]:
    """The link WE made, wherever it ended up. None if there is not one.

    Every place it could be, because the link may have been made when PATH,
    HOME or --bin-name were different -- the same reasoning remove_bin_link()
    already applies, and for the same reason. The manifest is consulted first
    and the PATH is consulted last, so a link recorded at install time is found
    even when nothing on today's PATH would reach it. One that IS on PATH wins,
    since that is the one the user's shell would run.
    """
    seen = set()
    candidates: List[Path] = []

    def consider(path: Optional[Path]) -> None:
        if path is None:
            return
        try:
            key = os.path.normpath(str(path))
        except Exception:
            return
        if key not in seen:
            seen.add(key)
            candidates.append(path)

    if man is not None:
        for entry in man.of_kind("symlink"):
            consider(Path(str(entry.get("path"))))
    for recorded in _recorded_links(install_dir):
        consider(recorded)
    for directory in link_candidates():
        consider(directory / bin_name)
    for entry_dir in _path_dirs():
        consider(Path(entry_dir) / bin_name)
    found = shutil.which(bin_name)
    consider(Path(found) if found else None)

    def _is_ours(path: Path) -> bool:
        # Pointing into THIS install dir is the ordinary case. But a checkout
        # that was moved or re-cloned leaves a link into the OLD root, and that
        # link is still ours -- it is the very thing the user is asking about
        # when `oe` stops working. plan_bin_link() already claims it by SHAPE
        # (a dangling symlink named <bin_name> whose target is */bin/<bin_name>);
        # filtering it out here is what made the two subsystems disagree about
        # the same file, and made the moved-checkout row in the runbook
        # unreachable.
        if _points_into(path, install_dir):
            return True
        try:
            if not path.is_symlink():
                return False
            dest = Path(os.path.realpath(str(path)))
            if dest.exists():
                return False          # a LIVE second install, not ours to claim
            # plan_bin_link always points at bin/<DEFAULT_BIN_NAME> even under
            # --bin-name, so the TARGET is the default name while the LINK
            # carries the custom one. Testing the target against bin_name
            # meant this branch could never fire for a custom name, which is
            # the disagreement it was added to remove.
            return (dest.name in (bin_name, DEFAULT_BIN_NAME)
                    and dest.parent.name == "bin")
        except Exception:
            return False

    ours = [p for p in candidates if _is_ours(p)]
    for link in ours:
        if _on_path(link.parent):
            return link
    return ours[0] if ours else None


def diagnose_path(install_dir: Path, *, bin_name: str = DEFAULT_BIN_NAME,
                  rc_override: Optional[str] = None,
                  man: Optional["manifest_mod.Manifest"] = None) -> Dict[str, Any]:
    """Everything the fix needs and the user wants to know. Writes nothing."""
    target = install_dir / "bin" / DEFAULT_BIN_NAME
    shell, rcs = _shell_bits()
    rc = normalise_dir(rc_override) if rc_override else _rc_target(shell, rcs)
    try:
        from oe import autostart as autostart_mod
        supported = autostart_mod.shell_supported(shell)
    except Exception:
        supported = shell in ("zsh", "bash", "sh", "dash", "ksh")

    found = shutil.which(bin_name)
    found_path = Path(found) if found else None
    # `_inside` as well as `_points_into`: somebody may have put <install>/bin
    # on PATH directly, which is a perfectly good install with no symlink in it.
    found_ours = bool(found_path and (_points_into(found_path, install_dir)
                                      or _inside(found_path, install_dir)))
    link = _our_link(install_dir, bin_name, man)

    diag: Dict[str, Any] = {
        "name": bin_name,
        "install_dir": install_dir,
        "target": target,
        "target_ok": target.is_file() and os.access(str(target), os.X_OK),
        "which": found_path,
        "which_is_ours": found_ours,
        # A command of this name that is NOT ours and IS reachable. Prepending
        # our directory would put ours in front of it -- which we will not do
        # without saying so.
        "shadow": None if found_ours else found_path,
        "link": link,
        "link_on_path": bool(link is not None and _on_path(link.parent)),
        "shell": shell,
        "rc": rc,
        "rc_exists": rc.is_file(),
        "rc_explicit": rc_override is not None,
        "shell_supported": supported,
        "dir_to_add": None,
        "block": "",
        "export": "",
        "state": "unknown",
    }

    if not diag["target_ok"]:
        diag["state"] = "no-target"
    elif found_ours:
        diag["state"] = "ok"
    elif link is not None and not diag["link_on_path"]:
        diag["state"] = "off-path"
    elif link is not None:
        # The link is in a directory the shell searches, yet the shell does not
        # find it. That is the link itself: dangling, or not executable.
        diag["state"] = "broken-link"
    elif _on_path(target.parent):
        # bin/ is searched and bin/oe is executable, but the name is not
        # resolving -- almost always the shell's command hash, not the install.
        diag["state"] = "rehash"
    else:
        diag["state"] = "not-linked"

    # WHICH directory the fix would add. Our link's directory when we have one,
    # because that is the conventional place and it exposes only `oe`. Otherwise
    # the checkout's own bin/, which needs no symlink at all -- the right answer
    # for a clone in an arbitrary directory with no writable bin dir in HOME.
    if diag["state"] in ("off-path", "not-linked"):
        diag["dir_to_add"] = link.parent if link is not None else target.parent
        diag["block"] = path_block_text(diag["dir_to_add"])
        diag["export"] = export_line(diag["dir_to_add"], shell)
    return diag


def render_path_report(diag: Dict[str, Any], *, fixing: bool,
                       will_write: bool) -> None:
    """Say what is true, then what would change. Never writes."""
    name = diag["name"]
    say()
    say(c("  PATH DIAGNOSIS", "1"))
    say("  " + "=" * 76)
    say(f"    command name       {name}")
    say(f"    this checkout      {diag['install_dir']}")
    say(f"    the executable     {diag['target']}   "
        + (c("ok", "32") if diag["target_ok"] else c("MISSING or not executable", "31;1")))
    which = diag["which"]
    if which is None:
        say(f"    `{name}` resolves to  " + c("nothing -- not on PATH", "33"))
    else:
        say(f"    `{name}` resolves to  {which}   "
            + (c("(ours)", "32") if diag["which_is_ours"] else c("(NOT ours)", "31;1")))
    link = diag["link"]
    if link is None:
        say("    our link           " + c("none found", "33"))
    else:
        say(f"    our link           {link}")
        say(f"    its directory      {link.parent}   "
            + (c("is on PATH", "32") if diag["link_on_path"]
               else c("is NOT on PATH", "33")))
    say(f"    login shell        {diag['shell']}"
        + ("" if diag["shell_supported"] else c("   (not one we can write for)", "33")))
    say(f"    rc file            {diag['rc']}"
        + ("" if diag["rc_exists"] else c("   (does not exist)", "33")))
    say()

    state = diag["state"]
    if state == "ok":
        say("  " + c(f"`{name}` is on PATH and it is this checkout. Nothing to fix.",
                     "32;1"))
        return
    if state == "no-target":
        fail(f"{diag['target']} is missing or not executable, so no amount of PATH "
             "will help. Re-clone the tree, or `chmod +x` it.")
        return
    if state == "broken-link":
        fail(f"{link} is in a directory on your PATH but does not run: the link is "
             "dangling or not executable.")
        say(f"    fix it by re-running the install, which re-points it: "
            + c(f"{HERE / 'install.py'} --yes", "1"))
        return
    if state == "rehash":
        warn(f"{diag['target'].parent} IS on your PATH and {diag['target'].name} is "
             f"executable, but the shell is not finding `{name}`.")
        say("    that is the shell's command hash, not the install:")
        say("      " + c("hash -r    (bash)", "1"))
        say("      " + c("rehash     (zsh)", "1"))
        say("    a new terminal needs neither.")
        return

    say(f"  `{name}` is not on your PATH. "
        + ("Its link is in a directory the shell does not search."
           if state == "off-path" else "No link of ours is installed."))
    if state == "not-linked" and diag["link"] is None:
        say(f"    a full install would also create the link: "
            + c(f"{HERE / 'install.py'} --yes", "1"))
    say()
    say(f"    would add to PATH  {diag['dir_to_add']}")
    say(f"    by editing         {diag['rc']}   ({diag['shell']})")
    say()
    for line in diag["block"].splitlines():
        say("      " + c(line, "2" if line.startswith("#") else "1"))
    say()

    if diag["shadow"] is not None:
        warn(f"`{name}` already resolves to {diag['shadow']}, which is not ours.")
        warn("  Adding our directory in front would SHADOW it, so this will not be "
             "written.")
        say(f"    install under another name instead: "
            + c(f"{HERE / 'install.py'} --yes --bin-name <other>", "1"))
        return
    if not diag["shell_supported"]:
        warn(f"the block above is POSIX shell and your login shell is "
             f"{diag['shell']}, which would not parse it. Nothing will be written.")
        if diag["shell"] == "fish":
            say(f"    the fish equivalent, for {diag['rc']}:")
            say("      " + c(export_line(diag["dir_to_add"], "fish"), "1"))
        return
    if not diag["rc_exists"]:
        warn(f"{diag['rc']} does not exist, and creating a shell rc file is a bigger "
             "decision than this command may make for you -- on macOS a new "
             "~/.bash_profile stops bash reading ~/.profile at all.")
        say(f"    create it first if that is what you want:  "
            + c(f"touch {diag['rc']}", "1"))
        return
    if not fixing:
        say("    " + c(f"nothing was written. To apply it: {HERE / 'install.py'} "
                       "--path-fix --yes", "2"))
    elif not will_write:
        say("    " + c("DRY RUN -- nothing written. Add --yes to apply.", "1"))


def apply_path_fix(diag: Dict[str, Any], install_dir: Path, *,
                   assume_yes: bool,
                   man: Optional["manifest_mod.Manifest"] = None) -> int:
    """Write the PATH block. Returns a process exit code.

    Every gate oe.autostart applies to the autostart line applies here, because
    it is the same file and the same stakes: a numbered backup that is read back
    and compared byte for byte, `<shell> -n` on the candidate BEFORE it is put
    in place and again on what actually landed, a delimited block so a later
    removal is an exact cut, and a temp file + os.replace so no reader ever sees
    half of either version.
    """
    rc: Path = diag["rc"]
    from oe import autostart as autostart_mod

    if not diag["rc_explicit"]:
        # The same refusal autostart makes, for the same already-observed bug: a
        # process whose HOME points at a scratch tree but whose $ZDOTDIR still
        # points at the real one would otherwise edit the real ~/.zshrc.
        try:
            autostart_mod.assert_inside_home(rc)
        except Exception as exc:
            fail(str(exc))
            return 2

    before = manifest_mod.digest(rc)
    try:
        result = autostart_mod.edit_block(
            rc, begin=PATH_BEGIN_MARKER, end=PATH_END_MARKER,
            block=diag["block"], dry_run=not assume_yes)
    except Exception as exc:
        fail(f"refused to edit {rc}: {type(exc).__name__}: {exc}")
        return 3

    if not assume_yes:
        # render_path_report() has already said "DRY RUN"; the one thing it
        # could not know is whether the block is already there, since that
        # needs the rc read that edit_block() just did.
        if result["action"] == "already-installed":
            say()
            say(c(f"  {rc} already carries this exact block.", "32"))
            say("  " + c(f"if `{diag['name']}` is still not found, this shell has "
                         f"not read it yet: open a new terminal, or "
                         f"`source {rc}`.", "2"))
        return 0

    if result["action"] == "already-installed":
        say()
        say(c(f"  {rc} already carries this exact block; nothing was written.", "32"))
        say("  " + c(f"open a new terminal, or: source {rc}", "1"))
        return 0
    if result["action"] == "no-rc":
        fail(f"{rc} does not exist; nothing was written.")
        return 2

    say()
    say(f"  backup      {result['backup']}")
    say(f"  {'updated' if result['action'] == 'updated' else 'wrote':<7}     {rc}"
        f"   ({result['blocks']} block)")
    if result.get("syntax_after") is True:
        say("  " + c(f"verified: {rc} still parses.", "32"))
    elif result.get("syntax_after") is False:
        # Should be unreachable -- the candidate was checked before the write --
        # but if it ever happens, the backup is the recovery and must be named.
        fail(f"{rc} does NOT parse after the write. Restore it: "
             f"cp {result['backup']} {rc}")
        return 3
    else:
        say("  " + c("could not syntax-check (that shell is not installed here).",
                     "2"))

    if man is not None:
        man.record(rc, kind="shell-rc", action="modified", before=before,
                   wrote=manifest_mod.digest(rc), backup=result.get("backup"))
        man.save()

    say()
    say(c("  Now open a new terminal, or run:", "1"))
    say("      " + c(f"source {rc}", "1"))
    say(f"  then: {diag['name']} doctor")
    return 0


def drop_path_block(install_dir: Path, man: "manifest_mod.Manifest", *,
                    apply: bool) -> List[str]:
    """Cut the PATH block back out of every rc file the manifest says we edited.

    The block is the one thing --path-fix leaves in a file that is not ours, so
    an uninstall that ignored it would leave a directory on somebody's PATH
    pointing at a checkout they just removed. Harmless -- a missing directory on
    PATH is a no-op -- but it is exactly the kind of litter the manifest exists
    to make impossible.

    Surgical whatever the checksum says, and that is not a shortcut: the cut is
    delimited, so it takes our block and nothing else, and an rc file that HAS
    changed since we wrote it is the normal case -- people edit their shell
    config. Comparing checksums would only tell us something we would not act
    on.
    """
    changes: List[str] = []
    from oe import autostart as autostart_mod
    for entry in list(man.of_kind("shell-rc")):
        rc = Path(str(entry.get("path")))
        try:
            if not rc.is_file():
                man.forget(rc, "shell-rc")
                continue
            text = rc.read_text(encoding="utf-8", errors="surrogateescape")
            if not autostart_mod.find_blocks_of(
                    text, [(PATH_BEGIN_MARKER, PATH_END_MARKER)]):
                man.forget(rc, "shell-rc")   # already gone, by hand or otherwise
                continue
        except Exception:
            continue
        changes.append(f"remove the PATH block from {rc}")
        if not apply:
            continue
        try:
            result = autostart_mod.edit_block(
                rc, begin=PATH_BEGIN_MARKER, end=PATH_END_MARKER, remove_only=True)
        except Exception as exc:
            # A refusal here means the backup did not verify or the result would
            # not parse. Both leave the file untouched, which is the right
            # outcome; say so rather than claim a removal that did not happen.
            warn(f"left {rc} alone: {type(exc).__name__}: {exc}")
            changes[-1] += "  (FAILED)"
            continue
        if result.get("backup"):
            changes[-1] += f"   (backup: {result['backup']})"
        man.forget(rc, "shell-rc")
    return changes


def path_doctor(install_dir: Path, *, bin_name: str = DEFAULT_BIN_NAME,
                fix: bool = False, assume_yes: bool = False,
                rc_override: Optional[str] = None) -> int:
    """`--path-doctor` / `--path-fix`. Exit 0 when `oe` is (or will be) reachable.

    Split into diagnose / render / apply so the diagnosis is testable on its own
    and so --path-doctor can be a pure read: it calls the first two and stops.
    """
    man = manifest_mod.Manifest.load(install_dir)
    diag = diagnose_path(install_dir, bin_name=bin_name, rc_override=rc_override,
                         man=man)
    render_path_report(diag, fixing=fix, will_write=assume_yes)
    if diag["state"] == "ok":
        return 0
    if not fix:
        return 1
    # Every reason we would refuse to write is already rendered above, in the
    # user's words rather than an exception. Refusing quietly here keeps the
    # exit code honest without saying it twice.
    if diag["state"] in ("no-target", "broken-link", "rehash") \
            or diag["shadow"] is not None or not diag["shell_supported"] \
            or not diag["rc_exists"]:
        return 1
    return apply_path_fix(diag, install_dir, assume_yes=assume_yes, man=man)


# ---------------------------------------------------------------------------
# reports_root: the value the checkout shipped with is the PACKAGER's, not yours
# ---------------------------------------------------------------------------

# config.json is machine-local and is NOT tracked by the repository: it holds
# this machine's reports_root, so a tracked copy would both publish a local path
# and make `git pull` abort on a dirty working tree. A clone therefore arrives
# with no config.json at all, which is a fully supported state --
# paths.load_config() falls back to the code defaults -- and this file seeds one
# from the tracked example so there is something to edit.
CONFIG_NAME = "config.json"
CONFIG_EXAMPLE_NAME = "config.example.json"


def plan_reports_root(install_dir: Path) -> Dict[str, Any]:
    """Decide whether config.json's reports_root belongs to THIS machine.

    config.json travels with the tree, so whatever is in it is the choice of
    whoever packaged it. On their machine it is a real directory; on yours it is
    a path that names somebody else's checkout and does not exist -- and the
    runtime would go on and CREATE it, so the first thing a new user gets is a
    directory named after a stranger's project appearing in their home, with
    their reports inside it.
    The rule is the narrowest one that separates the two cases and that anybody
    can check by hand: a reports_root that already EXISTS is this machine's and
    is kept; one that does not is inherited and is reset to the portable
    default beside Claude Code's own config. Reads only; writes nothing.
    """
    plan: Dict[str, Any] = {"action": "none", "path": install_dir / CONFIG_NAME,
                            "current": "", "new": None, "why": "",
                            "effective": None, "source": None}
    default = claude_home() / "reports" / "usage"
    plan["effective"] = default
    try:
        raw_text = plan["path"].read_text(encoding="utf-8")
        cfg = json.loads(raw_text)
    except FileNotFoundError:
        # A clone: config.json is untracked, so the example is the only one
        # there. Copying it costs nothing and gives the user a file to edit
        # with every key named; its reports_root IS the portable default, so
        # `effective` above is already the right answer either way.
        example = install_dir / CONFIG_EXAMPLE_NAME
        if example.is_file():
            plan["action"] = "create"
            plan["source"] = example
            plan["why"] = (f"no {CONFIG_NAME} here yet; {CONFIG_EXAMPLE_NAME} is "
                           "the defaults, and config.json is yours to edit")
            return plan
        plan["why"] = f"no {CONFIG_NAME}; the portable default is used"
        return plan
    except Exception as exc:
        plan["why"] = f"config.json unreadable ({type(exc).__name__}); left alone"
        return plan
    if not isinstance(cfg, dict):
        plan["why"] = "config.json is not an object; left alone"
        return plan
    current = str(cfg.get("reports_root") or "").strip()
    plan["current"] = current
    if not current:
        plan["why"] = "config.json names no reports_root; the portable default is used"
        return plan
    try:
        expanded = Path(current).expanduser()
    except Exception:
        expanded = None
    if expanded is None:
        plan["action"] = "rewrite"
        plan["new"] = default
        plan["why"] = "the configured reports_root is not a usable path"
        return plan
    plan["effective"] = expanded
    if expanded == default:
        plan["action"] = "keep"
        plan["why"] = "already the portable default"
        return plan
    if expanded.is_dir():
        plan["action"] = "keep"
        plan["why"] = "it exists on this machine, so it is a deliberate local choice"
        return plan
    plan["action"] = "rewrite"
    plan["new"] = default
    plan["effective"] = default
    plan["why"] = (f"{expanded} does not exist on this machine, so it is the value "
                   "the checkout shipped with rather than yours")
    return plan


def render_reports_root(plan: Dict[str, Any], *, will_write: bool) -> None:
    if plan["action"] == "create":
        say()
        say("  REPORTS")
        say(("    creating           " if will_write else "    would create       ")
            + c(str(plan["path"]), "1") + f"  from {CONFIG_EXAMPLE_NAME}")
        say("    " + c(plan["why"], "2"))
        return
    if plan["action"] == "rewrite":
        say()
        say("  REPORTS")
        say(f"    config.json says   {plan['current']}")
        say("    " + c(plan["why"], "2"))
        say(("    rewriting to       " if will_write else "    would rewrite to   ")
            + c(str(plan["new"]), "1"))


def apply_reports_root(plan: Dict[str, Any]) -> bool:
    """Create config.json from the example, or rewrite exactly one value in it,
    preserving every other key and the key order (json.load keeps insertion
    order)."""
    path: Path = plan["path"]
    if plan["action"] == "create":
        source = plan.get("source")
        if source is None or not Path(source).is_file() or path.exists():
            return False
        try:
            shutil.copy2(str(source), str(path))
        except Exception as exc:
            warn(f"could not create {path} from {source}: "
                 f"{type(exc).__name__}: {exc}")
            return False
        say(f"  config      {path}  created from {CONFIG_EXAMPLE_NAME}")
        return True
    if plan["action"] != "rewrite" or plan["new"] is None:
        return False
    try:
        cfg = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(cfg, dict):
            return False
        before = {k: v for k, v in cfg.items() if k != "reports_root"}
        keys_before = list(cfg.keys())
        # Write the ~ form when the target really is under this user's home:
        # a config.json that says "~/.claude/reports/usage" is correct on every
        # machine, so a tree re-shared from here needs no rewrite at all. An
        # absolute path is used when CLAUDE_CONFIG_DIR has moved it elsewhere.
        new_text = str(plan["new"])
        home = str(_home())
        if new_text.startswith(home + os.sep):
            new_text = "~" + new_text[len(home):]
        cfg["reports_root"] = new_text
        if list(cfg.keys()) != keys_before or \
                {k: v for k, v in cfg.items() if k != "reports_root"} != before:
            warn("refusing to rewrite config.json: the round-trip changed something "
                 "other than reports_root")
            return False
        atomic_replace(path, json.dumps(cfg, indent=2, ensure_ascii=False) + "\n")
    except Exception as exc:
        warn(f"could not rewrite {path}: {type(exc).__name__}: {exc}")
        return False
    say(f"  config      {path}  reports_root -> {cfg['reports_root']}")
    return True



# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="install.py",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="Install Overwatch Enforcer into a Claude Code settings file.",
        epilog="""
how the flags compose
---------------------
  install.py                 checklist, prompts, then a DRY RUN diff. Writes nothing.
  install.py --yes           checklist, prompts, then WRITES. --yes is the only
                             authorisation to write; it does not skip the prompts.
  install.py --yes --non-interactive
                             checklist, defaults for every prompt, then WRITES.
                             This is the CI / scripted form.
  install.py --check         the checklist alone. Writes nothing, ever. Exit 1 if
                             this machine is not ready.
  install.py --uninstall --yes
                             remove exactly our entries and restore the original
                             bytes when nothing else changed, and remove the
                             `oe` symlink this installer created.
  install.py --path-doctor   why is `oe` not found? Writes nothing, ever.
  install.py --path-fix --yes
                             fix it: an idempotent PATH block in the rc file
                             your login shell really reads.

undoing an install
------------------
  Every file this installer touches is recorded in ONE manifest under state/:
  path, what we did, the checksum before, the checksum of what we wrote, the
  backup, the settings scope. --uninstall reads it.

  It does NOT blindly restore a backup, and that is the important part. A
  settings.json collects MCP servers, permissions and other tools' hooks for
  months after an install; writing March's copy over September's file would
  destroy all of it. So the default is SURGICAL removal -- only our own
  entries -- and the manifest is what makes that exact rather than heuristic.
  When the file's checksum still matches what we wrote, nobody has touched it,
  a verbatim restore is provably safe, and that is what happens. When it does
  not match, the uninstall says so, names the backup, and keeps your edits.
  --restore-backup is the explicit opt-in for the other choice.

putting `oe` on PATH
--------------------
  A successful install also symlinks `oe` into the first writable one of
  $XDG_BIN_HOME, ~/.local/bin, ~/bin -- preferring one that is ALREADY on
  PATH. When none of them is on PATH the link is still made and the exact
  export line for your shell's rc file is printed; when none is writable only
  the export line is printed. An `oe` that belongs to something else is never
  overwritten: use --bin-name to install under another name. --no-link opts
  out entirely.
""")
    parser.add_argument("--dir", dest="directory",
                        help="the directory this package ALREADY lives in -- the "
                             "installer wires up a checkout, it does not copy one "
                             "(default: the directory install.py is in; prompted "
                             "when there is a terminal)")
    parser.add_argument("--scope", choices=("user", "project", "local"),
                        help="which settings file gets the hooks "
                             "(default: recommended, prompted when there is a terminal)")
    parser.add_argument("--settings",
                        help="an explicit settings file path; overrides --scope "
                             "(use a copy to rehearse)")
    parser.add_argument("--yes", action="store_true",
                        help="authorise the write. Without it this is a dry run.")
    parser.add_argument("--non-interactive", action="store_true",
                        help="never prompt; take the default for every question")
    parser.add_argument("--check", action="store_true",
                        help="print the dependency checklist and exit; writes nothing")
    parser.add_argument("--uninstall", action="store_true",
                        help="remove exactly what we installed")
    parser.add_argument("--force-statusline", action="store_true",
                        help="replace a statusLine that belongs to something else")
    parser.add_argument("--interpreter", default="auto",
                        help="auto (default) | python3 | an explicit path. Whatever "
                             "you give is EXECUTED and version-checked before it is "
                             "written into the settings file.")
    parser.add_argument("--no-backup", action="store_true", help="skip the .bak copy")
    parser.add_argument("--no-binary-probe", action="store_true",
                        help="skip reading the Claude Code binary to confirm each "
                             "hook event (it reads the whole binary)")
    parser.add_argument("--allow-missing-claude", action="store_true",
                        help="downgrade 'Claude Code not found' from a failure to a "
                             "warning (wiring hooks ahead of installing it)")
    parser.add_argument("--only", choices=("all", "hooks", "statusline"), default="all",
                        help="which of our two managed keys to touch")
    parser.add_argument("--no-link", action="store_true",
                        help="do not put `oe` on PATH; print the export line instead")
    parser.add_argument("--link-dir",
                        help="the directory to symlink `oe` into "
                             "(default: the first writable one of $XDG_BIN_HOME, "
                             "~/.local/bin, ~/bin -- preferring one already on PATH)")
    parser.add_argument("--bin-name", default=DEFAULT_BIN_NAME,
                        help="the command name to install on PATH (default: oe). "
                             "Use this when something else already owns `oe`.")
    parser.add_argument("--path-doctor", action="store_true",
                        help="diagnose why `oe` is not found, and exit. Writes "
                             "nothing, ever. Exit 1 when it is not reachable. "
                             "Runnable by its full path -- which is the situation "
                             "you are in when you need it.")
    parser.add_argument("--path-fix", action="store_true",
                        help="the same diagnosis, then FIX it: a delimited, "
                             "idempotent PATH block in the rc file your login "
                             "shell actually reads. Dry run unless --yes.")
    parser.add_argument("--rc",
                        help="the shell rc file --path-fix should edit (default: "
                             "the one your login shell reads; name a copy to "
                             "rehearse)")
    parser.add_argument("--restore-backup", action="store_true",
                        help="with --uninstall: write the byte-exact PRE-INSTALL "
                             "settings file back, DISCARDING everything added to "
                             "it since. Says what it would destroy first, and is "
                             "still a dry run without --yes.")
    return parser


def _manifest_settings_targets(install_dir: Path) -> List[Dict[str, Any]]:
    """The settings files the install RECORD says we wrote into, in order.

    Read-only, and it never raises: this is consulted to choose the uninstall
    target, which must not be decided from the current working directory.
    Loading its own Manifest rather than taking
    main()'s is deliberate -- main() opens the manifest at step 5, after the
    target has already been chosen, and moving that load earlier would make
    `--check` (which must run on a tree with no state/ at all) depend on it.
    """
    rows: List[Dict[str, Any]] = []
    try:
        man = manifest_mod.Manifest.load(install_dir)
        if man.status != "ok":
            return []
        for entry in man.of_kind("settings"):
            raw = entry.get("path")
            if not isinstance(raw, str) or not raw:
                continue
            scope = entry.get("scope")
            rows.append({
                "path": Path(raw),
                "scope": scope if isinstance(scope, str) and scope else "recorded",
                "why": "named in the install record",
            })
    except Exception:
        return []
    return rows


def _detected_settings_targets(install_dir: Path) -> List[Dict[str, Any]]:
    """Settings files reachable from here that still carry THIS checkout's entries.

    The backstop for a manifest that was deleted, and the reason the match is
    made with `install_dir` rather than by shape: an entry pointing at somebody
    else's copy of this tool is not ours to remove, and counting it would send
    the uninstall at a file it can only report "nothing to remove" about.
    """
    rows: List[Dict[str, Any]] = []
    try:
        table = scope_table()
    except Exception:
        return []
    for row in table:
        path = row.get("path")
        if not isinstance(path, Path):
            continue
        try:
            if not path.is_file():
                continue
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            continue          # unreadable or invalid: the checklist's problem
        if not isinstance(data, dict):
            continue
        count = count_ours(data, install_dir)
        if count:
            rows.append({
                "path": path,
                "scope": str(row.get("scope") or "detected"),
                "why": f"still holds {count} entr{'y' if count == 1 else 'ies'} "
                       "pointing at this checkout",
            })
    return rows


def uninstall_targets(install_dir: Path) -> List[Dict[str, Any]]:
    """Every settings file an uninstall of `install_dir` has to clean, deduped.

    The record first, then anything still wired here that the record does not
    mention. An install writes into ONE scope, so this is normally one row --
    but somebody who installed into two scopes has two files to clean, and
    cleaning one of them while exiting 0 is the failure this replaces.
    """
    out: List[Dict[str, Any]] = []
    seen = set()
    for row in (_manifest_settings_targets(install_dir)
                + _detected_settings_targets(install_dir)):
        try:
            key = os.path.normpath(str(row["path"]))
        except Exception:
            key = str(row["path"])
        if key in seen:
            continue
        seen.add(key)
        out.append(row)
    return out


def stranded_targets(install_dir: Path, settings_path: Path, args
                     ) -> List[Dict[str, Any]]:
    """Files that still carry our entries after a pass that removed nothing.

    The check that turns the old silent success into an audible failure. It is
    skipped when the caller named a file with --settings: that is either the
    user pointing at one file deliberately, or one of the extra-scope passes
    above, and neither should be told off for the contents of a file it was
    never asked to touch.
    """
    if args.settings:
        return []
    try:
        here = os.path.normpath(str(settings_path))
    except Exception:
        here = str(settings_path)
    out = []
    for row in uninstall_targets(install_dir):
        try:
            other = os.path.normpath(str(row["path"]))
        except Exception:
            other = str(row["path"])
        if other != here:
            out.append(row)
    return out


def warn_no_record(recorded: List[Dict[str, Any]], args, path_rows: List[str]) -> None:
    """The one case nothing on this machine can prove, said out loud.

    An uninstall that finds no settings file AND no install record naming one,
    but still had a PATH link of ours to take away, has evidence that an install
    happened and no evidence of where its hooks went. That is the shape that
    strands somebody: a settings file in a project the user is not standing in,
    unreachable from here, with the record gone, leaving live hooks behind a
    deleted checkout.
    """
    if args.settings or recorded or not path_rows:
        return
    warn("this run took away a PATH link that pointed at this checkout, but found "
         "no settings file carrying its entries and no install record naming one. "
         "If the install was made from inside a project, re-run --uninstall from "
         "that directory BEFORE deleting the checkout: hooks left in a "
         "project-local settings file keep firing, and point at a script that will "
         "not be there.")


def report_stranded(stranded: List[Dict[str, Any]], settings_path: Path) -> int:
    """Say which file really holds the entries, and exit non-zero.

    Deliberately loud and deliberately non-zero: the state this replaces was a
    cheerful "nothing to remove" and exit 0 on a machine that still ran three of
    our hooks on every session, which no script and no user could detect. The
    PATH link is left alone on this path too -- `oe` is the command that undoes
    the thing this run just failed to undo.
    """
    fail(f"{settings_path} holds none of our entries, but another settings file "
         "does. Nothing was removed from either.")
    for row in stranded:
        fail(f"    {row['scope']:<10} {row['path']}")
        fail(f"    {'':<10} " + str(row["why"]))
    fail("Re-run with --settings pointing at that file, or from the directory the "
         "install was made in. `oe` is left on PATH so you can.")
    return 2


def render_uninstall_targets(targets: List[Dict[str, Any]]) -> None:
    say()
    say("  UNINSTALL TARGETS")
    say("  " + "=" * 76)
    say("  " + c("chosen from what this install actually touched, not from the "
                 "directory you are standing in", "2"))
    for row in targets:
        say(f"  {str(row['scope']):<10} {row['path']}")
        say(f"  {'':<10} " + c(str(row["why"]), "2"))
    if len(targets) > 1:
        say("  " + c(f"{len(targets)} files: each one is cleaned in its own pass "
                     "below.", "36"))


def resolve_settings_path(args, install_dir: Path, interactive: bool
                          ) -> Tuple[Path, str, bool]:
    """(path, scope, is_committed_scope)."""
    rows = scope_table(args.settings)
    recommended, reason = recommend_scope(rows, install_dir)
    render_scopes(rows, recommended, reason)

    if args.settings:
        row = rows[0]
        return row["path"], "--settings", False

    chosen = args.scope
    if chosen is None:
        available = [r["scope"] for r in rows]
        options = tuple(dict.fromkeys(available))
        chosen = ask_choice("Settings scope", options, recommended, interactive)
    matches = [r for r in rows if r["scope"] == chosen]
    if not matches:
        fail(f"--scope {chosen} is not available here "
             f"(no .claude directory above {Path.cwd()})")
        raise SystemExit(2)
    row = matches[0]
    if row["committed"]:
        say(c(COMMITTED_HOOKS_WARNING, "33"))
        if interactive:
            answer = ask_choice("Write hooks into a committed settings file anyway?",
                                ("yes", "no"), "no", interactive)
            if answer != "yes":
                fail("aborted at the committed-hooks prompt; nothing was written")
                raise SystemExit(2)
    return row["path"], chosen, bool(row["committed"])


def validate_combination(install_dir: Path, settings_path: Path, scope: str) -> None:
    """The two axes are independent, so the COMBINATION needs its own check."""
    say()
    say("  COMBINATION")
    say(f"    install dir     {install_dir}")
    say(f"    settings scope  {scope}  ->  {settings_path}")
    project = None
    for row in scope_table():
        if row["scope"] == "project":
            project = row["path"].parent.parent
            break
    if scope in ("project", "local") and project is not None:
        if _is_within(install_dir, project):
            say(c("    ok: the package lives inside the project the settings belong "
                  "to, so the two travel together.", "32"))
        else:
            warn("the package lives OUTSIDE this project but the hooks are being "
                 "written into the project's settings. That works on this machine "
                 "and nowhere else.")
    if scope == "user" and project is not None and _is_within(install_dir, project):
        warn("the package lives inside a project checkout but the hooks are going "
             "into the USER scope. If that checkout is ever deleted or moved, every "
             "session on this machine gets a failing hook. Either keep the clone "
             "somewhere permanent, or use --scope local so the two travel together.")
    if scope == "user" and not _is_within(install_dir, Path.home()):
        warn(f"{install_dir} is outside your home directory; make sure it is on a "
             "volume that is mounted before Claude Code starts.")


def warn_stale_autostart(install_dir: Path) -> None:
    """One line when the OPTIONAL shell block still guards a previous checkout.

    Re-cloning into a new directory repairs the settings entries and the PATH
    link, but not the `oe autostart` block: its `-x <old>/bin/oe` guard just
    stops matching, so the supervisor silently never starts and the shell says
    nothing. Read-only, and deliberately: writing to somebody's rc file is that
    command's job, not this one's -- this only names it.
    """
    try:
        from oe import autostart as autostart_mod
        rc = autostart_mod.default_rc()
        if not rc.is_file():
            return
        text = rc.read_text(encoding="utf-8", errors="surrogateescape")
        spans = autostart_mod.find_blocks(text)
        if not spans:
            return
        start, end = spans[0]
        target = autostart_mod.block_target(text[start:end])
        ours = install_dir / "bin" / DEFAULT_BIN_NAME
        if target is None or target == ours:
            return
    except Exception:
        return
    warn(f"the optional autostart block in {rc} still guards {target}, which is not "
         "this checkout, so the supervisor never starts and nothing says why. "
         f"Re-point it: {ours} autostart --install")


def main(argv: Optional[List[str]] = None) -> int:
    """Entry point. One line of bookkeeping around the run itself.

    An uninstall can now clean SEVERAL settings files in one invocation, and the
    exit code has to be the worst of them rather than the last of them: a run
    that refused to touch a corrupt file in one scope and succeeded in another
    must not report success, or the script driving it never learns that
    something was left behind.
    """
    global EXTRA_SCOPE_EXIT
    EXTRA_SCOPE_EXIT = 0
    code = _run(argv)
    return code or EXTRA_SCOPE_EXIT


def _run(argv: Optional[List[str]] = None) -> int:
    global LAST_RUN_NOOP, EXTRA_SCOPE_EXIT
    LAST_RUN_NOOP = False
    args = build_parser().parse_args(argv)
    interactive = stdin_is_interactive() and not args.non_interactive

    say()
    say(c("  Overwatch Enforcer -- installer", "1"))
    if not interactive:
        say(c("  non-interactive: every prompt takes its default.", "2"))

    # ---- 0. the PATH doctor ----------------------------------------------
    # Answered first, and without any of the prompts. It exists for somebody
    # whose `oe` is not found, and making them answer questions about settings
    # scopes to get a PATH diagnosis would be the wrong shape entirely. It also
    # takes the install directory from --dir or from this file's own location
    # rather than prompting: there is nothing to decide, only something to
    # report.
    if args.path_doctor or args.path_fix:
        if args.path_doctor and args.path_fix:
            fail("--path-doctor is the read-only half of --path-fix; pass one.")
            return 2
        fixing = bool(args.path_fix)
        if fixing and args.check:
            # --check's contract is that it writes nothing, ever. It outranks a
            # flag that would.
            warn("--check writes nothing; showing the diagnosis only.")
            fixing = False
        root = normalise_dir(args.directory) if args.directory else HERE
        return path_doctor(root, bin_name=args.bin_name, fix=fixing,
                           assume_yes=bool(args.yes), rc_override=args.rc)

    if args.restore_backup and not args.uninstall:
        fail("--restore-backup is what --uninstall does INSTEAD of removing our "
             "entries one by one; it is not an operation on its own. Re-run it as "
             "--uninstall --restore-backup.")
        return 2

    # ---- 1. the install directory ----------------------------------------
    install_dir = choose_install_dir(args.directory, interactive)
    upgrading = looks_installed(install_dir)
    say()
    say(f"  install directory  {install_dir}")
    # looks_installed() answers "is this a package tree?", which every clone is.
    # state/ answers "has this one ever been installed?" -- it is created by the
    # install itself and never tracked, so it is the only thing here that tells
    # a first run apart from an upgrade.
    if not upgrading:
        say("                     " + c("no package found here yet", "33"))
    elif (install_dir / "state").is_dir():
        say("                     " + c("existing install -- upgrade in place", "36"))
    else:
        say("                     " + c("a clean checkout -- first install", "32"))
    if not upgrading and not args.check:
        fail(f"{install_dir} does not contain oe/ and hooks/. This installer wires up "
             "a package that is already there; it does not copy one. Clone or move "
             "the tree first, then run its own install.py.")
        return 2

    # ---- 2. the settings file --------------------------------------------
    # An UNINSTALL takes its target from the install record, not from the
    # directory the user happens to be standing in. Choosing it from the cwd is
    # what let `--uninstall --yes`, run from HOME after an install made from a
    # project checkout, print "nothing to remove" and exit 0 while leaving every
    # hook entry and the statusLine wired -- and then take `oe` off PATH, so the
    # only command that could undo it was gone too. The record knew the answer
    # the whole time. An explicit --scope or --settings still wins: those are the
    # user overruling the record on purpose.
    recorded_targets: List[Dict[str, Any]] = []
    extra_targets: List[Dict[str, Any]] = []
    extras_noop = True
    if args.uninstall and not args.check and not args.settings and args.scope is None:
        recorded_targets = uninstall_targets(install_dir)

    if args.check and not args.settings and args.scope is None:
        settings_path = claude_home() / "settings.json"
        scope, committed = "user", False
    elif recorded_targets:
        render_uninstall_targets(recorded_targets)
        settings_path = Path(recorded_targets[0]["path"])
        scope = str(recorded_targets[0]["scope"])
        # The committed-scope warning is about WRITING hooks into a file a
        # teammate will clone. Taking them back out of one needs no such warning
        # and must never be gated behind a prompt.
        committed = False
        extra_targets = recorded_targets[1:]
    else:
        settings_path, scope, committed = resolve_settings_path(args, install_dir,
                                                                interactive)
        validate_combination(install_dir, settings_path, scope)

    # Every target after the first is cleaned by a full pass of this same code,
    # named explicitly with --settings so it resolves nothing and expands no
    # further. It runs BEFORE the primary pass reaches step 5 for one reason
    # that is not cosmetic: main() loads the manifest once and saves it once, so
    # a child that forgets its own row has to have finished before the parent
    # reads the file it will later write back.
    for target in extra_targets:
        say()
        say("  " + c(f"--- scope {target['scope']}: {target['path']} ---", "1"))
        child = ["--uninstall", "--settings", str(target["path"]),
                 "--dir", str(install_dir), "--only", args.only,
                 "--bin-name", args.bin_name, "--interpreter", args.interpreter,
                 # The PATH link and the rc block are machine-wide, not
                 # per-scope: the primary pass owns them, and a child that
                 # removed them would strand the user mid-run.
                 "--no-link", "--non-interactive"]
        if args.yes:
            child.append("--yes")
        if args.no_backup:
            child.append("--no-backup")
        if args.no_binary_probe:
            child.append("--no-binary-probe")
        if args.allow_missing_claude:
            child.append("--allow-missing-claude")
        if args.restore_backup:
            child.append("--restore-backup")
        code = _run(child)
        if not LAST_RUN_NOOP:
            extras_noop = False
        if code != 0:
            EXTRA_SCOPE_EXIT = max(EXTRA_SCOPE_EXIT, code)
            fail(f"the pass over {target['path']} exited {code}; continuing with "
                 "the remaining scope(s) so nothing is left half-removed.")
    if extra_targets:
        say()
        say("  " + c(f"--- scope {scope}: {settings_path} ---", "1"))

    # ---- 3. the interpreter ----------------------------------------------
    interpreter, why = resolve_interpreter(args.interpreter, install_dir, committed)

    # ---- 4. THE CHECKLIST. Nothing above here has written anything. -------
    # Check the root that will actually be USED, not the one the checkout was
    # packaged with -- otherwise the checklist green-lights a directory we are
    # about to replace, and reds a directory nobody will ever write to.
    reports_plan = plan_reports_root(install_dir)
    reports_root = reports_plan.get("effective")
    report = checklist_mod.build(
        install_dir, settings_path, interpreter,
        probe_binary=not args.no_binary_probe,
        # Removing hooks does not need Claude Code to be present. Uninstalling
        # Claude Code first and then taking out what it left behind is the
        # normal order, and it is exactly the case where this check would
        # otherwise refuse. The filesystem and settings rows still gate below;
        # only the "is Claude Code installed" row is waived, and only here.
        allow_missing_claude=(args.allow_missing_claude or args.uninstall),
        reports_root=reports_root)
    print(checklist_mod.render(report))
    say(f"  interpreter to bake in: {interpreter}")
    say("  " + c(why, "2"))
    say()

    if not report.ok:
        # An uninstall is gated only by what would make removal unsafe -- an
        # unreadable or unparseable settings file. Anything else is a
        # prerequisite for INSTALLING, and refusing to clean up because the
        # machine is not ready to install is backwards: it strands the user
        # with wired hooks and tells them to fix an irrelevance first.
        blocking = report.failures
        if args.uninstall:
            # Waive by RELEVANCE, not by group. Only a settings file we cannot
            # read or parse can make a removal unsafe; everything else on the
            # checklist is a prerequisite for INSTALLING. Grouping got this
            # wrong twice: there is no "Settings" group at all, and Filesystem
            # carries 'reports root' and 'free disk', neither of which has
            # anything to do with taking hooks back out.
            blocking = [r for r in report.failures
                        if "settings" in f"{r.group} {r.name}".lower()]
        if blocking:
            fail(f"{len(blocking)} hard failure(s). Nothing was written.")
            for row in blocking:
                fail(f"{row.group}/{row.name}: {row.found}")
            if any("settings" in f"{r.group} {r.name}".lower() for r in blocking):
                # A settings file this installer cannot read or parse is the one
                # failure it can point somewhere for. bin/oe-repair quotes the
                # offending line with a caret under the column, finds every
                # scope rather than just this one, and imports nothing from oe/
                # -- so it still runs on a machine where this installer's own
                # imports would not, which is why it is a separate file.
                say(f"  Diagnose the settings file: python3 {HERE}/bin/oe-repair")
            return 1
        if report.failures:
            warn(f"{len(report.failures)} check(s) failed, none of which prevent "
                 f"removal; continuing with the uninstall.")
    # Both of these belong to a FULL install. `oe install-statusline` runs this
    # same code with --only statusline and is documented as touching one
    # settings key and nothing else; putting a symlink on PATH and rewriting
    # config.json behind that command would make the documentation false.
    # The one record of what this install touches. Loaded here rather than at
    # the top because everything above this line is a read: --check must be able
    # to run on a tree that has no state/ directory at all, and a manifest is
    # about writes.
    man = manifest_mod.Manifest.load(install_dir)
    if man.status == "unreadable":
        warn(f"the install manifest at {man.path} could not be read; treating this "
             "as no record at all. The uninstall stays surgical -- it just cannot "
             "prove whether a file was edited since we wrote it.")

    whole_install = args.only == "all"
    if whole_install and not args.uninstall:
        warn_stale_autostart(install_dir)
    link_plan = plan_bin_link(install_dir, bin_name=args.bin_name,
                              explicit_dir=args.link_dir,
                              enabled=(not args.no_link and not args.uninstall
                                       and whole_install))
    if not whole_install:
        reports_plan = {"action": "none", "path": install_dir / CONFIG_NAME,
                        "current": "", "new": None, "why": "",
                        "effective": reports_root, "source": None}
    if not args.uninstall and whole_install:
        render_reports_root(reports_plan,
                            will_write=bool(args.yes) and not args.check)
        if not args.check:
            link_plan = offer_bin_link(link_plan, interactive)
        render_bin_link(link_plan, will_write=bool(args.yes) and not args.check)

    if args.check:
        say()
        say("  --check: the checklist only. Nothing was written.")
        return 0

    # ---- 5. read, merge, verify ------------------------------------------
    original_text = ""
    settings: Dict[str, Any] = {}
    created = False
    if settings_path.exists():
        try:
            original_text = read_exact(settings_path)
            settings = json.loads(original_text)
        except json.JSONDecodeError as exc:
            fail(f"{settings_path} is not valid JSON (line {exc.lineno}, col "
                 f"{exc.colno}: {exc.msg}).")
            fail("Refusing to rewrite a file we cannot parse -- we could not prove we "
                 "preserved your settings. Fix or move it and re-run.")
            return 2
        except Exception as exc:
            fail(f"cannot read {settings_path}: {type(exc).__name__}: {exc}")
            return 2
        if not isinstance(settings, dict):
            fail(f"{settings_path} is not a JSON object; refusing to touch it")
            return 2
    else:
        if args.uninstall:
            if args.restore_backup:
                # The settings file is gone, but the pre-install copy of it is
                # not -- and putting that back is precisely what somebody in
                # this situation is asking for. Handled here rather than below,
                # because "nothing to remove" is the wrong answer to it.
                return restore_pre_install(install_dir, settings_path, "", {},
                                           args, man)
            say(f"  {settings_path} does not exist; nothing to remove.")
            stranded = stranded_targets(install_dir, settings_path, args)
            if stranded:
                return report_stranded(stranded, settings_path)
            # The settings file is not the only thing an install leaves behind.
            rows = []
            if args.only == "all" and not args.no_link:
                rows = remove_bin_link(install_dir, bin_name=args.bin_name,
                                       apply=bool(args.yes))
                rows += drop_path_block(install_dir, man, apply=bool(args.yes))
                if rows:
                    say()
                    say("  PATH")
                    for row in rows:
                        say("    - " + row + ("" if args.yes else "   (dry run)"))
            warn_no_record(recorded_targets, args, rows)
            if args.yes:
                # The settings file is gone, so its row is stale whatever it
                # says; drop it rather than leave a record pointing at nothing.
                man.forget(settings_path, "settings")
                _forget_dead_links(install_dir, man)
                man.save()
            LAST_RUN_NOOP = not rows and extras_noop
            return 0
        created = True
        settings = {}
        original_text = ""
        say(f"  {settings_path} does not exist and will be created.")

    # --restore-backup replaces the whole merge rather than modifying it: it
    # writes bytes over the file instead of editing a parsed document, so the
    # key-by-key verification below -- which exists to prove we changed NOTHING
    # we do not own -- has nothing to say about it and must not be routed
    # through. It reports its own losses instead, in more detail.
    if args.restore_backup:
        return restore_pre_install(install_dir, settings_path, original_text,
                                   settings, args, man)

    before = copy.deepcopy(settings)
    say(f"  {len(before)} top-level key(s)"
        + (": " + ", ".join(before.keys()) if before else ""))
    state = install_state(before, install_dir)
    say(f"  current state: {c(state['state'], '36')}"
        f"  ({state['hooks_present']}/{state['hooks_expected']} hooks"
        + (", statusLine" if state["statusline"] else "") + ")")
    if state["state"] == "partial":
        warn("PARTIAL install detected -- missing: " + ", ".join(state["missing"]))
        warn("the merge below repairs it; nothing needs to be removed first.")
    say()

    pending_stash: Dict[str, Any] = {}
    consumed_stash: List[Path] = []
    try:
        if args.uninstall:
            changes = remove_ours(settings, install_dir, args.only, settings_path,
                                  consumed_stash)
            if args.only == "all":
                changes += sweep_stale(settings, install_dir)
        else:
            changes = []
            if args.only == "all":
                changes += sweep_stale(settings, install_dir)
            if args.only in ("all", "hooks"):
                changes += merge_hooks(settings, interpreter, install_dir)
            if args.only in ("all", "statusline"):
                changes += merge_statusline(settings, interpreter, install_dir,
                                            args.force_statusline, settings_path,
                                            pending_stash)
    except SystemExit as exc:
        fail(str(exc))
        return 2

    def drop_link(apply_it: bool) -> List[str]:
        """Uninstall half of the PATH link. Only under --only all: a partial
        uninstall that still leaves the hooks wired must not take the command
        that manages them off PATH."""
        if not (args.uninstall and args.only == "all" and not args.no_link):
            return []
        rows = remove_bin_link(install_dir, bin_name=args.bin_name, apply=apply_it)
        # The rc block --path-fix wrote is part of the same undo: without it a
        # directory that no longer exists stays on the user's PATH for good.
        rows += drop_path_block(install_dir, man, apply=apply_it)
        if rows:
            say()
            say("  PATH")
            for row in rows:
                say("    - " + row + ("" if apply_it else "   (dry run)"))
        if apply_it:
            _forget_dead_links(install_dir, man)
        return rows

    problems = verify_untouched(before, settings)
    if problems:
        fail("ABORT -- the merge would have altered keys it does not own:")
        for problem in problems:
            fail("    " + problem)
        return 3

    touched = MANAGED_KEYS if args.only == "all" else (
        ("hooks",) if args.only == "hooks" else ("statusLine",))
    for key in [k for k in before if k in MANAGED_KEYS and k not in touched]:
        if json.dumps(before[key], sort_keys=True) != json.dumps(settings.get(key),
                                                                 sort_keys=True):
            fail(f"ABORT -- --only={args.only} altered {key}")
            return 3
    preserved = [k for k in before if k not in MANAGED_KEYS]
    say(f"  verified: {len(preserved)}/{len(preserved)} unmanaged keys byte-identical "
        "and in the original order")

    after_text = render(settings)
    baseline = baseline_path(install_dir, settings_path)

    # Before deciding anything, say what has happened to this file since we
    # wrote it. The manifest answers that from a checksum rather than a guess,
    # and the answer is what separates "restoring the backup is a perfect undo"
    # from "restoring the backup destroys six months of the user's config".
    if args.uninstall:
        render_uninstall_verdict(man.verdict(settings_path, "settings"),
                                 settings_path, baseline, man)

    # An uninstall that lands back on the document we first saw restores the
    # ORIGINAL BYTES, not a re-render of them. The equality test is the gate, not
    # the manifest verdict: it is the stronger evidence of the two -- it proves
    # the surgical removal actually arrived at the pre-install document, which is
    # the only thing that makes writing those bytes a no-op rather than a change.
    # (An --only hooks uninstall, for instance, correctly leaves our statusLine
    # in place, so the documents differ and the bytes must NOT be restored, even
    # though the file is untouched by anyone else.)
    restored_bytes = False
    if args.uninstall and baseline.exists():
        try:
            saved = read_exact(baseline)
            if json.loads(saved) == settings:
                after_text = saved
                restored_bytes = True
        except Exception:
            restored_bytes = False

    baseline_text = render(before) if not created else ""
    if original_text and baseline_text != original_text and not restored_bytes:
        warn("the file's current formatting is not json.dumps(indent=2); writing will")
        warn("  normalise it. The diff below is semantic -- inspect the whitespace too.")
    patch = diff(original_text if restored_bytes else baseline_text, after_text,
                 settings_path)

    if not changes and after_text == original_text:
        say()
        if args.uninstall:
            say("  not installed in this file; nothing to remove.")
            stranded = stranded_targets(install_dir, settings_path, args)
            if stranded:
                # Before the PATH link goes. Taking `oe` away on a run that
                # removed nothing is what left the user with live hooks and no
                # command to undo them with.
                return report_stranded(stranded, settings_path)
        else:
            say(c("  already installed and up to date; nothing to do.", "32"))
        link_rows = drop_link(bool(args.yes))
        if args.uninstall:
            warn_no_record(recorded_targets, args, link_rows)
        if not args.uninstall and args.yes:
            _apply_and_record_reports_root(reports_plan, man)
            apply_bin_link(link_plan, install_dir, man)
        if args.yes:
            man.save()
        LAST_RUN_NOOP = not link_rows and extras_noop
        return 0

    say()
    say("  changes:")
    for change in changes:
        say("    - " + change)
    if restored_bytes:
        say("    - restore the original bytes from " + str(baseline))
    say()
    say(colourise(patch) if patch else "  (no textual change)")

    if not args.yes:
        drop_link(False)
        say()
        say(c("  DRY RUN -- nothing written. Re-run with --yes to apply.", "1"))
        return 0

    # ---- 6. write, verify, roll back on failure --------------------------
    # Taken before anything is touched, so the manifest row records the file as
    # it genuinely was rather than as it is a few lines later.
    digest_before = manifest_mod.digest(settings_path)
    backup = None
    if settings_path.exists() and not args.no_backup:
        backup = next_backup(settings_path)
        shutil.copy2(settings_path, backup)
        if backup.read_bytes() != settings_path.read_bytes():
            fail(f"the backup at {backup} does not match the original; refusing to write")
            return 3
        say(f"  backup      {backup}")
    elif not settings_path.exists():
        settings_path.parent.mkdir(parents=True, exist_ok=True)

    if pending_stash.get("path") is not None:
        try:
            stash_path: Path = pending_stash["path"]
            stash_path.parent.mkdir(parents=True, exist_ok=True)
            stash_path.write_text(
                json.dumps(pending_stash["value"], indent=2) + "\n",
                encoding="utf-8")
            say(f"  stashed     {stash_path}  (the statusLine we displaced)")
            man.record(stash_path, kind="statusline-stash", action="stashed",
                       wrote=manifest_mod.digest(stash_path),
                       scope=scope)
        except Exception as exc:
            fail(f"could not stash the displaced statusLine ({exc}); refusing to "
                 "replace a statusLine we could not save first")
            return 3

    if not args.uninstall and original_text and not baseline.exists():
        try:
            baseline.parent.mkdir(parents=True, exist_ok=True)
            baseline.write_bytes(original_text.encode("utf-8"))
            say(f"  baseline    {baseline}  (byte-exact pre-install copy)")
        except Exception as exc:
            warn(f"could not record a baseline ({exc}); --uninstall will restore "
                 "semantically rather than byte-for-byte")

    try:
        atomic_replace(settings_path, after_text)
    except Exception as exc:
        fail(f"write failed: {type(exc).__name__}: {exc}")
        if backup is not None and backup.exists():
            try:
                same = backup.read_bytes() == settings_path.read_bytes()
            except Exception:
                same = False
            if same:
                # atomic_replace never got as far as os.replace, so the file on
                # disk is still the one we copied. Restoring it would be a no-op
                # and the .bak would be litter the user has to reason about.
                try:
                    backup.unlink()
                    say(f"  the file is untouched; removed the unused {backup}")
                except Exception:
                    pass
            else:
                try:
                    shutil.copy2(backup, settings_path)
                    fail(f"restored {settings_path} from {backup}")
                except Exception as restore_exc:
                    fail(f"COULD NOT RESTORE {settings_path} from {backup}: "
                         f"{type(restore_exc).__name__}: {restore_exc}")
                    fail(f"your original settings are intact at {backup} -- "
                         "copy it back by hand.")
        return 3

    try:
        written = json.loads(read_exact(settings_path))
    except Exception as exc:
        written = None
        fail(f"could not re-read what we wrote: {exc}")
    problems = verify_untouched(before, written) if isinstance(written, dict) \
        else ["the written file is not a JSON object"]
    if problems:
        fail("WROTE A FILE THAT FAILS VERIFICATION:")
        for problem in problems:
            fail("    " + problem)
        if backup is not None and backup.exists():
            shutil.copy2(backup, settings_path)
            fail(f"ROLLED BACK: restored {settings_path} from {backup}")
        return 3

    say(f"  wrote       {settings_path}")
    say("  verified on disk: every unmanaged key intact.")

    # Record AFTER the verification, never before it: a manifest row is a claim
    # that this is the file we left behind, and a write that failed verification
    # was rolled back to something else entirely.
    if not args.uninstall:
        man.record(settings_path, kind="settings",
                   action="created" if created else "modified",
                   before=digest_before,
                   wrote=manifest_mod.digest(settings_path),
                   backup=backup, scope=scope,
                   baseline=baseline if baseline.exists() else None)

    if args.uninstall:
        say()
        say("  removed:")
        for change in changes:
            say("    - " + change)
        if restored_bytes:
            say(c("  the file is byte-identical to the copy taken before install.",
                  "32;1"))
            try:
                baseline.unlink()
            except Exception:
                pass
        for stash in consumed_stash:
            # Restored and written. Leaving it would restore it again into
            # whatever file is uninstalled next.
            try:
                stash.unlink()
                say(f"  consumed    {stash}")
            except Exception:
                pass
            man.forget(stash, "statusline-stash")
        # This settings file is no longer ours to account for. Only this one:
        # the manifest may hold rows for other scopes somebody installed into,
        # and an uninstall of one file must not forget the others.
        man.forget(settings_path, "settings")
        drop_link(True)
    else:
        # Both of these come AFTER the settings write, and only after it
        # verified: a symlink to a tool whose hooks did not land is a worse
        # state than no symlink at all, because it looks installed.
        _apply_and_record_reports_root(reports_plan, man)
        linked = apply_bin_link(link_plan, install_dir, man)
        what = {"statusline": "status line", "hooks": "hooks"}.get(args.only, "hooks")
        say()
        say(f"  Start a new Claude Code session for the {what} to load.")
        if linked:
            say(f"  Then: {args.bin_name} doctor")
        else:
            # The plan's own target: --bin-name renames the LINK, never the file
            # it aims at, so bin/<bin_name> is a path that does not exist.
            say(f"  Then: {link_plan['target']} doctor")
            say(f"  If `{args.bin_name}` is not found in a new terminal:")
            say(f"      {HERE / 'install.py'} --path-doctor")

    # One save for the whole run. The manifest is bookkeeping about writes that
    # have already landed and been verified, so it is written last and its
    # failure is a warning rather than an abort -- an uninstall degrades to
    # surgical-only, which is what it does on a fresh machine anyway.
    if not man.save():
        warn(f"could not write the install manifest at {man.path}; the install "
             "itself is fine, but the uninstall will not be able to prove whether "
             "a file was edited since we wrote it.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
